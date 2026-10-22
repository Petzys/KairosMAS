"""The enforcement point of one agent host.

It sits at the host boundary and sees everything that crosses it: the agent's
external effects (tool calls here; HTTP requests and file operations in the
deployed stack), the agent's A2A requests to other agents and the replies that
come back, and the requests other agents send it and the replies it sends. It
numbers what it sees (the agent's sequencer lives in the monitor), asks the
cluster's decision point, and applies the answer: forward, block, stall, stub.

Stalling a message uses the protocol's own states, so a caller only ever sees a
delay: a streamed message on hold is a task in state 'working', a denied one is
'rejected' with a notice. Released messages carry the monitor's message id next
to them (a header only enforcement points read), which the receiving side uses to
record the delivery and join labels.
"""
from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kairos.adapters.agentdojo.translate import call_to_event, result_to_event
from kairos.core.events import Channel, Event
from kairos.engine.decision import Decision
from kairos.mas import notices
from kairos.mas.a2a.adapter import A2AAdapter, CommKind, Delivery, InterAgentMessage
from kairos.mas.a2a.protocol import (
    Artifact, ArtifactUpdate, ErrorCode, Message, Part, ProtocolError, Response, RpcError,
    StatusUpdate, Task, TaskState, TaskStatus, new_id, parse_response,
)
from kairos.mas.agent import AgentMonitor, MessageRecord, MsgStatus, Outcome
from kairos.mas.fabric import MonitorFabric
from kairos.mas.transport import KMID_HEADER, EventStream, Headers, Network
from kairos.speculative.effects import EffectKind

FROM_HEADER = "x-kairos-from"          # requester of a poll (who receives the content)

ToolExecutor = Callable[[str, dict[str, Any]], tuple[Any, str | None]]


@dataclass(slots=True)
class ToolOutcome:
    text: str
    error: str | None = None
    executed: bool = False
    held: bool = False


@dataclass(slots=True)
class _LocalTask:
    """A streamed request as its sender sees it, under the id the sender knows."""
    id: str
    url: str
    request: InterAgentMessage
    record: MessageRecord | None
    stream: EventStream = field(default_factory=EventStream)
    state: TaskState = TaskState.SUBMITTED
    texts: list[str] = field(default_factory=list)
    data: list[dict[str, Any]] = field(default_factory=list)
    notice: str = ""
    context_id: str = field(default_factory=lambda: new_id("ctx-"))
    alias_of: "_LocalTask | None" = None


class EnforcementPoint:
    def __init__(self, fabric: MonitorFabric, agent_id: str, network: Network, *,
                 adapter: A2AAdapter | None = None, defense: bool = True,
                 formatter: Callable[[Any], str] = str) -> None:
        self.fabric = fabric
        self.agent_id = agent_id
        self.network = network
        self.adapter = adapter or A2AAdapter()
        self.defense = defense
        self.formatter = formatter
        self.server: Any = None                       # the agent's A2A server (set by the host)
        self._tasks: dict[str, _LocalTask] = {}
        self._released_replies: dict[tuple[str | None, str], str] = {}
        self._lock = threading.Lock()
        self._threads: list[threading.Thread] = []

    @property
    def spec(self):
        return self.fabric.spec

    @property
    def monitor(self) -> AgentMonitor:
        return self.fabric.agent(self.agent_id)

    def reset(self) -> None:
        with self._lock:
            self._tasks.clear()
            self._released_replies.clear()
            self._threads.clear()

    def join(self, timeout: float = 30.0) -> None:
        """Wait for background deliveries started by this host."""
        for t in list(self._threads):
            t.join(timeout)

    def _spawn(self, fn: Callable[..., Any], *args: Any) -> None:
        t = threading.Thread(target=fn, args=args, daemon=True)
        with self._lock:
            self._threads.append(t)
        t.start()

    # =====================================================================
    # external effects (the single-agent KAIROS path, per call)
    # =====================================================================
    def call_tool(self, tc: Any, execute: ToolExecutor) -> ToolOutcome:
        """One tool call of the agent. Mirrors adapters/agentdojo/hooks.PolicyEnforcer
        for a single call; abort notices are queued on the monitor and handed to
        the agent by its harness (drain_notices)."""
        if not self.defense:
            res, err = execute(tc.function, dict(tc.args))
            return ToolOutcome(self.formatter(res), err, executed=True)
        mon = self.monitor
        with mon.lock:
            mon.executor = lambda cr, args: execute(cr.function, args)
            event = call_to_event(tc, turn_id=0)
            stage = mon.gate(event)
            decision = stage.decision.value
            if decision == "DENY":
                return ToolOutcome("", f"Blocked by reference monitor: {stage.reason or stage.produced_by}")
            ev = mon.event_view(event, call_ref=tc, decision=stage)
            if mon.can_adjudicate(decision, ev):
                ok, verdict = mon.adjudicate(ev)
                if not ok:
                    return ToolOutcome("", notices.get_refused(tc.function, verdict.rationale))
                eff = None
            else:
                eff = mon.speculate(decision, ev)

            if eff is not None and eff.kind is EffectKind.STUB:
                return ToolOutcome(str(eff.stub_value), held=True)
            if eff is not None and eff.kind is EffectKind.BLOCK:
                return ToolOutcome("", f"Blocked: {eff.reason}")
            args = dict(tc.args)
            if eff is not None and eff.kind is EffectKind.RESOLVE:
                r = mon.resolve(eff.trigger.name if eff.trigger else "RESOLVE", pending=ev)
                assert r is not None
                _cdec, branch, outcome = r
                if mon.hold_notice == "honest":
                    dup = next((d for d in outcome.dispatched
                                if d[0].tool == tc.function and d[0].args == tc.args), None)
                    if dup is not None:            # a re-issue answered with the real result
                        _, real_res, real_err = dup
                        text = self.formatter(real_res)
                        if real_err is None:
                            mon.admit_result(result_to_event(tc, text, turn_id=0))
                        return ToolOutcome(text, real_err, executed=True)
                re_stage = mon.gate(call_to_event(tc, turn_id=0))
                if re_stage.decision is Decision.DENY:
                    return ToolOutcome("", f"Blocked: {re_stage.reason}")
                re_ev = mon.event_view(call_to_event(tc, turn_id=0), call_ref=tc, decision=re_stage)
                if mon.can_adjudicate(re_stage.decision.value, re_ev):
                    ok, verdict = mon.adjudicate(re_ev)
                    if not ok:
                        return ToolOutcome("", notices.get_refused(tc.function, verdict.rationale))
                    re_eff = None
                else:
                    re_eff = mon.speculate(re_stage.decision.value, re_ev)
                if re_eff is not None and re_eff.kind is EffectKind.STUB:
                    return ToolOutcome(str(re_eff.stub_value), held=True)
                if re_eff is not None and re_eff.kind is not EffectKind.EXECUTE:
                    return ToolOutcome("", "A prior speculative action was reverted; this action "
                                           "could not be completed automatically. If it is part of "
                                           "your original request, please re-issue it.")
                if any(branch.stubs.contains_marker(v) for v in args.values()):
                    args = branch.stubs.substitute_real(args)
            res, err = execute(tc.function, args)
            text = self.formatter(res)
            if err is None:
                mon.admit_result(result_to_event(tc, text, turn_id=0))
            return ToolOutcome(text, err, executed=True)

    def terminal(self) -> bool:
        """The agent finished a task. Returns True if a resolution withheld
        something (its notices are queued: drain_notices)."""
        if not self.defense:
            return False
        r = self.monitor.on_terminal()
        return bool(r is not None and r[2].aborted)

    def drain_notices(self) -> list[str]:
        return self.monitor.drain_notices() if self.defense else []

    # =====================================================================
    # A2A client side: the agent's requests to other agents
    # =====================================================================
    def send(self, url: str, body: bytes) -> bytes:
        """A blocking request (message/send), a poll or a control call."""
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return Response(id=None, error=RpcError(int(ErrorCode.INVALID_REQUEST), str(e))).to_bytes()
        if msg.kind is CommKind.POLL:
            return self._poll(url, msg, body)
        if msg.kind is CommKind.CONTROL:
            return self._forward(url, body)[0]
        if msg.delivery is Delivery.STREAMING:          # message/send with blocking=false
            local = self._start(url, msg, body)
            return self._snapshot(local, msg).to_bytes()
        dest = self.spec.agent_at(url)
        if dest is None:
            return self._external(url, msg, body)
        if not self.defense:
            return self._forward(url, body)[0]
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, delivery=Delivery.BLOCKING)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.REJECT:
            return self.adapter.rejected(msg, new_id("task-"), d.notice)
        resp, hdrs = self._forward(url, body, rec)
        self._accept_reply(hdrs)
        return resp

    def send_stream(self, url: str, body: bytes) -> EventStream:
        """A streaming request (message/stream) or a resubscription."""
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            s = EventStream()
            s.put(Response(id=None, error=RpcError(int(ErrorCode.INVALID_REQUEST), str(e))).to_bytes())
            s.close()
            return s
        if msg.kind is CommKind.POLL:
            s = EventStream()
            s.put(self._poll(url, msg, body))
            s.close()
            return s
        return self._start(url, msg, body).stream

    def _start(self, url: str, msg: InterAgentMessage, body: bytes) -> _LocalTask:
        dest = self.spec.agent_at(url)
        local = _LocalTask(id=new_id("task-"), url=url, request=msg, record=None,
                           context_id=msg.context_id or new_id("ctx-"))
        with self._lock:
            self._tasks[local.id] = local
        if dest is None or not self.defense:
            if dest is None:
                local.stream.put(self._external(url, msg, body))
                local.stream.close()
                return local
            self._spawn(self._forward_stream, local, body)
            return local
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, delivery=Delivery.STREAMING)
        local.record = rec
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.REJECT:
            self._reject_local(local, d.notice)
        elif d.outcome is Outcome.HOLD:
            local.state = TaskState.WORKING
            local.stream.put(self.adapter.working(msg, local.id))
            rec.on_release = lambda _r: self._spawn(self._forward_stream, local, body)
            rec.on_drop = lambda _r, notice: self._reject_local(local, notice)
        elif d.duplicate_of is not None:
            orig = self._task_for(d.duplicate_of)
            local.alias_of = orig
            local.state = TaskState.WORKING
            local.stream.put(self.adapter.working(msg, local.id))
            local.stream.close()
        else:
            self._spawn(self._forward_stream, local, body)
        return local

    def _task_for(self, record: MessageRecord) -> _LocalTask | None:
        with self._lock:
            return next((t for t in self._tasks.values() if t.record is record), None)

    def _reject_local(self, local: _LocalTask, notice: str) -> None:
        local.state = TaskState.REJECTED
        local.notice = notice
        local.stream.put(self.adapter.rejected(local.request, local.id, notice))
        local.stream.close()

    def _forward(self, url: str, body: bytes, rec: MessageRecord | None = None) -> tuple[bytes, Headers]:
        headers: Headers = {FROM_HEADER: self.agent_id}
        if rec is not None:
            headers[KMID_HEADER] = rec.kmid
        try:
            return self.network.request(url, body, headers)
        except ConnectionError as e:
            return Response(id=None, error=RpcError(int(ErrorCode.INTERNAL_ERROR), str(e))).to_bytes(), {}

    def _forward_stream(self, local: _LocalTask, body: bytes) -> None:
        headers: Headers = {FROM_HEADER: self.agent_id}
        if local.record is not None:
            headers[KMID_HEADER] = local.record.kmid
        try:
            upstream = self.network.stream(local.url, body, headers)
        except ConnectionError as e:
            self._reject_local(local, f"transport error: {e}")
            return
        for ev_body, hdrs in upstream:
            self._accept_reply(hdrs)
            local.stream.put(self._localize(local, ev_body))
        local.stream.close()

    def _localize(self, local: _LocalTask, body: bytes) -> bytes:
        """Track the task's state and present it under the sender's task id."""
        try:
            resp = parse_response(body)
        except ProtocolError:
            return body
        res = resp.result
        if isinstance(res, Task):
            res.id = local.id
            local.state = res.status.state
            for a in res.artifacts:
                self._collect(local, a.parts)
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, StatusUpdate):
            res.task_id = local.id
            local.state = res.status.state
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, ArtifactUpdate):
            res.task_id = local.id
            self._collect(local, res.artifact.parts)
        elif resp.error is not None:
            local.state, local.notice = TaskState.FAILED, resp.error.message
        return resp.to_bytes()

    @staticmethod
    def _collect(local: _LocalTask, parts: list) -> None:
        for p in parts:
            if p.kind == "text" and p.text:
                local.texts.append(p.text)
            elif p.kind == "data" and p.data is not None:
                local.data.append(p.data)

    def _poll(self, url: str, msg: InterAgentMessage, body: bytes) -> bytes:
        """tasks/get or resubscribe for a task this agent started. Asking for a
        held task's outcome is a dependency on the held effect: resolve now."""
        with self._lock:
            local = self._tasks.get(msg.task_id or "")
        if local is None:
            resp, hdrs = self._forward(url, body)
            self._accept_reply(hdrs)
            return resp
        target = local.alias_of or local
        if self.defense and target.record is not None and target.record.status is MsgStatus.HELD:
            self.monitor.await_held(target.record)
        return self._snapshot(target, msg, as_id=local.id).to_bytes()

    def _snapshot(self, local: _LocalTask, msg: InterAgentMessage, as_id: str | None = None) -> Response:
        parts = [Part.from_text(t) for t in local.texts] + [Part.from_data(d) for d in local.data]
        status = TaskStatus(local.state, message=Message.agent_text(local.notice) if local.notice else None)
        task = Task(id=as_id or local.id, context_id=local.context_id, status=status,
                    artifacts=[Artifact(parts=parts)] if parts else [])
        rpc_id = msg.raw.id if hasattr(msg.raw, "id") else None
        return Response(id=rpc_id, result=task)

    def _accept_reply(self, headers: Headers) -> None:
        """A reply carrying released content arrived: record the delivery here."""
        if not self.defense:
            return
        rec = self.fabric.message(headers.get(KMID_HEADER))
        if rec is not None and rec.receiver == self.agent_id and rec.status is MsgStatus.RELEASED:
            self.fabric.deliver(rec)

    def _external(self, url: str, msg: InterAgentMessage, body: bytes) -> bytes:
        """A2A to a party outside the system: an external effect like any other
        request to the outside, under the cluster's external contact book."""
        if not self.defense:
            return self._forward(url, body)[0]
        mon = self.monitor
        with mon.lock:
            content: dict[str, Any] = {"message": msg.text}
            ev = Event(0.0, Channel.NET, "POST", self.agent_id, url, content, {"function": "a2a.external"})
            stage = mon.gate(ev)
            if stage.decision is Decision.DENY:
                return self.adapter.rejected(msg, new_id("task-"), notices.message_rejected(url, stage.reason))
            if stage.decision is Decision.REVIEW:
                view = mon.event_view(ev, call_ref=None, decision=stage)
                ok, verdict = mon.adjudicate_effect(view, (), mode="sync_external")
                if not ok:
                    return self.adapter.rejected(msg, new_id("task-"),
                                                 notices.message_rejected(url, verdict.rationale))
        return self._forward(url, body)[0]

    # =====================================================================
    # A2A server side: other agents' requests to this agent
    # =====================================================================
    def serve(self, body: bytes, headers: Headers) -> tuple[bytes, Headers]:
        rec = self.fabric.message(headers.get(KMID_HEADER))
        requester = rec.sender if rec is not None else headers.get(FROM_HEADER)
        if self.defense and rec is not None and rec.receiver == self.agent_id:
            self.fabric.deliver(rec)
        resp = self.server.handle(body)
        if not self.defense or requester not in self.spec.agents:
            return resp, {}
        return self._gate_reply(resp, requester, rec.kmid if rec else None)

    def serve_stream(self, body: bytes, headers: Headers) -> EventStream:
        rec = self.fabric.message(headers.get(KMID_HEADER))
        requester = rec.sender if rec is not None else headers.get(FROM_HEADER)
        if self.defense and rec is not None and rec.receiver == self.agent_id:
            self.fabric.deliver(rec)
        upstream = self.server.handle_stream(body)
        if not self.defense or requester not in self.spec.agents:
            return upstream
        out = EventStream()

        def pump() -> None:
            blocked = False
            for ev_body, _ in upstream:
                if blocked:
                    continue
                gated, hdrs = self._gate_reply(ev_body, requester, rec.kmid if rec else None)
                out.put(gated, hdrs)
                blocked = hdrs.get("x-kairos-withheld") == "1"
            out.close()

        self._spawn(pump)
        return out

    def _gate_reply(self, body: bytes, requester: str, in_reply_to: str | None) -> tuple[bytes, Headers]:
        """Content leaving this agent for `requester`: a reply, decided like a
        blocking message (the agent has finished; nothing later to wait for)."""
        try:
            reply = self.adapter.parse_replies(body)[0]
        except ProtocolError:
            return body, {}
        if not reply.has_content:
            return body, {}
        key = (reply.task_id, reply.text + repr(reply.data))
        with self._lock:
            known = self._released_replies.get(key)
        if known is not None:                       # the same content, already released
            return body, {KMID_HEADER: known}
        rec = self.fabric.new_message(self.agent_id, requester, reply.text, reply.data, reply=True,
                                      in_reply_to=in_reply_to)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.RELEASE:
            with self._lock:
                self._released_replies[key] = rec.kmid
            return body, {KMID_HEADER: rec.kmid}
        self.monitor.notify(notices.reply_withheld(requester, rec.reason or "denied"))
        return self._withheld(body, reply), {"x-kairos-withheld": "1"}

    def _withheld(self, body: bytes, reply: InterAgentMessage) -> bytes:
        """The reply replaced by a failed task carrying the monitor's notice."""
        try:
            resp = parse_response(body)
        except ProtocolError:
            resp = Response(id=None)
        notice = notices.reply_unavailable(self.agent_id)
        status = TaskStatus(TaskState.FAILED, message=Message.agent_text(notice))
        task_id = reply.task_id or new_id("task-")
        ctx = reply.context_id or new_id("ctx-")
        if isinstance(resp.result, (StatusUpdate, ArtifactUpdate)):
            result: Any = StatusUpdate(task_id, ctx, status, final=True)
        else:
            result = Task(id=task_id, context_id=ctx, status=status)
        return Response(id=resp.id, result=result).to_bytes()
