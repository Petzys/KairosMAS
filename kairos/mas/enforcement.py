"""The enforcement point of one agent host.

It sits at the host boundary and sees everything that crosses it: the agent's
external effects (tool calls here; HTTP requests and file operations in the
deployed stack), the agent's A2A requests to other agents and the replies that
come back, and the requests other agents send it and the replies it sends. It
numbers what it sees (the agent's sequencer lives in the monitor), asks the
cluster's decision point, and applies the answer: forward, block, stall, stub.

Stalling a message uses the protocol's own states, so a caller only ever sees a
delay: a streamed message on hold is a task in state 'working', a denied one is
'rejected' with a notice.

Three rules keep the channel honest against an adversarial agent:
  * forward exactly what was decided: requests and replies are re-serialized from
    the checked view (no metadata, no history, no agent-chosen ids the monitor
    cannot map); a reply that does not parse is withheld, never passed through;
  * a poll or control call is forwarded only for a task the agent started, under
    the peer's real task id;
  * a released message travels with the monitor's id, a single-use capability for
    exactly its bytes (digest checked where it is consumed). A request that carries
    no valid capability comes from a party the monitor does not vouch for: its
    content is untrusted, and the reply to it is an external effect.
"""
from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kairos.adapters.agentdojo.translate import call_to_event, result_to_event
from kairos.engine.decision import Decision
from kairos.mas import notices
from kairos.mas.a2a.adapter import A2AAdapter, CommKind, Delivery, InterAgentMessage
from kairos.mas.a2a.protocol import (
    Artifact, ArtifactUpdate, ErrorCode, Message, Method, Part, ProtocolError, Request, Response,
    RpcError, StatusUpdate, Task, TaskState, TaskStatus, new_id, parse_request, parse_response,
)
from kairos.mas.agent import AgentMonitor, MessageRecord, MsgStatus, Outcome
from kairos.mas.fabric import MonitorFabric
from kairos.mas.transport import KMID_HEADER, EventStream, Headers, Network
from kairos.speculative.effects import EffectKind

FROM_HEADER = "x-kairos-from"            # sending host (bookkeeping without a monitor only)
TASK_HEADER = "x-kairos-task"            # a poll: the monitor id of the request that started the task
PRINCIPAL_HEADER = "x-kairos-principal"  # the principal's channel (a deployment secret)
WITHHELD_HEADER = "x-kairos-withheld"
PRINCIPAL = "principal"
UNIDENTIFIED = "http://unidentified-requester.invalid/a2a"   # destination of a reply to nobody known

ToolExecutor = Callable[[str, dict[str, Any]], tuple[Any, str | None]]


def digest(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


@dataclass(slots=True)
class ToolOutcome:
    text: str
    error: str | None = None
    executed: bool = False
    held: bool = False


@dataclass(slots=True)
class _LocalTask:
    """A request the agent started without waiting for it (message/stream, or
    message/send with blocking=false), under the id the agent knows."""
    id: str
    url: str
    request: InterAgentMessage
    record: MessageRecord | None
    mode: str = "stream"                     # stream | poll
    peer: str | None = None                  # the destination agent (None: outside the system)
    remote_id: str | None = None             # the peer's id for the task
    stream: EventStream = field(default_factory=EventStream)
    mirrors: list[tuple[str, EventStream]] = field(default_factory=list)   # (alias id, stream)
    state: TaskState = TaskState.SUBMITTED
    texts: list[str] = field(default_factory=list)
    data: list[dict[str, Any]] = field(default_factory=list)
    notice: str = ""
    context_id: str = field(default_factory=lambda: new_id("ctx-"))
    alias_of: "_LocalTask | None" = None
    done: bool = False


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
        # ids a peer issued in its responses (task and context ids), with the monitor id
        # of the request they answered: the only foreign ids forwarded back to it
        self._peer_ids: dict[tuple[str, str], str | None] = {}
        self._released_replies: dict[tuple[str, str | None, str], str] = {}
        self._lock = threading.RLock()
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
            self._peer_ids.clear()
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
        """A blocking request (message/send), a non-blocking send, a poll or a control call."""
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return _error(None, ErrorCode.INVALID_REQUEST, str(e))
        if msg.kind in (CommKind.POLL, CommKind.CONTROL):
            return self._task_call(url, msg, body)
        if msg.delivery is Delivery.STREAMING:             # message/send with blocking=false
            local = self._start(url, msg, body, mode="poll")
            return self._snapshot(local, msg).to_bytes()
        dest = self.spec.agent_at(url)
        if not self.defense:
            if dest is not None:
                self._track_plain(dest, msg, reply=False, delivery=Delivery.BLOCKING)
            return self._forward(url, body)[0]
        if dest is None:
            ok, notice = self.monitor.decide_external(url, msg.text, msg.data)
            if not ok:
                return self.adapter.rejected(msg, new_id("task-"), notice)
            resp = self._forward(url, self._canonical(msg, None))[0]
            self._external_inbound(resp, url)
            return resp
        canon = self._canonical(msg, dest)
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, delivery=Delivery.BLOCKING)
        rec.digest = digest(canon)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.REJECT:
            return self.adapter.rejected(msg, new_id("task-"), d.notice)
        resp, hdrs = self._forward(url, canon, rec)
        self._accept_reply(resp, hdrs)
        self._learn_ids(dest, resp, rec.kmid)
        return resp

    def send_stream(self, url: str, body: bytes) -> EventStream:
        """A streaming request (message/stream) or a resubscription."""
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return _closed(_error(None, ErrorCode.INVALID_REQUEST, str(e)))
        req = msg.raw
        if msg.kind is CommKind.POLL and isinstance(req, Request) and req.method is Method.RESUBSCRIBE:
            return self._resubscribe(url, msg, body)
        if msg.kind in (CommKind.POLL, CommKind.CONTROL):
            return _closed(self._task_call(url, msg, body))
        if msg.delivery is Delivery.BLOCKING:              # message/send on a stream: answer once
            return _closed(self.send(url, body))
        return self._start(url, msg, body, mode="stream").stream

    # --- canonical forms ------------------------------------------------------
    def _canonical(self, msg: InterAgentMessage, dest: str | None) -> bytes:
        """What leaves: the checked parts, and only ids the destination itself
        issued (or the peer's id behind one of this agent's local task ids)."""
        task_id = context_id = None
        with self._lock:
            if msg.task_id:
                local = self._tasks.get(msg.task_id)
                if local is not None and local.peer == dest and local.remote_id:
                    task_id = local.remote_id
                elif dest is not None and (dest, msg.task_id) in self._peer_ids:
                    task_id = msg.task_id
            if msg.context_id and dest is not None and (dest, msg.context_id) in self._peer_ids:
                context_id = msg.context_id
        return self.adapter.canonical_request(msg, task_id=task_id, context_id=context_id)

    def _learn_ids(self, dest: str, body: bytes, kmid: str | None) -> None:
        try:
            resp = parse_response(body)
        except ProtocolError:
            return
        res = resp.result
        ids = []
        if isinstance(res, Task):
            ids = [res.id, res.context_id]
        elif isinstance(res, (StatusUpdate, ArtifactUpdate)):
            ids = [res.task_id, res.context_id]
        elif isinstance(res, Message):
            ids = [res.task_id, res.context_id]
        with self._lock:
            for i in ids:
                if i:
                    self._peer_ids.setdefault((dest, i), kmid)

    # --- tasks the agent started ----------------------------------------------
    def _start(self, url: str, msg: InterAgentMessage, body: bytes, *, mode: str) -> _LocalTask:
        dest = self.spec.agent_at(url)
        local = _LocalTask(id=new_id("task-"), url=url, request=msg, record=None, mode=mode, peer=dest,
                           context_id=msg.context_id or new_id("ctx-"))
        with self._lock:
            self._tasks[local.id] = local
        if not self.defense:
            if dest is not None:
                self._track_plain(dest, msg, reply=False, delivery=Delivery.STREAMING)
            self._spawn(self._dispatch, local, body)
            return local
        if dest is None:
            ok, notice = self.monitor.decide_external(url, msg.text, msg.data)
            if not ok:
                self._reject_local(local, notice)
            else:
                self._spawn(self._dispatch, local, self._canonical(msg, None))
            return local
        canon = self._canonical(msg, dest)
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, delivery=Delivery.STREAMING)
        rec.digest = digest(canon)
        local.record = rec
        # the callbacks are in place BEFORE the decision: whichever thread later
        # resolves the branch the message may be held in will find them
        rec.on_release = lambda _r: self._spawn(self._dispatch, local, canon)
        rec.on_drop = lambda _r, notice: self._reject_local(local, notice)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.REJECT:
            self._reject_local(local, d.notice)
        elif d.outcome is Outcome.HOLD:
            local.state = TaskState.WORKING
            local.stream.put(self.adapter.working(msg, local.id))
        elif d.duplicate_of is not None:
            self._alias(local, d.duplicate_of, msg)
        else:
            self._spawn(self._dispatch, local, canon)
        return local

    def _alias(self, local: _LocalTask, original: MessageRecord, msg: InterAgentMessage) -> None:
        """A re-sent held message, delivered once: the new task mirrors the original."""
        with self._lock:
            orig = next((t for t in self._tasks.values() if t.record is original), None)
            if orig is None:
                local.state, local.notice = TaskState.FAILED, "the original task is unknown"
                local.stream.put(self.adapter.rejected(msg, local.id, local.notice))
                local.stream.close()
                return
            local.alias_of = orig
            local.stream.put(self._snapshot(orig, msg, as_id=local.id).to_bytes())
            if orig.done:
                local.stream.close()
            else:
                orig.mirrors.append((local.id, local.stream))

    def _dispatch(self, local: _LocalTask, body: bytes) -> None:
        if local.mode == "poll":
            resp, hdrs = self._forward(local.url, body, local.record)
            self._settle_response(local, resp, hdrs)
            return
        headers = self._headers(local.record)
        try:
            upstream = self.network.stream(local.url, body, headers)
        except ConnectionError as e:
            self._reject_local(local, f"transport error: {e}")
            return
        for ev_body, hdrs in upstream:
            self._accept_reply(ev_body, hdrs)
            if local.peer is None:
                self._external_inbound(ev_body, local.url)
            self._emit(local, ev_body)
        self._finish(local)

    def _settle_response(self, local: _LocalTask, resp: bytes, hdrs: Headers) -> None:
        self._accept_reply(resp, hdrs)
        if local.peer is None:
            self._external_inbound(resp, local.url)
        self._emit(local, resp)
        if local.state.is_final:
            self._finish(local)

    def _headers(self, rec: MessageRecord | None, task_rec: str | None = None) -> Headers:
        h: Headers = {FROM_HEADER: self.agent_id}
        if rec is not None:
            h[KMID_HEADER] = rec.kmid
        if task_rec is not None:
            h[TASK_HEADER] = task_rec
        return h

    def _forward(self, url: str, body: bytes, rec: MessageRecord | None = None,
                 task_rec: str | None = None) -> tuple[bytes, Headers]:
        try:
            return self.network.request(url, body, self._headers(rec, task_rec))
        except ConnectionError as e:
            return _error(None, ErrorCode.INTERNAL_ERROR, str(e)), {}

    def _emit(self, local: _LocalTask, body: bytes) -> None:
        """Track the task and hand an event to the agent under its local id (and to
        every task mirroring it)."""
        resp = self._track(local, body)
        if resp is None:
            return
        local.stream.put(_relabel(resp, local.id))
        with self._lock:
            mirrors = list(local.mirrors)
        for mid, s in mirrors:
            s.put(_relabel(resp, mid))

    def _finish(self, local: _LocalTask) -> None:
        with self._lock:
            local.done = True
            mirrors, local.mirrors = list(local.mirrors), []
        local.stream.close()
        for _mid, s in mirrors:
            s.close()

    def _track(self, local: _LocalTask, body: bytes) -> Response | None:
        try:
            resp = parse_response(body)
        except ProtocolError:
            return None
        res = resp.result
        if isinstance(res, Task):
            local.remote_id = local.remote_id or res.id
            local.state = res.status.state
            local.texts, local.data = [], []
            for a in res.artifacts:
                self._collect(local, a.parts)
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, StatusUpdate):
            local.remote_id = local.remote_id or res.task_id
            local.state = res.status.state
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, ArtifactUpdate):
            local.remote_id = local.remote_id or res.task_id
            self._collect(local, res.artifact.parts)
        elif resp.error is not None:
            local.state, local.notice = TaskState.FAILED, resp.error.message
        return resp

    @staticmethod
    def _collect(local: _LocalTask, parts: list) -> None:
        for p in parts:
            if p.kind == "text" and p.text:
                local.texts.append(p.text)
            elif p.kind == "data" and p.data is not None:
                local.data.append(p.data)

    def _reject_local(self, local: _LocalTask, notice: str) -> None:
        local.state = TaskState.REJECTED
        local.notice = notice
        self._emit(local, self.adapter.rejected(local.request, local.id, notice))
        self._finish(local)

    def _task_call(self, url: str, msg: InterAgentMessage, body: bytes) -> bytes:
        """tasks/get or tasks/cancel. For a task this agent started: answered here, or
        forwarded canonically under the peer's id. For a task a peer issued in a
        blocking answer: forwarded canonically. Anything else is unknown -- a poll is
        content leaving the host too, and must not carry what was never decided."""
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        with self._lock:
            local = self._tasks.get(msg.task_id or "")
        if local is None:
            dest = self.spec.agent_at(url)
            if not self.defense:
                return self._forward(url, body)[0]
            with self._lock:
                known = dest is not None and (dest, msg.task_id or "") in self._peer_ids
                kmid = self._peer_ids.get((dest, msg.task_id or "")) if known else None
            if not known:
                return _error(rpc_id, ErrorCode.TASK_NOT_FOUND, f"unknown task {msg.task_id!r}")
            resp, hdrs = self._forward(url, self.adapter.canonical_poll(msg, msg.task_id or ""),
                                       task_rec=kmid)
            self._accept_reply(resp, hdrs)
            return resp
        target = local.alias_of or local
        held = (self.defense and target.record is not None and target.record.status is MsgStatus.HELD)
        if msg.kind is CommKind.CONTROL:
            if held or target.remote_id is None or target.state.is_final:
                return _error(rpc_id, ErrorCode.TASK_NOT_CANCELABLE,
                              "the task cannot be canceled now" + (" (held for review)" if held else ""))
            resp, hdrs = self._forward(target.url, self.adapter.canonical_poll(msg, target.remote_id),
                                       task_rec=target.record.kmid if target.record else None)
            self._accept_reply(resp, hdrs)
            return self._relabel_for(resp, local.id)
        if held:
            self.monitor.await_held(target.record)
        if (target.mode == "poll" and target.remote_id and not target.state.is_final
                and target.record is not None and target.record.status is not MsgStatus.HELD
                and target.record.status is not MsgStatus.REJECTED):
            poll = self.adapter.canonical_poll(msg, target.remote_id)
            resp, hdrs = self._forward(target.url, poll, task_rec=target.record.kmid)
            self._settle_response(target, resp, hdrs)
        return self._snapshot(target, msg, as_id=local.id).to_bytes()

    def _resubscribe(self, url: str, msg: InterAgentMessage, body: bytes) -> EventStream:
        with self._lock:
            local = self._tasks.get(msg.task_id or "")
        if local is None:
            return _closed(self._task_call(url, msg, body))
        target = local.alias_of or local
        if self.defense and target.record is not None and target.record.status is MsgStatus.HELD:
            self.monitor.await_held(target.record)
        out = EventStream()
        with self._lock:
            out.put(self._snapshot(target, msg, as_id=local.id).to_bytes())
            if target.done or target.mode == "poll":
                out.close()
            else:
                target.mirrors.append((local.id, out))
        return out

    def _snapshot(self, local: _LocalTask, msg: InterAgentMessage, as_id: str | None = None) -> Response:
        parts = [Part.from_text(t) for t in local.texts] + [Part.from_data(d) for d in local.data]
        status = TaskStatus(local.state, message=Message.agent_text(local.notice) if local.notice else None)
        task = Task(id=as_id or local.id, context_id=local.context_id, status=status,
                    artifacts=[Artifact(parts=parts)] if parts else [])
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        return Response(id=rpc_id, result=task)

    @staticmethod
    def _relabel_for(body: bytes, task_id: str) -> bytes:
        try:
            return _relabel(parse_response(body), task_id)
        except ProtocolError:
            return body

    def _accept_reply(self, body: bytes, headers: Headers) -> None:
        """Released content arrived for this agent: record the delivery (once, and
        only for exactly the bytes that were released)."""
        if not self.defense:
            return
        rec = self.fabric.message(headers.get(KMID_HEADER))
        if (rec is not None and rec.receiver == self.agent_id and rec.status is MsgStatus.RELEASED
                and rec.digest == digest(body)):
            self.fabric.deliver(rec)

    def _external_inbound(self, body: bytes, url: str) -> None:
        """Content from a party outside the system reached this agent."""
        if not self.defense:
            return
        try:
            reply = self.adapter.parse_replies(body)[0]
        except ProtocolError:
            return
        if reply.has_content:
            self.monitor.on_external_inbound(reply.text, source=f"a2a.external:{url}")

    # =====================================================================
    # A2A server side: requests to this agent
    # =====================================================================
    def _identify(self, body: bytes, headers: Headers) -> tuple[str | None, str | None]:
        """Who is asking: a monitored agent (a valid, unconsumed capability for exactly
        these bytes, or a poll about a request it made), the principal (the
        deployment's secret), or nobody the monitor vouches for (None)."""
        if not self.defense:
            return headers.get(FROM_HEADER), None
        token = headers.get(PRINCIPAL_HEADER)
        if token and token == self.fabric.principal_token:
            return PRINCIPAL, None
        rec = self.fabric.message(headers.get(KMID_HEADER))
        if (rec is not None and rec.receiver == self.agent_id and rec.status is MsgStatus.RELEASED
                and not rec.reply and rec.digest == digest(body)):
            self.fabric.deliver(rec)
            return rec.sender, rec.kmid
        trec = self.fabric.message(headers.get(TASK_HEADER))
        if (trec is not None and trec.receiver == self.agent_id and not trec.reply
                and trec.status is MsgStatus.DELIVERED and _is_task_call(body)):
            return trec.sender, trec.kmid
        try:
            text = self.adapter.parse_request("", body).text
        except ProtocolError:
            text = ""
        if text:
            self.monitor.on_external_inbound(text)
        return None, None

    def serve(self, body: bytes, headers: Headers) -> tuple[bytes, Headers]:
        requester, in_reply_to = self._identify(body, headers)
        resp = self.server.handle(body)
        return self._gate_reply(resp, requester, in_reply_to)

    def serve_stream(self, body: bytes, headers: Headers) -> EventStream:
        requester, in_reply_to = self._identify(body, headers)
        upstream = self.server.handle_stream(body)
        if requester == PRINCIPAL:
            return upstream
        out = EventStream()

        def pump() -> None:
            blocked = False
            for ev_body, _ in upstream:
                if blocked:
                    continue
                gated, hdrs = self._gate_reply(ev_body, requester, in_reply_to)
                out.put(gated, hdrs)
                blocked = hdrs.get(WITHHELD_HEADER) == "1"
            out.close()

        self._spawn(pump)
        return out

    def _track_plain(self, dest: str, msg: InterAgentMessage, *, reply: bool, delivery: Delivery) -> None:
        """Without a monitor nothing is decided, but the traffic is still counted, so
        an undefended run is measured like a defended one."""
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, reply=reply, delivery=delivery)
        rec.intra = self.spec.same_cluster(self.agent_id, dest)
        rec.status, rec.decision = MsgStatus.DELIVERED, "nodefense"

    def _gate_reply(self, body: bytes, requester: str | None,
                    in_reply_to: str | None) -> tuple[bytes, Headers]:
        """Content leaving this agent for whoever asked: a reply, decided like a
        blocking message (the agent has finished; nothing later to wait for). The
        principal gets the answer; anyone unidentified is a party outside the system."""
        if requester == PRINCIPAL:
            return body, {}
        if not self.defense:
            try:
                reply = self.adapter.parse_replies(body)[0]
            except ProtocolError:
                return body, {}
            if reply.has_content and requester in self.spec.agents:
                self._track_plain(requester, reply, reply=True, delivery=Delivery.BLOCKING)
            return body, {}
        canon = self.adapter.canonical_reply(body)
        if canon is None:                                    # not a well-formed A2A response
            self.monitor.notify(notices.reply_withheld(requester or "the requester",
                                                       "it was not a well-formed A2A response"))
            return _error(None, ErrorCode.INTERNAL_ERROR, notices.reply_unavailable(self.agent_id)), \
                {WITHHELD_HEADER: "1"}
        cbody, reply = canon
        if not reply.has_content:
            return cbody, {}
        if requester is None or requester not in self.spec.agents:
            ok, _notice = self.monitor.decide_external(UNIDENTIFIED, reply.text, reply.data)
            return (cbody, {}) if ok else (self._withheld(cbody, reply), {WITHHELD_HEADER: "1"})
        key = (requester, reply.task_id, digest(cbody))
        with self._lock:
            known = self._released_replies.get(key)
        if known is not None:                       # the same bytes, already released to it
            return cbody, {KMID_HEADER: known}
        rec = self.fabric.new_message(self.agent_id, requester, reply.text, reply.data, reply=True,
                                      in_reply_to=in_reply_to)
        rec.digest = digest(cbody)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.RELEASE:
            with self._lock:
                self._released_replies[key] = rec.kmid
            return cbody, {KMID_HEADER: rec.kmid}
        self.monitor.notify(notices.reply_withheld(requester, rec.reason or "denied"))
        return self._withheld(cbody, reply), {WITHHELD_HEADER: "1"}

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


def _error(rpc_id: Any, code: int, message: str) -> bytes:
    return Response(id=rpc_id, error=RpcError(int(code), message)).to_bytes()


def _closed(body: bytes) -> EventStream:
    s = EventStream()
    s.put(body)
    s.close()
    return s


def _relabel(resp: Response, task_id: str) -> bytes:
    """A response presented under another task id (the agent's local id)."""
    res = resp.result
    if isinstance(res, Task):
        res = Task(id=task_id, context_id=res.context_id, status=res.status, artifacts=res.artifacts)
    elif isinstance(res, StatusUpdate):
        res = StatusUpdate(task_id, res.context_id, res.status, res.final)
    elif isinstance(res, ArtifactUpdate):
        res = ArtifactUpdate(task_id, res.context_id, res.artifact, res.last_chunk)
    return Response(id=resp.id, result=res, error=resp.error).to_bytes()


def _is_task_call(body: bytes) -> bool:
    try:
        return parse_request(body).method in (Method.GET_TASK, Method.RESUBSCRIBE, Method.CANCEL_TASK)
    except ProtocolError:
        return False
