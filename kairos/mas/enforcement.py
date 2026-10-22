"""The enforcement point of one agent host.

It sits at the host boundary and sees everything that crosses it: the agent's
external effects (tool calls here; HTTP requests and file operations in the
deployed stack), the agent's A2A requests to other agents and the replies that
come back, and the requests other agents send it and the replies it sends. It
numbers what it sees (the agent's sequencer lives in the monitor), asks the
cluster's decision point, and applies the answer: forward, block, stall, stub.

Stalling a message uses the protocol's own states, so a caller only ever sees a
delay: a streamed message on hold is a task in TASK_STATE_WORKING, a denied one is
TASK_STATE_REJECTED with a notice. A2A v1.0 only: a request for another protocol
version is refused before anything is decided or forwarded.

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
    RpcError, StatusUpdate, Task, TaskList, TaskState, TaskStatus, new_id, parse_request,
    parse_response, rpc_id_of, version_error, version_headers, version_supported,
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
    """A request the agent started without waiting for it (SendStreamingMessage, or
    SendMessage with returnImmediately), under the ids the agent knows: its task and
    context ids stay the same for the task's lifetime, whatever the peer issues."""
    id: str
    url: str
    request: InterAgentMessage
    record: MessageRecord | None
    mode: str = "stream"                     # stream | poll
    peer: str | None = None                  # the destination agent (None: outside the system)
    remote_id: str | None = None             # the peer's id for the task
    remote_context: str | None = None        # the peer's id for its context
    stream: EventStream = field(default_factory=EventStream)
    mirrors: list[tuple[str, str, EventStream]] = field(default_factory=list)  # (task id, context id, stream)
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
        # of the request they answered: the only foreign ids forwarded back to it.
        # Keyed by peer: an agent of the system, or an outside endpoint's URL.
        self._peer_ids: dict[tuple[str, str], str | None] = {}
        # contexts the agent named that the peer did not issue -> the peer's own
        self._contexts: dict[tuple[str, str], str] = {}
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
            self._contexts.clear()
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
    def send(self, url: str, body: bytes, headers: Headers | None = None) -> bytes:
        """A blocking request (SendMessage), a non-blocking one (returnImmediately), a
        poll or a control call. `headers` are the agent's A2A service parameters (None:
        an in-process caller of this implementation)."""
        if not version_supported(headers):
            return version_error(rpc_id_of(body), headers)
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return _error(rpc_id_of(body), e.code, str(e))
        if msg.kind is CommKind.UNSUPPORTED:
            return self._unsupported(url, msg)
        if msg.kind in (CommKind.POLL, CommKind.CONTROL):
            return self._task_call(url, msg, body)
        dest = self.spec.agent_at(url)
        if self.defense and (refused := self._continuation_refused(msg, dest, url)) is not None:
            return refused
        if msg.delivery is Delivery.STREAMING:             # SendMessage with returnImmediately
            local = self._start(url, msg, body, mode="poll")
            return self._snapshot(local.alias_of or local, msg, view=local).to_bytes()
        if not self.defense:
            if dest is not None:
                self._track_plain(dest, msg, reply=False, delivery=Delivery.BLOCKING)
            return self._forward(url, body)[0]
        key = _peer_key(dest, url)
        task_id, ctx = self._ids_for(msg, key)
        canon = self.adapter.canonical_request(msg, task_id=task_id, context_id=ctx)
        if dest is None:
            ok, notice = self.monitor.decide_external(url, msg.text, msg.data)
            if not ok:
                return self.adapter.rejected(msg, new_id("task-"), notice)
            resp = self._forward(url, canon)[0]
            self._external_inbound(resp, url)
            self._learn_ids(key, resp, None)
            return self._agent_view(resp, msg, (task_id, ctx), key)
        rec = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, delivery=Delivery.BLOCKING)
        rec.digest = digest(canon)
        d = self.monitor.decide_send(rec)
        if d.outcome is Outcome.REJECT:
            return self.adapter.rejected(msg, new_id("task-"), d.notice)
        resp, hdrs = self._forward(url, canon, rec)
        self._accept_reply(resp, hdrs)
        self._learn_ids(key, resp, rec.kmid)
        return self._agent_view(resp, msg, (task_id, ctx), key)

    def send_stream(self, url: str, body: bytes, headers: Headers | None = None) -> EventStream:
        """A streaming request (SendStreamingMessage) or a subscription (SubscribeToTask)."""
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return _closed(_error(rpc_id_of(body), e.code, str(e)))
        req = msg.raw
        if msg.kind is CommKind.UNSUPPORTED:
            return _closed(self._unsupported(url, msg))
        if msg.kind is CommKind.POLL and isinstance(req, Request) and req.method is Method.SUBSCRIBE:
            return self._subscribe(url, msg, body)
        if msg.kind in (CommKind.POLL, CommKind.CONTROL):
            return _closed(self._task_call(url, msg, body))
        if msg.delivery is Delivery.BLOCKING:              # SendMessage on a stream: answer once
            return _closed(self.send(url, body))
        if self.defense and (refused := self._continuation_refused(msg, self.spec.agent_at(url), url)) is not None:
            return _closed(refused)
        return self._start(url, msg, body, mode="stream").stream

    def _unsupported(self, url: str, msg: InterAgentMessage) -> bytes:
        """Operations the monitor answers itself instead of relaying. ListTasks lists
        the tasks this agent started at that peer (all a caller may see there anyway);
        push notifications and the extended card are not offered."""
        req = msg.raw
        assert isinstance(req, Request)
        if req.method is Method.LIST_TASKS:
            key = _peer_key(self.spec.agent_at(url), url)
            ctx, status = req.params.get("contextId"), req.params.get("status")
            with self._lock:
                mine = [(t, t.alias_of or t) for t in self._tasks.values() if _peer_key(t.peer, t.url) == key]
            tasks = [r for view, t in mine
                     if isinstance(r := self._snapshot(t, msg, view=view).result, Task)
                     and (not ctx or r.context_id == ctx) and (not status or r.status.state.value == status)]
            return Response(id=req.id, result=TaskList(tasks, "", len(tasks), len(tasks)), bare=True).to_bytes()
        if req.method.push_config:
            return Response(id=req.id, error=RpcError.info(
                ErrorCode.PUSH_NOTIFICATION_NOT_SUPPORTED, "Push notifications are not supported",
                "PUSH_NOTIFICATION_NOT_SUPPORTED")).to_bytes()
        if req.method is Method.GET_EXTENDED_CARD:
            return Response(id=req.id, error=RpcError.info(
                ErrorCode.EXTENDED_AGENT_CARD_NOT_CONFIGURED, "No extended agent card is configured",
                "EXTENDED_AGENT_CARD_NOT_CONFIGURED")).to_bytes()
        return Response(id=req.id, error=RpcError.info(
            ErrorCode.UNSUPPORTED_OPERATION, f"{req.method.value} is not supported here",
            "UNSUPPORTED_OPERATION")).to_bytes()

    # --- ids ----------------------------------------------------------------
    def _ids_for(self, msg: InterAgentMessage, key: str) -> tuple[str | None, str | None]:
        """The task and context ids that leave with a request: only ids the peer itself
        issued, or the peer's ids behind this agent's local ones. Any other id is
        agent-chosen text and stays behind."""
        task_id = context_id = None
        with self._lock:
            if msg.task_id:
                local = self._tasks.get(msg.task_id)
                target = (local.alias_of or local) if local is not None else None
                if target is not None and _peer_key(local.peer, local.url) == key and target.remote_id:
                    task_id = target.remote_id
                elif (key, msg.task_id) in self._peer_ids:
                    task_id = msg.task_id
            if msg.context_id:
                if (key, msg.context_id) in self._peer_ids:
                    context_id = msg.context_id
                else:
                    context_id = self._contexts.get((key, msg.context_id))
        return task_id, context_id

    def _canonical(self, msg: InterAgentMessage, dest: str | None, url: str) -> bytes:
        task_id, context_id = self._ids_for(msg, _peer_key(dest, url))
        return self.adapter.canonical_request(msg, task_id=task_id, context_id=context_id)

    def _continuation_refused(self, msg: InterAgentMessage, dest: str | None, url: str) -> bytes | None:
        """A message continuing a task names a task this agent knows at that peer
        (spec 3.4.2: else TaskNotFoundError), one the peer has seen: a task still on
        hold, or rejected before it left, takes no further messages."""
        if msg.kind is not CommKind.REQUEST or not msg.task_id:
            return None
        key = _peer_key(dest, url)
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        with self._lock:
            local = self._tasks.get(msg.task_id)
            if local is not None and _peer_key(local.peer, local.url) == key:
                target = local.alias_of or local
                if msg.context_id and msg.context_id != local.context_id:
                    return Response(id=rpc_id, error=RpcError(
                        ErrorCode.INVALID_PARAMS, "contextId does not match the task's context")).to_bytes()
                if target.remote_id:
                    return None
                why = "is in a terminal state" if target.state.is_final else "is still working"
                return Response(id=rpc_id, error=RpcError.info(
                    ErrorCode.UNSUPPORTED_OPERATION, f"The task {why}", "UNSUPPORTED_OPERATION",
                    taskId=msg.task_id)).to_bytes()
            if (key, msg.task_id) in self._peer_ids:
                return None
        return _task_not_found(rpc_id, msg.task_id)

    def _agent_view(self, body: bytes, msg: InterAgentMessage, sent: tuple[str | None, str | None],
                    key: str) -> bytes:
        """A blocking answer under the ids the agent used. A continuation of one of its
        local tasks stays under that task's ids. A context the agent named that the
        peer did not issue -- the peer opened its own -- stays the agent's (spec 3.4.1:
        a client's contextId is preserved or the request refused, never silently
        replaced); follow-ups in it reach the peer's."""
        sent_task, sent_ctx = sent
        as_task = msg.task_id if msg.task_id and sent_task != msg.task_id else None
        as_ctx = msg.context_id if msg.context_id and sent_ctx != msg.context_id else None
        if as_task is None and as_ctx is None:
            return body
        try:
            resp = parse_response(body)
        except ProtocolError:
            return body
        res = resp.result
        if resp.error is not None or res is None:
            return body
        peer_ctx = getattr(res, "context_id", None)
        with self._lock:
            local = self._tasks.get(as_task) if as_task else None
            if as_ctx and peer_ctx:
                self._contexts.setdefault((key, as_ctx), peer_ctx)
        ctx = as_ctx or (local.context_id if local is not None else None) or peer_ctx or ""
        return _relabel(resp, as_task, ctx)

    def _learn_ids(self, key: str, body: bytes, kmid: str | None) -> None:
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
                    self._peer_ids.setdefault((key, i), kmid)

    # --- tasks the agent started ----------------------------------------------
    def _start(self, url: str, msg: InterAgentMessage, body: bytes, *, mode: str) -> _LocalTask:
        dest = self.spec.agent_at(url)
        with self._lock:
            prev = self._tasks.get(msg.task_id or "")
            if prev is not None and _peer_key(prev.peer, prev.url) == _peer_key(dest, url):
                # a continuation of a local task: the same task for the agent, now
                # tracked through this request (the peer's events cover the whole task)
                target = prev.alias_of or prev
                local = _LocalTask(id=prev.id, url=url, request=msg, record=None, mode=mode, peer=dest,
                                   context_id=prev.context_id, remote_id=target.remote_id,
                                   remote_context=target.remote_context)
            else:
                local = _LocalTask(id=new_id("task-"), url=url, request=msg, record=None, mode=mode,
                                   peer=dest, context_id=msg.context_id or new_id("ctx-"))
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
                self._spawn(self._dispatch, local, self._canonical(msg, None, url))
            return local
        canon = self._canonical(msg, dest, url)
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
            local.stream.put(self.adapter.working(msg, local.id, context_id=local.context_id))
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
                local.stream.put(self.adapter.rejected(msg, local.id, local.notice, context_id=local.context_id))
                local.stream.close()
                return
            local.alias_of = orig
            local.stream.put(self._snapshot(orig, msg, view=local).to_bytes())
            if orig.done:
                local.stream.close()
            else:
                orig.mirrors.append((local.id, local.context_id, local.stream))

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
        h: Headers = {**version_headers(), FROM_HEADER: self.agent_id}
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

    def _emit(self, local: _LocalTask, body: bytes, *, from_peer: bool = True) -> None:
        """Track the task and hand an event to the agent under its local id (and to
        every task mirroring it)."""
        resp = self._track(local, body, from_peer=from_peer)
        if resp is None:
            return
        local.stream.put(_relabel(resp, local.id, local.context_id))
        with self._lock:
            mirrors = list(local.mirrors)
        for mid, mctx, s in mirrors:
            s.put(_relabel(resp, mid, mctx))

    def _finish(self, local: _LocalTask) -> None:
        with self._lock:
            local.done = True
            mirrors, local.mirrors = list(local.mirrors), []
        local.stream.close()
        for _mid, _mctx, s in mirrors:
            s.close()

    def _track(self, local: _LocalTask, body: bytes, *, from_peer: bool = True) -> Response | None:
        """Follow the task through an event. Only the peer's own events teach its ids:
        an answer the monitor gave itself (a rejection) carries the agent's."""
        try:
            resp = parse_response(body)
        except ProtocolError:
            return None
        res = resp.result
        if from_peer and isinstance(res, (Task, StatusUpdate, ArtifactUpdate, Message)):
            remote_id = res.id if isinstance(res, Task) else res.task_id
            local.remote_id = local.remote_id or remote_id
            if res.context_id:
                self._remember_context(local, res.context_id)
        if isinstance(res, Task):
            local.state = res.status.state
            local.texts, local.data = [], []
            for a in res.artifacts:
                self._collect(local, a.parts)
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, StatusUpdate):
            local.state = res.status.state
            if res.status.message is not None:
                local.notice = res.status.message.text()
        elif isinstance(res, ArtifactUpdate):
            self._collect(local, res.artifact.parts)
        elif isinstance(res, Message):                     # a direct answer, no task
            local.state = TaskState.COMPLETED
            self._collect(local, res.parts)
        elif resp.error is not None:
            local.state, local.notice = TaskState.FAILED, resp.error.message
        return resp

    def _remember_context(self, local: _LocalTask, remote_ctx: str) -> None:
        if local.remote_context is None:
            local.remote_context = remote_ctx
            with self._lock:
                self._contexts.setdefault((_peer_key(local.peer, local.url), local.context_id), remote_ctx)

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
        self._emit(local, self.adapter.rejected(local.request, local.id, notice, context_id=local.context_id),
                   from_peer=False)
        self._finish(local)

    def _task_call(self, url: str, msg: InterAgentMessage, body: bytes) -> bytes:
        """GetTask or CancelTask. For a task this agent started: answered here, or
        forwarded canonically under the peer's id. For a task a peer issued in a
        blocking answer: forwarded canonically. Anything else is unknown -- a poll is
        content leaving the host too, and must not carry what was never decided."""
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        with self._lock:
            local = self._tasks.get(msg.task_id or "")
        if local is None:
            if not self.defense:
                return self._forward(url, body)[0]
            known, kmid = self._peer_task(url, msg.task_id)
            if not known:
                return _task_not_found(rpc_id, msg.task_id)
            resp, hdrs = self._forward(url, self.adapter.canonical_poll(msg, msg.task_id or ""),
                                       task_rec=kmid)
            self._accept_reply(resp, hdrs)
            if self.spec.agent_at(url) is None:
                self._external_inbound(resp, url)
            return resp
        target = local.alias_of or local
        held = (self.defense and target.record is not None and target.record.status is MsgStatus.HELD)
        if msg.kind is CommKind.CONTROL:
            if held or target.remote_id is None or target.state.is_final:
                return Response(id=rpc_id, error=RpcError.info(
                    ErrorCode.TASK_NOT_CANCELABLE,
                    "Task cannot be canceled now" + (" (held for review)" if held else ""),
                    "TASK_NOT_CANCELABLE", taskId=local.id)).to_bytes()
            resp, hdrs = self._forward(target.url, self.adapter.canonical_poll(msg, target.remote_id),
                                       task_rec=target.record.kmid if target.record else None)
            self._accept_reply(resp, hdrs)
            if target.peer is None:
                self._external_inbound(resp, target.url)
            return self._relabel_for(resp, local.id, local.context_id)
        if held:
            self.monitor.await_held(target.record)
        if (target.mode == "poll" and target.remote_id and not target.state.is_final
                and target.record is not None and target.record.status is not MsgStatus.HELD
                and target.record.status is not MsgStatus.REJECTED):
            poll = self.adapter.canonical_poll(msg, target.remote_id)
            resp, hdrs = self._forward(target.url, poll, task_rec=target.record.kmid)
            self._settle_response(target, resp, hdrs)
        return self._snapshot(target, msg, view=local, bare=True).to_bytes()

    def _peer_task(self, url: str, task_id: str | None) -> tuple[bool, str | None]:
        """Whether the peer at `url` issued `task_id` to this agent, and the monitor id
        of the request it answered."""
        key = (_peer_key(self.spec.agent_at(url), url), task_id or "")
        with self._lock:
            return key in self._peer_ids, self._peer_ids.get(key)

    def _subscribe(self, url: str, msg: InterAgentMessage, body: bytes) -> EventStream:
        with self._lock:
            local = self._tasks.get(msg.task_id or "")
        if local is None:
            return self._subscribe_peer(url, msg, body)
        target = local.alias_of or local
        if self.defense and target.record is not None and target.record.status is MsgStatus.HELD:
            self.monitor.await_held(target.record)
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        with self._lock:
            if target.state.is_final:              # SubscribeToTask on a terminal task (spec 9.4.6)
                return _closed(Response(id=rpc_id, error=RpcError.info(
                    ErrorCode.UNSUPPORTED_OPERATION, "The task is in a terminal state",
                    "UNSUPPORTED_OPERATION", taskId=local.id)).to_bytes())
            if target.mode == "poll":
                pass                               # no stream of our own: subscribe at the peer
            else:
                out = EventStream()
                out.put(self._snapshot(target, msg, view=local).to_bytes())
                if target.done:
                    out.close()
                else:
                    target.mirrors.append((local.id, local.context_id, out))
                return out
        return self._subscribe_remote(target, local, msg)

    def _subscribe_remote(self, target: _LocalTask, view: _LocalTask, msg: InterAgentMessage) -> EventStream:
        """A subscription to a returnImmediately task: relayed to the peer under its
        task id, its events presented under the agent's ids. A task the peer has not
        seen yet (still on hold, or released a moment ago) is answered with its
        current state; the agent polls on."""
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        rec = target.record
        if not target.remote_id or (self.defense and rec is not None and rec.status is not MsgStatus.DELIVERED):
            return _closed(self._snapshot(target, msg, view=view).to_bytes())
        try:
            upstream = self.network.stream(target.url, self.adapter.canonical_poll(msg, target.remote_id),
                                           self._headers(None, rec.kmid if rec is not None else None))
        except ConnectionError as e:
            return _closed(_error(rpc_id, ErrorCode.INTERNAL_ERROR, str(e)))
        out = EventStream()

        def pump() -> None:
            for ev_body, hdrs in upstream:
                self._accept_reply(ev_body, hdrs)
                if target.peer is None:
                    self._external_inbound(ev_body, target.url)
                resp = self._track(target, ev_body)
                if resp is not None:
                    out.put(_relabel(resp, view.id, view.context_id))
            out.close()

        self._spawn(pump)
        return out

    def _subscribe_peer(self, url: str, msg: InterAgentMessage, body: bytes) -> EventStream:
        """SubscribeToTask for a task a peer issued in a blocking answer: relayed as a
        stream, canonically and under the peer's id, like a poll."""
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        if self.defense:
            known, kmid = self._peer_task(url, msg.task_id)
            if not known:
                return _closed(_task_not_found(rpc_id, msg.task_id))
            body = self.adapter.canonical_poll(msg, msg.task_id or "")
        else:
            kmid = None
        try:
            upstream = self.network.stream(url, body, self._headers(None, kmid))
        except ConnectionError as e:
            return _closed(_error(rpc_id, ErrorCode.INTERNAL_ERROR, str(e)))
        out = EventStream()

        external = self.spec.agent_at(url) is None

        def pump() -> None:
            for ev_body, hdrs in upstream:
                self._accept_reply(ev_body, hdrs)
                if external:
                    self._external_inbound(ev_body, url)
                out.put(ev_body)
            out.close()

        self._spawn(pump)
        return out

    def _snapshot(self, local: _LocalTask, msg: InterAgentMessage, *, view: _LocalTask | None = None,
                  bare: bool = False) -> Response:
        """The task as this agent knows it, under the ids of `view` (a task mirroring
        `local`): a SendMessage / stream answer (wrapped) or a GetTask result (`bare`)."""
        view = view or local
        parts = [Part.from_text(t) for t in local.texts] + [Part.from_data(d) for d in local.data]
        status = TaskStatus(local.state, message=Message.agent_text(local.notice) if local.notice else None)
        task = Task(id=view.id, context_id=view.context_id, status=status,
                    artifacts=[Artifact(parts=parts)] if parts else [])
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        return Response(id=rpc_id, result=task, bare=bare)

    @staticmethod
    def _relabel_for(body: bytes, task_id: str, context_id: str) -> bytes:
        try:
            return _relabel(parse_response(body), task_id, context_id)
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
        if not version_supported(headers):
            return version_error(rpc_id_of(body), headers), {}
        requester, in_reply_to = self._identify(body, headers)
        resp = self.server.handle(body, version_headers())
        return self._gate_reply(resp, requester, in_reply_to)

    def serve_stream(self, body: bytes, headers: Headers) -> EventStream:
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        requester, in_reply_to = self._identify(body, headers)
        upstream = self.server.handle_stream(body, version_headers())
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
            result: Any = StatusUpdate(task_id, ctx, status)
        else:
            result = Task(id=task_id, context_id=ctx, status=status)
        return Response(id=resp.id, result=result, bare=resp.bare and isinstance(result, Task)).to_bytes()


def _error(rpc_id: Any, code: int, message: str) -> bytes:
    return Response(id=rpc_id, error=RpcError(int(code), message)).to_bytes()


def _task_not_found(rpc_id: Any, task_id: str | None) -> bytes:
    return Response(id=rpc_id, error=RpcError.info(ErrorCode.TASK_NOT_FOUND, "Task not found",
                                                   "TASK_NOT_FOUND", taskId=task_id or "")).to_bytes()


def _closed(body: bytes) -> EventStream:
    s = EventStream()
    s.put(body)
    s.close()
    return s


def _peer_key(dest: str | None, url: str) -> str:
    """Who issues a peer's ids: an agent of the system, or an outside endpoint."""
    return dest if dest is not None else url


def _relabel(resp: Response, task_id: str | None, context_id: str) -> bytes:
    """A response presented under other task and context ids (the agent's own)."""
    res = resp.result
    if isinstance(res, Task):
        res = Task(id=task_id or res.id, context_id=context_id, status=res.status, artifacts=res.artifacts)
    elif isinstance(res, StatusUpdate):
        res = StatusUpdate(task_id or res.task_id, context_id, res.status)
    elif isinstance(res, ArtifactUpdate):
        res = ArtifactUpdate(task_id or res.task_id, context_id, res.artifact, res.append, res.last_chunk)
    elif isinstance(res, Message):
        res = Message(role=res.role, parts=res.parts, message_id=res.message_id,
                      context_id=context_id, task_id=task_id or res.task_id)
    return Response(id=resp.id, result=res, error=resp.error, bare=resp.bare).to_bytes()


def _is_task_call(body: bytes) -> bool:
    try:
        return parse_request(body).method in (Method.GET_TASK, Method.SUBSCRIBE, Method.CANCEL_TASK)
    except ProtocolError:
        return False
