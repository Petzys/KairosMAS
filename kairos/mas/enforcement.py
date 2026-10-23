"""The enforcement point of one agent host.

It sits at the host boundary and sees everything that crosses it: the agent's
external effects (tool calls here; HTTP requests and file operations in the deployed
stack), the agent's A2A requests to other agents and the replies that come back, and
the requests other agents send it and the replies it sends. It numbers what it sees
(the agent's sequencer lives in the monitor), asks the cluster's decision point, and
applies the answer: forward, block, stall, stub.

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

Reading guide. `EnforcementPoint` has three faces, in this order in the file:
  1. external effects: `call_tool` (the single-agent KAIROS path, one call at a time);
  2. the A2A client side, the agent's requests to others: `send` (blocking, polls,
     control calls) and `send_stream` (streams, subscriptions). A request the agent
     does not wait for becomes a `_LocalTask`, which the agent knows under ids this
     host issues; `_start` creates it and `_dispatch` forwards it once released;
  3. the A2A server side, requests to this agent: `serve` / `serve_stream`, which
     identify the requester (`_identify`) and decide the agent's reply (`_gate_reply`).
Module-level helpers at the bottom build error responses and re-label responses.
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
from kairos.mas.trace import emit
from kairos.mas.transport import KMID_HEADER, EventStream, Headers, Network
from kairos.speculative.effects import EffectKind

# Monitor headers (see transport.py): read and written by enforcement points only.
FROM_HEADER = "x-kairos-from"            # sending host (bookkeeping without a monitor only)
TASK_HEADER = "x-kairos-task"            # a poll: the monitor id of the request that started the task
PRINCIPAL_HEADER = "x-kairos-principal"  # the principal's channel (a deployment secret)
WITHHELD_HEADER = "x-kairos-withheld"    # set on a reply the monitor replaced by a notice
PRINCIPAL = "principal"
UNIDENTIFIED = "http://unidentified-requester.invalid/a2a"   # destination of a reply to nobody known

# Executes one tool call for real: (function name, arguments) -> (result, error).
ToolExecutor = Callable[[str, dict[str, Any]], tuple[Any, str | None]]


def digest(body: bytes) -> str:
    """The sha256 a monitor id is bound to: a capability for exactly these bytes."""
    return hashlib.sha256(body).hexdigest()


@dataclass(slots=True)
class ToolOutcome:
    """What the agent gets back for a tool call."""
    text: str
    error: str | None = None
    executed: bool = False      # the call really ran
    held: bool = False          # the call was held; `text` is a stub


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
    texts: list[str] = field(default_factory=list)       # text parts received so far
    data: list[dict[str, Any]] = field(default_factory=list)   # data parts received so far
    notice: str = ""                         # the latest status message (e.g. a rejection notice)
    context_id: str = field(default_factory=lambda: new_id("ctx-"))
    alias_of: "_LocalTask | None" = None     # a re-sent held message mirrors its original task
    done: bool = False


class EnforcementPoint:
    """The monitor at one agent's host boundary (see the module docstring).

    `defense=False` turns the host into a plain relay that only counts traffic, so an
    undefended run is measured like a defended one. `formatter` turns tool results
    into the text the agent sees. `server` is the agent's own A2A server, set by the
    host after construction.

    `_lock` (re-entrant) protects the bookkeeping below; it is never held while
    asking the monitor for a decision.
    """

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
        # The agent's tasks at other agents, by the local task id the agent knows.
        self._tasks: dict[str, _LocalTask] = {}
        # ids a peer issued in its responses (task and context ids), with the monitor id
        # of the request they answered: the only foreign ids forwarded back to it.
        # Keyed by peer: an agent of the system, or an outside endpoint's URL.
        self._peer_ids: dict[tuple[str, str], str | None] = {}
        # contexts the agent named that the peer did not issue -> the peer's own
        self._contexts: dict[tuple[str, str], str] = {}
        # replies already released: (requester, task id, digest) -> monitor id. The same
        # bytes to the same requester are not decided twice (polls repeat answers).
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
        """Forget everything about earlier sessions."""
        with self._lock:
            self._tasks.clear()
            self._peer_ids.clear()
            self._contexts.clear()
            self._released_replies.clear()
            self._threads.clear()

    def join(self, timeout: float = 30.0) -> None:
        """Wait for background deliveries started by this host."""
        for thread in list(self._threads):
            thread.join(timeout)

    def _spawn(self, fn: Callable[..., Any], *args: Any) -> None:
        """Run `fn` in a background thread (forwarding a stream, pumping events)."""
        thread = threading.Thread(target=fn, args=args, daemon=True)
        with self._lock:
            self._threads.append(thread)
        thread.start()

    # =====================================================================
    # external effects (the single-agent KAIROS path, per call)
    # =====================================================================
    def call_tool(self, tc: Any, execute: ToolExecutor) -> ToolOutcome:
        """One tool call of the agent. Mirrors adapters/agentdojo/hooks.PolicyEnforcer
        for a single call; abort notices are queued on the monitor and handed to
        the agent by its harness (drain_notices).

        `tc` is the agent's tool call (an AgentDojo FunctionCall); `execute` runs a
        call for real. This wrapper only records the call and its outcome for the
        flight recorder; `_call_tool` does the work."""
        call_id = str(getattr(tc, "id", "") or "")
        emit(self.fabric, "tool.call", agent=self.agent_id, tool=tc.function, args=dict(tc.args),
             call_id=call_id)
        outcome = self._call_tool(tc, execute)
        if outcome.executed:
            status = "executed"
        elif outcome.held:
            status = "held"
        elif outcome.error:
            status = "blocked"
        else:
            status = "answered"
        emit(self.fabric, "tool.result", agent=self.agent_id, tool=tc.function, call_id=call_id,
             status=status, text=outcome.text, error=outcome.error)
        return outcome

    def _call_tool(self, tc: Any, execute: ToolExecutor) -> ToolOutcome:
        """The single-agent path: gate the call, then either decide it on the spot
        (a reviewed read), or let the speculative machine run, hold or stub it, or
        resolve the open branch first.

        The whole decision runs under the monitor's lock, so a call is decided against
        a stable view of the agent's labels and branch."""
        if not self.defense:
            result, error = execute(tc.function, dict(tc.args))
            return ToolOutcome(self.formatter(result), error, executed=True)

        monitor = self.monitor
        with monitor.lock:
            # A held call that is committed later is executed through this executor.
            monitor.executor = lambda call_ref, args: execute(call_ref.function, args)
            event = call_to_event(tc, turn_id=0)
            stage = monitor.gate(event)
            decision = stage.decision.value
            if decision == "DENY":
                return ToolOutcome("", f"Blocked by reference monitor: {stage.reason or stage.produced_by}")
            view = monitor.event_view(event, call_ref=tc, decision=stage)
            if monitor.can_adjudicate(decision, view):
                # A reviewed read: the oracle decides it now (single-agent sync-GET).
                approved, verdict = monitor.adjudicate(view)
                if not approved:
                    return ToolOutcome("", notices.get_refused(tc.function, verdict.rationale))
                effect = None
            else:
                effect = monitor.speculate(decision, view)

            if effect is not None and effect.kind is EffectKind.STUB:
                return ToolOutcome(str(effect.stub_value), held=True)
            if effect is not None and effect.kind is EffectKind.BLOCK:
                return ToolOutcome("", f"Blocked: {effect.reason}")
            args = dict(tc.args)
            if effect is not None and effect.kind is EffectKind.RESOLVE:
                # The machine wants the open branch resolved before this call.
                resolution = monitor.resolve(effect.trigger.name if effect.trigger else "RESOLVE",
                                             pending=view)
                assert resolution is not None
                _commit_decision, branch, outcome = resolution
                if monitor.hold_notice == "honest":
                    # The agent re-issued a call that was held: answer with the real
                    # result of the original, which the resolution just committed.
                    for held, real_result, real_error in outcome.dispatched:
                        if held.tool == tc.function and held.args == tc.args:
                            text = self.formatter(real_result)
                            if real_error is None:
                                monitor.admit_result(result_to_event(tc, text, turn_id=0))
                            return ToolOutcome(text, real_error, executed=True)
                # Otherwise the call is gated again, as if just issued: the resolution
                # may have changed the labels.
                second_stage = monitor.gate(call_to_event(tc, turn_id=0))
                if second_stage.decision is Decision.DENY:
                    return ToolOutcome("", f"Blocked: {second_stage.reason}")
                second_view = monitor.event_view(call_to_event(tc, turn_id=0), call_ref=tc,
                                                 decision=second_stage)
                if monitor.can_adjudicate(second_stage.decision.value, second_view):
                    approved, verdict = monitor.adjudicate(second_view)
                    if not approved:
                        return ToolOutcome("", notices.get_refused(tc.function, verdict.rationale))
                    second_effect = None
                else:
                    second_effect = monitor.speculate(second_stage.decision.value, second_view)
                if second_effect is not None and second_effect.kind is EffectKind.STUB:
                    return ToolOutcome(str(second_effect.stub_value), held=True)
                if second_effect is not None and second_effect.kind is not EffectKind.EXECUTE:
                    return ToolOutcome("", "A prior speculative action was reverted; this action "
                                           "could not be completed automatically. If it is part of "
                                           "your original request, please re-issue it.")
                # The call may carry a stub value from a held call that was committed:
                # replace it by the real value before executing.
                if any(branch.stubs.contains_marker(value) for value in args.values()):
                    args = branch.stubs.substitute_real(args)
            result, error = execute(tc.function, args)
            text = self.formatter(result)
            if error is None:
                monitor.admit_result(result_to_event(tc, text, turn_id=0))
            return ToolOutcome(text, error, executed=True)

    def terminal(self) -> bool:
        """The agent finished a task. Returns True if a resolution withheld
        something (its notices are queued: drain_notices)."""
        if not self.defense:
            return False
        resolution = self.monitor.on_terminal()
        return bool(resolution is not None and resolution[2].aborted)

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

        dest = self.spec.agent_at(url)          # None: a party outside the system
        # A message continuing a task must name a task the agent can refer to at this
        # peer; anything else is refused here, before a decision is made.
        if self.defense:
            refusal = self._continuation_refused(msg, dest, url)
            if refusal is not None:
                return refusal
        if msg.delivery is Delivery.STREAMING:             # SendMessage with returnImmediately
            local = self._start(url, msg, body, mode="poll")
            return self._snapshot(local.alias_of or local, msg, view=local).to_bytes()
        if not self.defense:
            if dest is not None:
                self._track_plain(dest, msg, reply=False, delivery=Delivery.BLOCKING)
            return self._forward(url, body)[0]

        # What leaves is the canonical form of what was checked, never the agent's bytes,
        # and it carries only ids the peer itself issued.
        key = _peer_key(dest, url)
        task_id, context_id = self._ids_for(msg, key)
        canonical = self.adapter.canonical_request(msg, task_id=task_id, context_id=context_id)

        if dest is None:
            # A party outside the system: an external effect, decided like one.
            approved, notice = self.monitor.decide_external(url, msg.text, msg.data)
            if not approved:
                return self.adapter.rejected(msg, new_id("task-"), notice)
            response = self._forward(url, canonical)[0]
            self._external_inbound(response, url)
            self._learn_ids(key, response, None)
            return self._agent_view(response, msg, (task_id, context_id), key)

        # An agent of the system: register the message and bind its monitor id to
        # exactly these bytes; the receiving host accepts it only for that digest.
        record = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data,
                                         delivery=Delivery.BLOCKING)
        record.digest = digest(canonical)
        decision = self.monitor.decide_send(record)
        if decision.outcome is Outcome.REJECT:
            # The sender sees a rejected task carrying the monitor's notice.
            return self.adapter.rejected(msg, new_id("task-"), decision.notice)
        response, reply_headers = self._forward(url, canonical, record)
        self._accept_reply(response, reply_headers)
        self._learn_ids(key, response, record.kmid)
        return self._agent_view(response, msg, (task_id, context_id), key)

    def send_stream(self, url: str, body: bytes, headers: Headers | None = None) -> EventStream:
        """A streaming request (SendStreamingMessage) or a subscription (SubscribeToTask)."""
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        try:
            msg = self.adapter.parse_request(url, body)
        except ProtocolError as e:
            return _closed(_error(rpc_id_of(body), e.code, str(e)))
        request = msg.raw
        if msg.kind is CommKind.UNSUPPORTED:
            return _closed(self._unsupported(url, msg))
        if msg.kind is CommKind.POLL and isinstance(request, Request) and request.method is Method.SUBSCRIBE:
            return self._subscribe(url, msg, body)
        if msg.kind in (CommKind.POLL, CommKind.CONTROL):
            return _closed(self._task_call(url, msg, body))
        if msg.delivery is Delivery.BLOCKING:              # SendMessage on a stream: answer once
            return _closed(self.send(url, body))
        if self.defense:
            refusal = self._continuation_refused(msg, self.spec.agent_at(url), url)
            if refusal is not None:
                return _closed(refusal)
        return self._start(url, msg, body, mode="stream").stream

    def _unsupported(self, url: str, msg: InterAgentMessage) -> bytes:
        """Operations the monitor answers itself instead of relaying. ListTasks lists
        the tasks this agent started at that peer (all a caller may see there anyway);
        push notifications and the extended card are not offered."""
        request = msg.raw
        assert isinstance(request, Request)
        if request.method is Method.LIST_TASKS:
            key = _peer_key(self.spec.agent_at(url), url)
            context_filter, status_filter = request.params.get("contextId"), request.params.get("status")
            with self._lock:
                # (the task as the agent knows it, the task whose state it shows)
                mine = [(task, task.alias_of or task) for task in self._tasks.values()
                        if _peer_key(task.peer, task.url) == key]
            tasks = []
            for view, task in mine:
                snapshot = self._snapshot(task, msg, view=view).result
                if not isinstance(snapshot, Task):
                    continue
                if context_filter and snapshot.context_id != context_filter:
                    continue
                if status_filter and snapshot.status.state.value != status_filter:
                    continue
                tasks.append(snapshot)
            return Response(id=request.id, result=TaskList(tasks, "", len(tasks), len(tasks)),
                            bare=True).to_bytes()
        if request.method.push_config:
            # A push would arrive at a webhook of the agent's choosing, past the ingress.
            return Response(id=request.id, error=RpcError.info(
                ErrorCode.PUSH_NOTIFICATION_NOT_SUPPORTED, "Push notifications are not supported",
                "PUSH_NOTIFICATION_NOT_SUPPORTED")).to_bytes()
        if request.method is Method.GET_EXTENDED_CARD:
            return Response(id=request.id, error=RpcError.info(
                ErrorCode.EXTENDED_AGENT_CARD_NOT_CONFIGURED, "No extended agent card is configured",
                "EXTENDED_AGENT_CARD_NOT_CONFIGURED")).to_bytes()
        return Response(id=request.id, error=RpcError.info(
            ErrorCode.UNSUPPORTED_OPERATION, f"{request.method.value} is not supported here",
            "UNSUPPORTED_OPERATION")).to_bytes()

    # --- ids ----------------------------------------------------------------
    # Task and context ids are free text the agent could fill with anything. Only ids
    # a peer issued itself may go back to that peer; the agent's own tasks get local
    # ids from this host, which are mapped to the peer's ids on the way out.
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
                    task_id = target.remote_id          # a local task: the peer's id behind it
                elif (key, msg.task_id) in self._peer_ids:
                    task_id = msg.task_id               # an id this peer issued
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
        sent_task, sent_context = sent
        # The ids to present: only where what was sent differs from what the agent used.
        as_task = msg.task_id if msg.task_id and sent_task != msg.task_id else None
        as_context = msg.context_id if msg.context_id and sent_context != msg.context_id else None
        if as_task is None and as_context is None:
            return body
        try:
            response = parse_response(body)
        except ProtocolError:
            return body
        result = response.result
        if response.error is not None or result is None:
            return body
        peer_context = getattr(result, "context_id", None)
        with self._lock:
            local = self._tasks.get(as_task) if as_task else None
            if as_context and peer_context:
                self._contexts.setdefault((key, as_context), peer_context)
        context = as_context or (local.context_id if local is not None else None) or peer_context or ""
        return _relabel(response, as_task, context)

    def _learn_ids(self, key: str, body: bytes, kmid: str | None) -> None:
        """Remember the task and context ids the peer issued in a response: the agent
        may use them in follow-ups to that peer."""
        try:
            response = parse_response(body)
        except ProtocolError:
            return
        result = response.result
        ids = []
        if isinstance(result, Task):
            ids = [result.id, result.context_id]
        elif isinstance(result, (StatusUpdate, ArtifactUpdate)):
            ids = [result.task_id, result.context_id]
        elif isinstance(result, Message):
            ids = [result.task_id, result.context_id]
        with self._lock:
            for issued in ids:
                if issued:
                    self._peer_ids.setdefault((key, issued), kmid)

    # --- tasks the agent started ----------------------------------------------
    def _start(self, url: str, msg: InterAgentMessage, body: bytes, *, mode: str) -> _LocalTask:
        """Start a task the agent does not wait for (`mode`: "stream" or "poll").

        The agent gets a local task at once. The request itself is decided like any
        message: released (forwarded in the background), held (the task shows
        TASK_STATE_WORKING until the sender's next trigger), or rejected (the task is
        rejected with a notice)."""
        dest = self.spec.agent_at(url)
        with self._lock:
            previous = self._tasks.get(msg.task_id or "")
            if previous is not None and _peer_key(previous.peer, previous.url) == _peer_key(dest, url):
                # a continuation of a local task: the same task for the agent, now
                # tracked through this request (the peer's events cover the whole task)
                target = previous.alias_of or previous
                local = _LocalTask(id=previous.id, url=url, request=msg, record=None, mode=mode, peer=dest,
                                   context_id=previous.context_id, remote_id=target.remote_id,
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
            # A party outside the system: decided at once, like any external effect.
            approved, notice = self.monitor.decide_external(url, msg.text, msg.data)
            if not approved:
                self._reject_local(local, notice)
            else:
                self._spawn(self._dispatch, local, self._canonical(msg, None, url))
            return local

        canonical = self._canonical(msg, dest, url)
        record = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data,
                                         delivery=Delivery.STREAMING)
        record.digest = digest(canonical)
        local.record = record
        # the callbacks are in place BEFORE the decision: whichever thread later
        # resolves the branch the message may be held in will find them
        record.on_release = lambda _record: self._spawn(self._dispatch, local, canonical)
        record.on_drop = lambda _record, notice: self._reject_local(local, notice)
        decision = self.monitor.decide_send(record)
        if decision.outcome is Outcome.REJECT:
            self._reject_local(local, decision.notice)
        elif decision.outcome is Outcome.HOLD:
            # The caller only sees a task in progress, as if the peer were busy.
            local.state = TaskState.WORKING
            local.stream.put(self.adapter.working(msg, local.id, context_id=local.context_id))
        elif decision.duplicate_of is not None:
            self._alias(local, decision.duplicate_of, msg)
        else:
            self._spawn(self._dispatch, local, canonical)
        return local

    def _alias(self, local: _LocalTask, original: MessageRecord, msg: InterAgentMessage) -> None:
        """A re-sent held message, delivered once: the new task mirrors the original."""
        with self._lock:
            original_task = next((task for task in self._tasks.values() if task.record is original), None)
            if original_task is None:
                local.state, local.notice = TaskState.FAILED, "the original task is unknown"
                local.stream.put(self.adapter.rejected(msg, local.id, local.notice,
                                                       context_id=local.context_id))
                local.stream.close()
                return
            local.alias_of = original_task
            local.stream.put(self._snapshot(original_task, msg, view=local).to_bytes())
            if original_task.done:
                local.stream.close()
            else:
                # From now on, every event of the original is also put on this stream.
                original_task.mirrors.append((local.id, local.context_id, local.stream))

    def _dispatch(self, local: _LocalTask, body: bytes) -> None:
        """Forward a released request and relay what comes back to the agent's task.
        Runs in a background thread."""
        if local.mode == "poll":
            # returnImmediately: one response now; the agent polls for the rest.
            response, reply_headers = self._forward(local.url, body, local.record)
            self._settle_response(local, response, reply_headers)
            return
        headers = self._headers(local.record)
        try:
            upstream = self.network.stream(local.url, body, headers)
        except ConnectionError as e:
            self._reject_local(local, f"transport error: {e}")
            return
        for event_body, event_headers in upstream:
            self._accept_reply(event_body, event_headers)
            if local.peer is None:
                self._external_inbound(event_body, local.url)
            self._emit(local, event_body)
        self._finish(local)

    def _settle_response(self, local: _LocalTask, response: bytes, response_headers: Headers) -> None:
        """Take in one response for a polled task (record the delivery, update the task)."""
        self._accept_reply(response, response_headers)
        if local.peer is None:
            self._external_inbound(response, local.url)
        self._emit(local, response)
        if local.state.is_final:
            self._finish(local)

    def _headers(self, record: MessageRecord | None, task_record: str | None = None) -> Headers:
        """The headers a request leaves with: the A2A version, the sending host, and the
        monitor id of the released message (or, for a poll, of the request that started
        the task)."""
        headers: Headers = {**version_headers(), FROM_HEADER: self.agent_id}
        if record is not None:
            headers[KMID_HEADER] = record.kmid
        if task_record is not None:
            headers[TASK_HEADER] = task_record
        return headers

    def _forward(self, url: str, body: bytes, record: MessageRecord | None = None,
                 task_record: str | None = None) -> tuple[bytes, Headers]:
        """Send a request and wait for the response; a transport failure becomes a
        JSON-RPC error response."""
        try:
            return self.network.request(url, body, self._headers(record, task_record))
        except ConnectionError as e:
            return _error(None, ErrorCode.INTERNAL_ERROR, str(e)), {}

    def _emit(self, local: _LocalTask, body: bytes, *, from_peer: bool = True) -> None:
        """Track the task and hand an event to the agent under its local id (and to
        every task mirroring it)."""
        response = self._track(local, body, from_peer=from_peer)
        if response is None:
            return
        local.stream.put(_relabel(response, local.id, local.context_id))
        with self._lock:
            mirrors = list(local.mirrors)
        for mirror_id, mirror_context, stream in mirrors:
            stream.put(_relabel(response, mirror_id, mirror_context))

    def _finish(self, local: _LocalTask) -> None:
        """The task's stream has ended: close it and every mirror."""
        with self._lock:
            local.done = True
            mirrors, local.mirrors = list(local.mirrors), []
        local.stream.close()
        for _mirror_id, _mirror_context, stream in mirrors:
            stream.close()

    def _track(self, local: _LocalTask, body: bytes, *, from_peer: bool = True) -> Response | None:
        """Follow the task through an event. Only the peer's own events teach its ids:
        an answer the monitor gave itself (a rejection) carries the agent's."""
        try:
            response = parse_response(body)
        except ProtocolError:
            return None
        result = response.result
        if from_peer and isinstance(result, (Task, StatusUpdate, ArtifactUpdate, Message)):
            remote_id = result.id if isinstance(result, Task) else result.task_id
            local.remote_id = local.remote_id or remote_id
            if result.context_id:
                self._remember_context(local, result.context_id)
        if isinstance(result, Task):
            # A full snapshot of the task: replaces what was collected so far.
            local.state = result.status.state
            local.texts, local.data = [], []
            for artifact in result.artifacts:
                self._collect(local, artifact.parts)
            if result.status.message is not None:
                local.notice = result.status.message.text()
        elif isinstance(result, StatusUpdate):
            local.state = result.status.state
            if result.status.message is not None:
                local.notice = result.status.message.text()
        elif isinstance(result, ArtifactUpdate):
            self._collect(local, result.artifact.parts)
        elif isinstance(result, Message):                     # a direct answer, no task
            local.state = TaskState.COMPLETED
            self._collect(local, result.parts)
        elif response.error is not None:
            local.state, local.notice = TaskState.FAILED, response.error.message
        return response

    def _remember_context(self, local: _LocalTask, remote_ctx: str) -> None:
        """The peer's context id for a local task: follow-ups in the agent's context
        are mapped to it."""
        if local.remote_context is None:
            local.remote_context = remote_ctx
            with self._lock:
                self._contexts.setdefault((_peer_key(local.peer, local.url), local.context_id), remote_ctx)

    @staticmethod
    def _collect(local: _LocalTask, parts: list) -> None:
        for part in parts:
            if part.kind == "text" and part.text:
                local.texts.append(part.text)
            elif part.kind == "data" and part.data is not None:
                local.data.append(part.data)

    def _reject_local(self, local: _LocalTask, notice: str) -> None:
        """End a local task as rejected, with the monitor's notice."""
        local.state = TaskState.REJECTED
        local.notice = notice
        self._emit(local, self.adapter.rejected(local.request, local.id, notice, context_id=local.context_id),
                   from_peer=False)
        self._finish(local)

    # --- polls, cancellations and subscriptions -------------------------------
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
            response, reply_headers = self._forward(url, self.adapter.canonical_poll(msg, msg.task_id or ""),
                                                    task_record=kmid)
            self._accept_reply(response, reply_headers)
            if self.spec.agent_at(url) is None:
                self._external_inbound(response, url)
            return response

        target = local.alias_of or local
        held = (self.defense and target.record is not None and target.record.status is MsgStatus.HELD)
        if msg.kind is CommKind.CONTROL:
            # Cancelling: only a task the peer has (it was released) and that still runs.
            if held or target.remote_id is None or target.state.is_final:
                return Response(id=rpc_id, error=RpcError.info(
                    ErrorCode.TASK_NOT_CANCELABLE,
                    "Task cannot be canceled now" + (" (held for review)" if held else ""),
                    "TASK_NOT_CANCELABLE", taskId=local.id)).to_bytes()
            response, reply_headers = self._forward(
                target.url, self.adapter.canonical_poll(msg, target.remote_id),
                task_record=target.record.kmid if target.record else None)
            self._accept_reply(response, reply_headers)
            if target.peer is None:
                self._external_inbound(response, target.url)
            return self._relabel_for(response, local.id, local.context_id)

        if held:
            # Polling a held task is a dependency on it: resolve now (trigger AWAIT).
            self.monitor.await_held(target.record)
        if (target.mode == "poll" and target.remote_id and not target.state.is_final
                and target.record is not None and target.record.status is not MsgStatus.HELD
                and target.record.status is not MsgStatus.REJECTED):
            # A returnImmediately task: ask the peer for the current state.
            poll = self.adapter.canonical_poll(msg, target.remote_id)
            response, reply_headers = self._forward(target.url, poll, task_record=target.record.kmid)
            self._settle_response(target, response, reply_headers)
        return self._snapshot(target, msg, view=local, bare=True).to_bytes()

    def _peer_task(self, url: str, task_id: str | None) -> tuple[bool, str | None]:
        """Whether the peer at `url` issued `task_id` to this agent, and the monitor id
        of the request it answered."""
        key = (_peer_key(self.spec.agent_at(url), url), task_id or "")
        with self._lock:
            return key in self._peer_ids, self._peer_ids.get(key)

    def _subscribe(self, url: str, msg: InterAgentMessage, body: bytes) -> EventStream:
        """SubscribeToTask: a stream of the task's events, starting with its current
        state."""
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
                # Our own stream of the task: mirror it into the subscription.
                subscription = EventStream()
                subscription.put(self._snapshot(target, msg, view=local).to_bytes())
                if target.done:
                    subscription.close()
                else:
                    target.mirrors.append((local.id, local.context_id, subscription))
                return subscription
        return self._subscribe_remote(target, local, msg)

    def _subscribe_remote(self, target: _LocalTask, view: _LocalTask, msg: InterAgentMessage) -> EventStream:
        """A subscription to a returnImmediately task: relayed to the peer under its
        task id, its events presented under the agent's ids. A task the peer has not
        seen yet (still on hold, or released a moment ago) is answered with its
        current state; the agent polls on."""
        rpc_id = msg.raw.id if isinstance(msg.raw, Request) else None
        record = target.record
        if not target.remote_id or (self.defense and record is not None
                                    and record.status is not MsgStatus.DELIVERED):
            return _closed(self._snapshot(target, msg, view=view).to_bytes())
        try:
            upstream = self.network.stream(target.url, self.adapter.canonical_poll(msg, target.remote_id),
                                           self._headers(None, record.kmid if record is not None else None))
        except ConnectionError as e:
            return _closed(_error(rpc_id, ErrorCode.INTERNAL_ERROR, str(e)))
        subscription = EventStream()

        def pump() -> None:
            for event_body, event_headers in upstream:
                self._accept_reply(event_body, event_headers)
                if target.peer is None:
                    self._external_inbound(event_body, target.url)
                response = self._track(target, event_body)
                if response is not None:
                    subscription.put(_relabel(response, view.id, view.context_id))
            subscription.close()

        self._spawn(pump)
        return subscription

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
        subscription = EventStream()

        external = self.spec.agent_at(url) is None

        def pump() -> None:
            for event_body, event_headers in upstream:
                self._accept_reply(event_body, event_headers)
                if external:
                    self._external_inbound(event_body, url)
                subscription.put(event_body)
            subscription.close()

        self._spawn(pump)
        return subscription

    def _snapshot(self, local: _LocalTask, msg: InterAgentMessage, *, view: _LocalTask | None = None,
                  bare: bool = False) -> Response:
        """The task as this agent knows it, under the ids of `view` (a task mirroring
        `local`): a SendMessage / stream answer (wrapped) or a GetTask result (`bare`)."""
        view = view or local
        parts = [Part.from_text(text) for text in local.texts] + [Part.from_data(data) for data in local.data]
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

    # --- content arriving for this agent ------------------------------------
    def _accept_reply(self, body: bytes, headers: Headers) -> None:
        """Released content arrived for this agent: record the delivery (once, and
        only for exactly the bytes that were released)."""
        if not self.defense:
            return
        record = self.fabric.message(headers.get(KMID_HEADER))
        if (record is not None and record.receiver == self.agent_id and record.status is MsgStatus.RELEASED
                and record.digest == digest(body)):
            self.fabric.deliver(record)

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
        deployment's secret), or nobody the monitor vouches for (None).

        Returns (requester, the monitor id of the request it made). Accepting a
        capability delivers the message: the receiver's labels join the sender's."""
        if not self.defense:
            return headers.get(FROM_HEADER), None
        token = headers.get(PRINCIPAL_HEADER)
        if token and token == self.fabric.principal_token:
            return PRINCIPAL, None
        # A released request, for exactly these bytes, not consumed yet.
        record = self.fabric.message(headers.get(KMID_HEADER))
        if (record is not None and record.receiver == self.agent_id and record.status is MsgStatus.RELEASED
                and not record.reply and record.digest == digest(body)):
            self.fabric.deliver(record)
            return record.sender, record.kmid
        # A poll (or cancel, or subscription) about a request that was delivered here.
        poll_record = self.fabric.message(headers.get(TASK_HEADER))
        if (poll_record is not None and poll_record.receiver == self.agent_id and not poll_record.reply
                and poll_record.status is MsgStatus.DELIVERED and _is_task_call(body)):
            return poll_record.sender, poll_record.kmid
        # Nobody the monitor vouches for: its content is untrusted input to the agent.
        try:
            text = self.adapter.parse_request("", body).text
        except ProtocolError:
            text = ""
        if text:
            self.monitor.on_external_inbound(text)
        return None, None

    def serve(self, body: bytes, headers: Headers) -> tuple[bytes, Headers]:
        """A request to this agent, answered once: the agent's answer, gated."""
        if not version_supported(headers):
            return version_error(rpc_id_of(body), headers), {}
        requester, in_reply_to = self._identify(body, headers)
        response = self.server.handle(body, version_headers())
        return self._gate_reply(response, requester, in_reply_to)

    def serve_stream(self, body: bytes, headers: Headers) -> EventStream:
        """A streamed request to this agent: every event of the agent's stream is
        gated like a reply. Once one is withheld, the rest of the stream is dropped."""
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        requester, in_reply_to = self._identify(body, headers)
        upstream = self.server.handle_stream(body, version_headers())
        if requester == PRINCIPAL:
            return upstream
        gated_stream = EventStream()

        def pump() -> None:
            blocked = False
            for event_body, _ in upstream:
                if blocked:
                    continue
                gated, gated_headers = self._gate_reply(event_body, requester, in_reply_to)
                gated_stream.put(gated, gated_headers)
                blocked = gated_headers.get(WITHHELD_HEADER) == "1"
            gated_stream.close()

        self._spawn(pump)
        return gated_stream

    def _track_plain(self, dest: str, msg: InterAgentMessage, *, reply: bool, delivery: Delivery) -> None:
        """Without a monitor nothing is decided, but the traffic is still counted, so
        an undefended run is measured like a defended one."""
        record = self.fabric.new_message(self.agent_id, dest, msg.text, msg.data, reply=reply,
                                         delivery=delivery)
        record.intra = self.spec.same_cluster(self.agent_id, dest)
        record.status, record.decision = MsgStatus.DELIVERED, "nodefense"
        ends = {"kmid": record.kmid, "from": self.agent_id, "to": dest}
        emit(self.fabric, "msg.send", **ends, text=record.content, reply=reply, delivery=delivery.value,
             intra=record.intra)
        emit(self.fabric, "msg.outcome", **ends, outcome="released", by="nodefense", intra=record.intra)
        emit(self.fabric, "msg.deliver", **ends, reply=reply)

    def _gate_reply(self, body: bytes, requester: str | None,
                    in_reply_to: str | None) -> tuple[bytes, Headers]:
        """Content leaving this agent for whoever asked: a reply, decided like a
        blocking message (the agent has finished; nothing later to wait for). The
        principal gets the answer; anyone unidentified is a party outside the system.

        Returns the bytes to send back and the monitor headers to send with them."""
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

        canonical = self.adapter.canonical_reply(body)
        if canonical is None:                                    # not a well-formed A2A response
            self.monitor.notify(notices.reply_withheld(requester or "the requester",
                                                       "it was not a well-formed A2A response"))
            return _error(None, ErrorCode.INTERNAL_ERROR, notices.reply_unavailable(self.agent_id)), \
                {WITHHELD_HEADER: "1"}
        canonical_body, reply = canonical
        if not reply.has_content:
            # A bare status ("working") carries nothing to decide.
            return canonical_body, {}
        if requester is None or requester not in self.spec.agents:
            approved, _notice = self.monitor.decide_external(UNIDENTIFIED, reply.text, reply.data)
            if approved:
                return canonical_body, {}
            return self._withheld(canonical_body, reply), {WITHHELD_HEADER: "1"}

        key = (requester, reply.task_id, digest(canonical_body))
        with self._lock:
            known = self._released_replies.get(key)
        if known is not None:                       # the same bytes, already released to it
            return canonical_body, {KMID_HEADER: known}
        record = self.fabric.new_message(self.agent_id, requester, reply.text, reply.data, reply=True,
                                         in_reply_to=in_reply_to)
        record.digest = digest(canonical_body)
        decision = self.monitor.decide_send(record)
        if decision.outcome is Outcome.RELEASE:
            with self._lock:
                self._released_replies[key] = record.kmid
            return canonical_body, {KMID_HEADER: record.kmid}
        # Withheld: the agent learns that its reply did not reach the requester.
        self.monitor.notify(notices.reply_withheld(requester, record.reason or "denied"))
        return self._withheld(canonical_body, reply), {WITHHELD_HEADER: "1"}

    def _withheld(self, body: bytes, reply: InterAgentMessage) -> bytes:
        """The reply replaced by a failed task carrying the monitor's notice."""
        try:
            response = parse_response(body)
        except ProtocolError:
            response = Response(id=None)
        notice = notices.reply_unavailable(self.agent_id)
        status = TaskStatus(TaskState.FAILED, message=Message.agent_text(notice))
        task_id = reply.task_id or new_id("task-")
        context_id = reply.context_id or new_id("ctx-")
        # Keep the shape of what was replaced: a stream event stays a stream event.
        if isinstance(response.result, (StatusUpdate, ArtifactUpdate)):
            result: Any = StatusUpdate(task_id, context_id, status)
        else:
            result = Task(id=task_id, context_id=context_id, status=status)
        return Response(id=response.id, result=result, bare=response.bare and isinstance(result, Task)).to_bytes()


def _error(rpc_id: Any, code: int, message: str) -> bytes:
    return Response(id=rpc_id, error=RpcError(int(code), message)).to_bytes()


def _task_not_found(rpc_id: Any, task_id: str | None) -> bytes:
    return Response(id=rpc_id, error=RpcError.info(ErrorCode.TASK_NOT_FOUND, "Task not found",
                                                   "TASK_NOT_FOUND", taskId=task_id or "")).to_bytes()


def _closed(body: bytes) -> EventStream:
    """A stream with exactly one event (an answer or an error)."""
    stream = EventStream()
    stream.put(body)
    stream.close()
    return stream


def _peer_key(dest: str | None, url: str) -> str:
    """Who issues a peer's ids: an agent of the system, or an outside endpoint."""
    return dest if dest is not None else url


def _relabel(resp: Response, task_id: str | None, context_id: str) -> bytes:
    """A response presented under other task and context ids (the agent's own)."""
    result = resp.result
    if isinstance(result, Task):
        result = Task(id=task_id or result.id, context_id=context_id, status=result.status,
                      artifacts=result.artifacts)
    elif isinstance(result, StatusUpdate):
        result = StatusUpdate(task_id or result.task_id, context_id, result.status)
    elif isinstance(result, ArtifactUpdate):
        result = ArtifactUpdate(task_id or result.task_id, context_id, result.artifact, result.append,
                                result.last_chunk)
    elif isinstance(result, Message):
        result = Message(role=result.role, parts=result.parts, message_id=result.message_id,
                         context_id=context_id, task_id=task_id or result.task_id)
    return Response(id=resp.id, result=result, error=resp.error, bare=resp.bare).to_bytes()


def _is_task_call(body: bytes) -> bool:
    """Is this a request about an existing task (GetTask, SubscribeToTask, CancelTask)?"""
    try:
        return parse_request(body).method in (Method.GET_TASK, Method.SUBSCRIBE, Method.CANCEL_TASK)
    except ProtocolError:
        return False
