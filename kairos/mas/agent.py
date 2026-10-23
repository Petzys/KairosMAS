"""KAIROS for one agent of a multi-agent system.

An AgentMonitor is the state a cluster's decision point keeps for one member: the
agent's own trust closure T and sensitivity set S (joined with those of every agent
it heard from), its speculative state machine, its trace, and its slice of the causal
log. It extends the single-agent ReferenceMonitor, so every external effect of the
agent takes exactly the single-agent path (gate -> speculation -> oracle -> commit).
On top of that it adds the inter-agent channel:

  * intra-cluster messages are logged and released at once: never stalled, never a
    resolution trigger;
  * a message leaving the cluster is an irreversible effect, released like an
    external request (policy first, the oracle on REVIEW):
      - BLOCKING (SendMessage): decided before it is sent; an open branch is
        resolved first, then the message is decided on its own (the oracle sees
        only what happened before it);
      - STREAMING (SendStreamingMessage): a stallable effect, held in the agent's
        speculative scope and released at its next resolution trigger (the oracle
        sees the later evidence); the sender meanwhile sees TASK_STATE_WORKING.
  * a reply leaving the cluster is decided like a blocking message: the agent has
    finished, there is no later trigger to wait for.

Resolution is always per agent, and the oracle only decides about this agent's held
effects -- but it sees their lineage, which may run through other agents.

Reading guide: `MessageRecord` is a message's life (PENDING -> HELD/RELEASED ->
DELIVERED, or REJECTED). In `AgentMonitor`, start with `decide_send` (the outbound
channel) and `on_receive` (the inbound one), then `resolve` and `_after_resolution`
(what happens when a branch is decided), then `adjudicate_effect` (one effect decided
on the spot). Every method that touches the agent's state takes `self.lock`.
"""
from __future__ import annotations

import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

from kairos.core.events import Channel, Event, HttpMethod
from kairos.core.extract import embedded_values
from kairos.core.store import LabelSnapshot, TokenStore
from kairos.engine.decision import Decision, StageResult
from kairos.engine.integrity import _declared_strategies, _trusted
from kairos.judge.commit import AutoCommitGate
from kairos.judge.oracle import judge_call_record
from kairos.mas import notices
from kairos.mas.a2a.adapter import Delivery
from kairos.mas.causal import AgentClock, CausalEvent, CausalLog, EventId, EventKind, VectorClock
from kairos.mas.policy import (
    annotate_intra_cluster, build_engines, evaluate_message, message_event,
)
from kairos.mas.spec import A2A_EXTERNAL, A2A_REPLY, A2A_SEND, MASSpec
from kairos.mas.trace import emit
from kairos.monitor import ReferenceMonitor, SessionResult
from kairos.speculative.branch import Branch, HeldAction
from kairos.speculative.effects import EffectKind, State
from kairos.speculative.machine import EventView, ResolveOutcome, SpeculativeMachine

if TYPE_CHECKING:
    from kairos.mas.fabric import MonitorFabric

# The pseudo-tool under which a received message appears in the agent's trace.
RECV_TOOL = "a2a.recv"
_CLIP = 4000


def _clip(s: str, n: int = _CLIP) -> str:
    """`s` cut to `n` characters (for logs and traces, never for decisions)."""
    return s if len(s) <= n else s[:n] + "…"


class MsgStatus(str, Enum):
    PENDING = "pending"
    HELD = "held"            # stalled in the sender's speculative scope
    RELEASED = "released"    # cleared to leave the sender's boundary
    DELIVERED = "delivered"  # recorded at the receiver
    REJECTED = "rejected"    # denied (never left)


@dataclass(slots=True)
class MessageRecord:
    """One message between agents of the system, as the monitor tracks it. The
    monitor's message id (`kmid`) keys the happens-before edge SEND -> RECV; agents
    never see it."""
    kmid: str
    sender: str
    receiver: str
    text: str
    data: list[dict[str, Any]] = field(default_factory=list)   # structured parts
    reply: bool = False                    # a reply to a request (else a request)
    delivery: Delivery = Delivery.BLOCKING
    in_reply_to: str | None = None         # the kmid of the request this answers
    status: MsgStatus = MsgStatus.PENDING
    intra: bool = False                    # sender and receiver in the same cluster
    was_held: bool = False
    decision: str = ""                     # what decided it ("axes", "oracle", "echo", ...)
    reason: str = ""
    annotations: dict[str, Any] = field(default_factory=dict)  # intra-cluster check results
    send_event: EventId | None = None      # the sender's SEND event ...
    send_clock: VectorClock | None = None  # ... and its clock: the receiver's RECV depends on it
    labels: LabelSnapshot | None = None    # the sender's T and S when it wrote the message
    # sha256 of the canonical bytes released under this id: the id is a single-use
    # capability for exactly that content (checked where it is consumed)
    digest: str | None = None
    created: float = field(default_factory=time.monotonic)
    released_at: float | None = None
    # set by the enforcement point while the message is held: what to do when a later
    # resolution releases or drops it
    on_release: Callable[["MessageRecord"], None] | None = None
    on_drop: Callable[["MessageRecord", str], None] | None = None

    @property
    def content(self) -> str:
        """Everything the message carries, as one text (what is checked)."""
        if not self.data:
            return self.text
        return self.text + "\n" + json.dumps(self.data, ensure_ascii=False, sort_keys=True)

    def summary(self) -> dict[str, Any]:
        return {"kmid": self.kmid, "from": self.sender, "to": self.receiver, "reply": self.reply,
                "delivery": self.delivery.value, "intra": self.intra, "status": self.status.value,
                "was_held": self.was_held,
                "decision": self.decision, "reason": self.reason,
                **({"annotations": self.annotations} if self.annotations else {})}


class Outcome(str, Enum):
    RELEASE = "release"     # send it now
    HOLD = "hold"           # stalled until the sender's next trigger
    REJECT = "reject"       # never sent; the sender gets a notice


@dataclass(slots=True)
class MessageDecision:
    """What `decide_send` tells the enforcement point to do with a message."""
    outcome: Outcome
    record: MessageRecord
    notice: str = ""
    # RELEASE of a re-sent message: the identical held message released by the
    # resolution its re-send triggered (deliver once, answer both with its result)
    duplicate_of: MessageRecord | None = None


Resolution = tuple[Any, Branch, ResolveOutcome]     # (CommitDecision, branch, outcome)


class AgentMonitor(ReferenceMonitor):
    """The monitor of one agent (see the module docstring).

    Two locks: `lock` (re-entrant) serialises everything that reads or changes the
    agent's labels, branch and trace. `_notice_lock` protects only the queue of notices
    for the agent; it is never held while another lock is taken, so any thread may
    queue a notice at any time.
    """

    def __init__(
        self,
        spec: MASSpec,
        agent_id: str,
        *,
        fabric: "MonitorFabric",
        log: CausalLog,
        judge: Any = None,
        commit_gate: Any = None,
        mode: str = "full",
        hold_notice: str = "honest",
        max_held_per_branch: int = 1,
        max_stall_seconds: float = 120.0,
        sync_get: bool = True,
    ) -> None:
        store = TokenStore(owner=agent_id)
        engines = build_engines(spec, agent_id, store, mode=mode)
        machine = SpeculativeMachine(max_held_per_branch=max_held_per_branch,
                                     max_stall_seconds=max_stall_seconds, hold_notice=hold_notice)
        super().__init__(spec.agent_policy(agent_id), effector=None, engine=engines.engine,
                         store=store, machine=machine, judge=judge,
                         commit_gate=commit_gate or AutoCommitGate(), sync_get=sync_get)
        self.spec = spec
        self.agent_id = agent_id
        self.cluster_id = spec.agents[agent_id].cluster
        self.engines = engines
        self.fabric = fabric
        self.log = log
        self.clock = AgentClock(agent_id)
        self.lock = threading.RLock()
        # Set once a resolution withheld something of this agent; the oracle is shown
        # earlier denials of agents in an effect's lineage.
        self.flagged = False
        self.denials: list[EventId] = []
        self._notices: list[str] = []
        self._notice_lock = threading.Lock()      # never held while taking another lock
        # dispatches a committed held tool call: (call_ref, real_args) -> (result, error)
        self.executor: Callable[[Any, dict[str, Any]], tuple[Any, Any]] | None = None
        self.oracle_calls = 0
        self._heard_from: dict[str, list[str]] = {}     # agent -> content it sent us (lowercased)
        # held tool calls resolved so far: call id -> ("committed", result, error) | ("aborted", ...)
        self.call_outcomes: dict[str, tuple[str, Any, Any]] = {}

    # --- causal log ---------------------------------------------------------
    def record_event(self, kind: EventKind, payload: dict[str, Any], *, msg_id: str | None = None,
                     after: EventId | None = None, merge: VectorClock | None = None) -> CausalEvent:
        """Number an event of this agent and submit it to the decision point's log.
        `after`/`merge` link a RECV to the SEND it depends on."""
        seq, clock = self.clock.stamp(merge)
        event = CausalEvent(self.agent_id, seq, kind, clock, payload, msg_id, after, time.time())
        self.log.submit(event)
        return event

    # --- the single-agent path, logged --------------------------------------
    def begin_session(self, user_prompt: str) -> None:
        """Only the entry agent is seeded: T_0 reaches every other agent through the
        label joins of the messages its work descends from."""
        with self.lock:
            super().begin_session(user_prompt)
            self.record_event(EventKind.PROMPT, {"prompt": _clip(user_prompt)})

    def gate(self, event: Event) -> StageResult:
        """The policy decision on one effect (the single-agent gate), recorded."""
        with self.lock:
            result = super().gate(event)
            emit(self.fabric, "gate", agent=self.agent_id, cluster=self.cluster_id,
                 target=event.metadata.get("function") or event.object, decision=result.decision.value,
                 by=result.produced_by, reason=result.reason, channel=getattr(event.channel, "value", None))
            self.record_event(EventKind.TOOL_CALL, {
                "tool": event.metadata.get("function") or event.object,
                "args": dict(event.content) if isinstance(event.content, dict) else {},
                "decision": result.decision.value, "by": result.produced_by,
                "reason": result.reason})
            return result

    def admit_result(self, event: Event) -> None:
        """A tool result entering the agent: labelled (single-agent path) and logged."""
        with self.lock:
            super().admit_result(event)
            self.record_event(EventKind.TOOL_RESULT, {"tool": event.object,
                                                      "result": _clip(str(event.content))})

    def adjudicate(self, ev: EventView):
        """A reviewed read, decided inline (single-agent sync-GET), logged."""
        return self.adjudicate_effect(ev, (), mode="sync_get")

    def resolve_branch(self, execute_fn, pending: EventView | None = None):
        """The single-agent entry point, routed through `resolve`. `execute_fn`
        dispatches held tool calls when no executor is bound."""
        with self.lock:
            if self.executor is None:
                self.executor = execute_fn
            resolution = self.resolve("IN_TURN" if pending is not None else "TERMINAL", pending)
            assert resolution is not None, "resolve_branch without an open branch"
            return resolution

    # --- resolution ---------------------------------------------------------
    def resolve(self, trigger: str, pending: EventView | None = None) -> Resolution | None:
        """Resolve the open branch now, for any trigger. Committed held effects are
        dispatched (tool calls executed, messages released); aborted ones dropped.
        None when no branch is open."""
        with self.lock:
            if self.machine.state is not State.BRANCH or self.machine.active is None:
                return None
            # The oracle must see the complete causal past of what it decides.
            self._await_lineage()
            commit_decision, branch, outcome = ReferenceMonitor.resolve_branch(
                self, self._dispatch, pending=pending)
            self._after_resolution(trigger, commit_decision, branch, outcome)
            return commit_decision, branch, outcome

    def _dispatch(self, call_ref: Any, args: dict[str, Any]) -> tuple[Any, Any]:
        """Carry out one committed held effect: release a held message, or execute a
        held tool call through the executor the enforcement point bound."""
        if isinstance(call_ref, MessageRecord):
            self._release_held(call_ref)
            return f"message to {call_ref.receiver} released", None
        if self.executor is None:
            return "", "no executor bound for held tool calls"
        return self.executor(call_ref, args)

    def _after_resolution(self, trigger: str, commit_decision: Any, branch: Branch,
                          outcome: ResolveOutcome) -> None:
        """Book-keeping after a branch was decided: remember what happened to each held
        tool call, drop the held messages that were aborted, log the DECISION, and --
        if anything was withheld -- flag the agent and tell it, and the agents it
        messaged meanwhile, that those actions never happened."""
        self.oracle_calls += 1
        emit(self.fabric, "resolution", agent=self.agent_id, cluster=self.cluster_id, trigger=trigger,
             committed=[self._action_summary(held) for held in outcome.committed],
             aborted=[self._action_summary(held) for held in outcome.aborted],
             rationale=commit_decision.verdict.rationale, decided_by=commit_decision.source,
             errors=[[held.tool, str(error)] for held, _result, error in outcome.dispatched if error])

        # The enforcement point answers an agent that re-issues a held call from these.
        for held, result, error in outcome.dispatched:
            call_id = getattr(held.call_ref, "id", None)
            if call_id is not None and not isinstance(held.call_ref, MessageRecord):
                self.call_outcomes[str(call_id)] = ("committed", result, error)

        withheld: list[tuple[str, dict[str, Any]]] = []
        for held in outcome.aborted:
            withheld.append((held.tool, held.args))
            if isinstance(held.call_ref, MessageRecord):
                self._drop_held(held.call_ref, commit_decision.verdict.rationale)
            elif getattr(held.call_ref, "id", None) is not None:
                self.call_outcomes[str(held.call_ref.id)] = ("aborted", None,
                                                             commit_decision.verdict.rationale)

        decision_event = self.record_event(EventKind.DECISION, {
            "mode": "branch", "trigger": trigger,
            "committed": [self._action_summary(held) for held in outcome.committed],
            "aborted": [self._action_summary(held) for held in outcome.aborted],
            "rationale": commit_decision.verdict.rationale, "decided_by": commit_decision.source})
        if outcome.aborted:
            self.flagged = True
            self.denials.append(decision_event.id)
            self.notify(notices.abort_notice(withheld))
            # Receivers of messages sent while these actions were pending may have been
            # told they happened.
            self.fabric.notify_downstream(self.agent_id, since=branch.opened_at, withheld=withheld)

    @staticmethod
    def _action_summary(held: HeldAction) -> dict[str, Any]:
        args = {key: _clip(str(value), 300) for key, value in held.args.items()}
        return {"tool": held.tool, "args": args}

    def adjudicate_effect(self, ev: EventView, embedded: tuple[str, ...], *, mode: str) -> tuple[bool, Any]:
        """Decide ONE effect now, with no branch: what the agent has done so far is
        the evidence (sync GETs, blocking messages, replies). Returns (approved?,
        the oracle's verdict).

        The effect is wrapped in a one-action branch so that the oracle and the commit
        gate see it exactly as they see a held effect at a resolution."""
        with self.lock:
            self._await_lineage()
            branch = Branch(branch_id=f"sync-{mode}", opened_at=0.0, opened_reason=ev.reason)
            branch.held_calls.append(HeldAction(call_ref=ev.call_ref, tool=ev.tool, args=ev.args,
                                                provenance=ev.provenance, reason=ev.reason,
                                                embedded=embedded))
            branch.untrusted_content = list(self.session.untrusted_content)
            branch.judge_trace = [call for call in self.session.calls
                                  if call["decision"] == "ALLOW" and call.get("result") is not None]
            branch.prior_resolutions = list(self.session.resolutions)
            verdict = self.judge.evaluate(self.store.user_prompt(), branch)
            commit_decision = self.commit_gate.decide(branch, verdict)
            approved = all(commit_decision.mask) if commit_decision.mask else bool(commit_decision.commit)
            self.oracle_calls += 1

            # Recorded like a resolution, so that later oracle calls see this decision.
            self.session.resolutions.append({
                "branch": branch.branch_id, "trigger": ev.reason,
                "committed": [ev.tool] if approved else [], "aborted": [] if approved else [ev.tool],
                "aborted_actions": [] if approved else [
                    {"tool": ev.tool, "ids": SessionResult._action_ids(ev.tool, ev.args, ev.provenance)}],
                "commit": approved, "decided_by": commit_decision.source,
                "judge_consistent": verdict.consistent,
                "rationale": verdict.rationale, "flagged": verdict.flagged, "commit_errors": [],
                mode: True, **judge_call_record(verdict)})
            self.attribution[f"{'EXECUTE' if approved else 'REFUSE'}:{mode}"] += 1

            summary = {"tool": ev.tool, "args": {key: _clip(str(value), 300) for key, value in ev.args.items()}}
            decision_event = self.record_event(EventKind.DECISION, {
                "mode": mode, "trigger": mode, "committed": [summary] if approved else [],
                "aborted": [] if approved else [summary], "rationale": verdict.rationale,
                "decided_by": commit_decision.source})
            if not approved:
                self.flagged = True
                self.denials.append(decision_event.id)
            return approved, verdict

    def on_terminal(self) -> Resolution | None:
        """The agent finished its own work (a task): resolve an open branch."""
        with self.lock:
            resolution = self.resolve("TERMINAL")
            self.record_event(EventKind.TERMINAL, {})
            return resolution

    def await_held(self, record: MessageRecord) -> Resolution | None:
        """The sender needs the outcome of a message it streamed and that is still
        held: a dependency on the held effect, so resolve now (otherwise the sender
        would wait on its own stall)."""
        with self.lock:
            branch = self.machine.active
            if record.status is MsgStatus.HELD and branch is not None and any(
                    held.call_ref is record for held in branch.held_calls):
                return self.resolve("AWAIT")
            return None

    def tick(self, now: float | None = None) -> Resolution | None:
        """Budget check for an agent that has gone quiet with effects on hold: the
        session budget bounds how long a hand-off can be delayed."""
        with self.lock:
            branch = self.machine.active
            now = time.monotonic() if now is None else now
            if branch is not None and self.machine.state is State.BRANCH and \
                    now - branch.opened_at > self.machine.max_stall_seconds:
                return self.resolve("BUDGET")
            return None

    def notify(self, text: str) -> None:
        """Queue a notice for the agent; its harness hands it over (`drain_notices`)."""
        emit(self.fabric, "notice", agent=self.agent_id, text=text)
        with self._notice_lock:
            self._notices.append(text)

    def drain_notices(self) -> list[str]:
        with self._notice_lock:
            queued, self._notices = self._notices, []
            return queued

    # --- the inter-agent channel: outbound ----------------------------------
    def _await_lineage(self) -> None:
        """An effect is decided once all causally preceding events have arrived."""
        if not self.fabric.await_lineage(self.clock.current):
            self.attribution["WARN:lineage_incomplete"] += 1

    def decide_send(self, record: MessageRecord) -> MessageDecision:
        """Decide a message this agent emits: release it, hold it, or reject it.

        Every message is first evaluated by the policy and recorded as a SEND event
        (the point of emission). Then, by kind: intra-cluster messages are released at
        once; denied ones rejected; replies and blocking requests decided on the spot
        (`_decide_blocking`); streamed requests go through the speculative machine
        (`_decide_streaming`)."""
        with self.lock:
            self._await_lineage()
            spec = self.spec
            record.intra = spec.same_cluster(record.sender, record.receiver)
            emit(self.fabric, "msg.send", kmid=record.kmid, **{"from": record.sender}, to=record.receiver,
                 text=record.content, reply=record.reply, delivery=record.delivery.value,
                 intra=record.intra, in_reply_to=record.in_reply_to)
            stage = self._evaluate(record)
            emit(self.fabric, "gate", agent=self.agent_id, cluster=self.cluster_id, kmid=record.kmid,
                 target=f"message to {record.receiver}", decision=stage.decision.value,
                 by=stage.produced_by, reason=stage.reason, channel="a2a")
            # Inside a cluster nothing is stalled, but a cheap check may annotate the log
            # for the oracle's later benefit.
            if record.intra and spec.cluster_of(self.agent_id).policy.intra_cluster_checks == "annotate":
                record.annotations = annotate_intra_cluster(
                    spec, self.engines, record.sender, record.receiver, record.text, record.data,
                    reply=record.reply)
            # the SEND event is the point of emission: the receiver inherits the labels
            # the sender held when it wrote the message
            record.labels = self.store.snapshot()
            send_event = self.record_event(EventKind.SEND, {
                "to": record.receiver, "reply": record.reply, "delivery": record.delivery.value,
                "intra": record.intra, "decision": stage.decision.value, "by": stage.produced_by,
                "reason": stage.reason, "text": _clip(record.content, 1500),
                **({"annotations": record.annotations} if record.annotations else {})},
                msg_id=record.kmid)
            record.send_event, record.send_clock = send_event.id, send_event.clock
            self.session.record(message_event(spec, record.sender, record.receiver, record.text,
                                              record.data, reply=record.reply), stage)
            self.attribution[f"{stage.decision.value}:{stage.produced_by}"] += 1
            record.decision, record.reason = stage.produced_by, stage.reason

            if record.intra:
                return self._released(record)
            if stage.decision is Decision.DENY:
                return self._rejected(record, notices.message_rejected(record.receiver, stage.reason))
            if record.reply or record.delivery is Delivery.BLOCKING:
                return self._decide_blocking(record, stage)
            return self._decide_streaming(record, stage)

    def _evaluate(self, record: MessageRecord) -> StageResult:
        """The policy's decision on a message, with the echo exemption applied."""
        stage = evaluate_message(self.spec, self.engines, record.sender, record.receiver, record.text,
                                 record.data, reply=record.reply)
        if (stage.decision is Decision.REVIEW and stage.produced_by == "embedded_identifiers"
                and self._only_echoes(record)):
            return StageResult(Decision.ALLOW, stage=1, produced_by="echo",
                               reason="payload identifiers the destination itself sent")
        return stage

    def _only_echoes(self, record: MessageRecord) -> bool:
        """Are the payload identifiers no trusted source vouches for all values the
        DESTINATION sent this agent? Then the message introduces nothing to it --
        a reply confirming the account it was asked to pay -- and the payload
        check, which is about introducing values, has nothing to protect."""
        heard = self._heard_from.get(record.receiver)
        if not heard:
            return False
        engine = self.engines.messages
        strategies = _declared_strategies(engine.policy, engine.default_strategy)
        for _kind, value in embedded_values(record.content):
            if _trusted(self.store, value, strategies, None, self.engines.peers):
                continue
            needle = value.lower()
            if not any(needle in text for text in heard):
                return False
        return True

    def _decide_blocking(self, record: MessageRecord, stage: StageResult) -> MessageDecision:
        """A reply or a blocking request: decided now, before anything leaves.

        If held effects are pending, they are resolved first (trigger BLOCKING_EFFECT):
        the message may build on them. If that resolution withheld something, the
        message may describe things that did not happen, so it is returned to the
        sender to re-compose. Otherwise the message is re-evaluated (the labels may
        have changed) and decided on its own: ALLOW releases it, REVIEW asks the
        oracle."""
        if self.machine.state is State.BRANCH:
            view, _ = self.message_view(record, stage)
            resolution = self.resolve("BLOCKING_EFFECT", pending=view)
            if resolution is not None and resolution[2].aborted:
                return self._rejected(record, notices.recompose(record.receiver))
            stage = self._evaluate(record)
            if stage.decision is Decision.DENY:
                return self._rejected(record, notices.message_rejected(record.receiver, stage.reason))
        if stage.decision is Decision.ALLOW:
            return self._released(record)
        view, embedded = self.message_view(record, stage)
        approved, verdict = self.adjudicate_effect(view, embedded, mode="sync_message")
        if approved:
            record.decision = "oracle"
            return self._released(record)
        record.decision, record.reason = "oracle", verdict.rationale
        return self._rejected(record, notices.message_rejected(record.receiver, verdict.rationale))

    def _decide_streaming(self, record: MessageRecord, stage: StageResult) -> MessageDecision:
        """A streamed request: the speculative machine decides whether it is released,
        held in the agent's branch, or first makes the machine resolve.

        The machine may ask to RESOLVE the open branch before it takes this message
        (another held effect, a loop, a full branch). After that resolution:
          * if it committed an identical held message to the same receiver, this
            message is its re-send: it is not sent again, the enforcement point answers
            it with the original's result (`duplicate_of`);
          * otherwise the message is evaluated and offered to the machine once more.
        """
        view, embedded = self.message_view(record, stage)
        effect = self.machine.on_gate(stage.decision.value, view)
        if effect.kind is EffectKind.RESOLVE:
            resolution = self.resolve(effect.trigger.name if effect.trigger else "RESOLVE", pending=view)
            if resolution is not None:
                duplicate = None
                for held in resolution[2].committed:
                    if (isinstance(held.call_ref, MessageRecord)
                            and held.call_ref.receiver == record.receiver
                            and held.call_ref.content == record.content):
                        duplicate = held.call_ref
                        break
                if duplicate is not None:      # the re-send of a held message: deliver it once
                    record.status = MsgStatus.RELEASED
                    record.decision = "duplicate"
                    self.fabric.track(record)
                    self._emit_outcome(record, "duplicate", of=duplicate.kmid)
                    return MessageDecision(Outcome.RELEASE, record, duplicate_of=duplicate)
            stage = self._evaluate(record)
            if stage.decision is Decision.DENY:
                return self._rejected(record, notices.message_rejected(record.receiver, stage.reason))
            view, embedded = self.message_view(record, stage)
            effect = self.machine.on_gate(stage.decision.value, view)
            if effect.kind is EffectKind.RESOLVE:
                return self._rejected(record, notices.message_rejected(
                    record.receiver, "a prior held action was reviewed first; re-send if still needed"))
        if effect.kind is EffectKind.EXECUTE:
            return self._released(record)
        if effect.kind is EffectKind.STUB:
            # Held: the machine added it to the open branch. Remember which of its
            # arguments are identifiers, for the oracle.
            assert self.machine.active is not None
            self.machine.active.held_calls[-1].embedded = embedded
            record.status = MsgStatus.HELD
            record.was_held = True
            self.fabric.track(record)
            self._emit_outcome(record, "held")
            return MessageDecision(Outcome.HOLD, record)
        return self._rejected(record, notices.message_rejected(record.receiver, effect.reason))

    def message_view(self, record: MessageRecord, stage: StageResult) -> tuple[EventView, tuple[str, ...]]:
        """The machine's and the oracle's view of a message: destination, content,
        and each identifier the content carries with its provenance.

        Each identifier becomes an argument of its own (`iban_1`, `url_2`, ...) so that
        provenance and the oracle's attention apply to it individually. Returns the
        view and the names of those identifier arguments."""
        args: dict[str, Any] = {"to_agent": record.receiver, "message": _clip(record.text)}
        if record.data:
            args["data"] = _clip(json.dumps(record.data, ensure_ascii=False, sort_keys=True))
        provenance = {}
        embedded: list[str] = []
        for index, (kind, value) in enumerate(embedded_values(record.content), 1):
            key = f"{kind}_{index}"
            args[key] = value
            provenance[key] = self._provenance(value)
            embedded.append(key)
        view = EventView(tool=A2A_REPLY if record.reply else A2A_SEND, args=args, is_outbound=True,
                         is_revertable=False, consequential={key: args[key] for key in embedded},
                         provenance=provenance, call_ref=record,
                         reason=stage.reason or stage.produced_by)
        return view, tuple(embedded)

    def _emit_outcome(self, record: MessageRecord, outcome: str, **extra: Any) -> None:
        emit(self.fabric, "msg.outcome", kmid=record.kmid, **{"from": record.sender}, to=record.receiver,
             outcome=outcome, by=record.decision, reason=record.reason, intra=record.intra, **extra)

    def _released(self, record: MessageRecord) -> MessageDecision:
        record.status = MsgStatus.RELEASED
        record.released_at = time.monotonic()
        self.fabric.track(record)
        self._trace_sent(record, "delivered")
        self._emit_outcome(record, "released")
        return MessageDecision(Outcome.RELEASE, record)

    def _rejected(self, record: MessageRecord, notice: str) -> MessageDecision:
        record.status = MsgStatus.REJECTED
        self.fabric.track(record)
        self._emit_outcome(record, "rejected", notice=notice)
        return MessageDecision(Outcome.REJECT, record, notice)

    def _release_held(self, record: MessageRecord) -> None:
        """A held message was committed: mark it released and let the enforcement point
        send it (its `on_release` callback)."""
        record.status = MsgStatus.RELEASED
        record.released_at = time.monotonic()
        self._trace_sent(record, "delivered")
        emit(self.fabric, "msg.release", kmid=record.kmid, **{"from": record.sender}, to=record.receiver)
        if record.on_release is not None:
            record.on_release(record)

    def _drop_held(self, record: MessageRecord, reason: str) -> None:
        """A held message was aborted: it never leaves, and the sender's waiting task
        is rejected with a notice (its `on_drop` callback)."""
        record.status = MsgStatus.REJECTED
        record.reason = reason
        emit(self.fabric, "msg.drop", kmid=record.kmid, **{"from": record.sender}, to=record.receiver,
             reason=reason)
        if record.on_drop is not None:
            record.on_drop(record, notices.message_rejected(record.receiver, reason))

    def _trace_sent(self, record: MessageRecord, result: str) -> None:
        """Add a sent message to the agent's trace, where the oracle reads it like a
        tool call."""
        args: dict[str, Any] = {"to_agent": record.receiver, "message": _clip(record.text, 1500)}
        self.session.calls.append({"tool": A2A_REPLY if record.reply else A2A_SEND,
                                   "decision": "ALLOW", "args": args, "result": result})

    # --- parties outside the system -----------------------------------------
    def decide_external(self, url: str, text: str, data: list[dict[str, Any]] | None = None) -> tuple[bool, str]:
        """Content leaving the system for a party the spec does not list: an A2A
        request to an outside endpoint, or a reply to an unidentified requester. An
        external, irreversible effect with blocking semantics: an open branch is
        resolved first, then the effect is decided on its own (policy, then the
        oracle on REVIEW). Returns (release?, notice)."""
        with self.lock:
            self._await_lineage()
            content: dict[str, Any] = {"message": text}
            if data:
                content["data"] = json.dumps(data, ensure_ascii=False, sort_keys=True)
            event = Event(time.time(), Channel.NET, HttpMethod.POST.value, self.agent_id, url, content,
                          {"function": A2A_EXTERNAL})
            if self.machine.state is State.BRANCH:
                view = self.event_view(event, call_ref=None, decision=self.engine.evaluate(event))
                resolution = self.resolve("BLOCKING_EFFECT", pending=view)
                if resolution is not None and resolution[2].aborted:
                    return False, notices.recompose(url)
            stage = self.gate(event)
            if stage.decision is Decision.DENY:
                return False, notices.message_rejected(url, stage.reason or stage.produced_by)
            if stage.decision is Decision.ALLOW:
                return True, ""
            approved, verdict = self.adjudicate_effect(self.event_view(event, call_ref=None, decision=stage),
                                                       (), mode="sync_external")
            return approved, "" if approved else notices.message_rejected(url, verdict.rationale)

    def on_external_inbound(self, text: str, source: str = "a2a.external") -> CausalEvent:
        """A request from a party that is neither a monitored agent nor the principal
        reached this agent: untrusted content, recorded like a received message (it
        carries no labels and no causal past the monitor knows)."""
        with self.lock:
            emit(self.fabric, "inbound.external", agent=self.agent_id, source=source, text=text)
            self.store.record_text(text, source)
            event = self.record_event(EventKind.RECV, {"from": source, "reply": False, "intra": False,
                                                       "text": _clip(text, 1500)})
            self.session.calls.append({"tool": RECV_TOOL, "decision": "ALLOW",
                                       "args": {"from": source, "kind": "request"}, "result": _clip(text)})
            self.session.record_untrusted(RECV_TOOL, text[:2000])
            return event

    # --- the inter-agent channel: inbound -----------------------------------
    def on_receive(self, record: MessageRecord) -> CausalEvent:
        """A message delivered to this agent. Its sender's labels join this agent's
        (T and S, owners kept); its content is recorded for provenance, and shown to
        the oracle as untrusted data -- agents are not the principal."""
        with self.lock:
            if record.labels is not None:
                self.store.join(record.labels)
            source = f"{RECV_TOOL}:{record.sender}"
            self.store.record_text(record.content, source)
            # The RECV depends on the sender's SEND: the sender's lineage becomes ours.
            event = self.record_event(EventKind.RECV, {
                "from": record.sender, "reply": record.reply, "intra": record.intra,
                "text": _clip(record.content, 1500)},
                msg_id=record.kmid, after=record.send_event, merge=record.send_clock)
            # Kept for the echo exemption (see _only_echoes).
            self._heard_from.setdefault(record.sender, []).append(record.content.lower())
            self.session.calls.append({"tool": RECV_TOOL, "decision": "ALLOW",
                                       "args": {"from": record.sender,
                                                "kind": "reply" if record.reply else "request"},
                                       "result": _clip(record.content)})
            self.session.record_untrusted(RECV_TOOL, record.content[:2000])
            record.status = MsgStatus.DELIVERED
            return event

    # --- reporting ----------------------------------------------------------
    def report(self) -> dict[str, Any]:
        with self.lock:
            summary = self.session.summary()
            summary["agent"] = self.agent_id
            summary["cluster"] = self.cluster_id
            summary["flagged"] = self.flagged
            summary["oracle_calls"] = self.oracle_calls
            summary["resolutions"] = list(self.session.resolutions)
            return summary
