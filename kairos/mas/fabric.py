"""Decision points and the fabric that connects them.

Each cluster has one logical *decision point* (DP). It holds the monitors of the
cluster's agents (their labels, speculative state and oracle) and the cluster's slice
of the causal log. A decision point can run on any trusted host: putting all of them
on one host gives a central monitor; spreading them out helps scale and isolates
failures. Only the *fabric* changes between the two. Here the fabric is in-process;
across hosts its calls (lineage queries, the message registry, delivery records)
would become RPCs between trusted hosts.

The fabric also keeps the *message registry*: every message an agent emits gets a
`MessageRecord`, keyed by the monitor's own message id (kmid). Enforcement points pass
that id to each other out of band (in monitor headers), and agents never see it. A
released message is accepted at the receiver only with its kmid and only for exactly
the bytes that were decided.

Reading guide: `MonitorFabric.begin_session` starts a run; `new_message` and `deliver`
are the message life cycle; `lineage`, `await_lineage` and `denials_in` answer the
oracle's questions about an effect's causal past; `report` summarises a run.
"""
from __future__ import annotations

import itertools
import secrets
import threading
from collections.abc import Callable
from typing import Any

from kairos.judge.commit import AutoCommitGate
from kairos.judge.oracle import DeterministicJudge
from kairos.mas import notices
from kairos.mas.a2a.adapter import Delivery
from kairos.mas.agent import AgentMonitor, MessageRecord, MsgStatus
from kairos.mas.causal import CausalEvent, CausalLog, EventId, EventKind, VectorClock
from kairos.mas.spec import ClusterSpec, MASSpec
from kairos.mas.trace import TracedJudge, TraceRecorder, emit

# Builds the oracle (judge) of one agent's monitor; it gets the monitor so that it can
# look at the agent's causal past.
JudgeFactory = Callable[[AgentMonitor], Any]


class ClusterDecisionPoint:
    """The decision point of one cluster: its members' monitors and its causal log."""

    def __init__(self, cluster: ClusterSpec, fabric: "MonitorFabric") -> None:
        self.id = cluster.id
        self.cluster = cluster
        self.fabric = fabric
        self.members = fabric.spec.members(cluster.id)
        # The log asks the fabric whether events of *other* clusters have arrived, so
        # that it can deliver its own events in causal order.
        self.log = CausalLog(foreign_delivered=fabric.delivered)
        self.agents: dict[str, AgentMonitor] = {}

    def owns(self, agent: str) -> bool:
        return agent in self.members


class MonitorFabric:
    """All decision points of a system, the message registry, and session state.

    Most constructor arguments are passed on to every agent's monitor:
    `mode`, `hold_notice` (what a held tool call returns to the agent),
    `max_held_per_branch`, `max_stall_seconds` (how long a held effect may wait for
    its agent's next trigger) and `sync_get`. `downstream_notices` controls whether
    receivers are told when something they were told about never happened.
    """

    def __init__(
        self,
        spec: MASSpec,
        *,
        judge_factory: JudgeFactory | None = None,
        commit_gate_factory: Callable[[], Any] | None = None,
        mode: str = "full",
        hold_notice: str = "honest",
        max_held_per_branch: int = 1,
        max_stall_seconds: float = 120.0,
        sync_get: bool = True,
        downstream_notices: bool = True,
        recorder: TraceRecorder | None = None,
    ) -> None:
        self.spec = spec
        self.recorder = recorder          # the run's flight recorder (kairos.mas.trace), if any
        self.judge_factory = judge_factory or (lambda _m: DeterministicJudge())
        self.commit_gate_factory = commit_gate_factory or AutoCommitGate
        self.monitor_kwargs = dict(mode=mode, hold_notice=hold_notice,
                                   max_held_per_branch=max_held_per_branch,
                                   max_stall_seconds=max_stall_seconds, sync_get=sync_get)
        self.downstream_notices = downstream_notices
        self._lock = threading.Lock()     # guards the message registry and session state
        self._ids = itertools.count(1)
        # Authenticates the principal's channel (a deployment's control endpoint) at the
        # entry agent's ingress. Never given to agents: a request that carries neither
        # this token nor a valid kmid comes from a party outside the system.
        self.principal_token = secrets.token_hex(16)
        self.dps: dict[str, ClusterDecisionPoint] = {}
        self.messages: dict[str, MessageRecord] = {}
        self.prompt = ""
        self._build()

    def _build(self) -> None:
        """Fresh decision points with fresh monitors, and an empty message registry."""
        self.dps = {cluster_id: ClusterDecisionPoint(cluster, self)
                    for cluster_id, cluster in self.spec.clusters.items()}
        self.messages = {}
        for dp in self.dps.values():
            for agent_id in dp.members:
                monitor = AgentMonitor(self.spec, agent_id, fabric=self, log=dp.log,
                                       commit_gate=self.commit_gate_factory(), **self.monitor_kwargs)
                monitor.judge = self.judge_factory(monitor)
                # With a flight recorder, every oracle call is recorded too.
                if self.recorder is not None and monitor.judge is not None:
                    monitor.judge = TracedJudge(monitor.judge, self.recorder, agent_id, dp.cluster.id)
                dp.agents[agent_id] = monitor

    # --- lifecycle ------------------------------------------------------------
    def begin_session(self, prompt: str) -> None:
        """A session starts from the principal's prompt with no prior state: fresh
        monitors everywhere, and the trust set T_0 seeded at the entry agent only.
        Every other agent obtains trust through the messages its work descends from."""
        with self._lock:
            self._build()
            self.prompt = prompt
        self.agent(self.spec.entry).begin_session(prompt)

    # --- lookup -----------------------------------------------------------------
    def dp_of(self, agent: str) -> ClusterDecisionPoint:
        return self.dps[self.spec.agents[agent].cluster]

    def agent(self, agent: str) -> AgentMonitor:
        return self.dp_of(agent).agents[agent]

    def monitors(self) -> list[AgentMonitor]:
        return [monitor for dp in self.dps.values() for monitor in dp.agents.values()]

    # --- causal log across decision points ------------------------------------
    def delivered(self, eid: EventId) -> bool:
        """Has the event `eid` (agent, sequence number) arrived at its decision point?
        Unknown agents (parties outside the system) have no events."""
        agent, _ = eid
        if agent not in self.spec.agents:
            return False
        return self.dp_of(agent).log.delivered(eid)

    def event(self, eid: EventId) -> CausalEvent | None:
        return self.dp_of(eid[0]).log.event(eid)

    def lineage(self, clock: VectorClock) -> dict[str, list[CausalEvent]]:
        """Every event `clock` covers, per agent: the causal past of the event the
        clock belongs to, back to the principal's prompt."""
        return {agent: self.dp_of(agent).log.events(agent, upto=seq)
                for agent, seq in clock.items() if agent in self.spec.agents}

    def await_lineage(self, clock: VectorClock, timeout: float = 5.0) -> bool:
        """Wait until every event in `clock`'s causal past has arrived (each decision
        point waits for its own agents). An effect is decided only on a complete
        past; returns False if something was still missing after `timeout`."""
        complete = True
        for dp in self.dps.values():
            agents = [agent for agent in clock.agents() if dp.owns(agent)]
            if agents:
                complete = dp.log.wait_for(clock, agents, timeout) and complete
        return complete

    def denials_in(self, clock: VectorClock, *, exclude: str | None = None) -> list[CausalEvent]:
        """DECISION events that withheld something and lie in `clock`'s lineage:
        the prior denials an oracle must see for an effect whose lineage passes
        through a flagged agent."""
        denials = []
        for agent, events in self.lineage(clock).items():
            if agent == exclude:
                continue
            denials += [event for event in events
                        if event.kind is EventKind.DECISION and event.payload.get("aborted")]
        return denials

    # --- messages ---------------------------------------------------------------
    def new_message(self, sender: str, receiver: str, text: str,
                    data: list[dict[str, Any]] | None = None, *, reply: bool = False,
                    delivery: Delivery = Delivery.BLOCKING,
                    in_reply_to: str | None = None) -> MessageRecord:
        """Register a message an agent is emitting and give it a fresh kmid. The
        record follows the message through its decision, release and delivery."""
        kmid = f"k{next(self._ids)}"
        record = MessageRecord(kmid=kmid, sender=sender, receiver=receiver, text=text,
                               data=list(data or []), reply=reply, delivery=delivery,
                               in_reply_to=in_reply_to)
        self.track(record)
        return record

    def track(self, record: MessageRecord) -> None:
        with self._lock:
            self.messages[record.kmid] = record

    def message(self, kmid: str | None) -> MessageRecord | None:
        """The record behind a kmid, or None (no id, or an id the monitor never issued)."""
        if kmid is None:
            return None
        with self._lock:
            return self.messages.get(kmid)

    def deliver(self, record: MessageRecord) -> CausalEvent:
        """Record a released message at its receiver: a RECV event in the receiver's
        log, and the join of the sender's labels into the receiver's."""
        event = self.agent(record.receiver).on_receive(record)
        emit(self, "msg.deliver", kmid=record.kmid, **{"from": record.sender}, to=record.receiver,
             reply=record.reply)
        # The new event may be what other buffered events were waiting for.
        for dp in self.dps.values():
            dp.log.retry()
        return event

    def notify_downstream(self, sender: str, *, since: float,
                          withheld: list[tuple[str, dict[str, Any]]]) -> None:
        """Tell the receivers of `sender`'s messages sent while its withheld actions
        were pending that those actions never happened (they may have been told they
        did)."""
        if not self.downstream_notices:
            return
        with self._lock:
            receivers = sorted({record.receiver for record in self.messages.values()
                                if record.sender == sender and record.created >= since
                                and record.status in (MsgStatus.RELEASED, MsgStatus.DELIVERED)})
        for receiver in receivers:
            self.agent(receiver).notify(notices.downstream_abort(sender, withheld))

    # --- budget -------------------------------------------------------------
    def tick(self, now: float | None = None) -> int:
        """Resolve branches whose stall budget is exhausted. Returns how many.

        Called by a watchdog in a deployment: an unmodified agent never tells the
        monitor that it is waiting on a held message, so the budget bounds the stall."""
        resolved = 0
        for monitor in self.monitors():
            if monitor.tick(now) is not None:
                resolved += 1
        return resolved

    # --- reporting ------------------------------------------------------------
    def report(self) -> dict[str, Any]:
        """The session in numbers: every message with its fate, every agent's
        monitor report, and totals."""
        with self._lock:
            messages = [record.summary() for record in self.messages.values()]
        inter_cluster = [message for message in messages if not message["intra"]]
        agents = {monitor.agent_id: monitor.report() for monitor in self.monitors()}
        return {
            "agents": agents,
            "messages": messages,
            "counts": {
                "messages": len(messages),
                "intra_cluster": len(messages) - len(inter_cluster),
                "inter_cluster": len(inter_cluster),
                "rejected": sum(message["status"] == MsgStatus.REJECTED.value for message in messages),
                "held": sum(message["was_held"] for message in messages),
                "oracle_calls": sum(report["oracle_calls"] for report in agents.values()),
                "flagged_agents": sorted(agent for agent, report in agents.items() if report["flagged"]),
            },
        }
