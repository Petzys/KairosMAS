"""Decision points and the fabric that connects them.

Each cluster has one logical decision point: the monitors of its members (labels,
speculative state, oracle calls) and their slice of the causal log. A decision
point can run on any trusted host; co-locating all of them on one host is the
central monitor, and separating them helps scale and isolates failures -- the
fabric is the only thing that changes. Here the fabric is in-process; across hosts
its calls (lineage queries, the message registry, delivery records) become RPCs
between trusted hosts.

Nothing in the fabric is visible to agents: the message registry is keyed by the
monitor's own message ids, which travel between enforcement points out of band.
"""
from __future__ import annotations

import itertools
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

JudgeFactory = Callable[[AgentMonitor], Any]


class ClusterDecisionPoint:
    def __init__(self, cluster: ClusterSpec, fabric: "MonitorFabric") -> None:
        self.id = cluster.id
        self.cluster = cluster
        self.fabric = fabric
        self.members = fabric.spec.members(cluster.id)
        self.log = CausalLog(foreign_delivered=fabric.delivered)
        self.agents: dict[str, AgentMonitor] = {}

    def owns(self, agent: str) -> bool:
        return agent in self.members


class MonitorFabric:
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
    ) -> None:
        self.spec = spec
        self.judge_factory = judge_factory or (lambda _m: DeterministicJudge())
        self.commit_gate_factory = commit_gate_factory or AutoCommitGate
        self.monitor_kwargs = dict(mode=mode, hold_notice=hold_notice,
                                   max_held_per_branch=max_held_per_branch,
                                   max_stall_seconds=max_stall_seconds, sync_get=sync_get)
        self.downstream_notices = downstream_notices
        self._lock = threading.Lock()
        self._ids = itertools.count(1)
        self.dps: dict[str, ClusterDecisionPoint] = {}
        self.messages: dict[str, MessageRecord] = {}
        self.prompt = ""
        self._build()

    def _build(self) -> None:
        self.dps = {cid: ClusterDecisionPoint(c, self) for cid, c in self.spec.clusters.items()}
        self.messages = {}
        for dp in self.dps.values():
            for aid in dp.members:
                mon = AgentMonitor(self.spec, aid, fabric=self, log=dp.log,
                                   commit_gate=self.commit_gate_factory(), **self.monitor_kwargs)
                mon.judge = self.judge_factory(mon)
                dp.agents[aid] = mon

    # --- lifecycle ------------------------------------------------------------
    def begin_session(self, prompt: str) -> None:
        """A session starts from the principal's prompt with no prior state: fresh
        monitors everywhere, T_0 seeded at the entry agent only."""
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
        return [m for dp in self.dps.values() for m in dp.agents.values()]

    # --- causal log across decision points ------------------------------------
    def delivered(self, eid: EventId) -> bool:
        agent, _ = eid
        if agent not in self.spec.agents:
            return False
        return self.dp_of(agent).log.delivered(eid)

    def event(self, eid: EventId) -> CausalEvent | None:
        return self.dp_of(eid[0]).log.event(eid)

    def lineage(self, clock: VectorClock) -> dict[str, list[CausalEvent]]:
        """Every event `clock` covers, per agent: the causal past of the event the
        clock belongs to, back to the principal's prompt."""
        return {a: self.dp_of(a).log.events(a, upto=s) for a, s in clock.items()
                if a in self.spec.agents}

    def await_lineage(self, clock: VectorClock, timeout: float = 5.0) -> bool:
        """An effect is decided once all causally preceding events have arrived."""
        ok = True
        for dp in self.dps.values():
            agents = [a for a in clock.agents() if dp.owns(a)]
            if agents:
                ok = dp.log.wait_for(clock, agents, timeout) and ok
        return ok

    def denials_in(self, clock: VectorClock, *, exclude: str | None = None) -> list[CausalEvent]:
        """DECISION events that withheld something and lie in `clock`'s lineage:
        the prior denials an oracle must see for an effect whose lineage passes
        through a flagged agent."""
        out = []
        for agent, evs in self.lineage(clock).items():
            if agent == exclude:
                continue
            out += [e for e in evs if e.kind is EventKind.DECISION and e.payload.get("aborted")]
        return out

    # --- messages ---------------------------------------------------------------
    def new_message(self, sender: str, receiver: str, text: str,
                    data: list[dict[str, Any]] | None = None, *, reply: bool = False,
                    delivery: Delivery = Delivery.BLOCKING,
                    in_reply_to: str | None = None) -> MessageRecord:
        kmid = f"k{next(self._ids)}"
        rec = MessageRecord(kmid=kmid, sender=sender, receiver=receiver, text=text,
                            data=list(data or []), reply=reply, delivery=delivery,
                            in_reply_to=in_reply_to)
        self.track(rec)
        return rec

    def track(self, record: MessageRecord) -> None:
        with self._lock:
            self.messages[record.kmid] = record

    def message(self, kmid: str | None) -> MessageRecord | None:
        if kmid is None:
            return None
        with self._lock:
            return self.messages.get(kmid)

    def deliver(self, record: MessageRecord) -> CausalEvent:
        """Record a released message at its receiver (RECV, label join)."""
        ev = self.agent(record.receiver).on_receive(record)
        for dp in self.dps.values():
            dp.log.retry()
        return ev

    def notify_downstream(self, sender: str, *, since: float,
                          withheld: list[tuple[str, dict[str, Any]]]) -> None:
        """Tell the receivers of `sender`'s messages sent while its withheld actions
        were pending that those actions never happened."""
        if not self.downstream_notices:
            return
        with self._lock:
            receivers = sorted({r.receiver for r in self.messages.values()
                                if r.sender == sender and r.created >= since
                                and r.status in (MsgStatus.RELEASED, MsgStatus.DELIVERED)})
        for rcv in receivers:
            self.agent(rcv).notify(notices.downstream_abort(sender, withheld))

    # --- budget -------------------------------------------------------------
    def tick(self, now: float | None = None) -> int:
        """Resolve branches whose stall budget is exhausted. Returns how many."""
        n = 0
        for m in self.monitors():
            if m.tick(now) is not None:
                n += 1
        return n

    # --- reporting ------------------------------------------------------------
    def report(self) -> dict[str, Any]:
        with self._lock:
            msgs = [r.summary() for r in self.messages.values()]
        inter = [m for m in msgs if not m["intra"]]
        agents = {m.agent_id: m.report() for m in self.monitors()}
        return {
            "agents": agents,
            "messages": msgs,
            "counts": {
                "messages": len(msgs),
                "intra_cluster": len(msgs) - len(inter),
                "inter_cluster": len(inter),
                "rejected": sum(m["status"] == MsgStatus.REJECTED.value for m in msgs),
                "held": sum(m["was_held"] for m in msgs),
                "oracle_calls": sum(a["oracle_calls"] for a in agents.values()),
                "flagged_agents": sorted(a for a, r in agents.items() if r["flagged"]),
            },
        }
