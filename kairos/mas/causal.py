"""Causal order across agents without a global clock.

Every event an enforcement point observes gets a per-agent sequence number; a
message adds one cross-agent edge, from the sender's SEND to the receiver's RECV,
keyed by the monitor's message id. Program order plus message edges form the
causal DAG of the session.

The lineage of an event -- every event that happened before it, back to the
principal's prompt -- is represented by a vector clock: entry X is the highest
sequence number of agent X the event depends on, so X's events 1..clock[X] are in
the lineage. Clocks are assigned by the enforcement points, which are in the TCB;
agents never see or supply them.

A decision point may receive its members' events out of order (the file and the
network channel of one host report separately). CausalLog delivers an event only
once its predecessor in program order and, for a RECV, the matching SEND have been
delivered, and lets a decision wait until a whole lineage has arrived: an effect is
decided once all causally preceding events are known.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

EventId = tuple[str, int]


class VectorClock:
    """Immutable map agent -> highest sequence number in the lineage."""

    __slots__ = ("_c",)

    def __init__(self, entries: Mapping[str, int] | Iterable[tuple[str, int]] | None = None) -> None:
        items = dict(entries or {})
        self._c: tuple[tuple[str, int], ...] = tuple(sorted((a, s) for a, s in items.items() if s > 0))

    def get(self, agent: str) -> int:
        for a, s in self._c:
            if a == agent:
                return s
        return 0

    def merge(self, other: VectorClock) -> VectorClock:
        out = dict(self._c)
        for a, s in other._c:
            if s > out.get(a, 0):
                out[a] = s
        return VectorClock(out)

    def tick(self, agent: str, seq: int) -> VectorClock:
        out = dict(self._c)
        out[agent] = max(seq, out.get(agent, 0))
        return VectorClock(out)

    def covers(self, event_id: EventId) -> bool:
        agent, seq = event_id
        return seq <= self.get(agent)

    def agents(self) -> list[str]:
        return [a for a, _ in self._c]

    def items(self) -> list[tuple[str, int]]:
        return list(self._c)

    def to_dict(self) -> dict[str, int]:
        return dict(self._c)

    def __le__(self, other: VectorClock) -> bool:
        return all(s <= other.get(a) for a, s in self._c)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VectorClock) and self._c == other._c

    def __hash__(self) -> int:
        return hash(self._c)

    def __repr__(self) -> str:
        return "VC(" + ", ".join(f"{a}:{s}" for a, s in self._c) + ")"


class EventKind(str, Enum):
    PROMPT = "prompt"            # the principal's prompt, delivered to the entry agent
    TOOL_CALL = "tool_call"      # an effect the agent attempted (external boundary)
    TOOL_RESULT = "tool_result"  # content entering the agent
    SEND = "send"                # a message the agent emitted (request or reply)
    RECV = "recv"                # a message delivered to the agent
    DECISION = "decision"        # a resolution / adjudication about this agent's effects
    TERMINAL = "terminal"        # the agent finished a task


@dataclass(frozen=True, slots=True)
class CausalEvent:
    agent: str
    seq: int
    kind: EventKind
    clock: VectorClock
    payload: Mapping[str, Any] = field(default_factory=dict)
    msg_id: str | None = None        # SEND / RECV: the monitor's message id
    after: EventId | None = None     # RECV: the SEND it depends on
    ts: float = 0.0

    @property
    def id(self) -> EventId:
        return (self.agent, self.seq)


class AgentClock:
    """The sequencer of one agent host. Thread-safe: the file and network channels
    of a host draw numbers from the same counter."""

    def __init__(self, agent: str) -> None:
        self.agent = agent
        self._seq = 0
        self._clock = VectorClock()
        self._lock = threading.Lock()

    def stamp(self, merge: VectorClock | None = None) -> tuple[int, VectorClock]:
        """Next sequence number and the event's clock (merged with `merge`, the
        clock of the SEND a RECV depends on)."""
        with self._lock:
            self._seq += 1
            clock = self._clock if merge is None else self._clock.merge(merge)
            self._clock = clock.tick(self.agent, self._seq)
            return self._seq, self._clock

    @property
    def current(self) -> VectorClock:
        with self._lock:
            return self._clock


class CausalLog:
    """The events of one decision point's member agents, delivered in causal order.

    `foreign_delivered(event_id)` answers whether an event of a NON-member agent has
    been delivered at its own decision point; a RECV here depends on a SEND there."""

    def __init__(self, foreign_delivered: Callable[[EventId], bool] | None = None) -> None:
        self._events: dict[str, list[CausalEvent]] = {}
        self._pending: list[CausalEvent] = []
        self._foreign = foreign_delivered or (lambda _eid: False)
        self._cv = threading.Condition()

    # --- delivery -----------------------------------------------------------
    def submit(self, event: CausalEvent) -> list[CausalEvent]:
        """Buffer `event` until deliverable; return every event delivered by it."""
        with self._cv:
            if self._is_delivered(event.id):
                return []
            self._pending.append(event)
            delivered = self._drain()
            if delivered:
                self._cv.notify_all()
            return delivered

    def retry(self) -> list[CausalEvent]:
        """Re-check pending events (a foreign SEND they wait on may have arrived)."""
        with self._cv:
            delivered = self._drain()
            if delivered:
                self._cv.notify_all()
            return delivered

    def _drain(self) -> list[CausalEvent]:
        delivered: list[CausalEvent] = []
        progress = True
        while progress:
            progress = False
            for ev in list(self._pending):
                if self._ready(ev):
                    self._pending.remove(ev)
                    self._events.setdefault(ev.agent, []).append(ev)
                    delivered.append(ev)
                    progress = True
        return delivered

    def _ready(self, ev: CausalEvent) -> bool:
        if self.frontier(ev.agent) != ev.seq - 1:
            return False
        if ev.after is None:
            return True
        return self._is_delivered(ev.after) or self._foreign(ev.after)

    def _is_delivered(self, eid: EventId) -> bool:
        agent, seq = eid
        return 0 < seq <= self.frontier(agent)

    # --- queries ------------------------------------------------------------
    def delivered(self, eid: EventId) -> bool:
        with self._cv:
            return self._is_delivered(eid)

    def frontier(self, agent: str) -> int:
        evs = self._events.get(agent)
        return evs[-1].seq if evs else 0

    def events(self, agent: str, upto: int | None = None) -> list[CausalEvent]:
        with self._cv:
            evs = list(self._events.get(agent, []))
        return evs if upto is None else [e for e in evs if e.seq <= upto]

    def event(self, eid: EventId) -> CausalEvent | None:
        agent, seq = eid
        with self._cv:
            evs = self._events.get(agent, [])
            return evs[seq - 1] if 0 < seq <= len(evs) else None

    def pending(self) -> list[CausalEvent]:
        with self._cv:
            return list(self._pending)

    def wait_for(self, clock: VectorClock, agents: Iterable[str], timeout: float = 5.0) -> bool:
        """Block until every event of `agents` covered by `clock` is delivered."""
        wanted = [(a, clock.get(a)) for a in agents]
        deadline = time.monotonic() + timeout
        with self._cv:
            while not all(self.frontier(a) >= s for a, s in wanted):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cv.wait(remaining)
            return True

    def __iter__(self) -> Iterator[CausalEvent]:
        with self._cv:
            evs = [e for agent_evs in self._events.values() for e in agent_evs]
        return iter(sorted(evs, key=lambda e: (e.ts, e.agent, e.seq)))
