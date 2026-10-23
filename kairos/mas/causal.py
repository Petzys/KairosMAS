"""Causal order across agents without a global clock.

Every event an enforcement point observes gets a per-agent sequence number. A message
adds one edge between agents, from the sender's SEND to the receiver's RECV, keyed by
the monitor's message id. Program order (each agent's own sequence) plus these
message edges form the causal DAG of the session.

The *lineage* of an event -- every event that happened before it, back to the
principal's prompt -- is represented by a vector clock: entry X is the highest
sequence number of agent X the event depends on, so X's events 1..clock[X] are in the
lineage. The enforcement points assign the clocks; they belong to the trusted
computing base, and agents never see or supply a clock.

A decision point may receive its members' events out of order (the file channel and
the network channel of one host report separately). `CausalLog` delivers an event
only once its predecessor in program order has been delivered and, for a RECV, once
the matching SEND has been delivered (possibly at another decision point). It also
lets a decision wait until a whole lineage has arrived: an effect is decided only
when all causally preceding events are known.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# An event's identity: (agent, sequence number). Sequence numbers start at 1.
EventId = tuple[str, int]


class VectorClock:
    """An immutable map agent -> highest sequence number in a lineage.

    Agents with no events in the lineage are simply absent (sequence 0). The entries
    are kept as a sorted tuple, so equal clocks compare and hash equal."""

    __slots__ = ("_entries",)

    def __init__(self, entries: Mapping[str, int] | Iterable[tuple[str, int]] | None = None) -> None:
        items = dict(entries or {})
        self._entries: tuple[tuple[str, int], ...] = tuple(
            sorted((agent, seq) for agent, seq in items.items() if seq > 0))

    def get(self, agent: str) -> int:
        """The highest sequence number of `agent` in the lineage (0: none)."""
        for known, seq in self._entries:
            if known == agent:
                return seq
        return 0

    def merge(self, other: VectorClock) -> VectorClock:
        """The lineage of both: the entry-wise maximum."""
        merged = dict(self._entries)
        for agent, seq in other._entries:
            if seq > merged.get(agent, 0):
                merged[agent] = seq
        return VectorClock(merged)

    def tick(self, agent: str, seq: int) -> VectorClock:
        """This lineage extended by `agent`'s event number `seq`."""
        ticked = dict(self._entries)
        ticked[agent] = max(seq, ticked.get(agent, 0))
        return VectorClock(ticked)

    def covers(self, event_id: EventId) -> bool:
        """Is the event part of this lineage?"""
        agent, seq = event_id
        return seq <= self.get(agent)

    def agents(self) -> list[str]:
        return [agent for agent, _ in self._entries]

    def items(self) -> list[tuple[str, int]]:
        return list(self._entries)

    def to_dict(self) -> dict[str, int]:
        return dict(self._entries)

    def __le__(self, other: VectorClock) -> bool:
        """Happened-before-or-equal: every event of this lineage is in `other`'s."""
        return all(seq <= other.get(agent) for agent, seq in self._entries)

    def __eq__(self, other: object) -> bool:
        return isinstance(other, VectorClock) and self._entries == other._entries

    def __hash__(self) -> int:
        return hash(self._entries)

    def __repr__(self) -> str:
        return "VC(" + ", ".join(f"{agent}:{seq}" for agent, seq in self._entries) + ")"


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
    """One event of one agent, with the clock of its lineage (which includes itself)."""
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
        """The next sequence number and the event's clock.

        `merge` is the clock of the SEND a RECV depends on: receiving a message makes
        the sender's whole lineage part of the receiver's."""
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
    been delivered at its own decision point: a RECV here may depend on a SEND there.

    Events are *submitted* in any order and *delivered* (appended to the log) once
    everything they depend on is delivered; until then they wait in `_pending`.
    """

    def __init__(self, foreign_delivered: Callable[[EventId], bool] | None = None) -> None:
        self._events: dict[str, list[CausalEvent]] = {}
        # The highest delivered sequence number per agent. Written only under _cv, but
        # READ without it: other decision points ask whether an event was delivered
        # while they hold their own log's lock. Taking ours there would take two log
        # locks in both orders, a deadlock between two clusters exchanging messages.
        self._frontier: dict[str, int] = {}
        self._pending: list[CausalEvent] = []
        self._foreign = foreign_delivered or (lambda _eid: False)
        # Guards _events, _pending and writes to _frontier; waiters in wait_for are
        # woken whenever something is delivered.
        self._cv = threading.Condition()

    # --- delivery -----------------------------------------------------------
    def submit(self, event: CausalEvent) -> list[CausalEvent]:
        """Buffer `event` until deliverable; return every event delivered by it
        (it may unblock events that were waiting for it)."""
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
        """Deliver pending events until none is ready. One delivery can make another
        ready (the next event of the same agent), hence the repeated passes."""
        delivered: list[CausalEvent] = []
        progress = True
        while progress:
            progress = False
            for event in list(self._pending):
                if self._ready(event):
                    self._pending.remove(event)
                    self._events.setdefault(event.agent, []).append(event)
                    self._frontier[event.agent] = event.seq
                    delivered.append(event)
                    progress = True
        return delivered

    def _ready(self, event: CausalEvent) -> bool:
        """Deliverable: the agent's previous event is delivered and, for a RECV, the
        SEND it depends on is delivered (here or at the sender's decision point)."""
        if self.frontier(event.agent) != event.seq - 1:
            return False
        if event.after is None:
            return True
        return self._is_delivered(event.after) or self._foreign(event.after)

    def _is_delivered(self, eid: EventId) -> bool:
        agent, seq = eid
        return 0 < seq <= self.frontier(agent)

    # --- queries ------------------------------------------------------------
    def delivered(self, eid: EventId) -> bool:
        """Lock-free: safe to call from another log's critical section."""
        return self._is_delivered(eid)

    def frontier(self, agent: str) -> int:
        return self._frontier.get(agent, 0)

    def events(self, agent: str, upto: int | None = None) -> list[CausalEvent]:
        """`agent`'s delivered events, optionally only those up to sequence `upto`."""
        with self._cv:
            events = list(self._events.get(agent, []))
        return events if upto is None else [event for event in events if event.seq <= upto]

    def event(self, eid: EventId) -> CausalEvent | None:
        agent, seq = eid
        with self._cv:
            events = self._events.get(agent, [])
            # Delivered events are stored in sequence order, starting at 1.
            return events[seq - 1] if 0 < seq <= len(events) else None

    def pending(self) -> list[CausalEvent]:
        with self._cv:
            return list(self._pending)

    def wait_for(self, clock: VectorClock, agents: Iterable[str], timeout: float = 5.0) -> bool:
        """Block until every event of `agents` covered by `clock` is delivered.
        Returns False if that did not happen within `timeout` seconds."""
        wanted = [(agent, clock.get(agent)) for agent in agents]
        deadline = time.monotonic() + timeout
        with self._cv:
            while not all(self.frontier(agent) >= seq for agent, seq in wanted):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    return False
                self._cv.wait(remaining)
            return True

    def __iter__(self) -> Iterator[CausalEvent]:
        """All delivered events, in timestamp order (for reports and displays)."""
        with self._cv:
            events = [event for agent_events in self._events.values() for event in agent_events]
        return iter(sorted(events, key=lambda event: (event.ts, event.agent, event.seq)))
