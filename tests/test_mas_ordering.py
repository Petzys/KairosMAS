"""Ordering across decision points: an effect is decided only once its causal
past has arrived, even when a host's channels report out of order."""
import threading

from kairos.mas.causal import CausalEvent, EventKind, VectorClock
from kairos.mas.fabric import MonitorFabric

from tests.mas_util import banking_spec


def _fabric():
    fab = MonitorFabric(banking_spec())
    fab.begin_session("hello")
    return fab


def test_await_lineage_waits_for_late_events() -> None:
    fab = _fabric()
    log = fab.dp_of("payments").log
    # payments' host reported seq 2 before seq 1 (two channels, one sequencer)
    late = CausalEvent("payments", 1, EventKind.TOOL_RESULT, VectorClock({"payments": 1}), {})
    early = CausalEvent("payments", 2, EventKind.TOOL_CALL, VectorClock({"payments": 2}), {})
    log.submit(early)
    clock = VectorClock({"payments": 2, "assistant": fab.agent("assistant").clock.current.get("assistant")})
    assert not fab.await_lineage(clock, timeout=0.05)
    t = threading.Timer(0.05, lambda: log.submit(late))
    t.start()
    assert fab.await_lineage(clock, timeout=2.0)
    t.join()
    assert [e.seq for e in log.events("payments")] == [1, 2]


def test_recv_waits_for_its_send_across_decision_points() -> None:
    fab = _fabric()
    rec = fab.new_message("assistant", "documents", "read the bill")
    d = fab.agent("assistant").decide_send(rec)
    fab.deliver(d.record)
    recv = fab.dp_of("documents").log.events("documents")[-1]
    assert recv.kind is EventKind.RECV and recv.after == rec.send_event
    assert fab.delivered(rec.send_event) and fab.delivered(recv.id)
    # the receiver's clock covers the sender's past: the lineage spans both clusters
    lineage = fab.lineage(recv.clock)
    assert set(lineage) == {"assistant", "documents"}
    assert [e.kind for e in lineage["assistant"]] == [EventKind.PROMPT, EventKind.SEND]


def test_lineage_of_an_unrelated_agent_is_empty() -> None:
    fab = _fabric()
    # accounts never heard from anyone: its lineage contains only itself
    ev = fab.agent("accounts").record_event(EventKind.TOOL_CALL, {"tool": "get_balance"})
    assert set(fab.lineage(ev.clock)) == {"accounts"}
