"""Causal order without a global clock: vector clocks, per-agent sequencing, and
delivery in causal order at a decision point."""
import random
import threading

from kairos.mas.causal import AgentClock, CausalEvent, CausalLog, EventKind, VectorClock


def _ev(agent, seq, kind=EventKind.TOOL_CALL, clock=None, after=None, msg_id=None):
    return CausalEvent(agent, seq, kind, clock or VectorClock({agent: seq}), {}, msg_id, after)


def test_vector_clock_merge_tick_covers() -> None:
    a = VectorClock({"x": 2, "y": 1})
    b = VectorClock({"y": 3, "z": 1})
    m = a.merge(b)
    assert m.to_dict() == {"x": 2, "y": 3, "z": 1}
    assert a <= m and b <= m and not m <= a
    assert m.covers(("y", 3)) and not m.covers(("y", 4)) and not m.covers(("w", 1))
    assert m.tick("x", 5).get("x") == 5
    assert VectorClock({"x": 0}) == VectorClock()          # zero entries are dropped


def test_agent_clock_merges_the_send_clock_into_a_recv() -> None:
    a, b = AgentClock("a"), AgentClock("b")
    a.stamp()
    seq, send_clock = a.stamp()                           # a's SEND
    b.stamp()
    rseq, recv_clock = b.stamp(merge=send_clock)          # b's RECV
    assert (seq, rseq) == (2, 2)
    assert recv_clock.to_dict() == {"a": 2, "b": 2}
    assert recv_clock.covers(("a", 2)) and not recv_clock.covers(("a", 3))


def test_agent_clock_is_thread_safe() -> None:
    c = AgentClock("a")
    seqs: list[int] = []
    lock = threading.Lock()

    def work():
        for _ in range(200):
            s, _ = c.stamp()
            with lock:
                seqs.append(s)

    ts = [threading.Thread(target=work) for _ in range(4)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert sorted(seqs) == list(range(1, 801))


def test_log_buffers_until_program_order_is_complete() -> None:
    log = CausalLog()
    assert log.submit(_ev("a", 2)) == []                  # seq 1 missing
    assert log.frontier("a") == 0 and len(log.pending()) == 1
    delivered = log.submit(_ev("a", 1))
    assert [e.seq for e in delivered] == [1, 2]
    assert log.frontier("a") == 2 and not log.pending()


def test_log_recv_waits_for_its_send_at_another_decision_point() -> None:
    sends: set = set()
    log = CausalLog(foreign_delivered=lambda eid: eid in sends)
    recv = _ev("b", 1, EventKind.RECV, after=("a", 3), msg_id="k1")
    assert log.submit(recv) == []
    sends.add(("a", 3))
    assert [e.id for e in log.retry()] == [("b", 1)]


def test_log_shuffled_delivery_is_causal() -> None:
    log = CausalLog()
    events = [_ev("a", i) for i in range(1, 30)] + [_ev("b", i) for i in range(1, 30)]
    events.append(_ev("b", 30, EventKind.RECV, after=("a", 29)))
    random.Random(7).shuffle(events)
    for e in events:
        log.submit(e)
    assert log.frontier("a") == 29 and log.frontier("b") == 30
    assert [e.seq for e in log.events("b")] == list(range(1, 31))


def test_wait_for_blocks_until_the_lineage_has_arrived() -> None:
    log = CausalLog()
    clock = VectorClock({"a": 2})
    assert not log.wait_for(clock, ["a"], timeout=0.05)
    t = threading.Timer(0.05, lambda: (log.submit(_ev("a", 1)), log.submit(_ev("a", 2))))
    t.start()
    assert log.wait_for(clock, ["a"], timeout=2.0)
    t.join()


def test_events_upto_and_lookup() -> None:
    log = CausalLog()
    for i in range(1, 6):
        log.submit(_ev("a", i))
    assert [e.seq for e in log.events("a", upto=3)] == [1, 2, 3]
    assert log.event(("a", 4)).seq == 4 and log.event(("a", 9)) is None
    assert log.delivered(("a", 5)) and not log.delivered(("a", 6))


def test_two_logs_waiting_on_each_other_do_not_deadlock() -> None:
    """Two decision points deliver RECVs that depend on each other's SENDs at the same
    time: each holds its own log while asking the other (regression: lock-order
    inversion between two clusters exchanging messages)."""
    logs: dict[str, CausalLog] = {}
    logs["a"] = CausalLog(foreign_delivered=lambda eid: logs["b"].delivered(eid))
    logs["b"] = CausalLog(foreign_delivered=lambda eid: logs["a"].delivered(eid))
    for i in range(1, 201):
        logs["a"].submit(_ev("a", i))
        logs["b"].submit(_ev("b", i))
    barrier = threading.Barrier(2)

    def run(me, other):
        barrier.wait()
        for i in range(201, 401):
            logs[me].submit(_ev(me, i, EventKind.RECV, after=(other, i - 200)))

    ts = [threading.Thread(target=run, args=("a", "b")), threading.Thread(target=run, args=("b", "a"))]
    for t in ts:
        t.start()
    for t in ts:
        t.join(timeout=10)
    assert not any(t.is_alive() for t in ts), "deadlock"
    assert logs["a"].frontier("a") == 400 and logs["b"].frontier("b") == 400
