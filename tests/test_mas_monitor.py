"""The per-agent monitor's message semantics, without a network.

  * intra-cluster: released at once, never touches the speculative machine;
  * blocking inter-cluster: an open branch is resolved first, then the message is
    decided on its own (policy, then the oracle synchronously);
  * streaming inter-cluster: a stallable effect held in the sender's scope and
    released or dropped at the sender's next resolution trigger (terminal,
    nested review, AWAIT, budget);
  * labels join on delivery; denials in the lineage; downstream notices.
"""
from kairos.core.events import Channel, Event
from kairos.core.tokens import Level
from kairos.mas.a2a.adapter import Delivery
from kairos.mas.agent import MsgStatus, Outcome
from kairos.mas.causal import EventKind
from kairos.mas.enforcement import EnforcementPoint
from kairos.mas.fabric import MonitorFabric
from kairos.mas.transport import InProcessNetwork
from kairos.speculative.effects import State

from tests.mas_util import ATTACKER_IBAN, BILL_IBAN, Env, ScriptedJudge, banking_spec, call


def _fabric(judges=None, prompt="Please pay the bill in bill.txt", **kw):
    spec = banking_spec()
    judges = judges or {}
    fab = MonitorFabric(spec, judge_factory=lambda m: judges.setdefault(m.agent_id, ScriptedJudge()), **kw)
    fab.begin_session(prompt)
    return fab


def _send(fab, sender, receiver, text, delivery=Delivery.BLOCKING, reply=False):
    rec = fab.new_message(sender, receiver, text, delivery=delivery, reply=reply)
    return rec, fab.agent(sender).decide_send(rec)


def _hold_transfer(fab, env, agent="payments", recipient=ATTACKER_IBAN):
    """Open a branch at `agent`: a transfer to a non-derivable recipient is held."""
    ep = EnforcementPoint(fab, agent, InProcessNetwork())
    out = ep.call_tool(call("send_money", recipient=recipient, amount=5.0, subject="x",
                            date="2022-01-01"), env.execute)
    assert out.held and fab.agent(agent).machine.state is State.BRANCH
    return ep


def test_intra_cluster_message_never_stalls_even_with_a_branch_open() -> None:
    fab, env = _fabric(), Env()
    _hold_transfer(fab, env)
    rec, d = _send(fab, "payments", "accounts", f"pay {ATTACKER_IBAN} please",
                   delivery=Delivery.STREAMING)
    mon = fab.agent("payments")
    assert d.outcome is Outcome.RELEASE and rec.intra
    assert mon.machine.state is State.BRANCH and len(mon.machine.active.held_calls) == 1
    assert ATTACKER_IBAN in rec.annotations["identifiers"]       # annotated, not stalled


def test_delivery_joins_labels_with_owners() -> None:
    fab, env = _fabric(), Env()
    accounts = fab.agent("accounts")
    ep = EnforcementPoint(fab, "accounts", InProcessNetwork())
    ep.call_tool(call("get_balance"), env.execute)                # HIGH taint at accounts
    rec, d = _send(fab, "accounts", "payments", "the balance is 1810.0")
    fab.deliver(rec)
    pay = fab.agent("payments")
    hits = [t for t in pay.store.sensitivity_set() if t.value == "1810"]
    assert hits and {t.owner for t in hits} == {"accounts"} and hits[0].level is Level.HIGH
    assert accounts.store.snapshot().owner == "accounts"
    recv = [e for e in fab.dp_of("payments").log.events("payments") if e.kind is EventKind.RECV]
    assert recv and recv[-1].after == rec.send_event and recv[-1].clock.covers(rec.send_event)


def test_blocking_review_is_adjudicated_synchronously() -> None:
    judges = {"assistant": ScriptedJudge([True])}
    fab = _fabric(judges)
    rec, d = _send(fab, "assistant", "payments", f"Send 98.70 to {BILL_IBAN}")
    assert d.outcome is Outcome.RELEASE and rec.decision == "oracle"
    (branch,) = judges["assistant"].seen
    assert branch.branch_id == "sync-sync_message"
    held = branch.held_calls[0]
    assert held.tool == "a2a.send" and held.embedded and BILL_IBAN in held.args.values()
    decision = [e for e in fab.dp_of("assistant").log.events("assistant") if e.kind is EventKind.DECISION]
    assert decision and decision[-1].payload["committed"]


def test_blocking_denial_rejects_and_flags() -> None:
    fab = _fabric({"assistant": ScriptedJudge([False])})
    rec, d = _send(fab, "assistant", "payments", f"Send 98.70 to {ATTACKER_IBAN}")
    mon = fab.agent("assistant")
    assert d.outcome is Outcome.REJECT and rec.status is MsgStatus.REJECTED
    assert "REJECTED" in d.notice and mon.flagged and mon.denials


def test_blocking_send_resolves_an_open_branch_first() -> None:
    # payments holds a transfer, then (blocking) reports to the assistant: the
    # branch is resolved before the message may leave.
    judges = {"payments": ScriptedJudge([True])}
    fab, env = _fabric(judges), Env()
    _hold_transfer(fab, env)
    rec, d = _send(fab, "payments", "assistant", "transfer done", reply=True)
    assert d.outcome is Outcome.RELEASE
    assert env.sent and env.sent[0]["recipient"] == ATTACKER_IBAN      # committed, then released
    assert judges["payments"].seen[0].pending_event["tool"] == "a2a.reply"


def test_blocking_send_after_an_abort_must_be_recomposed() -> None:
    fab, env = _fabric({"payments": ScriptedJudge([False])}), Env()
    _hold_transfer(fab, env)
    rec, d = _send(fab, "payments", "assistant", "transfer done", reply=True)
    assert d.outcome is Outcome.REJECT and "Re-compose" in d.notice
    assert not env.sent
    assert any("WITHHELD" in n for n in fab.agent("payments").drain_notices())


def test_streaming_review_is_held_and_released_at_terminal() -> None:
    fab = _fabric({"assistant": ScriptedJudge([True])})
    rec, d = _send(fab, "assistant", "payments", f"Send 98.70 to {BILL_IBAN}", Delivery.STREAMING)
    assert d.outcome is Outcome.HOLD and rec.status is MsgStatus.HELD and rec.was_held
    released = []
    rec.on_release = released.append
    fab.agent("assistant").on_terminal()
    assert released == [rec] and rec.status is MsgStatus.RELEASED


def test_streaming_hold_dropped_on_abort() -> None:
    fab = _fabric({"assistant": ScriptedJudge([False])})
    rec, d = _send(fab, "assistant", "payments", f"Send 98.70 to {ATTACKER_IBAN}", Delivery.STREAMING)
    dropped = []
    rec.on_drop = lambda r, notice: dropped.append(notice)
    fab.agent("assistant").on_terminal()
    assert rec.status is MsgStatus.REJECTED and dropped and "REJECTED" in dropped[0]
    assert fab.agent("assistant").flagged


def test_streaming_allow_is_released_at_once() -> None:
    fab = _fabric()
    rec, d = _send(fab, "assistant", "documents", "Please read bill.txt", Delivery.STREAMING)
    assert d.outcome is Outcome.RELEASE and fab.agent("assistant").machine.state is State.LINEAR


def test_second_held_effect_resolves_the_first() -> None:
    judges = {"assistant": ScriptedJudge([True])}
    fab = _fabric(judges)
    first, d1 = _send(fab, "assistant", "payments", f"Send 1 to {BILL_IBAN}", Delivery.STREAMING)
    released = []
    first.on_release = released.append
    second, d2 = _send(fab, "assistant", "payments", f"Send 2 to {ATTACKER_IBAN}", Delivery.STREAMING)
    assert released == [first]                                   # NESTED_REVIEW resolved #1
    assert d2.outcome is Outcome.HOLD and second.status is MsgStatus.HELD
    trig = [e.payload["trigger"] for e in fab.dp_of("assistant").log.events("assistant")
            if e.kind is EventKind.DECISION]
    assert trig == ["NESTED_REVIEW"]


def test_awaiting_a_held_message_resolves_now() -> None:
    fab = _fabric({"assistant": ScriptedJudge([True])})
    rec, _ = _send(fab, "assistant", "payments", f"Send 98.70 to {BILL_IBAN}", Delivery.STREAMING)
    released = []
    rec.on_release = released.append
    assert fab.agent("assistant").await_held(rec) is not None
    assert released == [rec]


def test_budget_releases_a_quiet_agent() -> None:
    fab = _fabric({"assistant": ScriptedJudge([True])}, max_stall_seconds=5.0)
    rec, _ = _send(fab, "assistant", "payments", f"Send 98.70 to {BILL_IBAN}", Delivery.STREAMING)
    mon = fab.agent("assistant")
    assert mon.tick(now=mon.machine.active.opened_at + 1) is None
    assert fab.tick(now=mon.machine.active.opened_at + 10) == 1
    assert rec.status is MsgStatus.RELEASED


def test_resent_held_message_is_delivered_once() -> None:
    fab = _fabric({"assistant": ScriptedJudge([True])}, hold_notice="honest")
    text = f"Send 98.70 to {BILL_IBAN}"
    first, _ = _send(fab, "assistant", "payments", text, Delivery.STREAMING)
    released = []
    first.on_release = released.append
    again, d = _send(fab, "assistant", "payments", text, Delivery.STREAMING)
    assert released == [first] and d.outcome is Outcome.RELEASE and d.duplicate_of is first


def test_denials_in_the_lineage_are_visible_downstream() -> None:
    fab = _fabric({"documents": ScriptedJudge([False])})
    # documents' first reply is denied (it relays the attacker's IBAN) ...
    r1, d1 = _send(fab, "documents", "assistant", f"also pay {ATTACKER_IBAN}", reply=True)
    assert d1.outcome is Outcome.REJECT
    # ... a later, clean reply reaches the assistant
    r2, d2 = _send(fab, "documents", "assistant", "the bill is 98.70", reply=True)
    assert d2.outcome is Outcome.RELEASE
    fab.deliver(r2)
    clock = fab.agent("assistant").clock.current
    denials = fab.denials_in(clock, exclude="assistant")
    assert [d.agent for d in denials] == ["documents"]


def test_abort_notifies_receivers_of_messages_sent_while_pending() -> None:
    fab, env = _fabric({"payments": ScriptedJudge([False])}), Env()
    _hold_transfer(fab, env)
    rec, d = _send(fab, "payments", "accounts", "I have sent the money")   # intra: released
    fab.deliver(rec)
    fab.agent("payments").on_terminal()                                     # transfer aborted
    notes = fab.agent("accounts").drain_notices()
    assert notes and "payments" in notes[0] and "send_money" in notes[0]


def test_external_effects_still_pass_full_kairos() -> None:
    # labels joined from a message make a transfer to the bill's IBAN derivable?
    # No: T only grows from the prompt and trusted sources, so a value an agent
    # merely SAYS stays non-derivable and the transfer is reviewed.
    fab = _fabric()
    rec, _ = _send(fab, "assistant", "payments", f"Pay {BILL_IBAN}")
    fab.deliver(rec)
    ev = Event(0.0, Channel.TOOL, "tool_call", "payments", "send_money",
               {"recipient": BILL_IBAN, "amount": 98.7}, {})
    assert fab.agent("payments").gate(ev).decision.value == "REVIEW"
