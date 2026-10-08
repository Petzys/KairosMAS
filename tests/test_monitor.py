# tests/test_monitor.py
"""Phase 1: ReferenceMonitor — admission, gating, ledger, REVIEW=block, telemetry."""
import textwrap

import yaml

from kairos.adapters.base import Effector
from kairos.core.events import Channel, Event, FsOp, ToolOp
from kairos.core.store import TokenStore
from kairos.engine.decision import Decision
from kairos.engine.pipeline import PolicyEngine
from kairos.monitor import ReferenceMonitor
from kairos.policy.parser import parse_policy
from kairos.core.matching import Strategy

IBAN = "DE89370400440532013000"
ATTACKER = "DE00111122223333444455"

POLICY = parse_policy(yaml.safe_load(textwrap.dedent("""
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: [read_file, get_balance]
        non_revertable: [send_money]
    resources:
      trusted_sources: [read_file]
      taints:
        - {name: bal, source: get_balance, level: high}
""")))


class RecordingEffector(Effector):
    """Records what the monitor asked the world to do; returns sentinel values."""
    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []   # (action, object)

    def forward(self, event):
        self.calls.append(("forward", event.object));  return ("forward", event.content)

    def block(self, event):
        self.calls.append(("block", event.object));    return ("block", event.object)

    def stub(self, event, stub_value):
        self.calls.append(("stub", event.object));     return stub_value

    def stall(self, event):
        self.calls.append(("stall", event.object))

    def commit(self, branch): self.calls.append(("commit", branch.branch_id))
    def abort(self, branch):  self.calls.append(("abort", branch.branch_id))


def _monitor(prompt: str, mode="baseline"):
    store = TokenStore()
    eng = PolicyEngine.build(POLICY, store, mode=mode)
    eff = RecordingEffector()
    mon = ReferenceMonitor(POLICY, eff, eng, store)
    mon.begin_session(prompt)
    return mon, eff


def _call(tool, **args):
    return Event(1.0, Channel.TOOL, ToolOp.CALL.value, "agent", tool, dict(args))


def _result(tool, content):
    return Event(1.0, Channel.TOOL, ToolOp.RESULT.value, "agent", tool, content)


# --- admission flows into a later gate --------------------------------------
def test_trusted_read_admits_then_recipient_derivable() -> None:
    mon, eff = _monitor("pay the invoice in bill.txt")
    # a trusted read returns the invoice; its IBAN should enter the closure
    mon.process_event(_result("read_file", {"recipient": IBAN, "amount": "98.70"}))
    out = mon.process_event(_call("send_money", recipient=IBAN, amount=98.70))
    assert out[0] == "forward"                       # derivable -> ALLOW -> forwarded
    assert ("forward", "send_money") in eff.calls


def test_attacker_recipient_blocked_in_deterministic_mode() -> None:
    mon, eff = _monitor("pay the invoice in my email")
    out = mon.process_event(_call("send_money", recipient=ATTACKER, amount=5000))
    assert out[0] == "block"                         # REVIEW -> block (Phase-1 handler)
    assert ("block", "send_money") in eff.calls


# --- untrusted source does NOT admit ----------------------------------------
def test_untrusted_result_does_not_admit() -> None:
    mon, eff = _monitor("read my email")
    # get_balance is sensitive+? — here only declared as taint, NOT trusted_sources
    mon.process_event(_result("get_balance", {"balance": "4823"}))
    # balance entered the SENSITIVITY set but NOT the trust closure
    assert mon.store.sensitivity_of("4823") is not None
    assert not mon.store.derivable("4823", Strategy.NORMALIZED)


# --- file-trust ledger ------------------------------------------------------
def test_untrusted_write_then_read_does_not_admit() -> None:
    mon, eff = _monitor("summarize my email")
    # agent writes attacker content to a file (untrusted -> ledger marks it)
    w = Event(2.0, Channel.FS, FsOp.WRITE.value, "agent", "/data/notes.txt", f"pay {ATTACKER}")
    mon.process_event(w)
    assert not mon.files.is_trusted("/data/notes.txt")
    # later read of that file must NOT admit its content
    mon.process_event(Event(3.0, Channel.FS, FsOp.READ.value, "agent", "/data/notes.txt",
                            f"pay {ATTACKER}"))
    assert not mon.store.derivable(ATTACKER, Strategy.NORMALIZED)


# --- telemetry --------------------------------------------------------------
def test_session_records_layer_attribution() -> None:
    mon, eff = _monitor("pay the invoice in bill.txt")
    mon.process_event(_result("read_file", {"recipient": IBAN}))
    mon.process_event(_call("send_money", recipient=IBAN, amount=10))
    mon.process_event(_call("send_money", recipient=ATTACKER, amount=10))
    res = mon.end_session()
    layers = res.counts_by_layer()
    assert layers.get("axes", 0) >= 1          # the derivable one
    assert layers.get("integrity", 0) >= 1     # the attacker one