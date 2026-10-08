"""Speculative-execution state machine
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Callable

from kairos.speculative.branch import Branch, HeldAction, Provenance
from kairos.speculative.effects import Effect, EffectKind, State, Trigger

@dataclass(slots=True)
class EventView:
    """Channel-agnostic view of a gated event the machine reasons over."""
    tool: str
    args: dict[str, Any]
    is_outbound: bool # state-changing / non-revertable
    is_revertable: bool # GET / overlay-write = revertable; POST/non_revertable = not
    consequential: dict[str, str] # field -> value (the gated identifiers)
    provenance: dict[str, Provenance]
    call_ref: Any # opaque handle for later execution
    reason: str = ""

@dataclass(slots=True)
class ResolveOutcome:
    committed: list[HeldAction] # caller executes these (in order)
    aborted: list[HeldAction] # caller drops these
    branch_id: str
    # (held, result, error) for every committed call the resolver dispatched. Filled
    # by ReferenceMonitor.resolve_branch so an in-turn caller can answer a re-issued
    # held call with the REAL result instead of executing it a second time (v2).
    dispatched: list[tuple[HeldAction, Any, Any]] = field(default_factory=list)

class SpeculativeMachine:
    def __init__(self, *, max_branches: int = 8, max_stall_seconds: float = 120.0, loop_threshold: int = 3,
                 max_held_per_branch: int = 1, hold_notice: str = "success") -> None:
        # hold_notice: what the agent is told for a held STATE-CHANGING call.
        #   "success" — plausible success stub (v1; every reported number).
        #   "honest"  — ON-HOLD notice: continue if independent, re-issue if dependent;
        #               a re-issue of a held call is Trigger 3 and resolves at once (v2).
        if hold_notice not in ("success", "honest"):
            raise ValueError(f"hold_notice must be 'success' or 'honest', got {hold_notice!r}")
        self.hold_notice = hold_notice
        self.state: State = State.LINEAR
        self.active: Branch | None = None
        self._branch_seq = 0
        self._branches_opened = 0
        self.max_branches = max_branches
        self.max_stall_seconds = max_stall_seconds
        self.loop_threshold = loop_threshold
        self.max_held_per_branch = max_held_per_branch
        self._stub_values: set[str] = set() # stub markers handed to the agent

    # --- per-event entry point ---
    def on_gate(self, decision: str, ev: EventView, *, now: float | None = None) -> Effect:
        now = time.monotonic() if now is None else now

        if self.state is State.LINEAR:
            if decision == "ALLOW":
                return Effect(EffectKind.EXECUTE)
            if decision == "DENY":
                return Effect(EffectKind.BLOCK, reason=ev.reason)
            return self._open_branch(ev, now) # REVIEW
        
        # state is BRANCH - triggers take precedence over absorbing the event
        trig = self._trigger_for(decision, ev, now)
        if trig is not None:
            return Effect(EffectKind.RESOLVE, trigger=trig, reason=trig.name)
        if decision == "DENY":
            return Effect(EffectKind.BLOCK, reason=ev.reason)
        # Uniform with LINEAR: any REVIEW is held (same as _open_branch's absorb),
        # so a flagged GET behaves identically whether or not a branch is already
        # open. Everything ALLOWed executes speculatively: reads (no effect),
        # revertable writes (undone by overlay/content_map on abort), GETs
        # (non-state-changing by HTTP contract). The unit of atomicity is the set
        # of held effects.
        if decision == "REVIEW" or (ev.is_outbound and not ev.is_revertable):
            return self._absorb(ev) # hold + stub
        self.active.note_allowed(ev.tool, ev.args)
        return Effect(EffectKind.EXECUTE) # read / overlay-write / GET

    def on_terminal(self) -> Effect | None:
        """ Trigger 6: agent finished while a branch is open -> resolve."""
        if self.state is State.BRANCH and self.active is not None:
            return Effect(EffectKind.RESOLVE, trigger=Trigger.TERMINAL)
        return None

    # --- resolution ---
    def begin_resolution(self) -> Branch:
        assert self.active is not None, "no active branch to resolve"
        self.state = State.RESOLUTION
        return self.active

    def resolve(self, commit: bool | list[bool]) -> ResolveOutcome:
        """Apply the verdict. commit=True -> caller executes held calls; else drop.
        Returns to LINEAR. The judge/human produced `commit`; the machine is
        agnostic to how."""
        assert self.active is not None and self.state is State.RESOLUTION
        b = self.active
        # bool → apply to all (back-compat); list → per-action
        if isinstance(commit, bool):
            mask = [commit] * len(b.held_calls)
        else:
            # pad/truncate defensively so length always matches held_calls
            mask = (list(commit) + [False] * len(b.held_calls))[:len(b.held_calls)]
        committed = [h for h, keep in zip(b.held_calls, mask) if keep]
        aborted   = [h for h, keep in zip(b.held_calls, mask) if not keep]
        outcome = ResolveOutcome(committed=committed, aborted=aborted, branch_id=b.branch_id)
        self.active = None
        self.state = State.LINEAR
        self._stub_values.clear()
        return outcome

    # -- internals ---
    def _open_branch(self, ev: EventView, now: float) -> Effect:
        self._branch_seq += 1
        self._branches_opened += 1
        self.active = Branch(
            branch_id=f"b{self._branch_seq}",
            opened_at=now,
            opened_reason=ev.reason
        )
        self.state = State.BRANCH
        return self._absorb(ev)

    def _extend_branch(self, ev: EventView) -> Effect:
        return self._absorb(ev)

    def _absorb(self, ev: EventView) -> Effect:
        assert self.active is not None
        b = self.active
        b.hold(HeldAction(call_ref=ev.call_ref, tool=ev.tool, args=ev.args,
                          provenance=ev.provenance, reason=ev.reason))
        # State-change: plausible success (the agent doesn't parse it). Held GET:
        # the agent WOULD read on the result — an honest "withheld" notice, never
        # a fake success it would hallucinate content from.
        if ev.is_revertable:
            stub = b.stubs.withheld_stub(ev.tool)
        elif self.hold_notice == "honest":
            stub = b.stubs.held_notice(ev.tool, ev.args)      # v2
        else:
            stub = b.stubs.result_stub(ev.tool)               # v1
        return Effect(EffectKind.STUB, stub_value=stub, reason=ev.reason)

    def _trigger_for(self, decision: str, ev: EventView, now: float) -> Trigger | None:
        b = self.active
        assert b is not None
        # 5 - budget (branch count or stall time)
        if self._branches_opened > self.max_branches or (now - b.opened_at) > self.max_stall_seconds:
            return Trigger.BUDGET
        # 1 - a stub value is about to flow into a NEW outbound call
        if ev.is_outbound and any(self._looks_stubbed(v) for v in ev.args.values()):
            return Trigger.STUB_INTO_OUTBOUND

        # 3 (v2, hold_notice='honest') — the agent RE-ISSUED a call that is currently
        # held. The notice told it to do exactly that when a later step depends on
        # the held effect, so resolve now; the caller answers the re-issue with the
        # real result of the committed dispatch (never a second execution). Checked
        # before NESTED_REVIEW so the trigger is named for what happened.
        if self.hold_notice == "honest" and self._is_reissue(ev):
            return Trigger.LOOP

        # 4 — another held-class event (any REVIEW, or a non-revertable state
        # change) arrives with the branch already at its hold capacity — resolve
        # the open branch first; the caller re-gates the triggering call. With
        # max_held_per_branch=1 (default) this is the single-transaction rule; a
        # larger capacity widens the branch instead: the event is absorbed below
        # and the judge later rules on all held actions TOGETHER (per-action
        # verdicts), so multi-step sequences are judged jointly. Held actions in
        # one branch are always mutually stub-independent — a call consuming a
        # stub hits STUB_INTO_OUTBOUND above before it could be absorbed — so
        # commit-one/abort-another never partially applies a dependency chain.
        if (len(b.held_calls) >= self.max_held_per_branch
                and (decision == "REVIEW" or (ev.is_outbound and not ev.is_revertable))):
            return Trigger.NESTED_REVIEW

        # 3 — loop on repeated REVERTABLE outbound churn (held calls are caught by
        # nested first, so loop is for GET-style stub-confusion repeats).
        if ev.is_outbound and ev.is_revertable and self._is_loop(ev):
            return Trigger.LOOP
        
        return None

    def _is_reissue(self, ev: EventView) -> bool:
        """Exact re-issue of a held call: same tool, same arguments."""
        b = self.active
        return b is not None and any(h.tool == ev.tool and h.args == ev.args for h in b.held_calls)

    def _looks_stubbed(self, value: Any) -> bool:
        return self.active is not None and self.active.stubs.contains_marker(value)

    def _is_loop(self, ev: EventView) -> bool:
        b = self.active
        assert b is not None
        similar = sum(1 for t in b.trace
                      if t.tool == ev.tool and set(t.args) == set(ev.args))
        return (similar + 1) >= self.loop_threshold

    @staticmethod
    def _same_shape(a: dict[str, Any], b: dict[str, Any]) -> bool:
        # same tool + same identifier-key set = "semantically similar" for loop
        # detection. Cool-down / value-equality refinement deferred (§4.7).
        return set(a) == set(b)