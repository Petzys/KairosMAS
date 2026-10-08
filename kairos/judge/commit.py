"""CommitGate
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Protocol

from kairos.judge.oracle import Verdict
from kairos.speculative.branch import Branch

@dataclass(slots=True)
class CommitDecision:
    commit: bool
    source: str # "judge" or "user"
    verdict: Verdict
    mask: list[bool] | None = None        # per-action commit mask, if the gate made one

class CommitGate(Protocol):
    def decide(self, branch: Branch, verdict: Verdict) -> CommitDecision: ...

class AutoCommitGate:
    """Judge is authoritative (benchmark configuration)."""
    def decide(self, branch: Branch, verdict: Verdict) -> CommitDecision:
        return CommitDecision(commit=verdict.consistent, source="judge", verdict=verdict, mask=verdict.per_action,)

class ManualCommitGate:
    """Human is final authority (walkthrough configuration). `present` shows the
    case and returns a per-action mask (list[bool] aligned to held_calls) or a
    single bool for the whole branch."""
    def __init__(self, present: Callable[[Branch, Verdict], list[bool] | bool] | None = None) -> None:
        self._present = present or _console_present

    def decide(self, branch: Branch, verdict: Verdict) -> CommitDecision:
        choice = self._present(branch, verdict)
        if isinstance(choice, bool):
            return CommitDecision(commit=choice, source="user", verdict=verdict, mask=None)
        return CommitDecision(commit=all(choice), source="user", verdict=verdict, mask=list(choice))


def _console_present(branch: Branch, verdict: Verdict) -> list[bool]:
    rec = "CONSISTENT" if verdict.consistent else "INCONSISTENT"
    print(f"\n── Branch {branch.branch_id} resolution ──")
    print(f"Judge overall: {rec} — {verdict.rationale}")
    if verdict.flagged:
        print(f"Flagged: {verdict.flagged}")
    mask: list[bool] = []
    for i, a in enumerate(branch.held_calls):
        hint = ""
        if verdict.per_action is not None and i < len(verdict.per_action):
            hint = "  (judge: consistent)" if verdict.per_action[i] else "  (judge: INCONSISTENT)"
        print(f"  [{i}] {a.tool}({a.args})  [{a.reason}]{hint}")
        mask.append(input(f"    commit action [{i}]? [y/N] ").strip().lower() == "y")
    return mask