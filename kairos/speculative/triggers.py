"""The six conditions that force branch resolution"""
from __future__ import annotations

from enum import Enum, auto

from kairos.core.events import Event
from kairos.speculative.branch import Branch

class Trigger(Enum):
    STUB_INTO_OUTBOUND = auto()   # 1 — proactive: stub about to flow into a new outbound call
    STUB_ERROR = auto()           # 2 — a stubbed call returned an error
    LOOP = auto()                 # 3 — agent re-issued a semantically similar stubbed call
    NESTED_REVIEW = auto()        # 4 — a second REVIEW would nest a branch
    BUDGET = auto()               # 5 — branch count / stall-time budget exhausted
    TERMINAL = auto()             # 6 — agent emitted a terminal response

class TriggerChecker:
    def __init__(self, max_branches: int = 8, max_stall_seconds: float = 120.0) -> None:
        self.max_branches = max_branches
        self.max_stall_seconds = max_stall_seconds

    def check(self, event: Event, branch: Branch) -> Trigger | None:
        """Return the first trigger this event fires inside `branch`, else None.
        Loop detection (Trigger 3) reuses the SequenceMatcher with a cool-down."""
        raise NotImplementedError