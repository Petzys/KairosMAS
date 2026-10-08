"""Decision codomain and priority resolution"""
from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from enum import Enum

class Decision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    REVIEW = "REVIEW"

_PRIORITY = { Decision.DENY: 3, Decision.REVIEW: 2, Decision.ALLOW: 1 }

def resolve(decisions: Iterable[Decision | None]) -> Decision | None:
    """Combine check results by priority DENY > REVIEW > ALLOW. None == pass. (4.6)"""
    present = [d for d in decisions if d is not None]
    if not present:
        return None
    return max(present, key=lambda d: _PRIORITY[d])

@dataclass(slots=True)
class StageResult:
    """Outcome of evaluating one event, with provenance for telemetry/eval."""
    decision: Decision
    stage: int          # 1 deterministic, 2 speculative, 3 resolution
    produced_by: str    # check/rule that fired
    reason: str = ""
    identifiers: dict[str, str] = field(default_factory=dict)   # gated identifier values