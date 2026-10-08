"""Token store records: the two axes of the data model
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum

class Level(IntEnum):
    """Sensitivity clearance, ordered for `>=` comparison against a destination."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def from_str(cls, s: str) -> "Level":
        return cls[s.strip().upper()]

@dataclass(frozen=True, slots=True)
class TrustToken:
    """A value derived from a trusted source (user prompt or policy-trusted tool)."""
    value: str
    source: str
    branch_origin: str | None = None     # None => committed; else owning branch (§4.3)
    timestamp: float = 0.0

@dataclass(frozen=True, slots=True)
class SensitivityToken:
    """A value carrying sensitive information at a declared level."""
    value: str
    level: Level
    source: str
    branch_origin: str | None = None
    timestamp: float = 0.0