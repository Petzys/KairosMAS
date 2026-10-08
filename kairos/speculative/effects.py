"""What the machine tells the caller to do"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto
from typing import Any

class State(Enum):
    LINEAR = auto()
    BRANCH = auto()
    RESOLUTION = auto()

class Trigger(Enum):
    STUB_INTO_OUTBOUND = auto() # 1
    STUB_ERROR = auto() # 2 (hooked, rarely fires in banking)
    LOOP = auto() # 3
    NESTED_REVIEW = auto() # 4
    BUDGET = auto() # 5
    TERMINAL = auto() # 6

class EffectKind(Enum):
    EXECUTE = auto() # linear ALLOW: run the call for real
    BLOCK = auto() # DENY: refuse
    STUB = auto() # REVIEW absorbed into branch: hand back a stub, hold the call
    RESOLVE = auto() # a trigger fired: caller must drive resolution now

@dataclass(slots=True)
class Effect:
    kind: EffectKind
    stub_value: Any = None # for STUB
    trigger: Trigger | None = None # for RESOLVE
    reason: str = ""
