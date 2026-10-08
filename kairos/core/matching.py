"""Derivability matching relation ⊆_match
"""

from __future__ import annotations

import re
from enum import Enum

_WS = re.compile(r"\s+") # whitespace for normalization
_WORD = re.compile(r"\w+", re.UNICODE)

class Strategy(str, Enum):
    EXACT = "exact"
    NORMALIZED = "normalized"
    TOKEN_SPLIT = "token_split"
    FUZZY = "fuzzy"

def normalize(s: str) -> str:
    """Lowercase, strip, collapse internal whitespace. (definitional helper)"""
    return _WS.sub(" ", s.strip().lower())

def tokenize(s: str) -> set[str]:
    """Word-level tokenizer, lowercased. Stopword/min-length policy is in extract.py.

    Note: tokenize LOWERCASES. A value admitted as all_tokens is therefore stored
    lowercased, so it will not satisfy EXACT against a mixed-case outbound value —
    use NORMALIZED (or admit via specific_fields/regex, which preserve case) for
    case-bearing identifiers like IBANs.
    """
    return {m.group(0).lower() for m in _WORD.finditer(s)}

def _edit_distance(a: str, b: str) -> int:
    """Levenshtein, iteractive two-row DP. (rapitfuzz can replace this for speed)"""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        cur = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            cur.append(min(prev[j] + 1, cur[j-1] + 1, prev[j-1] + cost))
        prev = cur
    return prev[-1]

def matches(value: str, token_value: str, strategy: Strategy, *, fuzzy_threshold: int = 2) -> bool:
    """Does `value` match a SINGLE `token_value` under `strategy`? (§4.5)

    Soundness (§4.5): EXACT is a strong guarantee (verbatim presence); NORMALIZED
    is nearly as strong; FUZZY weakens to approximate presence and on long strings
    can conflate distinct identifiers — a deliberate, documented trade-off.
    """
    if strategy is Strategy.EXACT:
        return value == token_value
    if strategy is Strategy.NORMALIZED:
        return normalize(value) == normalize(token_value)
    if strategy is Strategy.TOKEN_SPLIT:
        # Per-single-token containment. Kept so matches() is total; derivable()
        # implements the closure-wide version and does NOT call this branch.
        tv = tokenize(token_value)
        v = tokenize(value)
        return bool(v) and v <= tv
    if strategy is Strategy.FUZZY:
        return _edit_distance(normalize(value), normalize(token_value)) <= fuzzy_threshold
    raise ValueError(f"Unknown strategy: {strategy!r}")