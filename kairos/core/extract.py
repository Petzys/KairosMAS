"""extract(): content -> tokens that populate the closure"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from ada_url import URL

from kairos.core.matching import tokenize

# Conservative function-word list only — NO domain verbs (keep "send", "pay",
# "transfer" etc. so the prompt's intent words can still seed trust if needed).
STOPWORDS: frozenset[str] = frozenset({
    "the", "a", "an", "and", "or", "but", "if", "then", "else", "is", "are", "was",
    "were", "be", "been", "being", "to", "of", "in", "on", "at", "for", "with", "by",
    "from", "as", "that", "this", "these", "those", "it", "its", "i", "you", "he",
    "she", "they", "we", "me", "my", "your", "his", "her", "their", "our",
})

STRUCTURED_PATTERNS: dict[str, str] = {
    # path/filename: requires an alphabetic extension, so "98.70" is NOT a file
    "filename": r"[A-Za-z0-9_\-./]+\.[A-Za-z][A-Za-z0-9]{0,7}\b",
    "iban":     r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
    "url":      r"https?://[^\s'\"<>]+",
    "email":    r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
}

EMBEDDED_PATTERNS: dict[str, str] = {
    "url":   r"(?:https?://|www\.)[^\s'\"<>,;)\]}]+",
    "iban":  r"\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b",
    "email": r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b",
}


def embedded_values(text: str) -> list[tuple[str, str]]:
    """(kind, value) for every action-bearing identifier embedded in free text.

    Trailing sentence punctuation is stripped so "visit www.x.com." yields the host
    without the period. Order is deterministic (pattern order, then position)."""
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for kind, pat in EMBEDDED_PATTERNS.items():
        for m in re.finditer(pat, text):
            val = m.group(0).rstrip(".,;:!?")
            if val and val not in seen:
                seen.add(val)
                out.append((kind, val))
    return out


def _url_origin(url_str: str) -> str | None:
    """scheme://host[:port] for a URL string, or None if it doesn't parse as one.
    Mirrors action_class._origin so a preserved URL also authorizes its host."""
    try:
        if "://" not in url_str:
            url_str = f"https://{url_str}"
        return URL(url_str).origin
    except Exception:
        return None

class ExtractMode(str, Enum):
    ALL_TOKENS = "all_tokens"          # tokenize, drop stopwords, keep len >= min
    SPECIFIC_FIELDS = "specific_fields"  # only named fields of structured content
    REGEX = "regex"                     # substrings matching a declared pattern

@dataclass(slots=True)
class ExtractConfig:
    mode: ExtractMode = ExtractMode.ALL_TOKENS
    min_token_length: int = 3
    exclude_stopwords: bool = True
    fields: list[str] = field(default_factory=list)   # specific_fields mode
    pattern: str | None = None                         # regex mode
    preserve_patterns: list[str] = field(default_factory=list)  # whole-identifier regexes

def prompt_extract_config() -> ExtractConfig:
    """Default config for seeding T_0 from the user prompt: coarse tokens PLUS the
    common structured identifiers preserved whole (root of trust, so safe)."""
    return ExtractConfig(
        mode=ExtractMode.ALL_TOKENS,
        preserve_patterns=list(STRUCTURED_PATTERNS.values()),
    )

def _as_text(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, bytes):
        return content.decode("utf-8", errors="replace")
    return json.dumps(content, ensure_ascii=False, default=str)

# public alias: the store records raw admitted text (seen_verbatim, §4.6) and
# must coerce content exactly the way extraction does.
as_text = _as_text

def _as_mapping(content: Any) -> dict[str, Any]:
    if isinstance(content, dict):
        return content
    if isinstance(content, (str, bytes)):
        try:
            loaded = json.loads(content)
        except (ValueError, TypeError):
            return {}
        return loaded if isinstance(loaded, dict) else {}
    return {}

def _primary(content: Any, cfg: ExtractConfig) -> list[str]:
    if cfg.mode is ExtractMode.ALL_TOKENS:
        toks = tokenize(_as_text(content))
        if cfg.exclude_stopwords:
            toks = {t for t in toks if t not in STOPWORDS}
        return sorted(t for t in toks if len(t) >= cfg.min_token_length)
    if cfg.mode is ExtractMode.SPECIFIC_FIELDS:
        mapping = _as_mapping(content)
        return [str(mapping[f]) for f in cfg.fields if mapping.get(f) is not None]
    if cfg.mode is ExtractMode.REGEX:
        if not cfg.pattern:
            raise ValueError("regex extract mode requires a pattern")
        return [m.group(0) for m in re.finditer(cfg.pattern, _as_text(content))]
    raise ValueError(f"unknown extract mode: {cfg.mode!r}")

def extract(content: Any, cfg: ExtractConfig) -> list[str]:
    """Convert content into closure tokens per `cfg.mode` (4.5).

    - all_tokens:      coarse free-text default; lowercased, stopword/len filtered.
    - specific_fields: WHOLE values of named fields, case preserved (precise scope).
    - regex:           full-match substrings of a declared pattern, case preserved.
    """
    """Convert content into closure tokens: primary (by mode) + preserved (whole)."""
    primary = _primary(content, cfg)
    preserved: list[str] = []
    if cfg.preserve_patterns:
        text = _as_text(content)
        for pat in cfg.preserve_patterns:
            for m in re.finditer(pat, text):
                tok = m.group(0)
                preserved.append(tok)
                origin = _url_origin(tok)                  # also emit origin if URL-like
                if origin is not None and origin != tok:
                    preserved.append(origin)
    # dedup, deterministic order (primary first, then preserved), case preserved
    return list(dict.fromkeys(primary + preserved))
