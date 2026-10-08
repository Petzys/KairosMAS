"""Parsed policy representation
"""
from __future__ import annotations

from dataclasses import dataclass, field

from kairos.core.extract import ExtractConfig
from kairos.core.matching import Strategy
from kairos.core.tokens import Level
from kairos.engine.decision import Decision

@dataclass(slots=True)
class Duration:
    """<duration> ::= <number>("s"|"m"|"h") | "session"."""
    seconds: float | None # None means "session"

# context
@dataclass(slots=True)
class Context:
    name: str
    default_action: Decision
    revertable: list[str] = field(default_factory=list)
    non_revertable: list[str] = field(default_factory=list)
    description: str = ""
    scope: str = ""
    # navigational-reference GETs (§4.6): a GET whose sensitivity-carrying URL
    # appears verbatim in the prompt/admitted content. "allow" (default) treats
    # it as navigation, not exfiltration; "review" keeps the exfil REVIEW for
    # deployments where influence (drive-by visits) must also be reviewed.
    navigational_get: str = "allow"  # "allow" | "review"
    # Embedded-identifier check (§4.6): integrity-gate action-bearing values (URLs,
    # IBANs, emails) found inside PAYLOAD fields, not just in declared identifier
    # fields — a link in a message body is a destination for its recipient. Default
    # "allow" (no gating) so the evaluated baseline is unaffected; "review" enables it.
    embedded_identifiers: str = "allow"  # "allow" | "review"

# resources
@dataclass(slots=True)
class CbEntry:
    match: str
    max_level: Level
    fields: list[str] | None = None

@dataclass(slots=True)
class ContactBook:
    lookup_fields: list[str]
    on_miss: Decision = Decision.REVIEW
    entries: list[CbEntry] = field(default_factory=list)
    seed: dict[str, list[str]] = field(default_factory=dict)
    source: str = "host"

@dataclass(slots=True)
class TaintDef:
    name: str
    source: str                              # action/tool name
    level: Level
    params: dict[str, str] | None = None     # narrow to specific operations
    extract: ExtractConfig | None = None
    scan_strategy: Strategy | None = None

@dataclass(slots=True)
class RateLimit:
    id: str
    actions: list[str]
    group_by: str | None
    max_count: int
    window: Duration
    on_exceed: Decision

@dataclass(slots=True)
class TrustedSource:
    """A source whose ALLOWed results enter the trust closure (§4.5).

    `extract`/`scan_strategy` are optional per-source overrides; absent => the
    engine's defaults. Resolves the trusted-source strategy gap (§4.4 flag).
    """
    source: str
    extract: ExtractConfig | None = None
    scan_strategy: Strategy | None = None

@dataclass(slots=True)
class Resources:
    contact_book: ContactBook | None = None
    taints: list[TaintDef] = field(default_factory=list)
    trusted_sources: list[TrustedSource] = field(default_factory=list)
    rate_limits: list[RateLimit] = field(default_factory=list)

# rules
@dataclass(slots=True)
class ParamConstraint:
    """One of: in/not_in (contacts.<field>), equals, gt, lt, contains."""
    op: str
    value: object

@dataclass(slots=True)
class TaintCondition:
    has: list[str] = field(default_factory=list)
    has_not: list[str] = field(default_factory=list)
    level_gte: Level | None = None

@dataclass(slots=True)
class OriginCondition:
    param_in_user_prompt_key: str            # value must be derivable from the prompt
    required: bool = True

@dataclass(slots=True)
class MatchBlock:
    action: str | list[str]
    params: dict[str, ParamConstraint] = field(default_factory=dict)
    taint: TaintCondition | None = None
    origin: OriginCondition | None = None

@dataclass(slots=True)
class SimpleRule:
    id: str
    match: MatchBlock
    decision: Decision

@dataclass(slots=True)
class SeqStep:
    action: str
    params: dict[str, ParamConstraint] = field(default_factory=dict)

@dataclass(slots=True)
class SequenceRule:
    id: str
    sequence: list[SeqStep]
    window: Duration
    decision: Decision

Rule = SimpleRule | SequenceRule

# --- top level --------------------------------------------------------------
@dataclass(slots=True)
class Policy:
    version: str
    context: Context
    resources: Resources = field(default_factory=Resources)
    rules: list[Rule] = field(default_factory=list)
