"""YAML -> Policy, with validation against the Appendix A grammar
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, TypeVar

import yaml

from kairos.core.extract import STRUCTURED_PATTERNS, ExtractConfig, ExtractMode
from kairos.core.matching import Strategy
from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.policy.schema import (
    CbEntry, ContactBook, Context, Duration, MatchBlock, OriginCondition,
    ParamConstraint, Policy, RateLimit, Resources, Rule, SeqStep, SequenceRule,
    SimpleRule, TaintCondition, TaintDef, TrustedSource,
)

SUPPORTED_VERSION = "0.1"
_DURATION = re.compile(r"^(\d+)\s*([smh])$")
_CONSTRAINT_OPS = frozenset({"in", "not_in", "equals", "gt", "lt", "contains"})

class PolicyError(ValueError):
    """Raised when a policy file is malformed or violates the grammar."""

def load_policy(path: str | Path) -> Policy:
    """Read a YAML policy file and parse it into a Policy."""
    raw = yaml.safe_load(Path(path).read_text())
    if not isinstance(raw, dict):
        raise PolicyError(f"policy root must be a mapping, got {type(raw).__name__}")
    return parse_policy(raw)

def parse_policy(raw: dict[str, Any]) -> Policy:
    """Validate `raw` and build a Policy.  (§4.4 / Appendix A)"""
    _check_keys(raw, {"version", "context", "resources", "rules"}, "<root>")
    version = _version(raw.get("version"))
    if "context" not in raw:
        raise PolicyError("<root>: missing required 'context'")
    context = _parse_context(_mapping(raw["context"], "context"))
    resources = (
        _parse_resources(_mapping(raw["resources"], "resources"))
        if "resources" in raw else Resources()
    )
    rules = [
        _parse_rule(_mapping(r, f"rules[{i}]"), f"rules[{i}]")
        for i, r in enumerate(_list(raw.get("rules", []), "rules"))
    ]
    policy = Policy(version=version, context=context, resources=resources, rules=rules)
    _validate_references(policy)
    return policy

# typed accessors / coercion
T = TypeVar("T")

def _mapping(v: Any, path: str) -> dict[str, Any]:
    if not isinstance(v, dict):
        raise PolicyError(f"{path}: expected a mapping, got {type(v).__name__}")
    return v

def _list(v: Any, path: str) -> list[Any]:
    if not isinstance(v, list):
        raise PolicyError(f"{path}: expected a list, got {type(v).__name__}")
    return v

def _str(v: Any, path: str) -> str:
    if not isinstance(v, str):
        raise PolicyError(f"{path}: expected a string, got {type(v).__name__}")
    return v

def _int(v: Any, path: str) -> int:
    if not isinstance(v, int):
        raise PolicyError(f"{path}: expected an integer, got {type(v).__name__}")
    return v

def _str_list(v: Any, path: str) -> list[str]:
    if isinstance(v, str):
        return [v]
    return [_str(i, f"{path}[{j}]") for j, i in enumerate(_list(v, path))]

def _require(d: dict[str, Any], key: str, path: str) -> Any:
    if key not in d:
        raise PolicyError(f"{path}: missing required '{key}'")
    return d[key]

def _check_keys(d: dict[str, Any], allowed: set[str], path: str) -> None:
    unknown = set(d) - allowed
    if unknown:
        raise PolicyError(f"{path}: unknown keys: {', '.join(sorted(unknown))}")

def _version(v: Any) -> str:
    s = str(v).strip() if v is not None else ""
    if s in (SUPPORTED_VERSION, "0.10"):
        return SUPPORTED_VERSION
    raise PolicyError(f"<root>.version: expected {SUPPORTED_VERSION!r}, got {v!r}")

def _decision(v: Any, path: str) -> Decision:
    try:
        return Decision(_str(v, path).strip().upper())
    except ValueError:
        raise PolicyError(f"{path}: invalid decision {v!r} (ALLOW|DENY|REVIEW)") from None

def _level(v: Any, path: str) -> Level:
    try:
        return Level.from_str(_str(v, path))
    except (KeyError, ValueError):
        raise PolicyError(f"{path}: invalid level {v!r} (low|medium|high|critical)") from None


def _strategy(v: Any, path: str) -> Strategy:
    try:
        return Strategy(_str(v, path).strip().lower())
    except ValueError:
        raise PolicyError(
            f"{path}: invalid scan_strategy {v!r} (exact|normalized|token_split|fuzzy)"
        ) from None

def _duration(v: Any, path: str) -> Duration:
    s = _str(v, path).strip().lower()
    if s == "session":
        return Duration(seconds=None)
    m = _DURATION.match(s)
    if not m:
        raise PolicyError(f"{path}: invalid duration {v!r} (e.g. 30s, 5m, 2h, session)")
    n, unit = int(m.group(1)), m.group(2)
    return Duration(seconds=n * {"s": 1, "m": 60, "h": 3600}[unit])

# context
def _parse_context(d: dict[str, Any]) -> Context:
    _check_keys(d, {"name", "description", "scope", "default_action", "actions",
                    "navigational_get", "embedded_identifiers"}, "context")
    actions = _mapping(_require(d, "actions", "context"), "context.actions")
    _check_keys(actions, {"revertable", "non_revertable"}, "context.actions")
    nav = _str(d.get("navigational_get", "allow"), "context.navigational_get").strip().lower()
    if nav not in ("allow", "review"):
        raise PolicyError(f"context.navigational_get: expected 'allow' or 'review', got {nav!r}")
    # NB: YAML 1.1 parses bare `off`/`on` as booleans, and "off" is the natural thing
    # to type here — so accept the boolean forms and normalize them rather than
    # failing on a policy that reads perfectly well to a human.
    emb_raw = d.get("embedded_identifiers", "allow")
    if isinstance(emb_raw, bool):
        emb = "review" if emb_raw else "allow"
    else:
        emb = _str(emb_raw, "context.embedded_identifiers").strip().lower()
        emb = {"off": "allow", "no": "allow", "false": "allow",
               "on": "review", "yes": "review", "true": "review"}.get(emb, emb)
    if emb not in ("allow", "review"):
        raise PolicyError(
            f"context.embedded_identifiers: expected 'allow'/'off' or 'review', got {emb!r}")
    return Context(
        name=_str(_require(d, "name", "context"), "context.name"),
        default_action=_decision(_require(d, "default_action", "context"), "context.default_action"),
        revertable=_str_list(actions.get("revertable", []), "context.actions.revertable"),
        non_revertable=_str_list(actions.get("non_revertable", []), "context.actions.non_revertable"),
        description=_str(d.get("description", ""), "context.description"),
        scope=_str(d.get("scope", ""), "context.scope"),
        navigational_get=nav,
        embedded_identifiers=emb,
    )

# resources
def _parse_resources(d: dict[str, Any]) -> Resources:
    _check_keys(d, {"contact_book", "taints", "trusted_sources", "rate_limits"}, "resources")
    return Resources(
        contact_book=(
            _parse_contact_book(_mapping(d["contact_book"], "resources.contact_book"))
            if "contact_book" in d else None
        ),
        taints=[
            _parse_taint(_mapping(t, f"resources.taints[{i}]"), f"resources.taints[{i}]")
            for i, t in enumerate(_list(d.get("taints", []), "resources.taints"))
        ],
        trusted_sources=[
            _parse_trusted_source(t, f"resources.trusted_sources[{i}]")
            for i, t in enumerate(_list(d.get("trusted_sources", []), "resources.trusted_sources"))
        ],
        rate_limits=[
            _parse_rate_limit(_mapping(r, f"resources.rate_limits[{i}]"), f"resources.rate_limits[{i}]")
            for i, r in enumerate(_list(d.get("rate_limits", []), "resources.rate_limits"))
        ]
    )

def _parse_contact_book(d: dict[str, Any]) -> ContactBook:
    _check_keys(d, {"source", "lookup_fields", "on_miss", "entries", "seed"}, "resources.contact_book")
    entries = [
        _parse_cb_entry(_mapping(e, f"resources.contact_book.entries[{i}]"), f"resources.contact_book.entries[{i}]")
        for i, e in enumerate(_list(d.get("entries", []), "resources.contact_book.entries"))
    ]
    seed_raw = _mapping(d["seed"], "resources.contact_book.seed") if "seed" in d else {}
    seed = {k: _str_list(v, f"resources.contact_book.seed.{k}") for k, v in seed_raw.items()}
    return ContactBook(
        source=_str(d.get("source", "host"), "resources.contact_book.source"),
        lookup_fields=_str_list(_require(d, "lookup_fields", "resources.contact_book"),
                                "resources.contact_book.lookup_fields"),
        on_miss=_decision(d.get("on_miss", "REVIEW"), "resources.contact_book.on_miss"),
        entries=entries,
        seed=seed,
    )

def _parse_cb_entry(d: dict[str, Any], path: str) -> CbEntry:
    _check_keys(d, {"match", "max_level", "fields"}, path)
    return CbEntry(
        match=_str(_require(d, "match", path), f"{path}.match"),
        max_level=_level(_require(d, "max_level", path), f"{path}.max_level"),
        fields=_str_list(d["fields"], f"{path}.fields") if "fields" in d else None,
    )

def _parse_taint(d: dict[str, Any], path: str) -> TaintDef:
    _check_keys(d, {"name", "source", "params", "level", "extract", "scan_strategy"}, path)
    source = _str(_require(d, "source", path), f"{path}.source")
    return TaintDef(
        name=_str(d.get("name", source), f"{path}.name"),   # §4.4 nameless form: default to source
        source=source,
        level=_level(_require(d, "level", path), f"{path}.level"),
        params={k: _str(v, f"{path}.params.{k}") for k, v in _mapping(d["params"], f"{path}.params").items()}
        if "params" in d else None,
        extract=_parse_extract_config(_mapping(d["extract"], f"{path}.extract"), f"{path}.extract")
        if "extract" in d else None,
        scan_strategy=_strategy(d["scan_strategy"], f"{path}.scan_strategy") if "scan_strategy" in d else None,
    )

def _parse_trusted_source(v: Any, path: str) -> TrustedSource:
    """Bare string (defaults) OR mapping with optional extract/scan_strategy."""
    if isinstance(v, str):
        return TrustedSource(source=v)
    d = _mapping(v, path)
    _check_keys(d, {"source", "extract", "scan_strategy"}, path)
    return TrustedSource(
        source=_str(_require(d, "source", path), f"{path}.source"),
        extract=_parse_extract_config(_mapping(d["extract"], f"{path}.extract"), f"{path}.extract")
        if "extract" in d else None,
        scan_strategy=_strategy(d["scan_strategy"], f"{path}.scan_strategy") if "scan_strategy" in d else None,
    )

def _parse_rate_limit(d: dict[str, Any], path: str) -> RateLimit:
    _check_keys(d, {"id", "actions", "group_by", "max_count", "window", "on_exceed"}, path)
    return RateLimit(
        id=_str(_require(d, "id", path), f"{path}.id"),
        actions=_str_list(_require(d, "actions", path), f"{path}.actions"),
        group_by=_str(d["group_by"], f"{path}.group_by") if "group_by" in d else None,
        max_count=_int(_require(d, "max_count", path), f"{path}.max_count"),
        window=_duration(_require(d, "window", path), f"{path}.window"),
        on_exceed=_decision(_require(d, "on_exceed", path), f"{path}.on_exceed"),
    )

# extract config (incl. keep: -> preserve_patterns)
def _parse_extract_config(d: dict[str, Any], path: str) -> ExtractConfig:
    _check_keys(d, {"mode", "min_token_length", "exclude_stopwords", "fields", "pattern", "keep"}, path)
    mode = ExtractMode.ALL_TOKENS
    if "mode" in d:
        try:
            mode = ExtractMode(_str(d["mode"], f"{path}.mode").strip().lower())
        except ValueError:
            raise PolicyError(
                f"{path}.mode: invalid {d['mode']!r} (all_tokens|specific_fields|regex)"
            ) from None
    preserve: list[str] = []
    for name in _str_list(d.get("keep", []), f"{path}.keep"):
        if name not in STRUCTURED_PATTERNS:
            raise PolicyError(
                f"{path}.keep: unknown pattern {name!r} (known: {', '.join(sorted(STRUCTURED_PATTERNS))})"
            )
        preserve.append(STRUCTURED_PATTERNS[name])
    cfg = ExtractConfig(
        mode=mode,
        min_token_length=_int(d.get("min_token_length", 3), f"{path}.min_token_length"),
        exclude_stopwords=bool(d.get("exclude_stopwords", True)),
        fields=_str_list(d["fields"], f"{path}.fields") if "fields" in d else [],
        pattern=_str(d["pattern"], f"{path}.pattern") if "pattern" in d else None,
        preserve_patterns=preserve,
    )
    if cfg.mode is ExtractMode.REGEX and not cfg.pattern:
        raise PolicyError(f"{path}: regex mode requires 'pattern'")
    if cfg.mode is ExtractMode.SPECIFIC_FIELDS and not cfg.fields:
        raise PolicyError(f"{path}: specific_fields mode requires non-empty 'fields'")
    return cfg

# rules
def _parse_rule(d: dict[str, Any], path: str) -> Rule:
    has_match, has_seq = "match" in d, "sequence" in d
    if has_match and has_seq:
        raise PolicyError(f"{path}: a rule has either 'match' or 'sequence', not both")
    if has_match:
        _check_keys(d, {"id", "match", "decision"}, path)
        return SimpleRule(
            id=_str(_require(d, "id", path), f"{path}.id"),
            match=_parse_match_block(_mapping(d["match"], f"{path}.match"), f"{path}.match"),
            decision=_decision(_require(d, "decision", path), f"{path}.decision"),
        )
    if has_seq:
        _check_keys(d, {"id", "sequence", "window", "decision"}, path)
        steps = [
            _parse_seq_step(_mapping(s, f"{path}.sequence[{i}]"), f"{path}.sequence[{i}]")
            for i, s in enumerate(_list(d["sequence"], f"{path}.sequence"))
        ]
        return SequenceRule(
            id=_str(_require(d, "id", path), f"{path}.id"),
            sequence=steps,
            window=_duration(_require(d, "window", path), f"{path}.window"),
            decision=_decision(_require(d, "decision", path), f"{path}.decision"),
        )
    raise PolicyError(f"{path}: rule must contain 'match' (simple) or 'sequence'")


def _parse_match_block(d: dict[str, Any], path: str) -> MatchBlock:
    _check_keys(d, {"action", "params", "taint", "origin"}, path)
    action_raw = _require(d, "action", path)
    action = action_raw if isinstance(action_raw, str) else _str_list(action_raw, f"{path}.action")
    return MatchBlock(
        action=action,
        params=_parse_params(_mapping(d["params"], f"{path}.params"), f"{path}.params") if "params" in d else {},
        taint=_parse_taint_condition(_mapping(d["taint"], f"{path}.taint"), f"{path}.taint") if "taint" in d else None,
        origin=_parse_origin(_mapping(d["origin"], f"{path}.origin"), f"{path}.origin") if "origin" in d else None,
    )


def _parse_seq_step(d: dict[str, Any], path: str) -> SeqStep:
    _check_keys(d, {"action", "params"}, path)
    return SeqStep(
        action=_str(_require(d, "action", path), f"{path}.action"),
        params=_parse_params(_mapping(d["params"], f"{path}.params"), f"{path}.params") if "params" in d else {},
    )


def _parse_params(d: dict[str, Any], path: str) -> dict[str, ParamConstraint]:
    return {name: _parse_constraint(_mapping(c, f"{path}.{name}"), f"{path}.{name}") for name, c in d.items()}


def _parse_constraint(d: dict[str, Any], path: str) -> ParamConstraint:
    if len(d) != 1:
        raise PolicyError(f"{path}: constraint must be a single-key mapping ({'|'.join(sorted(_CONSTRAINT_OPS))})")
    op, value = next(iter(d.items()))
    if op not in _CONSTRAINT_OPS:
        raise PolicyError(f"{path}: unknown constraint op {op!r} ({'|'.join(sorted(_CONSTRAINT_OPS))})")
    if op in ("in", "not_in"):
        if not (isinstance(value, str) and value.startswith("contacts.")):
            raise PolicyError(f"{path}.{op}: expected 'contacts.<field>', got {value!r}")
    return ParamConstraint(op=op, value=value)


def _parse_taint_condition(d: dict[str, Any], path: str) -> TaintCondition:
    _check_keys(d, {"has", "has_not", "level_gte"}, path)
    return TaintCondition(
        has=_str_list(d["has"], f"{path}.has") if "has" in d else [],
        has_not=_str_list(d["has_not"], f"{path}.has_not") if "has_not" in d else [],
        level_gte=_level(d["level_gte"], f"{path}.level_gte") if "level_gte" in d else None,
    )


def _parse_origin(d: dict[str, Any], path: str) -> OriginCondition:
    _check_keys(d, {"param_in_user_prompt"}, path)
    inner = _mapping(_require(d, "param_in_user_prompt", path), f"{path}.param_in_user_prompt")
    _check_keys(inner, {"key", "required"}, f"{path}.param_in_user_prompt")
    return OriginCondition(
        param_in_user_prompt_key=_str(_require(inner, "key", f"{path}.param_in_user_prompt"),
                                      f"{path}.param_in_user_prompt.key"),
        required=bool(inner.get("required", True)),
    )


# cross-reference validation
def _validate_references(policy: Policy) -> None:
    """Every referenced action must be declared in context.actions (catches typos)."""
    known = set(policy.context.revertable) | set(policy.context.non_revertable)
    refs: dict[str, set[str]] = {}

    def add(where: str, *actions: str) -> None:
        refs.setdefault(where, set()).update(actions)

    for ts in policy.resources.trusted_sources:
        add("trusted_sources", ts.source)
    for t in policy.resources.taints:
        add(f"taint:{t.name}", t.source)
    for rl in policy.resources.rate_limits:
        add(f"rate_limit:{rl.id}", *rl.actions)
    for rule in policy.rules:
        if isinstance(rule, SimpleRule):
            acts = [rule.match.action] if isinstance(rule.match.action, str) else rule.match.action
            add(f"rule:{rule.id}", *acts)
        else:
            add(f"rule:{rule.id}", *(s.action for s in rule.sequence))

    problems = [
        f"{where} references undeclared action(s): {', '.join(sorted(a for a in actions if a not in known))}"
        for where, actions in refs.items()
        if not actions <= known
    ]
    if problems:
        raise PolicyError("undeclared actions (add to context.actions):\n  - " + "\n  - ".join(sorted(problems)))  