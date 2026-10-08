"""Integrity check.
"""
from __future__ import annotations

from kairos.core.extract import embedded_values
from kairos.core.matching import Strategy
from kairos.core.store import TokenStore
from kairos.engine.action_class import ActionClass, consequential_values
from kairos.engine.decision import Decision
from kairos.policy.contact_book import ContactBook
from kairos.policy.schema import Policy

def _declared_strategies(policy: Policy, default: Strategy) -> set[Strategy]:
    """Strategies the operator declared on any trusted source, plus the default.
    """
    strategies = {default}
    for ts in policy.resources.trusted_sources:
        if ts.scan_strategy is not None:
            strategies.add(ts.scan_strategy)
    return strategies

def _derivable_any(store: TokenStore, value: str, strategies: set[Strategy], branch: str | None) -> bool:
    return any(store.derivable(value, s, branch) for s in strategies)

def _url_forms(value: str) -> list[str]:
    """`value` plus the URL-normalised forms a user would plausibly have typed.
    """
    forms = [value]
    v = value.strip()
    if "://" in v:
        rest = v.split("://", 1)[1]
        host_path = rest.rstrip("/")
        host = host_path.split("/", 1)[0]
        forms.append(host_path)
        if host and host != host_path:
            forms.append(host)
        if ":" in host:                       # host:port -> host
            forms.append(host.split(":", 1)[0])
    return forms


def _trusted(
    store: TokenStore, value: str, strategies: set[Strategy],
    branch: str | None, contact_book: ContactBook | None,
) -> bool:
    for form in _url_forms(value):
        if _derivable_any(store, form, strategies, branch):
            return True
        if contact_book is not None and contact_book.is_known(form):
            return True
    return False

def check_integrity(
    event,
    action_class: ActionClass,
    store: TokenStore,
    policy: Policy,
    *,
    contact_book: ContactBook | None = None,
    branch: str | None = None,
    default_strategy: Strategy = Strategy.NORMALIZED,
) -> tuple[Decision | None, str]:
    """Return (decision, reason). None == integrity satisfied / not applicable.
    """
    if action_class is not ActionClass.NET_STATE_CHANGE:
        return None, "" # integrity only gates state changes; other classes always ok

    strategies = _declared_strategies(policy, default_strategy)
    id_fields = set(contact_book.lookup_fields) if contact_book is not None else None
    values = consequential_values(event, action_class, identifier_fields=id_fields)

    non_derivable = [
        name for name, v in values if not _trusted(store, v, strategies, branch, contact_book)
    ]
    if non_derivable:
        # Content-introduction. Irreversible -> REVIEW (never deterministic DENY).
        which = ", ".join(n for n in non_derivable if n != "__destination__") or "destination"
        return Decision.REVIEW, f"non-derivable value(s) in consequential position: {which}"
    return None, ""


def check_embedded_identifiers(
    event,
    action_class: ActionClass,
    store: TokenStore,
    policy: Policy,
    *,
    contact_book: ContactBook | None = None,
    branch: str | None = None,
    default_strategy: Strategy = Strategy.NORMALIZED,
) -> tuple[Decision | None, str]:
    """Integrity over action-bearing values embedded in PAYLOAD fields (§4.6).
    """
    if action_class is not ActionClass.NET_STATE_CHANGE:
        return None, ""
    if policy.context.embedded_identifiers != "review":
        return None, ""
    content = event.content
    if not isinstance(content, dict):
        return None, ""

    id_fields = set(contact_book.lookup_fields) if contact_book is not None else set()
    strategies = _declared_strategies(policy, default_strategy)

    flagged: list[str] = []
    for field, raw in content.items():
        if field in id_fields:
            continue                      # already adjudicated by check_integrity
        for elem in (raw if isinstance(raw, (list, tuple)) else [raw]):
            if not isinstance(elem, str):
                continue
            for kind, value in embedded_values(elem):
                if _trusted(store, value, strategies, branch, contact_book):
                    continue
                flagged.append(f"{kind} {value!r} in {field}")
    if flagged:
        return Decision.REVIEW, ("non-derivable identifier(s) embedded in payload: "
                                 + "; ".join(flagged[:3]))
    return None, ""