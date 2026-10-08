"""Confidentiality check
"""
from __future__ import annotations

from kairos.core.events import Channel
from kairos.core.matching import Strategy
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.action_class import ActionClass, consequential_values
from kairos.engine.decision import Decision, resolve
from kairos.policy.contact_book import ContactBook

def _outbound_texts(event) -> list[str]:
    """Everything leaving the boundary. NET includes the full URL (query/path may
    carry data); TOOL scans only argument values, not the policy-authorized name."""
    texts: list[str] = []
    if event.channel is Channel.NET and event.object:
        texts.append(event.object)
    c = event.content
    if isinstance(c, dict):
        for v in c.values():
            # flatten lists so a sensitive token in a list-valued arg is scanned
            for elem in (v if isinstance(v, (list, tuple)) else [v]):
                texts.append(str(elem))
    elif isinstance(c, str):
        texts.append(c)
    elif isinstance(c, bytes):
        texts.append(c.decode("utf-8", errors="replace"))
    return texts

def outbound_sensitivity(
    event, action_class: ActionClass, store: TokenStore,
    *, branch: str | None = None, strategy: Strategy = Strategy.TOKEN_SPLIT,
) -> Level | None:
    if action_class in (ActionClass.PASSIVE, ActionClass.FS_WRITE):
        return None
    best: Level | None = None
    for text in _outbound_texts(event):
        lvl = store.sensitivity_of(text, branch=branch, strategy=strategy)
        if lvl is not None and (best is None or lvl > best):
            best = lvl
    return best

def is_navigational_reference(
    event, action_class: ActionClass, store: TokenStore,
    *, branch: str | None = None, strategy: Strategy = Strategy.TOKEN_SPLIT,
) -> bool:
    if action_class is not ActionClass.NET_GET:
        return False
    sensitive = [t for t in _outbound_texts(event)
                 if store.sensitivity_of(t, branch=branch, strategy=strategy) is not None]
    return bool(sensitive) and all(store.seen_verbatim(t, branch) for t in sensitive)

def _destinations(event, action_class: ActionClass, contact_book: ContactBook | None) -> list[str]:
    """Where the data goes. NET -> origin (via consequential_values, so it uses
    ada_url origin logic). TOOL -> values of contact-book lookup_fields."""
    if event.channel is Channel.NET:
        return [v for name, v in consequential_values(event, action_class) if name == "__destination__"]
    if event.channel is Channel.TOOL and contact_book is not None and isinstance(event.content, dict):
        dests: list[str] = []
        for f in contact_book.lookup_fields:
            val = event.content.get(f)
            if val is None:
                continue
            # flatten list-valued destination fields (recipients/cc/bcc/participants)
            for elem in (val if isinstance(val, (list, tuple)) else [val]):
                dests.append(str(elem))
        return dests
    return []

def _clearance_decision(
    dest: str, data_level: Level, store: TokenStore,
    contact_book: ContactBook | None, branch: str | None,
) -> tuple[Decision | None, str]:
    if contact_book is not None:
        clearance = contact_book.clearance(dest)
        if clearance is not None:
            if data_level <= clearance:
                return None, ""
            return Decision.REVIEW, f"destination not cleared for {data_level.name.lower()}-sensitivity data"
    if store.derivable(dest, Strategy.NORMALIZED, branch):
        return None, "" # user/policy-vouched destination
    if contact_book is not None and contact_book.is_known(dest):
        return Decision.REVIEW, "destination known but no clearance declared"
    on_miss = contact_book.on_miss if contact_book is not None else Decision.REVIEW
    if on_miss is Decision.ALLOW:
        return None, ""
    return on_miss, "sensitive data to unknown destination (possible exfiltration)"

def check_confidentiality(
    event,
    action_class: ActionClass,
    store: TokenStore,
    contact_book: ContactBook | None,
    *,
    data_level: Level | None,
    branch: str | None = None,
) -> tuple[Decision | None, str]:
    """Return (decision, reason). `data_level` is precomputed by the caller via
    outbound_sensitivity (so the scan runs once and feeds integrity's
    carries_sensitive too). None data_level => non-sensitive => goes anywhere."""
    if action_class in (ActionClass.PASSIVE, ActionClass.FS_WRITE):
        return None, "" # fs write stays internal; confidentiality N/A
    if data_level is None:
        return None, ""

    dests = _destinations(event, action_class, contact_book)
    if not dests:
        return Decision.REVIEW, "sensitive data with no identifiable destinations"

    worst: Decision | None = None
    reason = ""
    for d in dests:
        dec, r = _clearance_decision(d, data_level, store, contact_book, branch)
        merged = resolve([worst, dec])
        if merged is not worst:
            worst, reason = merged, r
    return worst, (reason if worst is not None else "")