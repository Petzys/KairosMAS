"""Action classification
"""
from __future__ import annotations

from enum import Enum, auto

from kairos.core.events import Channel, HttpMethod, ToolOp, Event
from kairos.policy.schema import Policy
from ada_url import URL

class ActionClass(Enum):
    FS_WRITE = auto()
    NET_GET = auto()
    NET_STATE_CHANGE = auto()
    PASSIVE = auto()

def _is_numeric_scalar(v: object) -> bool:
    """True for ints/floats and for strings that are purely a number (amounts,
    counts, page sizes). These are value predicates, not injected identifiers —
    integrity does not gate them (contact book / rate limiter / threshold rules do)."""
    if isinstance(v, bool):
        return False
    if isinstance(v, (int, float)):
        return True
    if isinstance(v, str):
        s = v.strip().replace(",", "").replace("_", "")
        try:
            float(s)
            return True
        except ValueError:
            return False
    return False

def _origin(url_str: str) -> str:
    try:
        # If it's a bare host like "example.com", modern parsers need a base
        # or a fallback scheme to parse it properly, just like in JS.
        if "://" not in url_str:
            url_str = f"https://{url_str}"
            
        url = URL(url_str)
        # url.origin returns "scheme://host[:port]" directly!
        return url.origin
    except Exception:
        return url_str

def classify(event: Event, policy: Policy) -> ActionClass:
    """Map an event to its action class using channel/operation and policy actions."""
    ch = event.channel

    if ch is Channel.FS:
        return ActionClass.FS_WRITE if event.operation in ("write", "unlink") else ActionClass.PASSIVE

    if ch is Channel.NET:
        if event.operation == HttpMethod.GET.value:
            return ActionClass.NET_GET
        if event.operation in (HttpMethod.POST.value, HttpMethod.PUT.value, HttpMethod.DELETE.value):
            return ActionClass.NET_STATE_CHANGE
        return ActionClass.PASSIVE

    if ch is Channel.TOOL:
        if event.operation == ToolOp.RESULT.value:
            return ActionClass.PASSIVE
        # tool_call: state-changing if the operator declared it non_revertable.
        # A revertable tool_call that only reads is PASSIVE; one that emits data
        # outward is treated as a state-change sink so its args are gated.
        if event.object in policy.context.non_revertable:
            return ActionClass.NET_STATE_CHANGE
        return ActionClass.PASSIVE

    return ActionClass.PASSIVE

def consequential_values(event, action_class: ActionClass, identifier_fields=None) -> list[tuple[str, str]]:
    """Values subject to the integrity check
    """
    if action_class in (ActionClass.PASSIVE, ActionClass.FS_WRITE):
        return []

    content = event.content
    pairs: list[tuple[str, str]] = []

    if isinstance(content, dict):
        for k, v in content.items():
            if identifier_fields is not None and k not in identifier_fields:
                continue                       # non-identifier string = payload
            for elem in (v if isinstance(v, (list, tuple)) else [v]):
                if _is_numeric_scalar(elem):
                    continue                   # quantities → judge, not integrity
                if isinstance(elem, (str, int, float)) and not isinstance(elem, bool):
                    pairs.append((k, str(elem)))
    # elif isinstance(content, (str, bytes)):
    #     text = content.decode("utf-8", errors="replace") if isinstance(content, bytes) else content
    #     pairs.append(("body", text))

    # the destination itself is consequential (content-introduction can be the url/recipient, not just a param)
    if event.channel is Channel.NET and event.object:
        pairs.append(("__destination__", _origin(event.object)))

    return pairs