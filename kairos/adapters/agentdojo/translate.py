"""Translate AgentDojo FunctionCall <-> kairos Event.

AgentDojo tools are function calls, so events are Channel.TOOL and the action
class falls out of the policy's revertable/non_revertable split via classify() —
no HTTP-method table needed for tool suites like banking.

Tools whose CALL egresses data via its args (get_webpage(url), search(query))
must instead be gated as NET GET so confidentiality scans the outgoing value.
NET_GET_TOOLS lists them (empty for banking) — the principled successor to the
old _HTTP_METHOD_MAP.
"""
from __future__ import annotations

import time
from typing import Any

from kairos.core.events import Channel, Event, HttpMethod, ToolOp

# Tools whose CALL egresses data via a URL arg and returns remote content: gated as
# NET GET so the URL is confidentiality-scanned. A non-sensitive GET passes (fetching
# from arbitrary destinations is normal); only a URL carrying a sensitive token is held
# for destination clearance — exactly what the mitmproxy effector enforces in the real
# system, so simulation and production share one rule. Banking has no such tool. The
# state-changing web sink (slack post_webpage) is non_revertable and gated as usual.
NET_GET_TOOLS: dict[str, str] = {
    "get_webpage": "url",          # slack: arg 'url' is the outgoing destination
}


def call_to_event(tc: Any, turn_id: int) -> Event:
    """Assistant tool_call -> gated OUTBOUND event."""
    if tc.function in NET_GET_TOOLS:
        url = str(tc.args.get(NET_GET_TOOLS[tc.function], ""))
        return Event(time.monotonic(), Channel.NET, HttpMethod.GET.value, "agentdojo",
                     url, dict(tc.args),
                     {"tool_call_id": tc.id, "turn_id": turn_id, "function": tc.function})
    return Event(time.monotonic(), Channel.TOOL, ToolOp.CALL.value, "agentdojo",
                 tc.function, dict(tc.args),
                 {"tool_call_id": tc.id, "turn_id": turn_id})


def result_to_event(tc: Any, output: str, turn_id: int) -> Event:
    """Tool execution result -> INBOUND event for admission."""
    return Event(time.monotonic(), Channel.TOOL, ToolOp.RESULT.value, "agentdojo",
                 tc.function, output,
                 {"tool_call_id": tc.id, "turn_id": turn_id})