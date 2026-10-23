"""OpenAI-compatible endpoints that are not OpenAI.

AgentDojo's OpenAI element sends the system prompt in the `developer` role, OpenAI's
newer name for it. vLLM-based servers (the GWDG SAIA cloud, for one) accept such a
request, but their chat templates know only `system` and silently drop the message:
the agent never sees its instructions. For these endpoints the role is renamed back.
"""
from __future__ import annotations

from typing import Any


def system_role(client: Any) -> Any:
    """`developer` messages reach the endpoint as `system` messages."""
    orig = client.chat.completions.create

    def create(*args: Any, **kwargs: Any) -> Any:
        messages = kwargs.get("messages")
        if messages:
            kwargs["messages"] = [{**m, "role": "system"} if m.get("role") == "developer" else m
                                  for m in messages]
        return orig(*args, **kwargs)

    client.chat.completions.create = create
    return client


__all__ = ["system_role"]
