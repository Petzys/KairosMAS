"""Sandwiching (repeat the task after untrusted content), lifted to every agent. Run R07.

AgentDojo's `repeat_user_prompt` appends the user's query again after every round of tool
results, so the last instruction the model reads is the legitimate one. Lifted to a MAS, an
agent's task is the request it is handling: the principal's prompt for the entry agent, the
peer's request for every other agent. The repetition is built in `before_llm` for each
model call from the stored conversation, which is not changed.
"""
from __future__ import annotations

from typing import Any

from masbench.runner.defense import Defense


def is_request(message: dict[str, Any], first: bool) -> bool:
    content = message.get("content") or ""
    return message["role"] == "user" and (first or content.startswith("[Message from agent"))


class Sandwiching(Defense):
    name = "sandwiching"
    run_id = "R07"

    async def before_llm(self, agent: str, messages: list[dict[str, Any]],
                         tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        out: list[dict[str, Any]] = []
        task: str | None = None
        seen_user = False
        for i, m in enumerate(messages):
            out.append(m)
            if m["role"] == "user":
                if is_request(m, first=not seen_user):
                    task = m["content"]
                seen_user = True
            last_of_round = m["role"] == "tool" and (i + 1 == len(messages) or messages[i + 1]["role"] != "tool")
            if last_of_round and task is not None:
                out.append({"role": "user", "content": task})
        return out, tools


DEFENSE = Sandwiching
