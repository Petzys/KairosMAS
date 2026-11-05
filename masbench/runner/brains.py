"""What decides an agent's next step: an LLM, or a script that replays AgentDojo ground truth.

A brain sees the agent's conversation (OpenAI chat format) and its tool schemas and returns
the next assistant turn. The replay brains need no model and make the whole pipeline
(partition, A2A bus, defense hooks, scoring) testable offline.
"""
from __future__ import annotations

import json
import os
import uuid
from dataclasses import dataclass, field
from typing import Any, Protocol


@dataclass
class TurnCall:
    id: str
    name: str
    arguments: str  # JSON text as produced by the model


@dataclass
class Turn:
    content: str | None
    tool_calls: list[TurnCall] = field(default_factory=list)
    prompt_tokens: int = 0
    completion_tokens: int = 0

    def as_message(self) -> dict[str, Any]:
        msg: dict[str, Any] = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            msg["tool_calls"] = [{"id": c.id, "type": "function",
                                  "function": {"name": c.name, "arguments": c.arguments}}
                                 for c in self.tool_calls]
        return msg


class Brain(Protocol):
    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn: ...


def _call(name: str, args: dict[str, Any]) -> TurnCall:
    return TurnCall(id=f"call_{uuid.uuid4().hex[:12]}", name=name, arguments=json.dumps(args))


class LLMBrain:
    """OpenAI-compatible chat completions with tool calling (OpenAI, OpenRouter, vLLM, SAIA, UzL)."""

    def __init__(self, model: str, base_url: str | None = None, api_key_env: str = "OPENAI_API_KEY",
                 temperature: float = 0.0, max_retries: int = 3, timeout: float = 300.0,
                 extra_body: dict[str, Any] | None = None) -> None:
        from openai import AsyncOpenAI

        self.model, self.temperature, self.extra_body = model, temperature, extra_body or {}
        self.client = AsyncOpenAI(base_url=base_url, api_key=os.environ.get(api_key_env, "EMPTY"),
                                  max_retries=max_retries, timeout=timeout)

    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        resp = await self.client.chat.completions.create(
            model=self.model, messages=history, tools=tools or None,
            temperature=self.temperature, extra_body=self.extra_body or None)
        msg = resp.choices[0].message
        usage = resp.usage
        return Turn(
            content=msg.content,
            tool_calls=[TurnCall(id=c.id, name=c.function.name, arguments=c.function.arguments or "{}")
                        for c in (msg.tool_calls or [])],
            prompt_tokens=getattr(usage, "prompt_tokens", 0) or 0,
            completion_tokens=getattr(usage, "completion_tokens", 0) or 0,
        )


class ReplayOrchestrator:
    """Sends each ground-truth call to the agent that owns the tool, then gives the GT answer."""

    def __init__(self, plan: list[tuple[str, dict[str, Any]]], owner: dict[str, str],
                 final_output: str, mode: str = "sync") -> None:
        self.plan, self.owner, self.final_output, self.mode = plan, owner, final_output, mode

    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        done = sum(1 for m in history if m["role"] == "tool")
        if done < len(self.plan):
            fn, args = self.plan[done]
            tool = "send_message" if self.mode == "sync" else "send_message_async"
            return Turn(None, [_call(tool, {"agent_id": self.owner[fn],
                                            "message": json.dumps({"call": fn, "args": args})})])
        if self.mode == "async" and not any(
                m["role"] == "tool" and m["content"].startswith("Replies") for m in history):
            return Turn(None, [_call("wait_for_replies", {})])
        return Turn(self.final_output)


class ReplayWorker:
    """Executes the call in the request and answers with the tool result."""

    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        last = history[-1]
        if last["role"] == "user":
            try:
                req = json.loads(last["content"].split("\n", 1)[1])
            except (IndexError, ValueError):
                return Turn("Noted.")  # a notice (e.g. from a defense), not a request
            return Turn(None, [_call(req["call"], req["args"])])
        return Turn(last["content"])
