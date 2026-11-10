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
                 extra_body: dict[str, Any] | None = None, seed: int | None = None) -> None:
        from openai import AsyncOpenAI

        self.model, self.temperature, self.extra_body = model, temperature, extra_body or {}
        self.seed = seed
        self.client = AsyncOpenAI(base_url=base_url, api_key=os.environ.get(api_key_env, "EMPTY"),
                                  max_retries=max_retries, timeout=timeout)

    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        resp = await self.client.chat.completions.create(
            model=self.model, messages=history, tools=tools or None,
            temperature=self.temperature, extra_body=self.extra_body or None,
            **({} if self.seed is None else {"seed": self.seed}))
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


class ScriptedBrain:
    """Replays a case's ground-truth script for one agent (`Case.script[agent]`).

    The script holds one action list per activation (= per request the agent receives).
    Actions: `{"tool": name, "args": {...}}`, `{"send": agent, "text": ...}` (synchronous),
    `{"reply": text}` (ends the activation; default reply is the last tool result). In every
    string, `{last}` stands for the agent's latest tool result or peer answer and `{request}`
    for the request being handled, so content really flows through tools, messages and
    boards instead of being restated by the script."""

    def __init__(self, activations: list[list[dict[str, Any]]]) -> None:
        self.activations = [list(a) for a in activations]
        self.current: list[dict[str, Any]] | None = None

    @staticmethod
    def _fill(obj: Any, last: str, request: str) -> Any:
        if isinstance(obj, str):
            return obj.replace("{last}", last).replace("{request}", request)
        if isinstance(obj, dict):
            return {k: ScriptedBrain._fill(v, last, request) for k, v in obj.items()}
        if isinstance(obj, list):
            return [ScriptedBrain._fill(v, last, request) for v in obj]
        return obj

    async def step(self, history: list[dict[str, Any]], tools: list[dict[str, Any]]) -> Turn:
        last = next((m["content"] for m in reversed(history) if m["role"] == "tool"), "")
        last = last.split("\n", 1)[1] if last.startswith("Answer from `") and "\n" in last else last
        request = next((m["content"] for m in reversed(history) if m["role"] == "user"), "")
        if request.startswith("[Message from agent") and "\n" in request:
            request = request.split("\n", 1)[1]
        if self.current is None:
            self.current = self.activations.pop(0) if self.activations else []
        if not self.current:
            self.current = None
            return Turn(last or "Done.")
        action = self._fill(self.current.pop(0), last, request)
        if "reply" in action:
            self.current = None
            return Turn(action["reply"])
        if "send" in action:
            return Turn(None, [_call("send_message", {"agent_id": action["send"], "message": action["text"]})])
        return Turn(None, [_call(action["tool"], action.get("args", {}))])
