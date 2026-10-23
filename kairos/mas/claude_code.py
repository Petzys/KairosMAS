"""The `claude-code` oracle: the LLM judge on the Claude Code CLI, without an API key.

`claude -p` answers one headless turn on the user's Claude Code plan. As a judge it
is isolated from everything Claude Code normally brings: no tools, no MCP servers,
no settings or hooks, no project context (an empty working directory), no saved
session, and the oracle's system prompt in place of Claude Code's. What remains is
the model answering the oracle's prompt.

Select it with judge model `claude-code` (the CLI's default model) or
`claude-code:<model>` (`claude-code:sonnet`, `claude-code:opus`, a full model id).
Given a JSON schema, the CLI holds the answer to it (`--json-schema`): the oracle's
replies are then always well-formed.
Every call counts against the plan's usage limits: the client counts calls, tokens
and the CLI's cost estimate, and records failures. A run should stop on a failure
rather than let the oracle fail closed on, say, an exhausted quota.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

CLAUDE_CODE = "claude-code"
_NO_RETRY = ("usage limit", "limit reached", "credit balance", "invalid api key", "not logged in",
             "please run /login", "authentication")


def is_claude_code(model: str | None) -> bool:
    return bool(model) and (model == CLAUDE_CODE or str(model).startswith(CLAUDE_CODE + ":"))


def cli_model(model: str) -> str | None:
    """`claude-code:sonnet` -> `sonnet`; `claude-code` -> None (the CLI's default)."""
    return model.partition(":")[2] or None


class ClaudeCodeError(RuntimeError):
    """The CLI gave no answer (after retries)."""


@dataclass(slots=True)
class ClaudeCodeUsage:
    calls: int = 0
    input_tokens: int = 0          # including cache reads and writes
    output_tokens: int = 0
    cost_usd: float = 0.0          # the CLI's estimate (on a plan: usage, not a bill)
    seconds: float = 0.0
    models: set[str] = field(default_factory=set)
    errors: list[str] = field(default_factory=list)

    def snapshot(self) -> dict[str, Any]:
        return {"calls": self.calls, "input_tokens": self.input_tokens, "output_tokens": self.output_tokens,
                "cost_usd": round(self.cost_usd, 4), "seconds": round(self.seconds, 1),
                "models": sorted(self.models), "errors": len(self.errors)}


def _text(message: dict[str, Any]) -> str:
    c = message.get("content")
    if isinstance(c, str):
        return c
    return "\n".join(b.get("text", "") for b in c or [] if isinstance(b, dict))


def _render(turns: list[dict[str, Any]]) -> str:
    """The conversation as one prompt (the CLI takes one turn)."""
    if len(turns) == 1:
        return _text(turns[0])
    return "\n\n".join(f"[{m.get('role', 'user')}]\n{_text(m)}" for m in turns)


class ClaudeCodeChatClient:
    """`client.chat.completions.create(...)` answered by `claude -p`."""

    def __init__(self, model: str | None = None, *, json_schema: dict[str, Any] | None = None,
                 binary: str = "claude", timeout: float = 300.0, retries: int = 2, backoff: float = 10.0,
                 max_parallel: int = 4) -> None:
        self.model = model
        self.json_schema = json_schema
        self.binary = shutil.which(binary) or binary
        self.timeout = timeout
        self.retries = retries
        self.backoff = backoff
        self.usage = ClaudeCodeUsage()
        self._lock = threading.Lock()
        self._slots = threading.Semaphore(max_parallel)
        self._cwd = tempfile.mkdtemp(prefix="kairos-judge-")
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self.create))

    def command(self, system: str) -> list[str]:
        cmd = [self.binary, "-p", "--output-format", "json", "--tools", "", "--strict-mcp-config",
               "--setting-sources", "", "--no-session-persistence", "--system-prompt", system]
        if self.model:
            cmd += ["--model", self.model]
        if self.json_schema is not None:
            cmd += ["--json-schema", json.dumps(self.json_schema)]
        return cmd

    def create(self, model: str | None = None, messages: list[dict[str, Any]] | None = None,
               **_: Any) -> Any:
        """`model` is the caller's label for the judge, `temperature` & co. have no
        CLI counterpart: the CLI's model is the one this client was built with."""
        messages = messages or []
        system = "\n\n".join(_text(m) for m in messages if m.get("role") in ("system", "developer"))
        prompt = _render([m for m in messages if m.get("role") not in ("system", "developer")])
        error = ""
        for attempt in range(self.retries + 1):
            if attempt:
                time.sleep(self.backoff * attempt)
            t0 = time.monotonic()
            try:
                with self._slots:
                    out = subprocess.run(self.command(system), input=prompt, capture_output=True, text=True,
                                         timeout=self.timeout, cwd=self._cwd)
            except (OSError, subprocess.TimeoutExpired) as e:
                error = f"{type(e).__name__}: {e}"
                continue
            try:
                d = json.loads(out.stdout)
            except ValueError:
                d = {}
            if isinstance(d, dict) and not d.get("is_error") and out.returncode == 0 \
                    and isinstance(d.get("result"), str):
                return self._completion(d, time.monotonic() - t0)
            error = str((d.get("result") if isinstance(d, dict) else None) or out.stderr.strip()
                        or f"exit status {out.returncode}")[:500]
            if any(k in error.lower() for k in _NO_RETRY):
                break
        with self._lock:
            self.usage.errors.append(error)
        raise ClaudeCodeError(f"claude -p failed: {error}")

    def _completion(self, d: dict[str, Any], seconds: float) -> Any:
        u = d.get("usage") or {}
        prompt_tokens = sum(int(u.get(k) or 0) for k in
                            ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens"))
        completion_tokens = int(u.get("output_tokens") or 0)
        models = list((d.get("modelUsage") or {}).keys())
        with self._lock:
            self.usage.calls += 1
            self.usage.input_tokens += prompt_tokens
            self.usage.output_tokens += completion_tokens
            self.usage.cost_usd += float(d.get("total_cost_usd") or 0.0)
            self.usage.seconds += seconds
            self.usage.models.update(models)
        structured = d.get("structured_output")
        content = json.dumps(structured) if isinstance(structured, dict) else d["result"]
        message = SimpleNamespace(content=content, role="assistant", tool_calls=None, model_extra={})
        usage = SimpleNamespace(prompt_tokens=prompt_tokens, completion_tokens=completion_tokens,
                                total_tokens=prompt_tokens + completion_tokens, completion_tokens_details=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=message, finish_reason="stop", index=0)],
                               usage=usage, model=models[0] if models else (self.model or CLAUDE_CODE),
                               id=d.get("session_id"))


__all__ = ["CLAUDE_CODE", "ClaudeCodeChatClient", "ClaudeCodeError", "ClaudeCodeUsage", "cli_model",
           "is_claude_code"]
