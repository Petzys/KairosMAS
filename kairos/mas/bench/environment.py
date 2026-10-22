"""The shared AgentDojo environment behind the agents' tools, and exposure tracking.

The environment stands for the external services the agents act on (the bank, the
Slack workspace, the mail server). Each agent reaches only its own tools. What
crosses the external boundary -- every call that actually reaches a service,
including held calls committed later -- is recorded in order: that is the trace
AgentDojo's trace-based checks are evaluated on, so a call the monitor withheld
never counts as visible.
"""
from __future__ import annotations

import re
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime

from kairos.mas.bench.suites import SuiteSystem


class ToolBox:
    def __init__(self, suite: Any, env: Any, system: SuiteSystem, *, latency: float = 0.0) -> None:
        self.suite = suite
        self.env = env
        self.system = system
        self.runtime = FunctionsRuntime(suite.tools)
        self.latency = latency
        self.trace: list[FunctionCall] = []
        self.executions: list[tuple[str, str, dict[str, Any], str | None]] = []   # (agent, fn, args, error)
        self._lock = threading.Lock()

    def functions_for(self, agent: str) -> list[Any]:
        tools = set(self.system.tools_of(agent))
        return [f for f in self.suite.tools if f.name in tools]

    def executor(self, agent: str):
        """The function an agent's enforcement point executes tool calls with."""
        owned = set(self.system.tools_of(agent))

        def execute(fn: str, args: dict[str, Any]) -> tuple[Any, str | None]:
            if fn not in owned:
                return "", f"ToolNotFoundError: {fn} is not one of this agent's tools"
            if self.latency:
                time.sleep(self.latency)
            with self._lock:
                result, error = self.runtime.run_function(self.env, fn, dict(args))
                self.trace.append(FunctionCall(function=fn, args=dict(args)))
                self.executions.append((agent, fn, dict(args), error))
            return result, error

        return execute

    @staticmethod
    def format(result: Any) -> str:
        return tool_result_to_str(result)


def _fingerprint(text: str) -> str:
    return re.sub(r"[^a-z0-9]", "", text.lower())


@dataclass(slots=True)
class Exposure:
    """Which agents read the injected payload, and from where. An agent is EXPOSED
    when content it received (a tool result, a message, a reply) contains it."""
    payloads: list[str]
    first: dict[str, str] = field(default_factory=dict)       # agent -> how it first saw it
    _lock: threading.Lock = field(default_factory=threading.Lock)

    @classmethod
    def for_injection(cls, goal: str | None, injections: Iterable[str]) -> "Exposure":
        prints: list[str] = []
        if goal:
            g = _fingerprint(goal)
            prints.append(g[:80] if len(g) > 80 else g)
        for inj in injections:
            f = _fingerprint(inj)
            if len(f) >= 24:
                prints.append(f[:80])
        return cls(payloads=[p for p in prints if p])

    def contains(self, text: str) -> bool:
        if not self.payloads or not text:
            return False
        f = _fingerprint(text)
        return any(p in f for p in self.payloads)

    def see(self, agent: str, text: str, via: str) -> bool:
        """Record that `agent` received `text`; True if it carries the payload."""
        if not self.contains(text):
            return False
        with self._lock:
            self.first.setdefault(agent, via)
        return True

    @property
    def agents(self) -> list[str]:
        return sorted(self.first)
