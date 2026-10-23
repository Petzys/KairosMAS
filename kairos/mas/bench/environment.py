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
    """The suite's tools on one environment, shared by all agents of a session.
    `trace` is the ordered list of calls that really ran (see the module docstring);
    `latency` simulates slow services."""

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
        """The tool definitions `agent` may call (shown to an LLM agent as its tools)."""
        tools = set(self.system.tools_of(agent))
        return [function for function in self.suite.tools if function.name in tools]

    def executor(self, agent: str):
        """The function an agent's enforcement point executes tool calls with."""
        owned = set(self.system.tools_of(agent))

        def execute(fn: str, args: dict[str, Any]) -> tuple[Any, str | None]:
            if fn not in owned:
                return "", f"ToolNotFoundError: {fn} is not one of this agent's tools"
            if self.latency:
                time.sleep(self.latency)
            # One call at a time on the shared environment, recorded in the order it ran.
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
    """Lower-case letters and digits only: the payload is recognised however an agent
    re-quotes, re-wraps or re-punctuates it."""
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
        """What counts as the payload: the start of the injection task's goal, and the
        start of every injected text long enough not to match by accident."""
        prints: list[str] = []
        if goal:
            goal_print = _fingerprint(goal)
            prints.append(goal_print[:80] if len(goal_print) > 80 else goal_print)
        for injection in injections:
            injection_print = _fingerprint(injection)
            if len(injection_print) >= 24:
                prints.append(injection_print[:80])
        return cls(payloads=[fingerprint for fingerprint in prints if fingerprint])

    def contains(self, text: str) -> bool:
        """Does `text` carry the payload?"""
        if not self.payloads or not text:
            return False
        text_print = _fingerprint(text)
        return any(payload in text_print for payload in self.payloads)

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
