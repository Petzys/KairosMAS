"""The interface between the runner and a defense.

The runner calls these hooks at every point where something crosses an agent boundary. All
hooks are async: a defense may stall a call (hold an effect, wait for an oracle) simply by
awaiting. The defense never sees the case's attacker, scoring or labels, only what a deployed
monitor would see: the scenario, the principal's prompt, the cluster layout and the traffic.

Where existing defenses attach:

| Defense | Hooks |
|---|---|
| PI detector, spotlighting, sandwiching | after_tool, on_receive (tool outputs and received messages) |
| Progent | before_tool (per-agent privilege policy) |
| CaMeL / multi-CaMeL | make_brain (replaces the agent's LLM loop) |
| SafeFlow | before_tool (staged hard sinks), after_tool / on_receive (taint) |
| BlindGuard | on_message (graph of messages) |
| KAIROS (per agent), KAIROS MAS | before_tool, after_tool, on_message, on_receive, on_activation_end, drain_notices, ctx.execute_tool |
"""
from __future__ import annotations

from dataclasses import dataclass, field
from collections.abc import Callable
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from masbench.env import Environment
    from masbench.runner.brains import Brain
    from masbench.schema import AgentSpec, Layout, Scenario


@dataclass
class Verdict:
    action: Literal["allow", "deny", "replace"] = "allow"
    reason: str = ""
    replacement: str | None = None  # new text (message) or result (tool call) for "replace"

    @classmethod
    def allow(cls) -> Verdict:
        return cls()

    @classmethod
    def deny(cls, reason: str) -> Verdict:
        return cls("deny", reason)


@dataclass
class ToolCall:
    agent: str
    seq: int
    function: str
    args: dict[str, Any]


@dataclass
class Message:
    """One A2A message. Requests open a task, replies answer it."""

    id: str
    task_id: str
    kind: Literal["request", "reply"]
    sender: str
    receiver: str
    mode: Literal["sync", "async"]
    sender_seq: int
    text: str


@dataclass
class EndAction:
    """What a defense wants after an agent's activation ended (e.g. a branch was aborted).

    reenter=True: `notice` is appended as a user message and the agent continues (the
    runner allows this once per activation). reenter=False: `notice` is appended to the
    agent's final answer as a correction."""

    notice: str
    reenter: bool = False


@dataclass
class RunContext:
    scenario: Scenario
    layout: Layout | None
    user_prompt: str
    environment: Environment
    cluster_of: dict[str, str] = field(default_factory=dict)
    log: list[dict[str, Any]] = field(default_factory=list)  # goes to RunRecord.defense_log
    # execute_tool(agent, function, args, note) -> ToolOutcome: runs a call the defense
    # held and later committed. Must be called on the event-loop thread; it records the
    # call in the scored trace.
    execute_tool: Callable[[str, str, dict[str, Any], str], Any] | None = None


class Defense:
    """No defense. Subclasses override the hooks they need."""

    name = "undefended"

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.ctx: RunContext | None = None

    async def setup(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def system_prompt(self, agent: AgentSpec, prompt: str) -> str:
        return prompt

    def make_brain(self, agent: AgentSpec, default: Brain) -> Brain:
        return default

    async def before_tool(self, call: ToolCall) -> Verdict:
        return Verdict.allow()

    async def after_tool(self, call: ToolCall, result: str) -> str:
        return result

    async def on_message(self, msg: Message) -> Verdict:
        """Before delivery; requests and replies alike."""
        return Verdict.allow()

    async def on_receive(self, msg: Message, text: str) -> str:
        return text

    async def on_activation_end(self, agent: str) -> EndAction | None:
        """The agent finished handling one request (a KAIROS resolution trigger)."""
        return None

    def drain_notices(self, agent: str) -> list[str]:
        """Notices for the agent (e.g. KAIROS abort notices); the runner appends them as
        user messages before the agent's next LLM call."""
        return []

    async def on_final(self, text: str) -> Verdict:
        """The entry agent's answer to the principal (control channel)."""
        return Verdict.allow()

    async def finish(self) -> None:
        """End of run; flush pending decisions into ctx.log."""


REGISTRY: dict[str, type[Defense] | str] = {
    "undefended": Defense,
}


def load_defense(name: str, **options: Any) -> Defense:
    """`undefended` or `<module>:<Class>`."""
    import importlib

    if name in REGISTRY:
        cls = REGISTRY[name]
        if isinstance(cls, str):
            mod, _, attr = cls.partition(":")
            cls = getattr(importlib.import_module(mod), attr)
        return cls(**options)

    module, _, cls = name.partition(":")
    return getattr(importlib.import_module(module), cls)(**options)
