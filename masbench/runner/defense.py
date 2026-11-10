"""The interface between the runner and a defense.

The runner calls these hooks at every point where something crosses an agent boundary. All
traffic hooks are async: a defense may stall a call (hold an effect, wait for an oracle or a
detector) simply by awaiting. The defense never sees the case's attacker, scoring, labels or
the environment's internals, only what a deployed defense would see: the scenario (agents,
tools and their annotations, topology, boards), the principal's prompt and the traffic.
Defense-specific configuration (policies, cluster layouts, thresholds) comes in through the
defense's own options and is derived from the scenario's tool annotations.

Adapters live in `masbench/defenses/<name>/` (one directory per defense, loaded with
`--defense <name>`). Where existing defenses attach:

| Defense | Hooks |
|---|---|
| PI detector | after_tool, on_receive (deny / abort on a flagged tool output or message), ctx.llm |
| Spotlighting | system_prompt, after_tool, on_receive (mark untrusted text) |
| Sandwiching | before_llm (repeat the task after untrusted content) |
| Progent | before_tool (allow / deny / modify args per agent policy), before_llm (hide tools) |
| CaMeL | make_brain (own agent loop on `AgentHandle`: llm, call_tool, send) |
| multi-CaMeL | make_brain, Message.meta (capabilities travel with messages), supports (call tree only) |
| SafeFlow | after_tool / on_receive (taint), Message.meta, before_tool (validate before hard sinks), ctx.llm |
| BlindGuard | on_message + ctx.messages (message graph), ctx.isolate (prune flagged agents) |
| Staging monitors (KAIROS) | before_tool (hold with a stub), on_message, on_receive, on_activation_end, drain_notices, ctx.execute_tool (commit) |

Single-agent defenses are lifted per agent: every hook names the agent, and for a lifted
defense tool outputs and received messages are both untrusted input.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

if TYPE_CHECKING:
    from masbench.runner.brains import Brain, Turn
    from masbench.schema import AgentSpec, MessageRecord, Scenario, ToolCallRecord


@dataclass
class Verdict:
    """What a defense decides about a tool call, a tool output or a message.

    allow    go on unchanged
    deny     the call is not executed / the output or message is withheld; the agent gets an error
    replace  `replacement` stands in: as the tool result (the call is not executed), as the
             output text, or as the message text
    modify   before_tool only: execute with `args` instead of the agent's arguments
    abort    end the whole run now (AgentDojo-style detector behaviour)
    """

    action: Literal["allow", "deny", "replace", "modify", "abort"] = "allow"
    reason: str = ""
    replacement: str | None = None
    args: dict[str, Any] | None = None

    @classmethod
    def allow(cls) -> Verdict:
        return cls()

    @classmethod
    def deny(cls, reason: str) -> Verdict:
        return cls("deny", reason)

    @classmethod
    def replace(cls, replacement: str, reason: str = "") -> Verdict:
        return cls("replace", reason, replacement=replacement)

    @classmethod
    def modify(cls, args: dict[str, Any], reason: str = "") -> Verdict:
        return cls("modify", reason, args=args)

    @classmethod
    def abort(cls, reason: str) -> Verdict:
        return cls("abort", reason)


class DefenseAbort(Exception):
    """Raised by the runner when a hook returns `Verdict.abort`; ends the run."""


@dataclass
class ToolCall:
    agent: str
    seq: int
    function: str
    args: dict[str, Any]


@dataclass
class Message:
    """One A2A message. Requests open a task, replies answer it.

    `meta` belongs to the defense: whatever it puts there in `on_message` (or a defense's
    brain passes to `AgentHandle.send`) travels with the message and is visible in
    `on_receive`. Agents never see it."""

    id: str
    task_id: str
    kind: Literal["request", "reply"]
    sender: str
    receiver: str
    mode: Literal["sync", "async"]
    sender_seq: int
    text: str
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class EndAction:
    """What a defense wants after an agent's activation ended (e.g. a branch was aborted).

    reenter=True: `notice` is appended as a user message and the agent continues (the
    runner allows this once per activation). reenter=False: `notice` is appended to the
    agent's final answer as a correction."""

    notice: str
    reenter: bool = False


class AuxLLM:
    """A model client for the defense's own calls (detector, quarantined LLM, validator,
    oracle). Calls and tokens are metered in `RunRecord.defense_llm`."""

    async def complete(self, messages: list[dict[str, Any]],
                       tools: list[dict[str, Any]] | None = None) -> Turn:
        raise NotImplementedError


@dataclass
class AgentHandle:
    """What a defense's own agent loop (`make_brain`) may do in the name of one agent.

    Everything goes through the normal runner path: hooks, records, the scored trace."""

    id: str
    spec: AgentSpec
    tools: list[dict[str, Any]]  # OpenAI tool schemas: the agent's tools plus the A2A tools
    call_tool: Callable[[str, dict[str, Any]], Awaitable[str]]
    send: Callable[..., Awaitable[str]]  # send(receiver, text, mode="sync", meta=None) -> answer
    llm: Callable[..., Awaitable[Turn]]  # llm(messages, tools=None): the agent's model, metered


@dataclass
class RunContext:
    scenario: Scenario
    user_prompt: str
    log: list[dict[str, Any]] = field(default_factory=list)  # free-form, goes to RunRecord.defense_log
    # Live, read-only views of the run so far (e.g. the message graph for BlindGuard).
    messages: list[MessageRecord] = field(default_factory=list)
    tool_calls: list[ToolCallRecord] = field(default_factory=list)
    # execute_tool(agent, function, args, note) -> ToolOutcome: runs a call the defense
    # held and later committed. Must be called on the event-loop thread; it records the
    # call in the scored trace.
    execute_tool: Callable[[str, str, dict[str, Any], str], Any] | None = None
    # isolate(agent, reason): from now on the runner rejects every message from or to the agent.
    isolate: Callable[[str, str], None] | None = None
    # event(hook, agent, decision, reason="", target=""): add a row to RunRecord.defense_events.
    # The runner records every non-allow verdict itself; use this for flags that block nothing.
    event: Callable[..., None] | None = None
    # llm(model=None) -> AuxLLM. None when the run has no model endpoint (replay).
    llm: Callable[..., AuxLLM] | None = None
    # meter(calls, prompt_tokens, completion_tokens): account for model calls the defense
    # made with a client of its own (a library that brings its own client).
    meter: Callable[[int, int, int], None] | None = None


class Defense:
    """No defense. Subclasses override the hooks they need."""

    name = "none"

    def __init__(self, **options: Any) -> None:
        self.options = options
        self.ctx: RunContext | None = None

    def supports(self, scenario: Scenario) -> str | None:
        """A reason if the defense cannot run this scenario by design (e.g. it needs a call
        tree); such cases are recorded as not applicable instead of being run."""
        return None

    async def setup(self, ctx: RunContext) -> None:
        self.ctx = ctx

    def system_prompt(self, agent: AgentSpec, prompt: str) -> str:
        return prompt

    def make_brain(self, agent: AgentSpec, default: Brain, handle: AgentHandle) -> Brain:
        """Replace the agent's loop. The returned brain's `step` may run a whole plan through
        `handle` and return the final answer as a turn without tool calls."""
        return default

    async def before_llm(self, agent: str, messages: list[dict[str, Any]],
                         tools: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Before each model call of an agent: the conversation and tool schemas it is about
        to see. The returned view is used for this call only; the stored conversation is not
        changed."""
        return messages, tools

    async def before_tool(self, call: ToolCall) -> Verdict:
        return Verdict.allow()

    async def after_tool(self, call: ToolCall, result: str) -> str | Verdict:
        """The tool's output before the agent sees it: a new text, or a verdict."""
        return result

    async def on_message(self, msg: Message) -> Verdict:
        """Before delivery; requests and replies alike."""
        return Verdict.allow()

    async def on_receive(self, msg: Message, text: str) -> str | Verdict:
        """A delivered message before the receiving agent sees it: a new text, or a verdict."""
        return text

    async def on_activation_end(self, agent: str) -> EndAction | None:
        """The agent finished handling one request (e.g. a trigger to resolve held effects)."""
        return None

    def drain_notices(self, agent: str) -> list[str]:
        """Notices for the agent (e.g. that held actions were withheld); the runner appends them as
        user messages before the agent's next LLM call."""
        return []

    async def on_final(self, text: str) -> Verdict:
        """The entry agent's answer to the principal (control channel)."""
        return Verdict.allow()

    async def finish(self) -> None:
        """End of run; flush pending decisions into ctx.log."""


REGISTRY: dict[str, type[Defense]] = {"none": Defense, "undefended": Defense}
ENTRY_POINT_GROUP = "masbench.defenses"
ADAPTERS = "masbench.defenses"


def defense_class(name: str) -> type[Defense]:
    """Resolve, in this order: a name in REGISTRY, an adapter package
    `masbench/defenses/<name>/` (its `DEFENSE` class; `-` in the name reads as `_`; a package
    may also offer named variants in `DEFENSES`, e.g. `kairos-per-agent`), a name
    registered under the `masbench.defenses` entry-point group, or `<module>:<Class>`."""
    import importlib
    from importlib.metadata import entry_points
    from importlib.util import find_spec

    if name in REGISTRY:
        return REGISTRY[name]
    module, sep, cls = name.partition(":")
    if sep:
        return getattr(importlib.import_module(module), cls)
    ident = name.replace("-", "_")
    if ident.isidentifier():
        if find_spec(f"{ADAPTERS}.{ident}") is not None:
            return importlib.import_module(f"{ADAPTERS}.{ident}").DEFENSE
        head = ident.split("_")[0]  # a variant of an adapter: `kairos-per-agent` -> kairos.DEFENSES
        if find_spec(f"{ADAPTERS}.{head}") is not None:
            variants = getattr(importlib.import_module(f"{ADAPTERS}.{head}"), "DEFENSES", {})
            if name in variants:
                return variants[name]
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        if ep.name == name:
            return ep.load()
    raise ValueError(f"unknown defense {name!r}; known: {known_defenses()}, or give <module>:<Class>")


def known_defenses() -> list[str]:
    import pkgutil
    from importlib.metadata import entry_points
    from importlib.util import find_spec

    names = {n for n in REGISTRY if n != "undefended"} | {ep.name for ep in entry_points(group=ENTRY_POINT_GROUP)}
    spec = find_spec(ADAPTERS)
    if spec and spec.submodule_search_locations:
        names |= {m.name.replace("_", "-") for m in pkgutil.iter_modules(spec.submodule_search_locations)
                  if m.ispkg and not m.name.startswith("_")}
    return sorted(names)


def load_defense(name: str, **options: Any) -> Defense:
    return defense_class(name)(**options)
