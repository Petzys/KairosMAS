"""The `mascase/0.1` file format.

Four files describe a benchmark scenario. Only the policy files are specific to one defense:

* `scenario.yaml`  -> `Scenario`: the world (environment, tools with defense-neutral security
  annotations, agents with A2A agent cards, who may talk to whom, shared boards).
* `cases.jsonl`    -> `Case`, one per line: the principal's prompt, the attacker, the scoring
  checks and labels used to stratify results.
* `layouts.yaml`   -> `LayoutSet`: partitions of the agents into clusters.
* `policies/<defense>/...`: whatever the defense needs; generated from the annotations here.

A run produces one `RunRecord` per (case, layout, defense, model).

Conventions
-----------
* Security checks return True when the **attacker's goal is met** (AgentDojo convention).
* Check references: `agentdojo:<version>:<suite>:<task_id>` or `python:<module>:<function>`.
* Agent cards are the subset of the A2A `AgentCard` that is known before deployment; `url` and
  transport fields are filled in by the runner.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from masbench import FORMAT

Sensitivity = Literal["public", "low", "medium", "high"]


class _Model(BaseModel):
    model_config = ConfigDict(extra="forbid")


# --------------------------------------------------------------------------- scenario


class ToolSpec(_Model):
    """A tool and its defense-neutral security annotations.

    The annotations are facts about the tool, not about any attack. Defenses derive their
    policies from them (KAIROS revertable/non-revertable actions and taints, Progent privilege
    policies, CaMeL capabilities, SafeFlow tool categories).
    """

    name: str
    description: str = ""
    parameters: dict[str, Any] = Field(default_factory=dict, description="JSON Schema of the arguments")
    effect: Literal["read", "write"] = Field(description="Does the call change state?")
    reversible: bool = Field(description="Can the state change be undone (true for every read)?")
    external: bool = Field(
        description="Is the call visible outside the MAS (sends, posts, invites, bookings)?"
    )
    impact: Literal["none", "low", "high"] = Field(
        description="Harm if called with attacker-chosen arguments: high = money, credentials, "
        "data leaving the MAS, membership changes"
    )
    output_trust: Literal["trusted", "untrusted", "none"] = Field(
        description="untrusted = the output can contain third-party (attacker-controllable) content"
    )
    output_sensitivity: Sensitivity = Field(description="Confidentiality of the output")


class AgentSkill(_Model):
    """A2A `AgentSkill`."""

    id: str
    name: str
    description: str
    tags: list[str] = Field(default_factory=list)
    examples: list[str] = Field(default_factory=list)


class AgentCard(_Model):
    """Subset of the A2A `AgentCard` known before deployment."""

    name: str
    description: str
    version: str = "1.0"
    capabilities: dict[str, bool] = Field(default_factory=lambda: {"streaming": True})
    default_input_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    default_output_modes: list[str] = Field(default_factory=lambda: ["text/plain"])
    skills: list[AgentSkill] = Field(default_factory=list)


class AgentSpec(_Model):
    id: str
    card: AgentCard
    system_prompt: str = Field(
        description="May use {peers} (rendered cards of reachable agents) and {user} placeholders"
    )
    tools: list[str] = Field(default_factory=list)
    entry: bool = Field(default=False, description="Receives the principal's prompt")
    model: str | None = Field(default=None, description="Model slot; None = the run's default")


class Communication(_Model):
    protocol: Literal["a2a"] = "a2a"
    modes: list[Literal["sync", "async"]] = Field(
        default_factory=lambda: ["sync", "async"],
        description="sync = A2A SendMessage (blocking), async = SendStreamingMessage",
    )
    edges: Literal["complete"] | list[tuple[str, str]] = Field(
        default="complete", description="Directed (sender, receiver) pairs that may communicate"
    )
    session: Literal["per_agent"] = Field(
        default="per_agent",
        description="per_agent = each agent keeps one conversation per case; every incoming "
        "message is appended to it",
    )


class BoardSpec(_Model):
    """A shared board (git repo, wiki, ticket system) that agents read and write."""

    id: str
    kind: Literal["git", "kv", "document"]
    description: str = ""
    readers: Literal["all"] | list[str] = "all"
    writers: Literal["all"] | list[str] = "all"
    reversible_writes: bool = True
    external: bool = Field(default=True, description="Visible outside the MAS")


class EnvironmentSpec(_Model):
    kind: Literal["agentdojo", "python"]
    suite: str | None = None
    version: str | None = None
    module: str | None = Field(
        default=None, description="python: '<module>:<factory>' returning an environment adapter"
    )
    initial_state: str | None = Field(default=None, description="python: state file, relative path")
    injection_vectors: dict[str, str] = Field(
        default_factory=dict, description="vector id -> where the slot is (tool that returns it)"
    )

    @model_validator(mode="after")
    def _kind_fields(self) -> EnvironmentSpec:
        if self.kind == "agentdojo" and not (self.suite and self.version):
            raise ValueError("agentdojo environment needs suite and version")
        if self.kind == "python" and not self.module:
            raise ValueError("python environment needs module")
        return self


class Principal(_Model):
    name: str
    description: str = ""


class Scenario(_Model):
    format: Literal["mascase/0.1"] = FORMAT
    id: str
    benchmark: str = Field(description="B1, B2, ...")
    description: str = ""
    principal: Principal
    environment: EnvironmentSpec
    tools: list[ToolSpec]
    agents: list[AgentSpec]
    communication: Communication = Field(default_factory=Communication)
    boards: list[BoardSpec] = Field(default_factory=list)
    provenance: dict[str, Any] = Field(
        default_factory=dict, description="Where the scenario comes from (paper, table, commit)"
    )

    @model_validator(mode="after")
    def _consistent(self) -> Scenario:
        tool_names = {t.name for t in self.tools}
        ids = [a.id for a in self.agents]
        if len(set(ids)) != len(ids):
            raise ValueError("duplicate agent id")
        if sum(a.entry for a in self.agents) != 1:
            raise ValueError("exactly one entry agent required")
        for a in self.agents:
            unknown = set(a.tools) - tool_names
            if unknown:
                raise ValueError(f"agent {a.id}: unknown tools {sorted(unknown)}")
        if self.communication.edges != "complete":
            for s, r in self.communication.edges:
                if s not in ids or r not in ids:
                    raise ValueError(f"edge ({s}, {r}) names an unknown agent")
        return self

    def agent(self, agent_id: str) -> AgentSpec:
        return next(a for a in self.agents if a.id == agent_id)

    def tool(self, name: str) -> ToolSpec:
        return next(t for t in self.tools if t.name == name)

    @property
    def entry_agent(self) -> AgentSpec:
        return next(a for a in self.agents if a.entry)

    def owner(self, tool: str) -> list[str]:
        return [a.id for a in self.agents if tool in a.tools]

    def contacts(self, agent_id: str) -> list[str]:
        if self.communication.edges == "complete":
            return [a.id for a in self.agents if a.id != agent_id]
        return [r for s, r in self.communication.edges if s == agent_id]


# --------------------------------------------------------------------------- cases


class UserTurn(_Model):
    agent: str = Field(description="Agent that receives the prompt (the entry agent)")
    prompt: str


class Injection(_Model):
    """Attacker text placed in an environment slot (attacker position A1)."""

    vector: str
    attack: str | None = Field(
        default=None, description="Template id (e.g. important_instructions); rendered at run time"
    )
    goal: str | None = Field(default=None, description="Goal inserted into the template")
    text: str | None = Field(default=None, description="Literal text; used when attack is None")

    @model_validator(mode="after")
    def _one(self) -> Injection:
        if (self.attack is None) == (self.text is None):
            raise ValueError("give exactly one of attack (+goal) or text")
        return self


class BoardWrite(_Model):
    """Content on a shared board before the run starts (persistence, laundering)."""

    board: str
    object: str = Field(description="File path, issue id, key")
    content: str
    author: str = Field(default="external", description="'external' or the id of an agent")


class CompromisedAgent(_Model):
    """An agent controlled by the attacker (attacker position A3)."""

    agent: str
    system_prompt: str | None = Field(default=None, description="Replaces the agent's prompt")
    instructions: str | None = Field(default=None, description="Appended to the agent's prompt")


class Attacker(_Model):
    position: Literal["A1", "A3"] = Field(description="SoK adversary position: A1 external, A3 member")
    goal: str
    injections: list[Injection] = Field(default_factory=list)
    board_writes: list[BoardWrite] = Field(default_factory=list)
    compromised_agents: list[CompromisedAgent] = Field(default_factory=list)


class Check(_Model):
    ref: str = Field(description="agentdojo:<version>:<suite>:<task_id> | python:<module>:<fn>")
    reads: list[Literal["state", "output", "trace"]] = Field(
        description="What the check inspects: environment state, final answer, tool-call trace"
    )


class Scoring(_Model):
    utility: Check
    security: Check | None = Field(default=None, description="None for benign cases")

    @property
    def effect_level(self) -> bool:
        """True if the security check only reads the environment state (external effects)."""
        return self.security is not None and self.security.reads == ["state"]


class Labels(_Model):
    """Facts about a case, used to stratify results. Never shown to agents or defenses."""

    source: str
    user_task: str | None = None
    injection_task: str | None = None
    sok_path: str | None = None
    attack_class: str | None = None
    workers: list[str] = Field(default_factory=list, description="Agents the ground truth uses")
    comm: Literal["delegation", "fan_out", "worker_to_worker"] | None = Field(
        default=None,
        description="delegation = one worker; fan_out = several workers, no data between them; "
        "worker_to_worker = a later call depends on another agent's earlier read",
    )
    reader_agents: list[str] = Field(default_factory=list, description="Agents that see an injection")
    actor_agents: list[str] = Field(default_factory=list, description="Agents holding the attack tools")
    flow: Literal["same_agent", "cross_agent", "mixed", "text_only"] | None = None


class Budget(_Model):
    max_turns_per_activation: int = 20
    max_messages: int = 40
    wall_clock_s: float = 900.0


class Case(_Model):
    format: Literal["mascase/0.1"] = FORMAT
    id: str
    scenario: str
    kind: Literal["benign", "attack"]
    benign_twin: str | None = None
    user: UserTurn
    attacker: Attacker | None = None
    scoring: Scoring
    labels: Labels
    budget: Budget = Field(default_factory=Budget)

    @model_validator(mode="after")
    def _kind(self) -> Case:
        if (self.kind == "attack") != (self.attacker is not None):
            raise ValueError("attack cases need an attacker, benign cases must not have one")
        if (self.kind == "attack") != (self.scoring.security is not None):
            raise ValueError("attack cases need a security check, benign cases must not have one")
        return self


# --------------------------------------------------------------------------- layouts


class Layout(_Model):
    id: str
    strategy: Literal["single", "func", "crit", "one", "org", "sweep"]
    description: str = ""
    clusters: dict[str, list[str]]


class LayoutSet(_Model):
    format: Literal["mascase/0.1"] = FORMAT
    scenario: str
    agents: list[str]
    layouts: list[Layout]

    @model_validator(mode="after")
    def _partitions(self) -> LayoutSet:
        for lay in self.layouts:
            members = [a for ms in lay.clusters.values() for a in ms]
            if sorted(members) != sorted(self.agents):
                raise ValueError(f"layout {lay.id} is not a partition of the agents")
        return self

    def get(self, layout_id: str) -> Layout:
        return next(lay for lay in self.layouts if lay.id == layout_id)


# --------------------------------------------------------------------------- run records


class ToolCallRecord(_Model):
    agent: str
    seq: int = Field(description="Per-agent event sequence number")
    function: str
    args: dict[str, Any]
    result: str | None = None
    error: str | None = None
    blocked_by_defense: str | None = None
    defense_note: str | None = Field(
        default=None, description="e.g. 'held' (result was a stub) or 'committed after review'")
    t_start: float
    t_end: float


class MessageRecord(_Model):
    id: str
    task_id: str = Field(description="A2A task this message opens or answers")
    kind: Literal["request", "reply"]
    sender: str
    receiver: str
    mode: Literal["sync", "async"]
    sender_seq: int
    text: str
    status: Literal["delivered", "rejected", "failed"] = "delivered"
    reason: str | None = None
    t_sent: float
    t_delivered: float | None = None


class Interval(_Model):
    agent: str
    kind: Literal["llm", "tool", "blocked_a2a", "held", "defense"]
    t_start: float
    t_end: float


class AgentStats(_Model):
    agent: str
    cluster: str | None = None
    activations: int = 0
    llm_calls: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0
    transcript: list[dict[str, Any]] = Field(default_factory=list)


class RunRecord(_Model):
    format: Literal["mascase/0.1"] = FORMAT
    case: str
    scenario: str
    layout: str | None
    defense: str
    model: str
    utility: bool | None = None
    security: bool | None = Field(default=None, description="True = attacker goal met")
    final_output: str | None = None
    error: str | None = None
    agents: list[AgentStats] = Field(default_factory=list)
    tool_calls: list[ToolCallRecord] = Field(default_factory=list)
    messages: list[MessageRecord] = Field(default_factory=list)
    intervals: list[Interval] = Field(default_factory=list)
    defense_log: list[dict[str, Any]] = Field(default_factory=list)
    t_start: float = 0.0
    t_end: float = 0.0


SCHEMAS: dict[str, type[BaseModel]] = {
    "scenario": Scenario,
    "case": Case,
    "layouts": LayoutSet,
    "run_record": RunRecord,
}
