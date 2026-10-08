"""A speculative branch: the state accumulated while execution is provisional
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from kairos.speculative.stubs import StubRegistry

@dataclass(slots=True)
class Provenance:
    """Where a consequenital value came from - the judges sharpening signal."""
    source: str # tool/file that introduce it ("read_file:bill.txt")
    trusted: bool # was the source a policy trusted source?
    in_user_prompt: bool# derivable from T_0?

    def label(self) -> str:
        if self.in_user_prompt:
            return "user-prompt"
        return "untrusted-content" if not self.trusted else "trusted-source"

@dataclass(slots=True)
class HeldAction: 
    """One deferred outbound effect plus the metadata the judge will need."""
    call_ref: Any # opaque to the core (AgentDojo FunctionCall, etc.)
    tool: str
    args: dict[str, Any]
    provenance: dict[str, Provenance] # per consequential identifier
    reason: str # why it was held (the REVIEW reason)
    embedded: tuple[str, ...] = ()

@dataclass(slots=True)
class TraceEntry:
    tool: str
    decision: str
    args: dict[str, Any] = field(default_factory=dict)
    provenance: dict[str, str] = field(default_factory=dict) # field -> provenance label
    stubbed: bool = False

@dataclass(slots=True)
class Branch:
    branch_id: str
    opened_at: float
    opened_reason: str
    held_calls: list[HeldAction] = field(default_factory=list)
    content_map: dict[str, Any] = field(default_factory=dict) # speculative reads-back
    untrusted_content: list[tuple[str, str]] = field(default_factory=list)  # (source, raw text)
    trace: list[TraceEntry] = field(default_factory=list)
    judge_trace: list = field(default_factory=list)
    prior_resolutions: list = field(default_factory=list)  # earlier resolutions this task (judge context, A1)
    # The event that FORCED this resolution (Trigger 1/4), shown to the judge as
    # context only — it is re-gated separately after resolution, never adjudicated
    # here. {"tool", "args", "provenance" (field->label), "reason"} or None.
    pending_event: dict | None = None
    stubs: StubRegistry = field(default_factory=StubRegistry)
    review_count: int = 0

    def hold(self, action: HeldAction) -> None:
        self.held_calls.append(action)
        self.review_count += 1
        self.trace.append(TraceEntry(
            tool=action.tool,
            decision="REVIEW",
            args=action.args,
            provenance={k: p.label() for k, p in action.provenance.items()},
            stubbed=True
        ))

    def note_allowed(self, tool: str, args: dict[str, Any]) -> None:
        self.trace.append(TraceEntry(tool=tool, decision="ALLOW", args=args))

    def record_untrusted(self, source: str, text: str) -> None:
        self.untrusted_content.append((source, text))

    def has_held(self) -> bool:
        return bool(self.held_calls)