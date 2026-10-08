"""ReferenceMonitor — wires the core together
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, NamedTuple
from collections import Counter

from kairos.adapters.base import Effector
from kairos.core.events import Channel, Event, FsOp, ToolOp
from kairos.core.extract import ExtractConfig
from kairos.core.flowgraph import FlowGraph
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.decision import Decision, StageResult
from kairos.engine.pipeline import PolicyEngine
from kairos.policy.schema import Policy, TaintDef, TrustedSource
from kairos.engine.action_class import ActionClass, classify
from kairos.speculative.branch import Branch, HeldAction, Provenance, TraceEntry
from kairos.speculative.effects import Effect
from kairos.speculative.machine import EventView, SpeculativeMachine
from kairos.judge.oracle import judge_call_record
from kairos.core.matching import Strategy

# --- review handling (the Phase-1/Phase-2 seam) -----------------------------
class ReviewHandler(Protocol):
    def handle(self, event: Event, result: StageResult, effector: Effector) -> Any:
        """Resolve a REVIEW verdict. Phase 1: block. Phase 2: open a branch."""
        ...

class BlockingReviewHandler:
    """Phase-1 defailt: a REVIEW is trated as a block)."""
    def handle(self, event: Event, result: StageResult, effector: Effector) -> Any:
        return effector.block(event)

class DecisionRecord(NamedTuple):
    object: str
    decision: Decision
    produced_by: str
    reason: str
    identifiers: dict

# --- per-session telemetry (feeds the evaluation breakdown) -----------------
@dataclass(slots=True)
class SessionResult:
    decisions: list[DecisionRecord] = field(default_factory=list)
    untrusted_content: list[tuple[str, str]] = field(default_factory=list)
    resolutions: list[dict] = field(default_factory=list)
    calls: list[dict] = field(default_factory=list) # full per-call trace for the judge: tool, decision, args, result

    def record(self, event: Event, r: StageResult) -> None:
        self.decisions.append(DecisionRecord(event.object, r.decision, r.produced_by, r.reason, r.identifiers))

    def record_untrusted(self, source: str, text: str) -> None:
        self.untrusted_content.append((source, text))

    def record_call(self, event, r) -> None:
        self.decisions.append(DecisionRecord(event.object, r.decision, r.produced_by, r.reason, r.identifiers))
        args = dict(event.content) if isinstance(event.content, dict) else {}
        # NET-routed tool calls (get_webpage) carry object=URL but their RESULT event
        # arrives under the function name — key the call by the function so
        # record_result can attach the fetched content and the judge trace shows it.
        tool = event.metadata.get("function") or event.object
        self.calls.append({"tool": tool, "decision": r.decision.value,
                           "args": args, "result": None})

    def record_result(self, tool: str, result: str) -> None:
        # attach to the most recent call of this tool awaiting a result
        for c in reversed(self.calls):
            if c["tool"] == tool and c["result"] is None:
                c["result"] = result
                break

    @staticmethod
    def _action_ids(tool: str, args: dict, provenance: dict | None) -> dict:
        """The consequential identifiers of an action, for re-issue matching. Falls
        back to all args when no provenance-tracked identifier exists."""
        ids = {k: str(args.get(k)) for k in (provenance or {})}
        return ids or {k: str(v) for k, v in (args or {}).items()}

    def record_resolution(self, branch, verdict, cdec, outcome, commit_errors=None) -> None:
        self.resolutions.append({
            "branch": branch.branch_id,
            "trigger": branch.opened_reason,
            "committed": [h.tool for h in outcome.committed],
            "aborted": [h.tool for h in outcome.aborted],
            # Identifiers of the withheld actions, so a later judgement can tell a
            # genuine RE-ISSUE from a merely same-named action (see oracle).
            "aborted_actions": [
                {"tool": h.tool, "ids": self._action_ids(h.tool, h.args, h.provenance)}
                for h in outcome.aborted
            ],
            "commit": cdec.commit,
            "decided_by": cdec.source,
            "judge_consistent": verdict.consistent,
            "rationale": verdict.rationale,
            "flagged": verdict.flagged,
            "commit_errors": commit_errors or [],
            **judge_call_record(verdict),
        })

    def counts_by_layer(self) -> dict[str, int]:
        out: dict[str, int] = {}
        for d in self.decisions:
            out[d.produced_by] = out.get(d.produced_by, 0) + 1
        return out

    def summary(self) -> dict:
        """Per-task breakdown for logging: counts by decision:layer, the blocked
        actions with reasons, and the full ordered trace."""
        by_layer: dict[str, int] = {}
        for d in self.decisions:
            k = f"{d.decision.value}:{d.produced_by}"
            by_layer[k] = by_layer.get(k, 0) + 1
        trace = [{"tool": d.object, "decision": d.decision.value, "by": d.produced_by,
                  "reason": d.reason, "ids": d.identifiers} for d in self.decisions]
        blocked = [t for t in trace if t["decision"] != "ALLOW"]
        out = {"n_decisions": len(self.decisions), "by_layer": by_layer,
                "n_blocked": len(blocked), "blocked": blocked, "trace": trace}
        if self.resolutions:
            out["resolutions"] = self.resolutions
        return out

# --- file-trust ledger (§4.1 persistence defense) ---------------------------
class FileTrustLedger:
    """Per-path trust state. A write of UNTRUSTED content marks the path untrusted;
    a later read of an untrusted path must not admit its content to the closure."""
    def __init__(self) -> None:
        self._untrusted: set[str] = set()

    def mark(self, path: str, *, trusted: bool) -> None:
        if trusted:
            self._untrusted.discard(path)
        else:
            self._untrusted.add(path)

    def is_trusted(self, path: str) -> bool:
        return path not in self._untrusted


class ReferenceMonitor:
    def __init__(
        self,
        policy: Policy,
        effector: Effector,
        engine: PolicyEngine,
        store: TokenStore,
        *,
        review_handler: ReviewHandler | None = None,
        machine=None,
        judge=None,
        commit_gate=None,
        sync_get: bool = True,
    ) -> None:
        self.policy = policy
        self.effector = effector
        self.engine = engine
        self.store = store
        self.review_handler: ReviewHandler = review_handler or BlockingReviewHandler()
        self.flow = FlowGraph()
        self.files = FileTrustLedger()
        self.session = SessionResult()
        self.attribution: Counter[str] = Counter()   # persistent across tasks — EVAL instrument
        # index policy declarations by source for O(1) admission lookup
        self._trusted_by_source: dict[str, TrustedSource] = {
            ts.source: ts for ts in policy.resources.trusted_sources
        }
        self._taints_by_source: dict[str, TaintDef] = {
            t.source: t for t in policy.resources.taints
        }
        self.machine = machine # speculativeMachine or None
        self.judge = judge
        self.commit_gate = commit_gate
        # A REVIEWed read (NET_GET) is adjudicated SYNCHRONOUSLY rather than held:
        # a read changes no state, so there is nothing to be atomic about and
        # nothing to roll back — the only requirement is that the decision precede
        # the request. Holding it would only delay the content past the point the
        # agent needs it. Set False to fall back to hold-and-stub (ablation).
        self.sync_get = sync_get
        # Bounded terminal re-entry budget (A1): on a terminal-turn abort we may
        # notify the agent and let it retry legitimate actions ONCE per task, so a
        # falsely-aborted action is recoverable without risking an abort/retry spin.
        self.terminal_retry_budget = 1
        self._terminal_retries_left = self.terminal_retry_budget

    @property
    def speculative(self) -> bool:
        return self.machine is not None

    @property
    def hold_notice(self) -> str:
        """'success' (v1 stub) or 'honest' (v2 on-hold notice); see SpeculativeMachine."""
        return getattr(self.machine, "hold_notice", "success") if self.machine is not None else "success"

    def consume_terminal_retry(self) -> bool:
        """True (and decrements) if a terminal re-entry is still allowed this task."""
        if self._terminal_retries_left > 0:
            self._terminal_retries_left -= 1
            return True
        return False

    # --- build the machine's view of a gated event ------------------------
    def event_view(self, event, call_ref, decision) -> EventView:
        ac = classify(event, self.policy)
        is_outbound = ac in (ActionClass.NET_STATE_CHANGE, ActionClass.NET_GET)
        is_revertable = ac is not ActionClass.NET_STATE_CHANGE
        cb = getattr(self.engine, "contact_book", None)
        lookup = set(cb.lookup_fields) if cb else set()
        args = dict(event.content) if isinstance(event.content, dict) else {}
        # List-valued identifier fields (workspace recipients/cc/...) get per-element
        # provenance aggregated to the field's WORST case — str(list) would never be
        # derivable and would mislabel user-named recipients as untrusted to the judge.
        consequential: dict[str, str] = {}
        provenance: dict[str, Provenance] = {}
        for k, v in args.items():
            if k not in lookup:
                continue
            elems = [str(e) for e in (v if isinstance(v, (list, tuple)) else [v])]
            if not elems:
                continue
            consequential[k] = ", ".join(elems)
            provs = [self._provenance(e) for e in elems]
            provenance[k] = Provenance(
                source=next((p.source for p in provs
                             if not p.trusted and not p.in_user_prompt), provs[0].source),
                trusted=all(p.trusted for p in provs),
                in_user_prompt=all(p.in_user_prompt for p in provs),
            )
        return EventView(
            # NET-routed tools carry the URL in event.object; the machine's view
            # (stub texts, abort notices, judge prompts) should name the TOOL —
            # same keying as session.calls. Commit dispatch uses call_ref.function.
            tool=event.metadata.get("function") or event.object,
            args=args,
            is_outbound=is_outbound,
            is_revertable=is_revertable,
            consequential=consequential,
            provenance=provenance,
            call_ref=call_ref,
            reason=decision.reason or decision.produced_by
        )

    def _provenance(self, value: str) -> Provenance:
        in_prompt = self.store.in_user_prompt(value)
        trusted = self.store.derivable(value, Strategy.NORMALIZED)
        # `source` names the ORIGINATING source, not the category -- the category
        # is already carried by `trusted`/`in_user_prompt` and rendered by
        # label(). Naming the source is what lets a delegation be CHECKED rather
        # than inferred: the judge otherwise has to re-derive "this recipient came
        # from that read" by matching the value against trace text the attacker
        # wrote, so a value planted in a SECOND untrusted result can be credited
        # to the first. Falls back to the category when nothing claims the value
        # (composed values, or a source admitted before the store saw it).
        if in_prompt:
            source = "user-prompt"
        else:
            claims = self.store.sources_of(value)
            source = ", ".join(claims) if claims else (
                "trusted-source" if trusted else "untrusted-content")
        return Provenance(source=source, trusted=trusted, in_user_prompt=in_prompt)

    def speculate(self, decision_value: str, ev: EventView) -> Effect:
        return self.machine.on_gate(decision_value, ev)

    # --- synchronous adjudication of a reviewed read (no hold) -------------
    def can_adjudicate(self, decision_value: str, ev: EventView) -> bool:
        """Is this a REVIEWed read we can decide inline? (revertable outbound =
        NET_GET, judge available, no branch open). With a branch open the machine's
        NESTED_REVIEW ordering must win: the read may inform whether the held
        non-revertable calls should commit."""
        from kairos.speculative.effects import State
        return (self.sync_get
                and decision_value == "REVIEW"
                and ev.is_outbound and ev.is_revertable
                and self.judge is not None
                and self.machine is not None
                and self.machine.state is State.LINEAR)

    def adjudicate(self, ev: EventView):
        """Judge a single reviewed read NOW and return (execute?, verdict).

        Unlike resolve_branch this opens no branch, holds nothing and stubs nothing
        — a GET has no effect to defer. The judge sees the same evidence it would at
        a resolution (trace, prior resolutions, untrusted content), so a fetch the
        user's task genuinely needs is approved and executed inline (utility intact)
        while an injected drive-by fetch is refused before the request leaves.

        NOTE: DeterministicJudge is structural (untrusted-origin identifier not in
        the prompt → inconsistent) and will refuse benign content-derived URLs too;
        synchronous GET adjudication is only useful with a semantic (LLM) judge."""
        branch = Branch(branch_id="sync-get", opened_at=0.0, opened_reason=ev.reason)
        branch.held_calls.append(HeldAction(call_ref=ev.call_ref, tool=ev.tool, args=ev.args,
                                            provenance=ev.provenance, reason=ev.reason))
        branch.untrusted_content = list(self.session.untrusted_content)
        branch.judge_trace = [
            c for c in self.session.calls
            if c["decision"] == "ALLOW" and c.get("result") is not None
        ]
        branch.prior_resolutions = list(self.session.resolutions)

        verdict = self.judge.evaluate(self.store.user_prompt(), branch)
        cdec = self.commit_gate.decide(branch, verdict)
        ok = all(cdec.mask) if cdec.mask else bool(cdec.commit)

        self.session.resolutions.append({
            "branch": branch.branch_id,
            "trigger": ev.reason,
            "committed": [ev.tool] if ok else [],
            "aborted": [] if ok else [ev.tool],
            "aborted_actions": [] if ok else [
                {"tool": ev.tool, "ids": SessionResult._action_ids(ev.tool, ev.args, ev.provenance)}
            ],
            "commit": ok,
            "decided_by": cdec.source,
            "judge_consistent": verdict.consistent,
            "rationale": verdict.rationale,
            "flagged": verdict.flagged,
            "commit_errors": [],
            "sync_get": True,
            **judge_call_record(verdict),
        })
        self.attribution[f"{'EXECUTE' if ok else 'REFUSE'}:sync_get"] += 1
        return ok, verdict

    # --- resolution: judge -> commit gate -> execute committed ------------
    def resolve_branch(self, execute_fn, pending: EventView | None = None):
        """execute_fn(call_ref, real_args) dispatches a committed held call and
        returns AgentDojo's (result, error) tuple. Returns (CommitDecision, branch,
        outcome) so an in-turn caller can also handle the triggering call and notify
        the agent about aborted actions. Used by both the enforcer (in-turn) and the
        terminal resolver.

        `pending` is the event that forced this resolution (in-turn triggers only;
        terminal resolution has none). The judge sees it as context — a multi-step
        sequence is then visible at the first resolution — but never adjudicates
        it: the caller re-gates it against the post-resolution state."""
        branch = self.machine.begin_resolution()
        if pending is not None:
            branch.pending_event = {
                "tool": pending.tool,
                "args": dict(pending.args),
                "provenance": {k: p.label() for k, p in pending.provenance.items()},
                "origins": {k: p.source for k, p in pending.provenance.items()},
                "reason": pending.reason,
            }
        branch.untrusted_content = list(self.session.untrusted_content) # for the judge
        # the judge needs the WHOLE trace (linear reads before the branch), not
        # just branch-local events. Prepend the session trace.
        # branch.judge_trace = list(self.session.calls)
        branch.judge_trace = [
            c for c in self.session.calls
            if c["decision"] == "ALLOW" and c.get("result") is not None
        ]
        # Earlier resolutions this task (A1): a re-issued action after an abort
        # notice must be judged WITH that context, not identically re-refused.
        branch.prior_resolutions = list(self.session.resolutions)

        verdict = self.judge.evaluate(self.store.user_prompt(), branch)
        cdec = self.commit_gate.decide(branch, verdict)
        n = len(branch.held_calls)
        if cdec.mask is not None and len(cdec.mask) == n:
            mask = list(cdec.mask)
        else:
            mask = bool(cdec.commit)
        outcome = self.machine.resolve(mask)
        # A committed held call reported success to the agent when it was held; if
        # it now fails on real dispatch, that stub was a lie — surface it, don't
        # swallow it (A5). Recorded in the resolution and printed for the run log.
        commit_errors: list[tuple[str, str]] = []
        if outcome.committed:
            for held in outcome.committed:
                res, err = execute_fn(held.call_ref, branch.stubs.substitute_real(held.args))
                outcome.dispatched.append((held, res, err))
                if err is not None:
                    commit_errors.append((held.tool, str(err)))
                    print(f"[Spec] WARNING committed call failed after success stub: "
                          f"{held.tool} → {err}")
        self.session.record_resolution(branch, verdict, cdec, outcome, commit_errors)
        if outcome.committed and outcome.aborted:
            tag = "PARTIAL"
        elif outcome.committed:
            tag = "COMMIT"
        else:
            tag = "ABORT"
        self.attribution[f"{tag}:{branch.opened_reason[:24]}"] += 1
        return cdec, branch, outcome

    # --- lifecycle ---------------------------------------------------------
    def begin_session(self, user_prompt: str) -> None:
        """Seed the root of trust: T_0 = extract(user_prompt) (§4.5)."""
        self.store.seed(user_prompt)

    def end_session(self) -> SessionResult:
        return self.session

    def gate(self, event: Event) -> Decision:
        """Decision-only gate for an OUTBOUND event. Records flow + telemetry +
        attribution, returns the verdict. The caller applies the effect (in
        AgentDojo the adapter executes via its runtime)."""
        self.flow.record(event)
        result = self.engine.evaluate(event)
        # record_call appends to BOTH decisions and calls; calling record() as well
        # double-counted every decision in summary()/counts_by_layer (attribution is
        # counted once below and stays correct).
        self.session.record_call(event, result)
        self.attribution[f"{result.decision.value}:{result.produced_by}"] += 1
        return result

    def admit_result(self, event: Event) -> None:
        """Inbound admission: a tool_result / read. No gatting."""
        self.flow.record(event)
        self._admit(event)
        # remember the result text per tool call so the judge trace can show it
        self.session.record_result(event.object, str(event.content))
        if self.speculative and event.object not in self._trusted_by_source:
            self.session.record_untrusted(event.object, str(event.content)[:2000])

    def reset_session(self, user_prompt: str) -> None:
        """Per-task reset for benchmark reuse. Engine keeps its store ref, so
        clearing the store in place suffices — no engine rebuild (the prompt lives
        in the store). attribution is NOT cleared (it aggregates across the suite)."""
        self.store.clear()
        self.session = SessionResult()
        self.flow = FlowGraph()
        self.files = FileTrustLedger()
        self._terminal_retries_left = self.terminal_retry_budget
        if self.machine is not None:
            m = self.machine
            self.machine = SpeculativeMachine(
                max_branches=m.max_branches, max_stall_seconds=m.max_stall_seconds,
                loop_threshold=m.loop_threshold, max_held_per_branch=m.max_held_per_branch,
                hold_notice=getattr(m, "hold_notice", "success"))
        self.begin_session(user_prompt)

    # --- the entry point ---------------------------------------------------
    def process_event(self, event: Event) -> Any:
        """Evaluate one event end to end and return what the Effector applied.

        INBOUND results/reads -> admit tokens (no gating; reads send nothing out).
        OUTBOUND calls/requests -> gate via the engine, apply ALLOW/DENY/REVIEW.
        """
        if self.effector is None:
            raise RuntimeError("process_event needs an effector; AgentDojo uses gate/admit_result")
        if self._is_inbound(event):
            self.admit_result(event)
            return self.effector.forward(event)
        result = self.gate(event)
        if result.decision is Decision.ALLOW:
            out = self.effector.forward(event)
        elif result.decision is Decision.DENY:
            out = self.effector.block(event)
        else:
            out = self.review_handler.handle(event, result, self.effector)
        if event.channel is Channel.FS and event.operation == FsOp.WRITE.value and result.decision is Decision.ALLOW:
            self.files.mark(event.object, trusted=self._content_is_trusted(event))
        return out

    # --- classification of direction --------------------------------------
    @staticmethod
    def _is_inbound(event: Event) -> bool:
        """Inbound = brings content IN (result or a read). Outbound = sends out"""
        if event.channel is Channel.TOOL:
            return event.operation == ToolOp.RESULT.value
        if event.channel is Channel.FS:
            return event.operation in (FsOp.OPEN.value, FsOp.READ.value)
        return False # all NET requests are outbound (the GET body returns separately)

    # --- admission (§4.3, §4.5) --------------------------------------------
    def _admit(self, event: Event) -> None:
        """Admit tokens from a trusted and/or sensitive inbound result.

        Source is the tool name (TOOL) or the file path (FS read). A read of a path
        the ledger marks untrusted admits NOTHING (persistence defense, §4.1)."""
        source = event.object
        if event.channel is Channel.FS and not self.files.is_trusted(source):
            return # agent-writte-untrusted file -> its content never re-enters the closure

        trusted_decl = self._trusted_by_source.get(source)
        taint_decl = self._taints_by_source.get(source)
        if trusted_decl is None and taint_decl is None:
            return # neither trusted nor sensitive -> content stay out of both sets

        trusted = trusted_decl is not None
        level: Level | None = taint_decl.level if taint_decl is not None else None
        # per-source extract config: taint's extract wins, else trusted's, else default
        extract_cfg = (
            (taint_decl.extract if taint_decl and taint_decl.extract else None)
            or (trusted_decl.extract if trusted_decl and trusted_decl.extract else None)
            or ExtractConfig()
        )
        self.store.admit(event.content, source, trusted=trusted, level=level, 
                        branch_origin=None, extract_cfg=extract_cfg)

    def _content_is_trusted(self, event: Event) -> bool:
        """Is the written content derivable from the closure? (decides ledger mark)
        Conservative: any non-derivable token in the content -> untrusted write."""
        # MVP: a write is trusted iff its whole content is derivable under normalized
        from kairos.core.matching import Strategy
        text = event.content if isinstance(event.content, str) else str(event.content)
        return self.store.derivable(text, Strategy.NORMALIZED)

    