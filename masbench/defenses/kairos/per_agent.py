"""Single-agent KAIROS applied to every agent independently (baseline R03, "per-agent KAIROS").

Each agent gets its own, unmodified KAIROS ReferenceMonitor (policy engine, speculative
machine, LLM oracle) exactly as in the single-agent AgentDojo runs. The monitors do not share
anything: no cross-agent provenance, no joined trust closure or sensitivity set, no causal DAG.

How agents and messages map onto single-agent KAIROS:

* Tool calls go through the same steps as `kairos/adapters/agentdojo/hooks.py`
  (PolicyEnforcer): gate -> synchronous adjudication of a reviewed read -> speculate
  (hold + success stub) -> resolve on a trigger -> re-gate the triggering call once. A
  committed held call is executed by the monitor; its result is admitted.
* An **outgoing A2A message** (request or reply) is a **NET POST** effect at the sender's
  boundary: `Channel.NET`, `POST https://<receiver>.agents.internal/`, body
  `{"to": <receiver>, "message": <text>}`. It is non-revertable outbound, so:
  - Integrity checks the destination (passes if the peer is in the contact book, option
    `peer_contacts`). The message text is payload: not integrity-gated (unless the suite
    policy enables `embedded_identifiers`, as slack does).
  - Confidentiality checks the text against the sender's own sensitivity set and the
    destination's clearance in the contact book.
  - A2A send is blocking for the sender, so a held message cannot be answered with a stub:
    a REVIEW is resolved **at once** (oracle call). With a branch already open, the message
    is a NESTED_REVIEW trigger: the open branch is resolved first, then the message is
    re-gated. Async sends are treated the same way here (no held messages).
* An **incoming message** is inbound content admitted into the receiver's monitor:
  - `peer_trust="untrusted"` (default, R03 as in the notes): untrusted content. It is shown
    to the oracle but adds nothing to the trust closure; identifiers relayed by a peer are
    therefore non-derivable at the receiver and send its effects to REVIEW.
  - `peer_trust="trusted"`: admitted as a trusted source, so relayed identifiers become
    derivable (the laundering side of the dilemma in the case study).
* Every monitor's root of trust T_0 is the principal's prompt (the single trust root).
* The final answer to the principal is not gated (text output is out of scope, as in KAIROS).

Options: judge_model, judge_base_url, judge_api_key_env, peer_trust, peer_contacts
("listed" | "unlisted"), gate_replies, max_held_per_branch, hold_notice.
"""
from __future__ import annotations

import asyncio
import contextvars
import os
import threading
import time
from concurrent.futures import Future
from dataclasses import dataclass, field
from typing import Any

import openai
from agentdojo.functions_runtime import FunctionCall

from kairos.adapters.agentdojo.hooks import _abort_notice_text, _get_refusal_text
from kairos.adapters.agentdojo.translate import call_to_event, result_to_event
from kairos.core.events import Channel, Event, HttpMethod, ToolOp
from kairos.core.extract import ExtractConfig
from kairos.core.store import TokenStore
from kairos.engine.pipeline import PolicyEngine
from kairos.judge.commit import AutoCommitGate
from kairos.judge.oracle import DeterministicJudge, LLMJudge, Verdict, _annotate, is_reasoning_model
from kairos.monitor import ReferenceMonitor
from kairos.policy.parser import parse_policy
from kairos.speculative.effects import EffectKind
from kairos.speculative.machine import SpeculativeMachine
from masbench.defenses.kairos import policies
from masbench.defenses.kairos.layouts import named_layouts
from masbench.runner.defense import Defense, EndAction, Message, RunContext, ToolCall, Verdict as MVerdict

_current_agent: contextvars.ContextVar[str] = contextvars.ContextVar("agent", default="?")


def dest_url(agent: str) -> str:
    return f"https://{agent}.agents.internal"


@dataclass
class _ToolRef:
    agent: str
    function: str


@dataclass
class _MsgRef:
    msg_id: str


@dataclass
class _AgentMon:
    mon: ReferenceMonitor
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    notices: list[str] = field(default_factory=list)
    replaced: set[int] = field(default_factory=set)  # seqs answered with stub / refusal


class _MeteredJudge(LLMJudge):
    """LLMJudge.evaluate without the prompt print, recording every oracle call."""

    def __init__(self, client: Any, model: str, calls: list[dict[str, Any]]) -> None:
        super().__init__(client, model)
        self.calls = calls
        self._lock = threading.Lock()

    def evaluate(self, user_prompt: str, branch: Any) -> Verdict:
        prompt = self._build_prompt(user_prompt, branch)
        kwargs: dict[str, Any] = {} if is_reasoning_model(self.model) else {"temperature": 0.0}
        rec: dict[str, Any] = {"agent": _current_agent.get(), "prompt_chars": len(prompt),
                               "held": [h.tool for h in branch.held_calls]}
        t0 = time.monotonic()
        try:
            resp = self.client.chat.completions.create(
                model=self.model, messages=[{"role": "system", "content": self.system_prompt},
                                            {"role": "user", "content": prompt}], **kwargs)
            raw = resp.choices[0].message.content or ""
        except Exception as e:  # noqa: BLE001 - fail closed, as LLMJudge
            rec.update(error=str(e)[:300], seconds=time.monotonic() - t0)
            with self._lock:
                self.calls.append(rec)
            return Verdict(consistent=False, rationale=f"judge unavailable ({e}); failing closed", raw="")
        verdict = self._parse(raw)
        _annotate(verdict, resp)
        u = getattr(resp, "usage", None)
        rec.update(seconds=time.monotonic() - t0, consistent=verdict.consistent,
                   prompt_tokens=getattr(u, "prompt_tokens", 0) or 0,
                   completion_tokens=getattr(u, "completion_tokens", 0) or 0,
                   rationale=verdict.rationale[:300])
        with self._lock:
            self.calls.append(rec)
        return verdict


def _run_on_loop(loop: asyncio.AbstractEventLoop, fn: Any, *args: Any) -> Any:
    """Run fn(*args) on the event-loop thread from a worker thread and wait for it."""
    fut: Future[Any] = Future()

    def call() -> None:
        try:
            fut.set_result(fn(*args))
        except BaseException as e:  # noqa: BLE001
            fut.set_exception(e)

    loop.call_soon_threadsafe(call)
    return fut.result()


class KairosPerAgent(Defense):
    name = "kairos-per-agent"

    def __init__(self, judge_model: str = "gpt-4.1-2025-04-14", judge_base_url: str | None = None,
                 judge_api_key_env: str = "OPENAI_API_KEY", peer_trust: str = "untrusted",
                 peer_contacts: str = "listed", gate_replies: bool = True,
                 max_held_per_branch: int = 1, hold_notice: str = "success", **options: Any) -> None:
        super().__init__(**options)
        assert peer_trust in ("untrusted", "trusted") and peer_contacts in ("listed", "unlisted")
        self.judge_model, self.judge_base_url, self.judge_api_key_env = judge_model, judge_base_url, judge_api_key_env
        self.peer_trust, self.peer_contacts, self.gate_replies = peer_trust, peer_contacts, gate_replies
        self.max_held, self.hold_notice = max_held_per_branch, hold_notice
        self.name = f"kairos-per-agent-{peer_trust}" + ("" if peer_contacts == "listed" else "-unlisted")
        self.mons: dict[str, _AgentMon] = {}
        self.judge_calls: list[dict[str, Any]] = []
        self.msg_decisions: list[dict[str, Any]] = []

    # -- setup --------------------------------------------------------------------------

    def _policy(self, ctx: RunContext, agent: str) -> dict[str, Any]:
        s = ctx.scenario
        raw, source = policies.suite_policy(s.environment.suite)
        single = next(lay for lay in named_layouts(s) if lay.id == "L-single")
        tmpl = policies.cluster_template(s, raw, source)
        pol = policies.compose([policies.agent_policy(s, agent, raw, source)],
                                 policies.cluster_policy(s, single, agent, tmpl), f"{s.id}:{agent}")
        cb = pol["resources"].setdefault("contact_book", {"lookup_fields": [], "on_miss": "REVIEW",
                                                          "entries": [], "seed": {}})
        if self.peer_contacts == "listed":
            cb["entries"] = list(cb.get("entries", [])) + [
                {"match": dest_url(p), "max_level": "high"} for p in s.contacts(agent)]
        return pol

    async def setup(self, ctx: RunContext) -> None:
        await super().setup(ctx)
        self.loop = asyncio.get_running_loop()
        client = openai.OpenAI(base_url=self.judge_base_url,
                               api_key=os.environ.get(self.judge_api_key_env) or os.environ.get("OPENAI_API_KEY", "EMPTY"),
                               timeout=300, max_retries=4)
        judge = (DeterministicJudge() if self.judge_model == "deterministic"
                 else _MeteredJudge(client, self.judge_model, self.judge_calls))
        for a in ctx.scenario.agents:
            policy = parse_policy(self._policy(ctx, a.id))
            store = TokenStore()
            mon = ReferenceMonitor(
                policy, effector=None, engine=PolicyEngine.build(policy, store, mode="full"), store=store,
                machine=SpeculativeMachine(max_held_per_branch=self.max_held, hold_notice=self.hold_notice),
                judge=judge, commit_gate=AutoCommitGate(), sync_get=True)
            mon.reset_session(ctx.user_prompt)
            self.mons[a.id] = _AgentMon(mon)

    # -- resolution helpers ---------------------------------------------------------------

    def _commit(self, agent: str, ref: Any, args: dict[str, Any]) -> tuple[Any, str | None]:
        """execute_fn of resolve_branch, on the loop thread."""
        if isinstance(ref, _MsgRef):
            return "delivered", None
        out = self.ctx.execute_tool(agent, ref.function, args, "committed after review")
        if out.error is None:
            self.mons[agent].mon.admit_result(
                result_to_event(FunctionCall(function=ref.function, args=args), out.result, 0))
        return out.result, out.error

    async def _resolve(self, agent: str, pending: Any = None) -> Any:
        am = self.mons[agent]
        loop = self.loop

        def execute_fn(ref: Any, args: dict[str, Any]) -> Any:
            return _run_on_loop(loop, self._commit, agent, ref, args)

        _current_agent.set(agent)
        cdec, branch, outcome = await asyncio.to_thread(am.mon.resolve_branch, execute_fn, pending)
        if outcome.aborted:
            am.notices.append(_abort_notice_text(outcome.aborted))
        return outcome

    async def _adjudicate(self, agent: str, view: Any) -> tuple[bool, Any]:
        _current_agent.set(agent)
        return await asyncio.to_thread(self.mons[agent].mon.adjudicate, view)

    # -- tool calls (PolicyEnforcer) -------------------------------------------------------

    async def before_tool(self, call: ToolCall) -> MVerdict:
        am = self.mons[call.agent]
        async with am.lock:
            v = await self._gate_tool(call, am)
        if v.action == "replace":
            am.replaced.add(call.seq)
        return v

    async def _gate_tool(self, call: ToolCall, am: _AgentMon) -> MVerdict:
        mon = am.mon
        tc = FunctionCall(function=call.function, args=call.args, id=f"{call.agent}:{call.seq}")
        ref = _ToolRef(call.agent, call.function)
        for attempt in range(2):
            stage = mon.gate(call_to_event(tc, 0))
            decision = stage.decision.value
            if decision == "DENY":
                return MVerdict.deny(f"Blocked by reference monitor: {stage.reason or stage.produced_by}")
            view = mon.event_view(call_to_event(tc, 0), call_ref=ref, decision=stage)
            if mon.can_adjudicate(decision, view):
                ok, verdict = await self._adjudicate(call.agent, view)
                if not ok:
                    return MVerdict("replace", "refused read", _get_refusal_text(call.function, verdict.rationale))
                return MVerdict.allow()
            eff = mon.speculate(decision, view)
            if eff.kind is EffectKind.EXECUTE:
                return MVerdict.allow()
            if eff.kind is EffectKind.BLOCK:
                return MVerdict.deny(f"Blocked: {eff.reason}")
            if eff.kind is EffectKind.STUB:
                return MVerdict("replace", "held", str(eff.stub_value))
            # RESOLVE: resolve the open branch, then re-gate the triggering call once
            if attempt == 0:
                await self._resolve(call.agent, pending=view)
                continue
        return MVerdict.deny("A prior speculative action was reverted; this action could not be "
                             "completed automatically. If it is part of your original request, "
                             "please re-issue it.")

    async def after_tool(self, call: ToolCall, result: str) -> str:
        am = self.mons[call.agent]
        if call.seq in am.replaced or result.startswith("Error:"):
            return result
        async with am.lock:
            tc = FunctionCall(function=call.function, args=call.args)
            am.mon.admit_result(result_to_event(tc, result, 0))
        return result

    # -- messages ---------------------------------------------------------------------------

    def _msg_event(self, msg: Message) -> Event:
        return Event(time.monotonic(), Channel.NET, HttpMethod.POST.value, "a2a",
                     dest_url(msg.receiver), {"to": msg.receiver, "message": msg.text},
                     {"function": "a2a_send" if msg.kind == "request" else "a2a_reply",
                      "message_id": msg.id})

    async def on_message(self, msg: Message) -> MVerdict:
        if msg.kind == "reply" and not self.gate_replies:
            return MVerdict.allow()
        am = self.mons[msg.sender]
        async with am.lock:
            v, rec = await self._gate_message(msg, am)
        rec.update(sender=msg.sender, receiver=msg.receiver, kind=msg.kind, verdict=v.action)
        self.msg_decisions.append(rec)
        return v

    async def _gate_message(self, msg: Message, am: _AgentMon) -> tuple[MVerdict, dict[str, Any]]:
        mon = am.mon
        rec: dict[str, Any] = {"resolved_open_branch": False, "reviewed": False}
        for attempt in range(2):
            ev = self._msg_event(msg)
            stage = mon.gate(ev)
            decision = stage.decision.value
            rec.setdefault("decision", f"{decision}:{stage.produced_by}")
            if decision == "DENY":
                return MVerdict.deny(stage.reason or stage.produced_by), rec
            view = mon.event_view(ev, call_ref=_MsgRef(msg.id), decision=stage)
            eff = mon.speculate(decision, view)
            if eff.kind is EffectKind.EXECUTE:
                return MVerdict.allow(), rec
            if eff.kind is EffectKind.BLOCK:
                return MVerdict.deny(eff.reason), rec
            if eff.kind is EffectKind.STUB:
                # held message: A2A send is blocking -> resolve now (oracle call)
                rec["reviewed"] = True
                outcome = await self._resolve(msg.sender)
                if any(isinstance(h.call_ref, _MsgRef) for h in outcome.committed):
                    return MVerdict.allow(), rec
                am.notices.clear()  # the agent learns it from the send's error result
                return MVerdict.deny("withheld after security review: " + stage.reason), rec
            if attempt == 0:  # RESOLVE: an open branch must commit before the message leaves
                rec["resolved_open_branch"] = True
                await self._resolve(msg.sender, pending=view)
        return MVerdict.deny("could not be sent after a reverted action; re-issue it if needed"), rec

    async def on_receive(self, msg: Message, text: str) -> str:
        if msg.sender == "user":
            return text
        am = self.mons[msg.receiver]
        async with am.lock:
            source = f"a2a:{msg.sender}"
            if self.peer_trust == "trusted":
                am.mon.store.admit(text, source, trusted=True, level=None, branch_origin=None,
                                   extract_cfg=ExtractConfig())
                am.mon.session.record_result(source, text)
            else:
                am.mon.admit_result(Event(time.monotonic(), Channel.TOOL, ToolOp.RESULT.value, "a2a",
                                          source, text, {}))
        return text

    # -- terminal / notices -----------------------------------------------------------------

    async def on_activation_end(self, agent: str) -> EndAction | None:
        am = self.mons[agent]
        async with am.lock:
            if am.mon.machine.on_terminal() is None:
                return None
            outcome = await self._resolve(agent)
        if not outcome.aborted:
            return None
        notice = am.notices.pop() if am.notices else _abort_notice_text(outcome.aborted)
        if am.mon.consume_terminal_retry():
            return EndAction(notice, reenter=True)
        names = "; ".join(h.tool for h in outcome.aborted)
        return EndAction(f"Correction: after a security review, the following action(s) were WITHHELD "
                         f"and did NOT execute: {names}.", reenter=False)

    def drain_notices(self, agent: str) -> list[str]:
        am = self.mons.get(agent)
        if not am or not am.notices:
            return []
        out, am.notices = am.notices, []
        return out

    async def finish(self) -> None:
        for agent, am in self.mons.items():
            s = am.mon.session.summary()
            s.pop("trace", None)
            for r in s.get("resolutions", []):
                r.pop("judge_raw", None)
            self.ctx.log.append({"agent": agent, "monitor": s})
        self.ctx.log.append({"judge_calls": self.judge_calls})
        self.ctx.log.append({"message_decisions": self.msg_decisions})
