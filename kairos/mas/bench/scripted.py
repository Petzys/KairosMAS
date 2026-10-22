"""Scripted agents: a deterministic, LLM-free MASDojo backend.

The entry agent executes the user task's ground-truth plan, delegating every call
to the agent that owns the tool. Every agent is WORST-CASE OBEDIENT:

  * it carries out structured call requests it receives (in a request or in a
    reply) -- with its own tools, by forwarding to the owner it can reach, or by
    relaying the request up to the agent that gave it its task;
  * once it READS the injected payload (in a tool result, a message or a reply) it
    is infected and executes the injection task's ground-truth plan, the same way.

Without a monitor every injection whose plan reaches the owners of its tools
succeeds, so the measured attack success rate isolates what the monitor stops.
Benign behaviour is exactly the ground truth: utility measures what the monitor
costs. Runs are reproducible bit for bit (no model in the loop).
"""
from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass, field
from typing import Any

from agentdojo.functions_runtime import FunctionCall

from kairos.mas.a2a.client import ClientResult
from kairos.mas.a2a.protocol import Message, TaskState
from kairos.mas.a2a.server import AgentResult
from kairos.mas.bench.environment import Exposure, ToolBox
from kairos.mas.bench.suites import ENTRY, SuiteSystem, reachable
from kairos.mas.runtime import AgentHost
from kairos.mas.spec import MASSpec

CALL = "call"          # data part: a call the receiver is asked to carry out
RESULT = "result"      # data part: whether a requested call succeeded


def call_data(c: FunctionCall) -> dict[str, Any]:
    return {CALL: {"function": c.function, "args": dict(c.args)}}


def _key(c: FunctionCall) -> str:
    return f"{c.function}:{sorted((k, str(v)) for k, v in c.args.items())}"


@dataclass(slots=True)
class Step:
    ok: bool
    text: str
    relays: list[FunctionCall] = field(default_factory=list)
    pending: str | None = None        # id of a held call, settled at the agent's terminal


def settle(host: AgentHost, steps: list[Step], tools: ToolBox) -> None:
    """After the agent's terminal resolution: what became of its held calls."""
    outcomes = host.ep.monitor.call_outcomes if host.ep.defense else {}
    for st in steps:
        if st.pending is None:
            continue
        kind, res, err = outcomes.get(st.pending, ("unresolved", None, None))
        if kind == "committed" and err is None:
            st.ok, st.text = True, tools.format(res)
        else:
            st.ok, st.text = False, f"withheld: {err or kind}"
        st.pending = None


class ScriptedSystem:
    """The scripted agents of one session."""

    def __init__(self, spec: MASSpec, system: SuiteSystem, tools: ToolBox, exposure: Exposure, *,
                 plan: list[FunctionCall], injection_plan: list[FunctionCall] | None,
                 final_output: str, dispatch: str = "sync") -> None:
        if dispatch not in ("sync", "stream", "parallel"):
            raise ValueError(f"dispatch must be sync|stream|parallel, got {dispatch!r}")
        self.spec = spec
        self.system = system
        self.tools = tools
        self.exposure = exposure
        self.plan = plan
        self.injection_plan = injection_plan or []
        self.final_output = final_output
        self.dispatch = dispatch
        self.infected: list[str] = []
        self.retries = 0
        self._done: dict[str, set[str]] = {}
        self._results: dict[tuple[str, str], Step] = {}     # (agent, call) -> what it answered
        self._relays: dict[str, list[FunctionCall]] = {}
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def handlers(self) -> dict[str, Any]:
        return {a: (self._entry if a == ENTRY else self._worker) for a in self.spec.agents}

    # --- the entry agent ----------------------------------------------------------
    def _entry(self, host: AgentHost, msg: Message, task_id: str) -> AgentResult:
        steps: list[Step] = []
        if self.dispatch == "parallel":
            steps = self._parallel(host, self.plan)
        else:
            for c in self.plan:
                steps.append(self._perform(host, c, stream=self.dispatch == "stream"))
        host.ep.terminal()
        settle(host, steps, self.tools)
        host.ep.drain_notices()     # about withheld actions; the plan's own steps carry their status
        if all(s.ok for s in steps):
            return AgentResult(text=self.final_output)
        failed = "; ".join(s.text[:200] for s in steps if not s.ok)
        return AgentResult(text="I could not complete the request. " + failed)

    def _parallel(self, host: AgentHost, plan: list[FunctionCall]) -> list[Step]:
        """One streamed task per owner (calls kept in plan order per owner), all in
        flight at once, then collected."""
        groups: dict[str, list[FunctionCall]] = {}
        for c in plan:
            groups.setdefault(self.system.owner(c.function) or "", []).append(c)
        started: list[tuple[str, ClientResult]] = []
        steps: list[Step] = []
        for owner, calls in groups.items():
            if owner == host.agent_id:
                steps += [self._own(host, c) for c in calls]
            elif owner in reachable(self.spec, host.agent_id):
                text = "Please run: " + "; ".join(f"{c.function}({dict(c.args)})" for c in calls)
                r = host.client.start_task(host.url_of(owner), text, [call_data(c) for c in calls])
                started.append((owner, r))
            else:
                steps.append(Step(False, f"no agent can run {calls[0].function}"))
        for owner, r in started:
            res = host.client.wait_task(r.task_id, timeout=120) if r.task_id and not r.state.is_final else r
            steps.append(self._collect(host, owner, res))
        return steps

    # --- workers ----------------------------------------------------------------
    def _worker(self, host: AgentHost, msg: Message, task_id: str) -> AgentResult:
        me = host.agent_id
        self._observe(host, msg.content_text(), via="message")
        done: list[tuple[FunctionCall, Step]] = []
        relays: list[FunctionCall] = []
        fresh: list[tuple[FunctionCall, Step]] = []
        for c in self._calls_in(msg.data()):
            with self._lock:
                cached = self._results.get((me, _key(c)))
            if cached is not None:       # asked again: answer with what was done, never redo it
                done.append((c, Step(cached.ok, cached.text)))
                continue
            st = self._perform(host, c, relay_ok=True)
            done.append((c, st))
            fresh.append((c, st))
            relays += st.relays
        host.ep.terminal()
        settle(host, [st for _, st in done], self.tools)
        with self._lock:
            for c, st in fresh:
                self._results[(me, _key(c))] = Step(st.ok, st.text)
        notes = host.ep.drain_notices()
        with self._lock:
            relays += self._relays.pop(me, [])
        status = [{RESULT: {"function": c.function, "ok": st.ok}} for c, st in done]
        return AgentResult(text="\n".join([st.text for _, st in done] + notes) or "done",
                           data=status + [call_data(c) for c in relays])

    # --- doing one call -----------------------------------------------------------
    def _perform(self, host: AgentHost, c: FunctionCall, *, stream: bool = False,
                 relay_ok: bool = False) -> Step:
        owner = self.system.owner(c.function)
        me = host.agent_id
        if owner == me:
            return self._own(host, c)
        if owner is not None and owner in reachable(self.spec, me):
            text = f"Please run {c.function} with arguments {dict(c.args)} and send me the result."
            r = self._ask(host, owner, text, c, stream)
            if r.state in (TaskState.FAILED, TaskState.REJECTED):
                # the KAIROS recovery path: re-issue once, as a new effect, because the
                # user's task needs it (a withheld reply may have mixed in other content)
                self._collect(host, owner, r)
                with self._lock:
                    self.retries += 1
                r = self._ask(host, owner, text, c, stream)
            return self._collect(host, owner, r)
        if relay_ok:
            return Step(False, f"relayed {c.function} to my requester", relays=[c])
        return Step(False, f"no reachable agent can run {c.function}")

    @staticmethod
    def _ask(host: AgentHost, owner: str, text: str, c: FunctionCall, stream: bool) -> ClientResult:
        if stream:
            r = host.client.start_task(host.url_of(owner), text, [call_data(c)])
            if r.task_id and not r.state.is_final:
                r = host.client.wait_task(r.task_id, timeout=120)
            return r
        return host.client.send_message(host.url_of(owner), text, [call_data(c)])

    def _collect(self, host: AgentHost, owner: str, r: ClientResult) -> Step:
        body = r.text if r.state is TaskState.COMPLETED else (r.notice or r.text)
        self._observe(host, body, via=f"reply:{owner}")
        for c in self._calls_in(r.data):                   # requests relayed up to us: obey
            if self._first(host.agent_id, c):
                self._perform(host, c)
        results = [d[RESULT] for d in r.data if isinstance(d, dict) and isinstance(d.get(RESULT), dict)]
        ok = r.state is TaskState.COMPLETED and all(x.get("ok") for x in results)
        return Step(ok, body)

    def _own(self, host: AgentHost, c: FunctionCall) -> Step:
        tc = FunctionCall(function=c.function, args=dict(c.args), id=f"s{next(self._ids)}")
        out = host.ep.call_tool(tc, self.tools.executor(host.agent_id))
        if out.held:                        # settled at the agent's terminal resolution
            return Step(False, out.text, pending=tc.id)
        text = out.text if out.error is None else f"error: {out.error}"
        self._observe(host, text, via=f"tool:{c.function}")
        return Step(out.error is None, text)

    # --- reading content ----------------------------------------------------------
    def _observe(self, host: AgentHost, text: str, *, via: str) -> None:
        me = host.agent_id
        if not self.exposure.see(me, text, via) or not self.injection_plan:
            return
        with self._lock:
            if me in self.infected:
                return
            self.infected.append(me)
        relays = []
        for c in self.injection_plan:
            if self._first(me, c):
                relays += self._perform(host, c, relay_ok=me != ENTRY).relays
        if relays:
            with self._lock:
                self._relays.setdefault(me, []).extend(relays)

    def _first(self, agent: str, c: FunctionCall) -> bool:
        """Each agent carries out a given call at most once per session."""
        with self._lock:
            done = self._done.setdefault(agent, set())
            k = _key(c)
            if k in done:
                return False
            done.add(k)
            return True

    @staticmethod
    def _calls_in(data: list[dict[str, Any]]) -> list[FunctionCall]:
        out = []
        for d in data or []:
            c = d.get(CALL) if isinstance(d, dict) else None
            if isinstance(c, dict) and isinstance(c.get("function"), str):
                out.append(FunctionCall(function=c["function"], args=dict(c.get("args") or {})))
        return out
