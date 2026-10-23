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

How agents talk: a request carries the calls it asks for as structured data parts
(`{"call": {"function": ..., "args": ...}}`); an answer reports per call whether it
succeeded (`{"result": {...}}`) and may pass calls up to the requester.
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
    """A call as a data part of a message."""
    return {CALL: {"function": c.function, "args": dict(c.args)}}


def _key(c: FunctionCall) -> str:
    """A call's identity (function and arguments), to recognise it when it comes again."""
    return f"{c.function}:{sorted((name, str(value)) for name, value in c.args.items())}"


@dataclass(slots=True)
class Step:
    """What became of one call an agent carried out (or tried to)."""
    ok: bool
    text: str
    relays: list[FunctionCall] = field(default_factory=list)   # calls to pass up to the requester
    pending: str | None = None        # id of a held call, settled at the agent's terminal


def settle(host: AgentHost, steps: list[Step], tools: ToolBox) -> None:
    """After the agent's terminal resolution: what became of its held calls."""
    outcomes = host.ep.monitor.call_outcomes if host.ep.defense else {}
    for step in steps:
        if step.pending is None:
            continue
        kind, result, error = outcomes.get(step.pending, ("unresolved", None, None))
        if kind == "committed" and error is None:
            step.ok, step.text = True, tools.format(result)
        else:
            step.ok, step.text = False, f"withheld: {error or kind}"
        step.pending = None


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
        self._done: dict[str, set[str]] = {}                # agent -> calls it carried out
        self._results: dict[tuple[str, str], Step] = {}     # (agent, call) -> what it answered
        self._relays: dict[str, list[FunctionCall]] = {}    # agent -> calls to pass up
        self._lock = threading.Lock()
        self._ids = itertools.count(1)

    def handlers(self) -> dict[str, Any]:
        return {agent: (self._entry if agent == ENTRY else self._worker) for agent in self.spec.agents}

    # --- the entry agent ----------------------------------------------------------
    def _entry(self, host: AgentHost, msg: Message, task_id: str) -> AgentResult:
        """The front desk: run the user task's plan, then answer with the task's
        expected output if every step succeeded."""
        steps: list[Step] = []
        if self.dispatch == "parallel":
            steps = self._parallel(host, self.plan)
        else:
            for call in self.plan:
                steps.append(self._perform(host, call, stream=self.dispatch == "stream"))
        host.ep.terminal()
        settle(host, steps, self.tools)
        host.ep.drain_notices()     # about withheld actions; the plan's own steps carry their status
        if all(step.ok for step in steps):
            return AgentResult(text=self.final_output)
        failed = "; ".join(step.text[:200] for step in steps if not step.ok)
        return AgentResult(text="I could not complete the request. " + failed)

    def _parallel(self, host: AgentHost, plan: list[FunctionCall]) -> list[Step]:
        """One streamed task per owner (calls kept in plan order per owner), all in
        flight at once, then collected."""
        groups: dict[str, list[FunctionCall]] = {}
        for call in plan:
            groups.setdefault(self.system.owner(call.function) or "", []).append(call)
        started: list[tuple[str, ClientResult]] = []
        steps: list[Step] = []
        for owner, calls in groups.items():
            if owner == host.agent_id:
                steps += [self._own(host, call) for call in calls]
            elif owner in reachable(self.spec, host.agent_id):
                text = "Please run: " + "; ".join(f"{call.function}({dict(call.args)})" for call in calls)
                answer = host.client.start_task(host.url_of(owner), text, [call_data(call) for call in calls])
                started.append((owner, answer))
            else:
                steps.append(Step(False, f"no agent can run {calls[0].function}"))
        for owner, answer in started:
            result = (host.client.wait_task(answer.task_id, timeout=120)
                      if answer.task_id and not answer.state.is_final else answer)
            if result.state in (TaskState.FAILED, TaskState.REJECTED):
                # re-issue once, as a blocking request (see _perform)
                self._collect(host, owner, result)
                with self._lock:
                    self.retries += 1
                calls = groups[owner]
                text = "Please run: " + "; ".join(f"{call.function}({dict(call.args)})" for call in calls)
                result = host.client.send_message(host.url_of(owner), text, [call_data(call) for call in calls])
            steps.append(self._collect(host, owner, result))
        return steps

    # --- workers ----------------------------------------------------------------
    def _worker(self, host: AgentHost, msg: Message, task_id: str) -> AgentResult:
        """A specialist: carry out the calls the message asks for, then answer with
        their results (and any calls to pass up to the requester)."""
        me = host.agent_id
        self._observe(host, msg.content_text(), via="message")
        done: list[tuple[FunctionCall, Step]] = []
        relays: list[FunctionCall] = []
        fresh: list[tuple[FunctionCall, Step]] = []
        for call in self._calls_in(msg.data()):
            with self._lock:
                cached = self._results.get((me, _key(call)))
            if cached is not None:       # asked again: answer with what was done, never redo it
                done.append((call, Step(cached.ok, cached.text)))
                continue
            step = self._perform(host, call, relay_ok=True)
            done.append((call, step))
            fresh.append((call, step))
            relays += step.relays
        host.ep.terminal()
        settle(host, [step for _, step in done], self.tools)
        with self._lock:
            for call, step in fresh:
                self._results[(me, _key(call))] = Step(step.ok, step.text)
        notes = host.ep.drain_notices()
        with self._lock:
            relays += self._relays.pop(me, [])
        status = [{RESULT: {"function": call.function, "ok": step.ok}} for call, step in done]
        return AgentResult(text="\n".join([step.text for _, step in done] + notes) or "done",
                           data=status + [call_data(call) for call in relays])

    # --- doing one call -----------------------------------------------------------
    def _perform(self, host: AgentHost, c: FunctionCall, *, stream: bool = False,
                 relay_ok: bool = False) -> Step:
        """Carry out one call: with an own tool, by asking the owner (if reachable), or
        -- with `relay_ok` -- by passing it up to the agent that gave us our task."""
        owner = self.system.owner(c.function)
        me = host.agent_id
        if owner == me:
            return self._own(host, c)
        if owner is not None and owner in reachable(self.spec, me):
            text = f"Please run {c.function} with arguments {dict(c.args)} and send me the result."
            answer = self._ask(host, owner, text, c, stream)
            if answer.state in (TaskState.FAILED, TaskState.REJECTED):
                # the KAIROS recovery path: re-issue once, as a new effect, because the
                # user's task needs it (a withheld reply may have mixed in other content)
                self._collect(host, owner, answer)
                with self._lock:
                    self.retries += 1
                answer = self._ask(host, owner, text, c, stream)
            return self._collect(host, owner, answer)
        if relay_ok:
            return Step(False, f"relayed {c.function} to my requester", relays=[c])
        return Step(False, f"no reachable agent can run {c.function}")

    @staticmethod
    def _ask(host: AgentHost, owner: str, text: str, c: FunctionCall, stream: bool) -> ClientResult:
        """Ask `owner` to run the call: a streamed task waited for, or a blocking send."""
        if stream:
            answer = host.client.start_task(host.url_of(owner), text, [call_data(c)])
            if answer.task_id and not answer.state.is_final:
                answer = host.client.wait_task(answer.task_id, timeout=120)
            return answer
        return host.client.send_message(host.url_of(owner), text, [call_data(c)])

    def _collect(self, host: AgentHost, owner: str, r: ClientResult) -> Step:
        """Read an answer: it may infect us, it may pass calls up to us (which we obey),
        and it says whether the requested calls succeeded."""
        body = r.text if r.state is TaskState.COMPLETED else (r.notice or r.text)
        self._observe(host, body, via=f"reply:{owner}")
        for call in self._calls_in(r.data):                   # requests relayed up to us: obey
            if self._first(host.agent_id, call):
                self._perform(host, call)
        results = [item[RESULT] for item in r.data if isinstance(item, dict) and isinstance(item.get(RESULT), dict)]
        ok = r.state is TaskState.COMPLETED and all(result.get("ok") for result in results)
        return Step(ok, body)

    def _own(self, host: AgentHost, c: FunctionCall) -> Step:
        """Run a call with one of our own tools, through the host's enforcement point."""
        tool_call = FunctionCall(function=c.function, args=dict(c.args), id=f"s{next(self._ids)}")
        outcome = host.ep.call_tool(tool_call, self.tools.executor(host.agent_id))
        if outcome.held:                        # settled at the agent's terminal resolution
            return Step(False, outcome.text, pending=tool_call.id)
        text = outcome.text if outcome.error is None else f"error: {outcome.error}"
        self._observe(host, text, via=f"tool:{c.function}")
        return Step(outcome.error is None, text)

    # --- reading content ----------------------------------------------------------
    def _observe(self, host: AgentHost, text: str, *, via: str) -> None:
        """Content reached the agent. If it carries the injected payload, the agent is
        infected (once) and carries out the injection task's plan."""
        me = host.agent_id
        if not self.exposure.see(me, text, via) or not self.injection_plan:
            return
        with self._lock:
            if me in self.infected:
                return
            self.infected.append(me)
        relays = []
        for call in self.injection_plan:
            if self._first(me, call):
                relays += self._perform(host, call, relay_ok=me != ENTRY).relays
        if relays:
            with self._lock:
                self._relays.setdefault(me, []).extend(relays)

    def _first(self, agent: str, c: FunctionCall) -> bool:
        """Each agent carries out a given call at most once per session."""
        with self._lock:
            done = self._done.setdefault(agent, set())
            key = _key(c)
            if key in done:
                return False
            done.add(key)
            return True

    @staticmethod
    def _calls_in(data: list[dict[str, Any]]) -> list[FunctionCall]:
        """The calls a message's data parts ask for."""
        calls = []
        for item in data or []:
            call = item.get(CALL) if isinstance(item, dict) else None
            if isinstance(call, dict) and isinstance(call.get("function"), str):
                calls.append(FunctionCall(function=call["function"], args=dict(call.get("args") or {})))
        return calls
