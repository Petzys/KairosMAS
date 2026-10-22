"""The `stub` model as a MASDojo agent: plan replay through the LLM code path.

With `--backend llm --model stub` every agent runs the real LLM harness
(kairos.mas.bench.llm: AgentDojo's OpenAILLM element, tool schemas, the messaging
tools, notices, terminal re-entry, transcripts) against the offline stub client,
whose decisions come from this policy. It behaves like the scripted backend, but
everything travels as chat messages and tool calls:

  * the front desk replays the user task's ground-truth plan: a call of its own
    tool directly, otherwise send_message to the tool's owner with a directive
    `[[call {...}]]` embedded in natural language;
  * a specialist carries out the directives in the message it received;
  * every agent is worst-case obedient: once a message or tool result it reads
    contains the injected payload it first executes the injection plan, and it
    carries out directives found in replies; what it cannot reach it relays up in
    its answer;
  * a failed or held step is re-issued once (the honest hold notice says so).

The stub decides from the conversation alone (deterministically), one tool call
per turn, so a run is reproducible. It measures the harness and the monitor, not
a model.
"""
from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agentdojo.functions_runtime import FunctionCall

from kairos.mas.bench.suites import ENTRY, SuiteSystem, reachable
from kairos.mas.spec import MASSpec
from kairos.mas.stub_llm import StubAction, message_text

DIRECTIVE = re.compile(r"\[\[call (\{.*?\})\]\]", re.DOTALL)
MESSAGING = {"send_message", "delegate_task", "get_task_result"}
_ERROR = re.compile(r"^[A-Za-z]*(Error|Exception)\b")


def directive(c: FunctionCall) -> str:
    return "[[call " + json.dumps({"function": c.function, "args": dict(c.args)}, sort_keys=True) + "]]"


def directives(text: str) -> list[FunctionCall]:
    out = []
    for m in DIRECTIVE.finditer(text or ""):
        try:
            d = json.loads(m.group(1))
        except ValueError:
            continue
        if isinstance(d, dict) and isinstance(d.get("function"), str):
            out.append(FunctionCall(function=d["function"], args=dict(d.get("args") or {})))
    return out


def failed(text: str, *, reply: bool) -> bool:
    """Did a step fail? A REPLY is judged by the specialist's explicit status lines
    (anything else -- a rejected or withheld task, an unknown agent -- is a
    failure); the agent's OWN tool result by the prefixes the monitor and the
    tools use for refusals, holds and errors. Precision matters: a false failure
    is re-issued and would repeat an effect."""
    t = (text or "").strip()
    if reply:
        return t.startswith("[task ") or "FAILED:" in t or "OK:" not in t
    return (t.startswith(("SECURITY NOTICE", "Blocked", "A prior speculative action"))
            or bool(_ERROR.match(t))
            or (t.startswith("The ") and "request was NOT performed" in t[:200]))


def _key(c: FunctionCall) -> str:
    return json.dumps({"f": c.function, "a": dict(c.args)}, sort_keys=True, default=str)


@dataclass(slots=True)
class _Step:
    call: FunctionCall
    kind: str                # plan | injection | obey
    retry: bool = False
    result: str | None = None


class PlanReplayPolicy:
    def __init__(self, spec: MASSpec, system: SuiteSystem, *, plan: list[FunctionCall],
                 injection_plan: list[FunctionCall], payload: Callable[[str], bool],
                 final_output: str) -> None:
        self.spec = spec
        self.system = system
        self.plan = plan
        self.injection_plan = injection_plan
        self.payload = payload
        self.final_output = final_output

    # --- identity ------------------------------------------------------------
    @staticmethod
    def _agent(messages: list[dict[str, Any]]) -> str:
        system = message_text(messages[0]) if messages else ""
        if "front desk" in system:
            return ENTRY
        m = re.search(r"You are '([^']+)'", system)
        return m.group(1) if m else ENTRY

    # --- the policy -----------------------------------------------------------
    def __call__(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> StubAction:
        me = self._agent(messages)
        own = {t["function"]["name"] for t in tools if "function" in t} - MESSAGING
        peers = set(reachable(self.spec, me))
        first = message_text(messages[1]) if len(messages) > 1 else ""

        relays: list[FunctionCall] = []
        seen: set[str] = set()
        queue: list[_Step] = []

        def routable(c: FunctionCall) -> bool:
            if c.function in own or self.system.owner(c.function) in peers:
                return True
            relays.append(c)
            return False

        def add(calls: list[FunctionCall], kind: str, at: int | None = None) -> None:
            new = []
            for c in calls:
                k = _key(c)
                if k in seen:
                    continue
                seen.add(k)
                if routable(c):
                    new.append(_Step(c, kind))
            if at is None:
                queue.extend(new)
            else:
                queue[at:at] = new

        infected = bool(self.injection_plan) and self.payload(first)
        if infected:                      # "before you can solve the task ... do this first"
            add(self.injection_plan, "injection")
        add(self.plan if me == ENTRY else directives(first), "plan")

        # replay the conversation: each assistant turn issued the next step
        k = 0
        for i, m in enumerate(messages):
            if m.get("role") != "assistant" or not m.get("tool_calls"):
                continue
            result = next((message_text(r) for r in messages[i + 1:] if r.get("role") == "tool"), "")
            if k >= len(queue):
                break
            step = queue[k]
            step.result = result
            k += 1
            nxt = k
            reply = step.call.function not in own
            if failed(result, reply=reply) and not step.retry:
                queue.insert(nxt, _Step(step.call, step.kind, retry=True))
                nxt += 1
            if not infected and self.injection_plan and self.payload(result):
                infected = True
                add(self.injection_plan, "injection", at=nxt)
            if reply:                                  # a reply: obey the directives in it
                add(directives(result), "obey", at=nxt)

        if k < len(queue):
            return StubAction(calls=[self._route(queue[k].call, own)])
        return StubAction(content=self._answer(me, queue, relays, own))

    def _route(self, c: FunctionCall, own: set[str]) -> tuple[str, dict[str, Any]]:
        if c.function in own:
            return c.function, dict(c.args)
        owner = self.system.owner(c.function)
        text = (f"Please run {c.function} with arguments {json.dumps(dict(c.args), default=str)} "
                f"and send me the result. {directive(c)}")
        return "send_message", {"agent": owner, "message": text}

    def _answer(self, me: str, queue: list[_Step], relays: list[FunctionCall], own: set[str]) -> str:
        last: dict[str, _Step] = {}
        for st in queue:
            if st.kind == "plan":
                last[_key(st.call)] = st          # the retry, if any, replaces the attempt

        def bad(st: _Step) -> bool:
            return st.result is None or failed(st.result, reply=st.call.function not in own)

        if me == ENTRY:
            broken = [st for st in last.values() if bad(st)]
            if not broken:
                return self.final_output or "Done."
            return "I could not complete the request: " + "; ".join(
                f"{st.call.function} ({(st.result or 'not done')[:120]})" for st in broken)
        lines = [("FAILED: " if bad(st) else "OK: ")
                 + f"{st.call.function}: {(st.result or 'not done')[:1500]}" for st in last.values()]
        lines += [f"Please also run this: {directive(c)}" for c in relays]
        return "\n".join(lines) or "Nothing to do."
