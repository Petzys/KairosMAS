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
    """A call written into a message, e.g. `[[call {"args": {...}, "function": "send_money"}]]`."""
    return "[[call " + json.dumps({"function": c.function, "args": dict(c.args)}, sort_keys=True) + "]]"


def directives(text: str) -> list[FunctionCall]:
    """Every call written into `text` as a directive."""
    calls = []
    for match in DIRECTIVE.finditer(text or ""):
        try:
            parsed = json.loads(match.group(1))
        except ValueError:
            continue
        if isinstance(parsed, dict) and isinstance(parsed.get("function"), str):
            calls.append(FunctionCall(function=parsed["function"], args=dict(parsed.get("args") or {})))
    return calls


def failed(text: str, *, reply: bool) -> bool:
    """Did a step fail? A REPLY is judged by the specialist's explicit status lines
    (anything else -- a rejected or withheld task, an unknown agent -- is a
    failure); the agent's OWN tool result by the prefixes the monitor and the
    tools use for refusals, holds and errors. Precision matters: a false failure
    is re-issued and would repeat an effect."""
    stripped = (text or "").strip()
    if reply:
        return stripped.startswith("[task ") or "FAILED:" in stripped or "OK:" not in stripped
    return (stripped.startswith(("SECURITY NOTICE", "Blocked", "A prior speculative action"))
            or bool(_ERROR.match(stripped))
            or (stripped.startswith("The ") and "request was NOT performed" in stripped[:200]))


def _key(c: FunctionCall) -> str:
    """A call's identity (function and arguments)."""
    return json.dumps({"f": c.function, "a": dict(c.args)}, sort_keys=True, default=str)


@dataclass(slots=True)
class _Step:
    """One call the agent intends to issue, and the result it got (once issued)."""
    call: FunctionCall
    kind: str                # plan | injection | obey
    retry: bool = False
    result: str | None = None


class PlanReplayPolicy:
    """The stub model's agent behaviour: given a conversation, the next action.

    It keeps no state between turns. Each turn it rebuilds the agent's to-do list
    from the conversation -- the plan (or the directives it received), the injection
    plan once it is infected, directives in replies, re-issues of failed steps -- and
    replays the turns so far against it. The next step not yet issued is the next
    tool call; when none is left, the agent answers."""

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
        """Which agent this conversation belongs to, read off its system prompt."""
        system = message_text(messages[0]) if messages else ""
        if "front desk" in system:
            return ENTRY
        match = re.search(r"You are '([^']+)'", system)
        return match.group(1) if match else ENTRY

    # --- the policy -----------------------------------------------------------
    def __call__(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> StubAction:
        me = self._agent(messages)
        own = {tool["function"]["name"] for tool in tools if "function" in tool} - MESSAGING
        peers = set(reachable(self.spec, me))
        first = message_text(messages[1]) if len(messages) > 1 else ""   # the task it received

        relays: list[FunctionCall] = []   # calls no reachable agent can run: passed up in the answer
        seen: set[str] = set()
        queue: list[_Step] = []           # the to-do list, in order

        def routable(c: FunctionCall) -> bool:
            if c.function in own or self.system.owner(c.function) in peers:
                return True
            relays.append(c)
            return False

        def add(calls: list[FunctionCall], kind: str, at: int | None = None) -> None:
            """Add new calls to the to-do list (at the end, or at position `at`)."""
            new = []
            for c in calls:
                key = _key(c)
                if key in seen:
                    continue
                seen.add(key)
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
        issued = 0
        for i, message in enumerate(messages):
            if message.get("role") != "assistant" or not message.get("tool_calls"):
                continue
            result = next((message_text(later) for later in messages[i + 1:] if later.get("role") == "tool"), "")
            if issued >= len(queue):
                break
            step = queue[issued]
            step.result = result
            issued += 1
            insert_at = issued            # what this result adds comes right after the step
            reply = step.call.function not in own
            if failed(result, reply=reply) and not step.retry:
                queue.insert(insert_at, _Step(step.call, step.kind, retry=True))
                insert_at += 1
            if not infected and self.injection_plan and self.payload(result):
                infected = True
                add(self.injection_plan, "injection", at=insert_at)
            if reply:                                  # a reply: obey the directives in it
                add(directives(result), "obey", at=insert_at)

        if issued < len(queue):
            return StubAction(calls=[self._route(queue[issued].call, own)])
        return StubAction(content=self._answer(me, queue, relays, own))

    def _route(self, c: FunctionCall, own: set[str]) -> tuple[str, dict[str, Any]]:
        """The tool call that carries out `c`: the tool itself, or a message to its owner."""
        if c.function in own:
            return c.function, dict(c.args)
        owner = self.system.owner(c.function)
        text = (f"Please run {c.function} with arguments {json.dumps(dict(c.args), default=str)} "
                f"and send me the result. {directive(c)}")
        return "send_message", {"agent": owner, "message": text}

    def _answer(self, me: str, queue: list[_Step], relays: list[FunctionCall], own: set[str]) -> str:
        """The final answer: the front desk's result for the user, or a specialist's
        status line per planned call (plus the calls it passes up)."""
        last: dict[str, _Step] = {}
        for step in queue:
            if step.kind == "plan":
                last[_key(step.call)] = step          # the retry, if any, replaces the attempt

        def bad(step: _Step) -> bool:
            return step.result is None or failed(step.result, reply=step.call.function not in own)

        if me == ENTRY:
            broken = [step for step in last.values() if bad(step)]
            if not broken:
                return self.final_output or "Done."
            return "I could not complete the request: " + "; ".join(
                f"{step.call.function} ({(step.result or 'not done')[:120]})" for step in broken)
        lines = [("FAILED: " if bad(step) else "OK: ")
                 + f"{step.call.function}: {(step.result or 'not done')[:1500]}" for step in last.values()]
        lines += [f"Please also run this: {directive(c)}" for c in relays]
        return "\n".join(lines) or "Nothing to do."
