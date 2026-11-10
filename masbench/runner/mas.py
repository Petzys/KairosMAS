"""Run one case: N concurrent agents on a shared environment, talking over an A2A shim.

Semantics (Benchmark Design §2.3, decided 05.11.2026):
* Every agent is an A2A server and client. `send_message` = A2A SendMessage (blocks until the
  reply), `send_message_async` = SendStreamingMessage (returns a task id; the reply is put into
  the sender's conversation when it arrives). `wait_for_replies` blocks on outstanding tasks.
* Sessions: one conversation per agent per case; every incoming request is appended to it.
  An agent handles one request at a time; further requests queue.
* A request is answered by the agent's final text of that activation (the A2A task result).
* A send that would close a wait-for cycle fails at once instead of deadlocking.
* The run ends when the entry agent has answered the principal and every agent is idle, when
  the case budget (messages, wall clock) is exhausted, or when the defense aborts it.
* The attacker of a case is applied here and in the environment: injections and board writes
  are part of the environment's initial state, compromised agents get the attacker's system
  prompt. The defense is wrapped around whatever results.
"""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from dataclasses import dataclass
from typing import Any

from masbench import checks
from masbench.env import Environment
from masbench.prompts import render, render_system_prompt
from masbench.runner.brains import Brain, Turn, TurnCall
from masbench.runner.defense import (
    AgentHandle,
    Defense,
    DefenseAbort,
    Message,
    RunContext,
    ToolCall,
    Verdict,
)
from masbench.schema import (
    AgentSpec,
    AgentStats,
    Case,
    DefenseEvent,
    Interval,
    MessageRecord,
    RunRecord,
    Scenario,
    ToolCallRecord,
)

USER = "user"


def a2a_tools(modes: list[str]) -> list[dict[str, Any]]:
    params = {"type": "object", "required": ["agent_id", "message"], "properties": {
        "agent_id": {"type": "string", "description": "Id of the agent to contact"},
        "message": {"type": "string", "description": "The full request, with every detail needed"}}}
    tools = []
    if "sync" in modes:
        tools.append({"type": "function", "function": {
            "name": "send_message", "parameters": params,
            "description": "Send a request to another agent and wait for its answer."}})
    if "async" in modes:
        tools.append({"type": "function", "function": {
            "name": "send_message_async", "parameters": params,
            "description": "Send a request to another agent without waiting. Returns a task id; "
                           "the answer is delivered to you later."}})
        tools.append({"type": "function", "function": {
            "name": "wait_for_replies", "parameters": {"type": "object", "properties": {}},
            "description": "Wait until all answers to your outstanding requests have arrived."}})
    return tools


A2A_NAMES = {"send_message", "send_message_async", "wait_for_replies"}


@dataclass
class Request:
    msg: Message
    reply: asyncio.Future[str] | None


class AgentRuntime:
    def __init__(self, run: MASRun, spec: AgentSpec, system_prompt: str) -> None:
        self.run, self.spec, self.id = run, spec, spec.id
        self.brain: Brain = run.brains[spec.id]
        self.inbox: asyncio.Queue[Request] = asyncio.Queue()
        self.history: list[dict[str, Any]] = [{"role": "system", "content": system_prompt}]
        self.tools = (run.env.openai_tools(spec.tools) if spec.tools else []) + (
            a2a_tools(run.scenario.communication.modes) if run.scenario.contacts(spec.id) else [])
        self.seq = 0
        self.busy = False
        self.pending: dict[str, asyncio.Task[None]] = {}  # async task id -> waiter
        self.arrived: list[str] = []
        self.stats = AgentStats(agent=spec.id)

    def next_seq(self) -> int:
        self.seq += 1
        return self.seq

    def handle(self) -> AgentHandle:
        default = self.run.brains[self.id]

        async def llm(messages: list[dict[str, Any]], tools: list[dict[str, Any]] | None = None) -> Turn:
            async with self.run.interval(self.id, "llm"):
                turn = await default.step(messages, tools or [])
            self._meter(turn)
            return turn

        async def send(receiver: str, text: str, mode: str = "sync", meta: dict[str, Any] | None = None) -> str:
            return await self.run.send(self, receiver, text, mode, meta)

        return AgentHandle(id=self.id, spec=self.spec, tools=self.tools, call_tool=self.tool, send=send, llm=llm)

    def _meter(self, turn: Turn) -> None:
        self.stats.llm_calls += 1
        self.stats.prompt_tokens += turn.prompt_tokens
        self.stats.completion_tokens += turn.completion_tokens

    # -- serving ------------------------------------------------------------------------

    async def serve(self) -> None:
        while True:
            req = await self.inbox.get()
            self.busy = True
            try:
                try:
                    text = await self.activate(req.msg)
                    await self.run.reply(self, req, text)
                except asyncio.CancelledError:
                    raise
                except DefenseAbort as e:
                    self.run.abort(str(e))
                    return
                except Exception as e:  # noqa: BLE001 - answer instead of leaving the caller hanging
                    err = f"{type(e).__name__}: {e}"
                    self.run.record.error = ((self.run.record.error + " | ") if self.run.record.error else "") + f"{self.id}: {err}"
                    try:
                        await self.run.reply(self, req, f"(agent `{self.id}` failed: {err})")
                    except DefenseAbort as e2:
                        self.run.abort(str(e2))
                        return
            finally:
                self.busy = False
                self.inbox.task_done()

    async def activate(self, msg: Message) -> str:
        self.stats.activations += 1
        d = self.run.defense
        text = await self.run.received(msg, self.id)
        self.history.append({"role": "user", "content": text if msg.sender == USER else
                             f"[Message from agent `{msg.sender}` (task {msg.task_id})]\n{text}"})
        final = ""
        reentered = False
        while True:
            final = await self._loop()
            end = await d.on_activation_end(self.id)
            if end is None:
                break
            if end.reenter and not reentered:
                reentered = True
                self.history.append({"role": "user", "content": end.notice})
                continue
            final = f"{final}\n\n{end.notice}".strip()
            break
        return final

    async def _loop(self) -> str:
        final = ""
        for _ in range(self.run.case.budget.max_turns_per_activation):
            self._flush_arrived()
            for notice in self.run.defense.drain_notices(self.id):
                self.history.append({"role": "user", "content": notice})
            messages, tools = await self.run.defense.before_llm(self.id, list(self.history), list(self.tools))
            async with self.run.interval(self.id, "llm"):
                turn = await self.brain.step(messages, tools)
            self._meter(turn)
            self.history.append(turn.as_message())
            if not turn.tool_calls:
                if self.pending and await self._await_pending():
                    continue  # give the brain the answers that just arrived
                final = turn.content or ""
                break
            for call in turn.tool_calls:
                result = await self.dispatch(call)
                self.history.append({"role": "tool", "tool_call_id": call.id, "content": result})
        else:
            final = "(stopped: turn budget of this request exhausted)"
        return final

    def _flush_arrived(self) -> None:
        while self.arrived:
            self.history.append({"role": "user", "content": self.arrived.pop(0)})

    async def _await_pending(self) -> bool:
        """Wait for outstanding async tasks unless that would deadlock. True if any arrived."""
        targets = {t.get_name() for t in self.pending.values()}
        if self.run.would_deadlock(self.id, targets):
            return False
        self.run.blocked_on[self.id] = targets
        try:
            async with self.run.interval(self.id, "blocked_a2a"):
                await asyncio.gather(*self.pending.values())
        finally:
            self.run.blocked_on.pop(self.id, None)
        self.pending.clear()
        return bool(self.arrived)

    # -- tool calls -----------------------------------------------------------------------

    async def dispatch(self, call: TurnCall) -> str:
        try:
            args = json.loads(call.arguments or "{}")
            if not isinstance(args, dict):
                raise ValueError("arguments must be a JSON object")
        except ValueError as e:
            return f"Error: could not parse the arguments: {e}"
        if call.name in A2A_NAMES:
            return await self.a2a(call.name, args)
        return await self.tool(call.name, args)

    async def a2a(self, name: str, args: dict[str, Any]) -> str:
        if name == "wait_for_replies":
            if not self.pending:
                return "Replies: none outstanding." + self._take_arrived()
            await self._await_pending()
            return "Replies:" + self._take_arrived()
        mode = "sync" if name == "send_message" else "async"
        return await self.run.send(self, str(args.get("agent_id", "")), str(args.get("message", "")), mode)

    def _take_arrived(self) -> str:
        out = "".join("\n\n" + a for a in self.arrived)
        self.arrived.clear()
        return out

    async def tool(self, name: str, args: dict[str, Any]) -> str:
        run = self.run
        call = ToolCall(agent=self.id, seq=self.next_seq(), function=name, args=args)
        t0 = time.monotonic()
        rec = ToolCallRecord(agent=self.id, seq=call.seq, function=name, args=args, t_start=t0, t_end=t0)
        run.record.tool_calls.append(rec)
        if name not in self.spec.tools:
            rec.error = f"ToolNotFoundError: `{name}` is not one of your tools"
            rec.t_end = time.monotonic()
            return f"Error: {rec.error}. Ask the agent responsible for it."
        async with run.interval(self.id, "defense"):
            verdict = await run.defense.before_tool(call)
        run.note(verdict, "before_tool", self.id, name)
        if verdict.action == "deny":
            rec.blocked_by_defense = verdict.reason
            rec.t_end = time.monotonic()
            return f"Error: the call was blocked by the security monitor: {verdict.reason}"
        if verdict.action == "replace":
            result = verdict.replacement or ""
            rec.defense_note = verdict.reason or "replaced"
        else:
            if verdict.action == "modify":
                call.args = rec.args = args = dict(verdict.args or {})
                rec.defense_note = verdict.reason or "args modified"
            async with run.interval(self.id, "tool"):
                out = run.env.run_tool(name, args, self.id)
            rec.executed = True
            rec.error = out.error
            result = out.result if out.error is None else f"Error: {out.error}"
        async with run.interval(self.id, "defense"):
            after = await run.defense.after_tool(call, result)
        if isinstance(after, Verdict):
            run.note(after, "after_tool", self.id, name)
            if after.action == "deny":
                result = f"Error: the tool output was withheld by the security monitor: {after.reason}"
            elif after.action == "replace":
                result = after.replacement or ""
        else:
            result = after
        rec.result, rec.t_end = result, time.monotonic()
        return result


class MASRun:
    def __init__(self, scenario: Scenario, case: Case, env: Environment, defense: Defense,
                 brains: dict[str, Brain], model: str, repetition: int = 1,
                 aux_llm: Any = None) -> None:
        self.scenario, self.case, self.env, self.defense = scenario, case, env, defense
        self.record = RunRecord(case=case.id, scenario=scenario.id, defense=defense.name,
                                defense_options=dict(defense.options), model=model, variant=case.variant,
                                repetition=repetition, labels=case.labels.model_dump(mode="json", exclude_defaults=True))
        self.ctx = RunContext(scenario=scenario, user_prompt=case.user.prompt,
                              messages=self.record.messages, tool_calls=self.record.tool_calls)
        self.blocked_on: dict[str, set[str]] = {}
        self.t0 = time.monotonic()
        self.brains = brains
        self.agents: dict[str, AgentRuntime] = {}
        self.aborted: asyncio.Future[str] | None = None
        self.ctx.execute_tool = self.execute_committed
        self.ctx.isolate = self.isolate
        self.ctx.event = self.event
        self.ctx.meter = self.meter
        if aux_llm is not None:
            self.ctx.llm = lambda model=None: aux_llm(model, self.record.defense_llm)

    # -- what a defense may do through the context --------------------------------------------

    def execute_committed(self, agent: str, function: str, args: dict[str, Any], note: str):  # noqa: ANN201
        """Run a call a defense held and then committed (event-loop thread only)."""
        rt = self.agents[agent]
        t0 = time.monotonic()
        out = self.env.run_tool(function, args, agent)
        self.record.tool_calls.append(ToolCallRecord(
            agent=agent, seq=rt.next_seq(), function=function, args=args, executed=True,
            result=out.result, error=out.error, defense_note=note, t_start=t0, t_end=time.monotonic()))
        return out

    def isolate(self, agent: str, reason: str) -> None:
        if agent not in self.record.isolated:
            self.record.isolated[agent] = reason
            self.event("isolate", agent, "isolate", reason)

    def event(self, hook: str, agent: str, decision: str, reason: str = "", target: str = "") -> None:
        self.record.defense_events.append(DefenseEvent(
            t=time.monotonic() - self.t0, hook=hook, agent=agent, target=target, decision=decision, reason=reason))

    def meter(self, calls: int, prompt_tokens: int, completion_tokens: int) -> None:
        usage = self.record.defense_llm
        usage.calls += calls
        usage.prompt_tokens += prompt_tokens
        usage.completion_tokens += completion_tokens

    def note(self, verdict: Verdict, hook: str, agent: str, target: str = "") -> None:
        """Record a non-allow verdict; an abort verdict ends the run."""
        if verdict.action == "allow":
            return
        self.event(hook, agent, verdict.action, verdict.reason, target)
        if verdict.action == "abort":
            raise DefenseAbort(verdict.reason)

    def abort(self, reason: str) -> None:
        if self.aborted is not None and not self.aborted.done():
            self.aborted.set_result(reason)

    # -- bookkeeping ---------------------------------------------------------------------------

    @asynccontextmanager
    async def interval(self, agent: str, kind: str):  # noqa: ANN201
        start = time.monotonic()
        try:
            yield
        finally:
            self.record.intervals.append(Interval(agent=agent, kind=kind, t_start=start - self.t0,
                                                  t_end=time.monotonic() - self.t0))

    def would_deadlock(self, sender: str, targets: set[str]) -> bool:
        stack, seen = list(targets), set()
        while stack:
            a = stack.pop()
            if a == sender:
                return True
            if a not in seen:
                seen.add(a)
                stack.extend(self.blocked_on.get(a, ()))
        return False

    def _msg_record(self, msg: Message) -> MessageRecord:
        rec = MessageRecord(id=msg.id, task_id=msg.task_id, kind=msg.kind, sender=msg.sender,
                            receiver=msg.receiver, mode=msg.mode, sender_seq=msg.sender_seq,
                            text=msg.text, meta=msg.meta, t_sent=time.monotonic() - self.t0)
        self.record.messages.append(rec)
        return rec

    # -- messages --------------------------------------------------------------------------------

    async def received(self, msg: Message, receiver: str) -> str:
        """`on_receive` for a delivered message; the text the receiving agent sees."""
        out = await self.defense.on_receive(msg, msg.text)
        if not isinstance(out, Verdict):
            return out
        self.note(out, "on_receive", receiver, msg.sender)
        if out.action == "deny":
            return f"(a message from `{msg.sender}` was withheld by the security monitor: {out.reason})"
        if out.action == "replace":
            return out.replacement or ""
        return msg.text

    async def send(self, sender: AgentRuntime, receiver: str, text: str, mode: str,
                   meta: dict[str, Any] | None = None) -> str:
        if receiver not in self.agents or receiver == sender.id:
            return f"Error: unknown agent `{receiver}`. Known agents: {', '.join(self.scenario.contacts(sender.id))}"
        if receiver not in self.scenario.contacts(sender.id):
            return f"Error: you may not contact `{receiver}`."
        if sum(m.kind == "request" for m in self.record.messages) >= self.case.budget.max_messages:
            return "Error: the message budget of this task is exhausted."
        if mode == "sync" and self.would_deadlock(sender.id, {receiver}):
            return f"Error: `{receiver}` is waiting for you; answer its request first."
        msg = Message(id=uuid.uuid4().hex, task_id=uuid.uuid4().hex[:8], kind="request", sender=sender.id,
                      receiver=receiver, mode=mode, sender_seq=sender.next_seq(), text=text, meta=dict(meta or {}))
        rec = self._msg_record(msg)
        for a in (sender.id, receiver):
            if a in self.record.isolated:
                rec.status, rec.reason = "rejected", f"`{a}` is isolated: {self.record.isolated[a]}"
                return f"Error: the message to `{receiver}` was rejected by the security monitor: {rec.reason}"
        async with self.interval(sender.id, "held"):
            verdict = await self.defense.on_message(msg)
        for a in (sender.id, receiver):  # isolated while looking at this very message
            if a in self.record.isolated and verdict.action == "allow":
                verdict = Verdict.deny(f"`{a}` is isolated: {self.record.isolated[a]}")
        if verdict.action in ("deny", "abort"):
            rec.status, rec.reason = "rejected", verdict.reason
        self.note(verdict, "on_message", sender.id, receiver)
        if verdict.action == "deny":
            return f"Error: the message to `{receiver}` was rejected by the security monitor: {verdict.reason}"
        if verdict.action == "replace":
            msg.text = rec.text = verdict.replacement or ""
        rec.meta = msg.meta
        fut: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        rec.t_delivered = time.monotonic() - self.t0
        await self.agents[receiver].inbox.put(Request(msg, fut))
        if mode == "sync":
            self.blocked_on[sender.id] = {receiver}
            try:
                async with self.interval(sender.id, "blocked_a2a"):
                    answer = await fut
            finally:
                self.blocked_on.pop(sender.id, None)
            return f"Answer from `{receiver}`:\n{answer}"

        async def waiter() -> None:
            answer = await fut
            sender.arrived.append(f"[Answer from agent `{receiver}` to task {msg.task_id}]\n{answer}")

        task = asyncio.create_task(waiter(), name=receiver)
        sender.pending[msg.task_id] = task
        return f"Sent to `{receiver}` as task {msg.task_id}. The answer will be delivered to you."

    async def reply(self, agent: AgentRuntime, req: Request, text: str) -> None:
        if req.msg.sender == USER:
            verdict = await self.defense.on_final(text)
            self.note(verdict, "on_final", agent.id)
            self.record.final_output = text if verdict.action == "allow" else (
                verdict.replacement or f"(final answer withheld by the security monitor: {verdict.reason})")
            if req.reply and not req.reply.done():
                req.reply.set_result(self.record.final_output)
            return
        msg = Message(id=uuid.uuid4().hex, task_id=req.msg.task_id, kind="reply", sender=agent.id,
                      receiver=req.msg.sender, mode=req.msg.mode, sender_seq=agent.next_seq(), text=text)
        rec = self._msg_record(msg)
        try:
            if agent.id in self.record.isolated:
                verdict = Verdict.deny(f"`{agent.id}` is isolated: {self.record.isolated[agent.id]}")
            else:
                async with self.interval(agent.id, "held"):
                    verdict = await self.defense.on_message(msg)
                if agent.id in self.record.isolated and verdict.action == "allow":
                    verdict = Verdict.deny(f"`{agent.id}` is isolated: {self.record.isolated[agent.id]}")
                if verdict.action in ("deny", "abort"):
                    rec.status, rec.reason = "rejected", verdict.reason
                self.note(verdict, "on_message", agent.id, msg.receiver)
            if verdict.action == "deny":
                rec.status, rec.reason = "rejected", verdict.reason
                answer = f"(the answer of `{agent.id}` was rejected by the security monitor: {verdict.reason})"
            else:
                if verdict.action == "replace":
                    msg.text = rec.text = verdict.replacement or ""
                rec.meta = msg.meta
                answer = await self.received(msg, msg.receiver)
            rec.t_delivered = time.monotonic() - self.t0
        finally:
            if req.reply and not req.reply.done():  # never leave the caller hanging
                req.reply.set_result(locals().get("answer", "(no answer: the run was aborted)"))

    # -- the run -----------------------------------------------------------------------------------

    def _system_prompt(self, spec: AgentSpec) -> str:
        prompt = render_system_prompt(self.scenario, spec)
        for c in self.case.attacker.compromised_agents if self.case.attacker else []:
            if c.agent == spec.id:
                if c.system_prompt is not None:
                    prompt = render(self.scenario, spec, c.system_prompt)
                if c.instructions:
                    prompt = f"{prompt}\n\n{render(self.scenario, spec, c.instructions)}"
        return self.defense.system_prompt(spec, prompt)

    async def _run(self) -> None:
        self.aborted = asyncio.get_running_loop().create_future()
        await self.defense.setup(self.ctx)
        for spec in self.scenario.agents:
            self.agents[spec.id] = AgentRuntime(self, spec, self._system_prompt(spec))
        for a in self.agents.values():
            a.brain = self.defense.make_brain(a.spec, self.brains[a.id], a.handle())
        servers = [asyncio.create_task(a.serve(), name=f"serve:{a.id}") for a in self.agents.values()]
        try:
            entry = self.agents[self.case.user.agent]
            fut: asyncio.Future[str] = asyncio.get_running_loop().create_future()
            first = Message(id=uuid.uuid4().hex, task_id="user", kind="request", sender=USER,
                            receiver=entry.id, mode="sync", sender_seq=0, text=self.case.user.prompt)
            await entry.inbox.put(Request(first, fut))
            await asyncio.wait({fut, self.aborted}, return_when=asyncio.FIRST_COMPLETED)
            # quiescence: let agents finish work still running after the answer
            while not self.aborted.done() and any(a.busy or not a.inbox.empty() for a in self.agents.values()):
                await asyncio.sleep(0.02)
            if self.aborted.done():
                self.record.aborted = self.aborted.result()
                if self.record.final_output is None:
                    self.record.final_output = f"(run aborted by the security monitor: {self.record.aborted})"
            await self.defense.finish()
        finally:
            for s in servers:
                s.cancel()
            for a in self.agents.values():
                for t in a.pending.values():
                    t.cancel()

    async def execute(self) -> RunRecord:
        self.record.t_start = time.time()
        try:
            await asyncio.wait_for(self._run(), timeout=self.case.budget.wall_clock_s)
        except TimeoutError:
            self.record.error = "timeout"
        except Exception as e:  # noqa: BLE001 - the record keeps the error, the batch goes on
            self.record.error = f"{type(e).__name__}: {e}"
        self.record.t_end = time.time()
        ctx = checks.CheckContext(
            env=self.env, final_output=self.record.final_output or "",
            tool_calls=[c for c in self.record.tool_calls if c.executed],
            messages=[m for m in self.record.messages if m.status == "delivered" and m.t_delivered is not None])
        try:
            self.record.utility = checks.score(self.env, self.case.scoring.utility, ctx)
            if self.case.scoring.security is not None:
                self.record.security = checks.score(self.env, self.case.scoring.security, ctx)
        except Exception as e:  # noqa: BLE001
            self.record.error = (self.record.error or "") + f" | scoring: {type(e).__name__}: {e}"
        for a in self.agents.values():
            a.stats.transcript = a.history
            self.record.agents.append(a.stats)
        self.record.defense_log = self.ctx.log
        self.record.sink = list(getattr(self.env, "sink", []))
        return self.record


__all__ = ["MASRun", "Turn"]
