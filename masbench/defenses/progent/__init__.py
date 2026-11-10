"""Progent (Shi et al.), lifted to every agent. Run R08.

Uses the Progent library itself (`secagent`, vendored in the AutoDojo fork of AgentDojo
under `benchmark/autodojo/.../progent_defense/`), in the way that fork's `--defense progent`
does: a policy model writes a least-privilege JSON-schema policy for the agent's tools from
the query, every tool call is checked against it, and after each executed call the policy
model may refine the policy.

Lifting to a MAS:
* One policy per agent, over that agent's tools. The query a policy is generated from is the
  request the agent is handling: the principal's prompt for the entry agent, the peer's
  request for every other agent. A new request regenerates the policy.
* Always-allowed tools are the agent's read-only tools (`effect: read`), from the scenario's
  annotations. (The fork lists them per AgentDojo suite by hand; for the four B1 suites
  those lists are almost exactly the read tools.)
* With `gate_messages`, an agent's `send_message` is a tool with a policy of its own and
  requests are checked in `on_message`. Off by default: Progent is a tool-call defense.

`secagent` keeps one policy in module globals. The adapter keeps each agent's state and
swaps it in under a lock, so Progent's own model calls run one at a time per process.

Options: `policy_model` (default: the run's `--model`), `base_url`, `api_key_env`,
`generate`, `update`, `gate_messages`, `secagent_path`.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import os
import sys
import threading
from pathlib import Path
from typing import Any

from masbench.runner.defense import Defense, Message, RunContext, ToolCall, Verdict

VENDORED = Path(__file__).resolve().parents[3] / "benchmark/autodojo/agentdojo/src/agentdojo/agent_pipeline/progent_defense"
_LOCK = threading.Lock()
SEND_TOOL = {"name": "send_message", "description": "Send a request to another agent of the team.",
             "args": {"agent_id": {"type": "string", "description": "Id of the agent to contact"},
                      "message": {"type": "string", "description": "The full request"}}}


def load_secagent(path: str | None, policy_model: str, base_url: str | None, api_key_env: str,
                  generate: bool) -> Any:
    root = Path(path) if path else VENDORED
    if not (root / "secagent").is_dir():
        raise RuntimeError(f"Progent's `secagent` library not found under {root}; run benchmarks/setup_benchmarks.sh "
                           "or pass the option `secagent_path`")
    os.environ["SECAGENT_POLICY_MODEL"] = policy_model
    os.environ["SECAGENT_GENERATE"] = "True" if generate else "False"
    if base_url:
        os.environ["SECAGENT_BASE_URL"] = base_url
        os.environ["SECAGENT_API_KEY"] = os.environ.get(api_key_env, "EMPTY")
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))
    import secagent.tool as tool  # noqa: PLC0415

    tool.policy_model, tool.generate_policy = policy_model, generate
    return tool


class Progent(Defense):
    name = "progent"
    run_id = "R08"

    def __init__(self, policy_model: str | None = None, base_url: str | None = None,
                 api_key_env: str = "OPENAI_API_KEY", generate: bool = True, update: bool = True,
                 gate_messages: bool = False, secagent_path: str | None = None, **options: Any) -> None:
        super().__init__(policy_model=policy_model, base_url=base_url, api_key_env=api_key_env, generate=generate,
                         update=update, gate_messages=gate_messages, **options)
        self.policy_model, self.base_url, self.api_key_env = policy_model, base_url, api_key_env
        self.generate, self.update, self.gate_messages, self.path = generate, update, gate_messages, secagent_path
        self.state: dict[str, dict[str, Any]] = {}  # agent -> secagent globals

    async def setup(self, ctx: RunContext) -> None:
        await super().setup(ctx)
        if not self.policy_model:
            raise ValueError("progent needs the option `policy_model` (and `base_url`, `api_key_env` for its endpoint)")
        self.sec = load_secagent(self.path, self.policy_model, self.base_url, self.api_key_env, self.generate)
        for a in ctx.scenario.agents:
            tools = [{"name": t.name, "description": t.description, "args": t.parameters.get("properties", {})}
                     for t in ctx.scenario.tools if t.name in a.tools]
            if self.gate_messages and ctx.scenario.contacts(a.id):
                tools.append(SEND_TOOL)
            self.state[a.id] = {"available_tools": tools, "security_policy": None, "init_user_query": None}

    def _with(self, agent: str, fn: Any, *args: Any) -> Any:
        """Run a secagent function on the agent's policy state (blocking; holds the lock)."""
        with _LOCK:
            sec, st = self.sec, self.state[agent]
            sec.policy_model, sec.generate_policy = self.policy_model, self.generate
            sec.available_tools, sec.security_policy, sec.init_user_query = (
                st["available_tools"], st["security_policy"], st["init_user_query"])
            before = (sec.total_prompt_tokens, sec.total_completion_tokens)
            try:
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                    return fn(*args)  # the library prints its prompts and policies
            finally:
                st["security_policy"], st["init_user_query"] = sec.security_policy, sec.init_user_query
                used = (sec.total_prompt_tokens - before[0], sec.total_completion_tokens - before[1])
                if any(used):
                    self.ctx.meter(1, *used)

    def _init_policy(self, agent: str, query: str) -> None:
        sec = self.sec
        sec.reset_security_policy()
        if self.generate:
            sec.generate_security_policy(query, manual_check=False)
        reads = [t.name for t in self.ctx.scenario.tools
                 if t.effect == "read" and t.name in self.ctx.scenario.agent(agent).tools]
        sec.update_always_allowed_tools(reads, allow_all_no_arg_tools=False)

    async def on_receive(self, msg: Message, text: str) -> str:
        if msg.kind == "request" and self.state[msg.receiver]["available_tools"]:
            try:
                await asyncio.to_thread(self._with, msg.receiver, self._init_policy, msg.receiver, text)
            except Exception as e:  # noqa: BLE001 - a failed generation leaves only the always-allowed tools
                self.ctx.event("policy", msg.receiver, "generation-failed", f"{type(e).__name__}: {e}")
            self.ctx.log.append({"agent": msg.receiver, "policy": _jsonable(self.state[msg.receiver]["security_policy"])})
        return text

    async def _check(self, agent: str, tool: str, args: dict[str, Any]) -> Verdict:
        try:
            await asyncio.to_thread(self._with, agent, self.sec.check_tool_call, tool, args)
        except self.sec.ValidationError as e:
            return Verdict.deny(f"Tool call blocked by security policy: {e}")
        return Verdict.allow()

    async def before_tool(self, call: ToolCall) -> Verdict:
        return await self._check(call.agent, call.function, call.args)

    async def after_tool(self, call: ToolCall, result: str) -> str:
        if self.update and self.generate and not result.startswith("Error: the call was blocked"):
            try:
                await asyncio.to_thread(self._with, call.agent, self.sec.generate_update_security_policy,
                                        [{"name": call.function, "args": call.args}], str([result]), False)
            except Exception as e:  # noqa: BLE001 - as SECAGENT_IGNORE_UPDATE_ERROR: keep the policy
                self.ctx.event("policy", call.agent, "update-failed", f"{type(e).__name__}: {e}", call.function)
        return result

    async def on_message(self, msg: Message) -> Verdict:
        if self.gate_messages and msg.kind == "request":
            return await self._check(msg.sender, "send_message", {"agent_id": msg.receiver, "message": msg.text})
        return Verdict.allow()


def _jsonable(policy: Any) -> Any:
    if policy is None:
        return None
    return {k: [list(p[:4]) for p in v] for k, v in policy.items()}


DEFENSE = Progent
