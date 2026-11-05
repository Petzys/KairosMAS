"""masbench: format, B1 generation, runner semantics, defense hooks (no defense-specific code)."""
from __future__ import annotations

import asyncio
import json

import pytest

from masbench import io
from masbench.attacks import render_injections
from masbench.b1.partition import SUITES, TABLE_COUNTS
from masbench.env import make_environment
from masbench.runner.brains import ReplayWorker, Turn, _call
from masbench.runner.defense import REGISTRY, Defense, Verdict
from masbench.runner.mas import MASRun
from masbench.runner.run import RunConfig, run_batch
from masbench.schema import SCHEMAS, Case

SUITE_NAMES = list(SUITES)


@pytest.fixture(scope="module", params=SUITE_NAMES)
def suite(request: pytest.FixtureRequest) -> str:
    return request.param


def test_split_matches_multiagentdojo_table(suite: str) -> None:
    s = io.load_scenario(f"b1.{suite}")
    assert s.entry_agent.id == "orchestrator" and s.entry_agent.tools == []
    counts = {a.id: len(a.tools) for a in s.agents if not a.entry}
    assert counts == TABLE_COUNTS[suite]
    owned = [t for a in s.agents for t in a.tools]
    assert sorted(owned) == sorted(t.name for t in s.tools)  # every tool owned exactly once


def test_case_counts_match_agentdojo() -> None:
    cases = [c for name in SUITE_NAMES for c in io.load_cases(f"b1.{name}")]
    assert sum(c.kind == "benign" for c in cases) == 97
    assert sum(c.kind == "attack" for c in cases) == 629


def test_schema_files_are_current() -> None:
    for name, model in SCHEMAS.items():
        path = io.DATA.parent / "schema" / f"{name}.schema.json"
        assert json.loads(path.read_text()) == model.model_json_schema(), f"run `masbench.cli schema` ({name})"


def _direct(scenario, case: Case, attack: bool) -> tuple[bool, bool | None]:  # noqa: ANN001
    env = make_environment(scenario, case, render_injections(case, user="Emma Johnson", model_name="AI assistant"))
    plan, final = env.ground_truth(case.scoring.utility)
    if attack:
        plan = env.ground_truth(case.scoring.security)[0] + plan
    for f, a in plan:
        env.run_tool(f, a)
    sec = env.score(case.scoring.security, final, plan) if case.scoring.security else None
    return env.score(case.scoring.utility, final, plan), sec


@pytest.mark.parametrize("mode", ["sync", "async"])
def test_replay_through_agents_equals_direct_execution(suite: str, mode: str) -> None:
    """Routing every ground-truth call through the owning agent changes no score."""
    s = io.load_scenario(f"b1.{suite}")
    cases = io.load_cases(s.id)
    benign = [c for c in cases if c.kind == "benign"]
    attack = [c for c in cases if c.kind == "attack"][::9]
    for brain, sel in (("replay", benign), ("replay-attack", attack)):
        recs = asyncio.run(run_batch(s, sel, RunConfig(brain=brain, replay_mode=mode), None,
                                     concurrency=16, progress=False))
        by_id = {r.case: r for r in recs}
        for c in sel:
            r = by_id[c.id]
            assert r.error is None, (c.id, r.error)
            assert (r.utility, r.security) == _direct(s, c, brain == "replay-attack"), c.id
            if c.labels.workers:
                assert {m.receiver for m in r.messages if m.kind == "request"} >= set(c.labels.workers)


class _DenySends(Defense):
    name = "deny-sends"

    async def before_tool(self, call):  # noqa: ANN001, ANN201
        return Verdict.deny("no money") if call.function == "send_money" else Verdict.allow()

    async def on_message(self, msg):  # noqa: ANN001, ANN201
        if msg.receiver == "account":
            return Verdict.deny("account is off limits")
        return Verdict.allow()


def test_defense_hooks_block_tool_calls_and_messages() -> None:
    s = io.load_scenario("b1.banking")
    case = next(c for c in io.load_cases(s.id) if c.id == "b1.banking/user_task_0/injection_task_0")
    REGISTRY["deny-sends"] = _DenySends
    cfg = RunConfig(brain="replay-attack", defense="deny-sends")
    rec = asyncio.run(run_batch(s, [case], cfg, None, progress=False))[0]
    assert rec.security is False and rec.utility is False
    assert any(t.blocked_by_defense == "no money" for t in rec.tool_calls)

    case13 = next(c for c in io.load_cases(s.id) if c.id == "b1.banking/user_task_13")
    rec = asyncio.run(run_batch(s, [case13], RunConfig(brain="replay", defense="deny-sends"),
                                None, progress=False))[0]
    assert any(m.status == "rejected" and m.receiver == "account" for m in rec.messages)
    assert rec.utility is False


class _PingPong:
    """Calls the other agent synchronously once, then answers."""

    def __init__(self, other: str) -> None:
        self.other = other

    async def step(self, history, tools):  # noqa: ANN001, ANN201
        if history[-1]["role"] == "tool":
            return Turn(history[-1]["content"])
        return Turn(None, [_call("send_message", {"agent_id": self.other, "message": "ping"})])


def test_sync_cycle_fails_fast_instead_of_deadlocking() -> None:
    s = io.load_scenario("b1.slack")
    case = next(c for c in io.load_cases(s.id) if c.kind == "benign")
    env = make_environment(s, case, {})
    brains = {"orchestrator": _PingPong("slack"), "slack": _PingPong("orchestrator"), "web": ReplayWorker()}
    rec = asyncio.run(MASRun(s, case, env, Defense(), brains, "test").execute())
    assert rec.error is None
    assert "waiting for you" in rec.final_output




def test_masbench_imports_no_defense_code() -> None:
    """masbench stays defense-neutral: importing all of it loads no kairos module."""
    import subprocess
    import sys

    code = ("import sys, masbench.cli, masbench.runner.run, masbench.b1.generate; "
            "bad = sorted(m for m in sys.modules if m.split('.')[0] == 'kairos'); "
            "assert not bad, bad")
    subprocess.run([sys.executable, "-c", code], check=True)
