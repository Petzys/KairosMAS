"""masbench: format, B1 generation, runner semantics, defense hooks, KAIROS MAS policies."""
from __future__ import annotations

import asyncio
import json

import pytest
import yaml

from masbench import io
from masbench.attacks import render_injections
from masbench.b1.partition import SUITES, TABLE_COUNTS
from masbench.env import make_environment
from masbench.layouts import set_partitions
from masbench.policies import kairos_mas
from masbench.runner.brains import ReplayWorker, Turn, _call
from masbench.runner.defense import REGISTRY, Defense, Verdict
from masbench.runner.mas import MASRun
from masbench.runner.run import RunConfig, run_batch
from masbench.schema import SCHEMAS, Case

SUITE_NAMES = list(SUITES)
BELL = {3: 5, 4: 15, 5: 52}


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


def test_layouts(suite: str) -> None:
    ls = io.load_layouts(f"b1.{suite}")
    sweep = [lay for lay in ls.layouts if lay.strategy == "sweep"]
    assert len(sweep) == BELL[len(ls.agents)]
    assert {lay.id for lay in ls.layouts} >= {"L-single", "L-func", "L-crit", "L-one"}
    assert len(list(set_partitions(["a", "b", "c", "d"]))) == 15


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
    layout = io.load_layouts(s.id).get("L-func")
    for brain, sel in (("replay", benign), ("replay-attack", attack)):
        recs = asyncio.run(run_batch(s, sel, layout, RunConfig(brain=brain, replay_mode=mode), None,
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
    rec = asyncio.run(run_batch(s, [case], None, cfg, None, progress=False))[0]
    assert rec.security is False and rec.utility is False
    assert any(t.blocked_by_defense == "no money" for t in rec.tool_calls)

    case13 = next(c for c in io.load_cases(s.id) if c.id == "b1.banking/user_task_13")
    rec = asyncio.run(run_batch(s, [case13], None, RunConfig(brain="replay", defense="deny-sends"),
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
    rec = asyncio.run(MASRun(s, case, env, Defense(), brains, None, "test").execute())
    assert rec.error is None
    assert "waiting for you" in rec.final_output


def test_kairos_mas_policies_compose_back_to_suite_policy(suite: str) -> None:
    from kairos.policy.parser import parse_policy

    s = io.load_scenario(f"b1.{suite}")
    raw, source = kairos_mas.suite_policy(suite)
    agents = {a.id: kairos_mas.agent_policy(s, a.id, raw, source) for a in s.agents}
    tmpl = kairos_mas.cluster_template(s, raw, source)
    layouts = io.load_layouts(s.id)

    one = layouts.get("L-one")
    composed = kairos_mas.compose(list(agents.values()), kairos_mas.cluster_policy(s, one, "all", tmpl), suite)
    a, b = parse_policy(composed), parse_policy(raw)
    assert sorted(a.context.revertable) == sorted(b.context.revertable)
    assert sorted(a.context.non_revertable) == sorted(b.context.non_revertable)
    assert a.context.default_action == b.context.default_action
    assert a.context.navigational_get == b.context.navigational_get
    assert a.context.embedded_identifiers == b.context.embedded_identifiers
    assert sorted(t.name for t in a.resources.taints) == sorted(t.name for t in b.resources.taints)
    assert a.resources.contact_book == b.resources.contact_book
    assert a.rules == b.rules

    for lay in layouts.layouts:  # every partition, including the sweep, yields valid policies
        for c, members in lay.clusters.items():
            pol = kairos_mas.cluster_policy(s, lay, c, tmpl)
            parse_policy(kairos_mas.compose([agents[m] for m in members], pol, f"{suite}:{c}"))
            assert set(pol["contact_book"]["clusters"]) == set(lay.clusters) - {c}


def test_written_policies_are_current(suite: str) -> None:
    s = io.load_scenario(f"b1.{suite}")
    raw, source = kairos_mas.suite_policy(suite)
    base = kairos_mas.OUT / "b1" / suite
    for a in s.agents:
        assert yaml.safe_load((base / "agents" / f"{a.id}.yaml").read_text()) == \
            kairos_mas.agent_policy(s, a.id, raw, source), "run `masbench.cli policies`"


def test_kairos_per_agent_peer_trust_dilemma() -> None:
    """Replayed attack: relayed IBAN launders through trusted peers, is held when untrusted."""
    s = io.load_scenario("b1.banking")
    case = next(c for c in io.load_cases(s.id) if c.id == "b1.banking/user_task_0/injection_task_0")
    out = {}
    for trust in ("trusted", "untrusted"):
        cfg = RunConfig(brain="replay-attack", defense="kairos-per-agent",
                        defense_options={"judge_model": "deterministic", "peer_trust": trust})
        rec = asyncio.run(run_batch(s, [case], None, cfg, None, progress=False))[0]
        assert rec.error is None, rec.error
        out[trust] = rec
    assert out["trusted"].security is True
    assert out["untrusted"].security is False
    assert any(t.defense_note == "held" and t.function == "send_money" for t in out["untrusted"].tool_calls)
