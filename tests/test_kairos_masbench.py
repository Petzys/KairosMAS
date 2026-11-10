"""KAIROS adapter for masbench: cluster layouts, KAIROS MAS policies, per-agent KAIROS baseline."""
from __future__ import annotations

import asyncio

import pytest
import yaml

from masbench.defenses.kairos import policies
from masbench.defenses.kairos.layouts import load_layouts, scenario_dir, set_partitions
from masbench import io
from masbench.b1.partition import SUITES
from masbench.runner.defense import load_defense
from masbench.runner.run import RunConfig, run_batch

BELL = {3: 5, 4: 15, 5: 52}


@pytest.fixture(scope="module", params=list(SUITES))
def suite(request: pytest.FixtureRequest) -> str:
    return request.param


def test_layouts(suite: str) -> None:
    ls = load_layouts(f"b1.{suite}")
    sweep = [lay for lay in ls.layouts if lay.strategy == "sweep"]
    assert len(sweep) == BELL[len(ls.agents)]
    assert {lay.id for lay in ls.layouts} >= {"L-single", "L-func", "L-crit", "L-one"}
    assert len(list(set_partitions(["a", "b", "c", "d"]))) == 15


def test_kairos_mas_policies_compose_back_to_suite_policy(suite: str) -> None:
    from kairos.policy.parser import parse_policy

    s = io.load_scenario(f"b1.{suite}")
    raw, source = policies.suite_policy(suite)
    agents = {a.id: policies.agent_policy(s, a.id, raw, source) for a in s.agents}
    tmpl = policies.cluster_template(s, raw, source)
    layouts = load_layouts(s.id)

    one = layouts.get("L-one")
    composed = policies.compose(list(agents.values()), policies.cluster_policy(s, one, "all", tmpl), suite)
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
            pol = policies.cluster_policy(s, lay, c, tmpl)
            parse_policy(policies.compose([agents[m] for m in members], pol, f"{suite}:{c}"))
            assert set(pol["contact_book"]["clusters"]) == set(lay.clusters) - {c}


def test_written_policies_are_current(suite: str) -> None:
    s = io.load_scenario(f"b1.{suite}")
    raw, source = policies.suite_policy(suite)
    base = scenario_dir(f"b1.{suite}")
    for a in s.agents:
        assert yaml.safe_load((base / "agents" / f"{a.id}.yaml").read_text()) == \
            policies.agent_policy(s, a.id, raw, source), "run `python -m masbench.defenses.kairos`"


def test_kairos_per_agent_peer_trust_dilemma() -> None:
    """Replayed attack: relayed IBAN launders through trusted peers, is held when untrusted."""
    s = io.load_scenario("b1.banking")
    case = next(c for c in io.load_cases(s.id) if c.id == "b1.banking/user_task_0/injection_task_0")
    out = {}
    for trust in ("trusted", "untrusted"):
        cfg = RunConfig(brain="replay-attack", defense="kairos-per-agent",
                        defense_options={"judge_model": "deterministic", "peer_trust": trust})
        rec = asyncio.run(run_batch(s, [case], cfg, None, progress=False))[0]
        assert rec.error is None, rec.error
        out[trust] = rec
    assert out["trusted"].security is True
    assert out["untrusted"].security is False
    assert any(t.defense_note == "held" and t.function == "send_money" for t in out["untrusted"].tool_calls)


def test_kairos_per_agent_loads_by_entry_point_name() -> None:
    d = load_defense("kairos-per-agent", judge_model="deterministic")
    assert type(d).__module__ == "masbench.defenses.kairos.per_agent"
