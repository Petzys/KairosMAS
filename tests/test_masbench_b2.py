"""B2: the generated cases match the catalogue, and every case's ground truth replays."""
from __future__ import annotations

import asyncio
import subprocess
import sys

import pytest

from masbench import io
from masbench.b2.build import CATALOG, CORE, SEEDS
from masbench.b2.generate import build_all
from masbench.checks import path_crossed
from masbench.env import make_environment
from masbench.runner.run import RunConfig, run_batch

# Core cases whose attacker side is supplied as a seed file (masbench/b2/seeds/<core_id>.yaml).
# Without the file only their benign twin exists.
DEFERRED = {"B2-01", "B2-02", "B2-03", "B2-04", "B2-05", "B2-06", "B2-21", "B2-22", "B2-23", "B2-24",
            "B2-25", "B2-26", "B2-43", "B2-44", "B2-47"}
BUILT = build_all()
SCENARIOS = [s.id for s, _ in BUILT]


def test_data_files_are_current() -> None:
    for scn, cases in BUILT:
        assert io.load_scenario(scn.id) == scn, f"run `masbench.cli generate b2` ({scn.id})"
        assert io.load_cases(scn.id) == cases, f"run `masbench.cli generate b2` ({scn.id})"


def test_every_core_case_has_attack_twin_and_controls() -> None:
    cases = [c for _, cs in BUILT for c in cs]
    by_core: dict[str, list] = {}
    for c in cases:
        by_core.setdefault(c.labels.core_id, []).append(c)
    assert set(by_core) == set(CORE)
    for core_id, cs in by_core.items():
        row = CORE[core_id]
        if core_id in DEFERRED and not (SEEDS / f"{core_id}.yaml").exists():
            assert [c.kind for c in cs] == ["benign"], core_id
            continue
        assert sorted(c.kind for c in cs if c.kind != "control") == ["attack", "benign"], core_id
        assert {c.labels.case_id for c in cs if c.kind == "control"} == set(filter(None, row["controls"].split(";")))
        for c in cs:
            lab = c.labels
            assert (lab.primary_class, lab.origin, lab.adversary, lab.shared_board, lab.source) == (
                row["primary_class"], row["origin"], row["adversary"], row["shared_board"], row["source"]), c.id
            assert lab.case_id in CATALOG and lab.payload_source in ("verbatim", "adapted", "written") and lab.path_agents
            if c.attacker:
                assert c.attacker.position == row["adversary"]
                assert bool(c.attacker.compromised_agents) or "A3" not in row["adversary"] or c.kind == "control"
        assert "expected_mechanism" not in cs[0].model_dump_json()  # defense-specific, stays in the notes


@pytest.mark.parametrize("sid", SCENARIOS)
def test_ground_truth_replays(sid: str) -> None:
    """Attack script -> attacker goal met along the attack path; twin -> task done; control ->
    goal not met."""
    s, cases = io.load_scenario(sid), io.load_cases(sid)
    recs = {r.case: r for r in asyncio.run(run_batch(s, cases, RunConfig(brain="replay"), None, progress=False))}
    boards = {b.id: [t.name for t in s.tools if t.board == b.id] for b in s.boards}
    for c in cases:
        r = recs[c.id]
        assert r.error is None, (c.id, r.error)
        if c.kind == "attack":
            assert r.security is True, c.id
            assert path_crossed(c.labels.path_agents, [t for t in r.tool_calls if t.executed], r.messages, boards), c.id
        elif c.kind == "benign":
            assert r.utility is True and r.security is None, c.id
        else:
            assert r.security is False, c.id


@pytest.mark.parametrize("sid", [s for s in SCENARIOS if io.load_scenario(s).environment.kind == "python"])
def test_environment_reset_is_deterministic(sid: str) -> None:
    s = io.load_scenario(sid)
    for c in io.load_cases(sid):
        injections = {i.vector: i.text for i in c.attacker.injections} if c.attacker else {}
        a, b = make_environment(s, c, injections), make_environment(s, c, injections)
        assert (a.state, a.boards, a.sink) == (b.state, b.boards, b.sink), c.id
        vectors = set(s.environment.injection_vectors)
        assert set(injections) <= vectors, c.id


def test_simulated_b2_needs_neither_a_defense_nor_agentdojo() -> None:
    code = ("import sys, asyncio; from masbench import io; from masbench.runner.run import RunConfig, run_batch; "
            "s = io.load_scenario('b2.pipeline'); "
            "cases = [c for c in io.load_cases(s.id) if not (c.attacker and any(i.attack for i in c.attacker.injections))]; "
            "asyncio.run(run_batch(s, cases, RunConfig(brain='replay'), None, progress=False)); "
            "bad = sorted(m for m in sys.modules if m.split('.')[0] in ('kairos', 'agentdojo') "
            "or m.startswith('masbench.defenses')); assert not bad, bad")
    subprocess.run([sys.executable, "-c", code], check=True)
