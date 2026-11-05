"""masbench command line.

    python -m masbench.cli generate                    # B1 scenario dirs from AgentDojo
    python -m masbench.cli policies                    # KAIROS MAS agent + cluster policies
    python -m masbench.cli schema                      # JSON Schemas -> masbench/schema/*.json
    python -m masbench.cli validate                    # validate every scenario directory
    python -m masbench.cli run -s b1.banking -l L-func --brain replay
    python -m masbench.cli run -s b1.banking -l L-func --model gpt-4.1-2025-04-14 --kind benign
    python -m masbench.cli summarize runs_masbench
"""
from __future__ import annotations

import argparse
import asyncio
import json
from collections import defaultdict
from pathlib import Path

from masbench import io
from masbench.schema import SCHEMAS, RunRecord

SCHEMA_DIR = Path(__file__).parent / "schema"


def cmd_schema(_: argparse.Namespace) -> None:
    SCHEMA_DIR.mkdir(exist_ok=True)
    for name, model in SCHEMAS.items():
        (SCHEMA_DIR / f"{name}.schema.json").write_text(json.dumps(model.model_json_schema(), indent=1) + "\n")
    print(f"wrote {len(SCHEMAS)} schemas to {SCHEMA_DIR}")


def scenario_ids() -> list[str]:
    return sorted(f"{p.parent.parent.name}.{p.parent.name}" for p in io.DATA.glob("*/*/scenario.yaml"))


def cmd_validate(_: argparse.Namespace) -> None:
    for sid in scenario_ids():
        s = io.load_scenario(sid)
        cases = io.load_cases(sid)
        layouts = io.load_layouts(sid)
        ids = {c.id for c in cases}
        agents = {a.id for a in s.agents}
        for c in cases:
            assert c.scenario == sid and c.user.agent in agents, c.id
            assert c.benign_twin is None or c.benign_twin in ids, c.id
            for inj in c.attacker.injections if c.attacker else []:
                assert inj.vector in s.environment.injection_vectors, (c.id, inj.vector)
        assert set(layouts.agents) == agents
        print(f"{sid}: ok ({len(s.agents)} agents, {len(cases)} cases, {len(layouts.layouts)} layouts)")


def cmd_run(a: argparse.Namespace) -> None:
    from masbench.runner.run import RunConfig, run_batch

    s = io.load_scenario(a.scenario)
    cases = io.load_cases(a.scenario)
    if a.kind:
        cases = [c for c in cases if c.kind == a.kind]
    if a.cases:
        cases = [c for c in cases if any(c.id.endswith("/" + x) or c.id == x for x in a.cases)]
    if a.limit:
        cases = cases[: a.limit]
    layout = io.load_layouts(a.scenario).get(a.layout) if a.layout else None
    cfg = RunConfig(brain=a.brain, model=a.model, base_url=a.base_url, api_key_env=a.api_key_env,
                    attack=a.attack, injection_model_name=a.injection_model_name, defense=a.defense,
                    defense_options=json.loads(a.defense_options), replay_mode=a.replay_mode,
                    extra_body=json.loads(a.extra_body))
    recs = asyncio.run(run_batch(s, cases, layout, cfg, Path(a.out), a.concurrency))
    _print_summary(recs)


def _print_summary(recs: list[RunRecord]) -> None:
    groups: dict[tuple, list[RunRecord]] = defaultdict(list)
    for r in recs:
        groups[(r.defense, r.model, r.layout, r.scenario)].append(r)
    for key, rs in sorted(groups.items(), key=lambda kv: tuple(map(str, kv[0]))):
        ben = [r for r in rs if r.security is None]
        att = [r for r in rs if r.security is not None]
        pct = lambda xs, f: f"{100 * sum(map(f, xs)) / len(xs):5.1f}" if xs else "    -"  # noqa: E731
        print(" | ".join(map(str, key)),
              f"| Ub {pct(ben, lambda r: bool(r.utility))} (n={len(ben)})",
              f"| U {pct(att, lambda r: bool(r.utility))} | ASR {pct(att, lambda r: bool(r.security))} (n={len(att)})",
              f"| errors {sum(bool(r.error) for r in rs)}")


def cmd_summarize(a: argparse.Namespace) -> None:
    recs = [RunRecord.model_validate_json(p.read_text()) for p in Path(a.dir).rglob("*.json")]
    _print_summary(recs)


def main() -> None:
    p = argparse.ArgumentParser(prog="masbench")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("generate").set_defaults(fn=lambda a: __import__("masbench.b1.generate").b1.generate.main())
    sub.add_parser("policies").set_defaults(
        fn=lambda a: print(len(__import__("masbench.policies.kairos_mas").policies.kairos_mas.write_all()), "files"))
    sub.add_parser("schema").set_defaults(fn=cmd_schema)
    sub.add_parser("validate").set_defaults(fn=cmd_validate)
    r = sub.add_parser("run")
    r.add_argument("-s", "--scenario", required=True)
    r.add_argument("-l", "--layout", default="L-func")
    r.add_argument("--brain", default="llm", choices=["llm", "replay", "replay-attack"])
    r.add_argument("--model", default="gpt-4.1-2025-04-14")
    r.add_argument("--base-url")
    r.add_argument("--api-key-env", default="OPENAI_API_KEY")
    r.add_argument("--extra-body", default="{}", help="JSON merged into each chat request")
    r.add_argument("--attack", help="override the cases' attack template")
    r.add_argument("--injection-model-name", help="name injections address the agent with")
    r.add_argument("--defense", default="undefended", help="undefended | <module>:<Class>")
    r.add_argument("--defense-options", default="{}")
    r.add_argument("--replay-mode", default="sync", choices=["sync", "async"])
    r.add_argument("--kind", choices=["benign", "attack"])
    r.add_argument("--cases", nargs="*", help="case ids or suffixes, e.g. user_task_0/injection_task_1")
    r.add_argument("--limit", type=int)
    r.add_argument("--concurrency", type=int, default=4)
    r.add_argument("--out", default="runs_masbench")
    r.set_defaults(fn=cmd_run)
    sm = sub.add_parser("summarize")
    sm.add_argument("dir")
    sm.set_defaults(fn=cmd_summarize)
    a = p.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
