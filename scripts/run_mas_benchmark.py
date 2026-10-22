"""MASDojo: evaluate KAIROS MAS on AgentDojo's suites lifted to multi-agent systems.

Each run is a grid over suites x cluster layouts for one configuration. Results are
stored per (user task, injection task) under --logdir/<config tag>/<suite>/, so an
interrupted run resumes, and a summary per suite is printed and saved.

  # deterministic, no API key needed (scripted agents, ideal oracle):
  python scripts/run_mas_benchmark.py --suite all --layout one domain singleton
  python scripts/run_mas_benchmark.py --suite banking --defense off
  # LLM agents and the LLM oracle:
  python scripts/run_mas_benchmark.py --backend llm --model gpt-4o-mini --oracle llm \\
      --suite banking --layout domain
  # the same code paths offline, without an API key (stub model; not a measurement):
  python scripts/run_mas_benchmark.py --backend llm --model stub --oracle llm --judge-model stub

Reported per suite:
  utility        % benign user tasks solved
  utility_att    % user tasks solved under attack
  asr            % injection tasks whose effect became externally visible (lower is better)
  oracle         mean oracle calls per task (benign / attacked)
  msgs           mean inter-cluster messages per task, held and rejected among them
  exposed        mean agents / clusters that read the injected payload
  stopped        mean withheld actions at the cluster boundary / at the external boundary
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))

_src = os.environ.get("KAIROS_BENCHMARK_SRC")
for i, a in enumerate(sys.argv):
    if a == "--benchmark-src" and i + 1 < len(sys.argv):
        _src = sys.argv[i + 1]
if _src:
    sys.path.insert(0, str(Path(_src).resolve()))

from kairos.mas.bench.harness import RunConfig, run_suite, summarize  # noqa: E402
from kairos.mas.bench.oracles import ORACLES  # noqa: E402
from kairos.mas.bench.suites import LAYOUTS, SYSTEMS, BuildOptions, build_spec  # noqa: E402
from kairos.mas.spec_parser import dump_spec  # noqa: E402
from kairos.mas.stub_llm import is_stub  # noqa: E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--suite", nargs="+", default=["banking"], help=f"{' '.join(SYSTEMS)} or all")
    p.add_argument("--layout", nargs="+", default=["domain"], choices=LAYOUTS)
    p.add_argument("--backend", default="scripted", choices=["scripted", "llm"])
    p.add_argument("--defense", default="on", choices=["on", "off"])
    p.add_argument("--oracle", default="gt", choices=ORACLES)
    p.add_argument("--dispatch", default="sync", choices=["sync", "stream", "parallel"],
                   help="scripted entry agent: blocking sends, streamed sends awaited one by one, "
                        "or one streamed task per specialist in parallel")
    p.add_argument("--attack", default="important_instructions")
    p.add_argument("--no-attack", action="store_true", help="benign tasks only")
    p.add_argument("--attack-only", action="store_true", help="attacked pairs only")
    p.add_argument("--hold-notice", default="honest", choices=["honest", "success"])
    p.add_argument("--max-held-per-branch", type=int, default=1)
    p.add_argument("--message-identifiers", default="review", choices=["review", "allow"])
    p.add_argument("--message-review", default="policy", choices=["policy", "all"])
    p.add_argument("--user-tasks", nargs="*", default=None)
    p.add_argument("--injection-tasks", nargs="*", default=None)
    p.add_argument("--logdir", default=str(REPO_ROOT / "runs_mas"))
    p.add_argument("--force", action="store_true", help="ignore stored results")
    p.add_argument("--tool-latency", type=float, default=0.0, help="seconds per tool call")
    p.add_argument("--timeout", type=float, default=300.0, help="per task")
    p.add_argument("--benchmark-version", default="v1")
    p.add_argument("--benchmark-src", default=None, help="alternate agentdojo src (as run_benchmark.py)")
    p.add_argument("--model", default="gpt-4o-mini", help="llm backend: the agents' model")
    p.add_argument("--judge-model", default="gpt-4o-mini")
    p.add_argument("--judge-prompt", default="benchmark", choices=["benchmark", "production"])
    p.add_argument("--agent-base-url", default=None)
    p.add_argument("--agent-api-key-env", default="OPENROUTER_API_KEY")
    p.add_argument("--judge-base-url", default=None)
    p.add_argument("--judge-api-key-env", default="KAIROS_JUDGE_API_KEY")
    p.add_argument("--dump-spec", default=None, metavar="DIR",
                   help="write the generated system specs (YAML) for the chosen suites and layouts, then exit")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


_NO_KEY = ("; to run every LLM code path offline without a key, use the stub provider: "
           "--model stub / --judge-model stub (see .env.example)")


def _clients(args: argparse.Namespace):
    """Agent and judge clients, metered (only for the llm backend / llm oracle). The
    offline `stub` model needs no client here: each task builds its own."""
    if args.backend != "llm" and args.oracle != "llm":
        return None, None, None
    import openai

    from kairos.adapters.agentdojo.telemetry import TokenMeter, instrument_client
    meter = TokenMeter()
    client = None
    if args.backend == "llm" and not is_stub(args.model):
        base = args.agent_base_url or ("https://openrouter.ai/api/v1" if "/" in args.model else None)
        if base:
            key = os.environ.get(args.agent_api_key_env) or os.environ.get("OPENROUTER_API_KEY")
            if not key:
                sys.exit(f"ERROR: {args.model} routes to {base} but ${args.agent_api_key_env} is unset"
                         + _NO_KEY)
            client = instrument_client(openai.OpenAI(base_url=base, api_key=key), meter)
        else:
            if not os.environ.get("OPENAI_API_KEY"):
                sys.exit("ERROR: OPENAI_API_KEY not set" + _NO_KEY)
            client = instrument_client(openai.OpenAI(), meter)
    judge_client = None
    if args.oracle == "llm" and not is_stub(args.judge_model):
        if args.judge_base_url:
            key = os.environ.get(args.judge_api_key_env) or os.environ.get("OPENAI_API_KEY")
            if not key:
                sys.exit(f"ERROR: --judge-base-url needs ${args.judge_api_key_env} or $OPENAI_API_KEY"
                         + _NO_KEY)
            judge_client = instrument_client(openai.OpenAI(base_url=args.judge_base_url, api_key=key), meter)
        else:
            if not os.environ.get("OPENAI_API_KEY"):
                sys.exit("ERROR: the llm oracle needs OPENAI_API_KEY (or --judge-base-url)" + _NO_KEY)
            judge_client = instrument_client(openai.OpenAI(), meter)
    return client, judge_client, meter


def _fmt(v, suffix=""):
    return "-" if v is None else f"{v}{suffix}"


def main() -> int:
    args = parse_args()
    suites = list(SYSTEMS) if args.suite == ["all"] else args.suite
    for s in suites:
        if s not in SYSTEMS:
            print(f"ERROR: unknown suite {s!r} ({', '.join(SYSTEMS)})", file=sys.stderr)
            return 2
    if args.dump_spec:
        out = Path(args.dump_spec)
        out.mkdir(parents=True, exist_ok=True)
        for s in suites:
            for layout in args.layout:
                spec = build_spec(s, BuildOptions(layout=layout, message_identifiers=args.message_identifiers,
                                                  message_review=args.message_review))
                path = out / f"{s}-{layout}.yaml"
                path.write_text(dump_spec(spec))
                print(f"wrote {path}")
        return 0

    client, judge_client, meter = _clients(args)
    logdir = Path(args.logdir)
    table = []
    for s in suites:
        for layout in args.layout:
            cfg = RunConfig(
                suite=s, layout=layout, backend=args.backend, defense=args.defense == "on",
                oracle=args.oracle, dispatch=args.dispatch,
                attack="" if args.no_attack else args.attack, hold_notice=args.hold_notice,
                max_held_per_branch=args.max_held_per_branch,
                message_identifiers=args.message_identifiers, message_review=args.message_review,
                model=args.model, judge_model=args.judge_model, judge_prompt=args.judge_prompt,
                tool_latency=args.tool_latency, timeout=args.timeout,
                benchmark_version=args.benchmark_version)
            print(f"== {cfg.tag()} / {s}", flush=True)
            rows = run_suite(cfg, logdir=logdir, user_tasks=args.user_tasks,
                             injection_tasks=args.injection_tasks, benign=not args.attack_only,
                             attacked=not args.no_attack, force=args.force, client=client,
                             judge_client=judge_client, meter=meter, verbose=args.verbose,
                             progress=not args.quiet)
            summary = summarize(rows)
            (logdir / cfg.tag() / s).mkdir(parents=True, exist_ok=True)
            (logdir / cfg.tag() / s / "summary.json").write_text(json.dumps(summary, indent=1))
            table.append((s, layout, cfg, summary))

    print()
    print(f"{'suite':10} {'layout':9} {'defense':8} {'utility':>7} {'util_att':>8} {'asr':>6} "
          f"{'oracle b/a':>11} {'msgs':>6} {'held':>5} {'rej':>5} {'exposed a/c':>12} {'stopped c/e':>12}")
    for s, layout, cfg, sm in table:
        d = f"{cfg.oracle}" if cfg.defense else "off"
        print(f"{s:10} {layout:9} {d:8} {_fmt(sm['utility']):>7} {_fmt(sm['utility_under_attack']):>8} "
              f"{_fmt(sm['asr']):>6} {_fmt(sm['oracle_calls_benign'])+'/'+_fmt(sm['oracle_calls_attacked']):>11} "
              f"{_fmt(sm['inter_cluster_messages']):>6} {_fmt(sm['held_messages']):>5} "
              f"{_fmt(sm['rejected_messages']):>5} "
              f"{_fmt(sm['exposed_agents'])+'/'+_fmt(sm['exposed_clusters']):>12} "
              f"{_fmt(sm['stopped_at_cluster_boundary'])+'/'+_fmt(sm['stopped_at_external_boundary']):>12}")
        if sm["not_quiescent"]:
            print(f"   WARNING: {sm['not_quiescent']} task(s) did not reach quiescence")
    if meter is not None:
        print(f"\ntokens (last task): {meter.snapshot()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
