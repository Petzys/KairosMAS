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
  # agents on a rate-limited OpenAI-compatible endpoint, Claude Code (`claude -p`) as the oracle:
  python scripts/run_mas_benchmark.py --backend llm --model qwen3-30b-a3b-instruct-2507 \\
      --agent-base-url https://chat-ai.academiccloud.de/v1 --agent-api-key-env SAIA_API_KEY \\
      --agent-rpm 25 --agent-rph 190 --agent-max-requests 200 \\
      --oracle llm --judge-model claude-code:sonnet --judge-max-calls 60

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

from kairos.mas.bench.compat import system_role  # noqa: E402
from kairos.mas.bench.harness import RunConfig, run_suite, summarize  # noqa: E402
from kairos.mas.bench.limits import RateLimiter, limit_client  # noqa: E402
from kairos.mas.bench.oracles import ORACLES  # noqa: E402
from kairos.mas.bench.suites import LAYOUTS, SYSTEMS, BuildOptions, build_spec  # noqa: E402
from kairos.mas.claude_code import ClaudeCodeChatClient, cli_model, is_claude_code  # noqa: E402
from kairos.mas.oracle import VERDICT_SCHEMA  # noqa: E402
from kairos.mas.spec_parser import dump_spec  # noqa: E402
from kairos.mas.stub_llm import is_stub  # noqa: E402


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--suite", nargs="+", default=["banking"], help=f"{' '.join(SYSTEMS)} or all")
    p.add_argument("--layout", nargs="+", default=["domain"], choices=LAYOUTS)
    p.add_argument("--backend", default="scripted", choices=["scripted", "llm"])
    p.add_argument("--defense", nargs="+", default=["on"], choices=["on", "off"],
                   help="`on off` runs both conditions in one process (one request budget and pace)")
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
    p.add_argument("--judge-model", default="gpt-4o-mini",
                   help="llm oracle: a model name, `stub` (offline) or `claude-code[:<model>]` "
                        "(the Claude Code CLI, `claude -p`, on the user's plan)")
    p.add_argument("--judge-prompt", default="benchmark", choices=["benchmark", "production"])
    p.add_argument("--agent-base-url", default=None)
    p.add_argument("--agent-api-key-env", default="OPENROUTER_API_KEY")
    p.add_argument("--judge-base-url", default=None)
    p.add_argument("--judge-api-key-env", default="KAIROS_JUDGE_API_KEY")
    p.add_argument("--agent-rpm", type=int, default=None,
                   help="pace the agents' requests: at most N per minute (client side)")
    p.add_argument("--agent-rph", type=int, default=None, help="... and at most N per hour")
    p.add_argument("--agent-max-requests", type=int, default=None,
                   help="request budget of this invocation at the agents' endpoint; no task starts "
                        "that might not fit into what is left")
    p.add_argument("--task-reserve", type=int, default=40,
                   help="requests one task may need (budget and pacing checks before each task); "
                        "raised to the most any finished task used")
    p.add_argument("--judge-max-calls", type=int, default=None,
                   help="oracle call budget of this invocation (claude-code judge): no task starts "
                        "once it is spent")
    p.add_argument("--dump-spec", default=None, metavar="DIR",
                   help="write the generated system specs (YAML) for the chosen suites and layouts, then exit")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p.parse_args()


_NO_KEY = ("; to run every LLM code path offline without a key, use the stub provider: "
           "--model stub / --judge-model stub (see .env.example)")


def _clients(args: argparse.Namespace):
    """Agent and judge clients (only for the llm backend / llm oracle), the agents'
    rate limiter and the claude-code judge (each None when not used). The agents'
    client is metered; the offline `stub` model needs no client here: each task
    builds its own. The claude-code judge keeps its own account (per task in the
    results), apart from the agents' tokens."""
    none = (None, None, None, None, None)
    if args.backend != "llm" and args.oracle != "llm":
        return none
    import openai

    from kairos.adapters.agentdojo.telemetry import TokenMeter, instrument_client
    meter = TokenMeter()
    client = limiter = None
    if args.backend == "llm" and not is_stub(args.model):
        if args.agent_rpm or args.agent_rph or args.agent_max_requests is not None:
            limiter = RateLimiter(per_minute=args.agent_rpm, per_hour=args.agent_rph,
                                  budget=args.agent_max_requests)
        # with a limiter, the client's own HTTP retries are off: every attempt is counted
        opts: dict = {"max_retries": 0} if limiter is not None else {}
        base = args.agent_base_url or ("https://openrouter.ai/api/v1" if "/" in args.model else None)
        if base:
            key = os.environ.get(args.agent_api_key_env) or os.environ.get("OPENROUTER_API_KEY")
            if not key:
                sys.exit(f"ERROR: {args.model} routes to {base} but ${args.agent_api_key_env} is unset"
                         + _NO_KEY)
            # not OpenAI: its chat templates drop AgentDojo's `developer` messages
            raw = system_role(openai.OpenAI(base_url=base, api_key=key, **opts))
        else:
            if not os.environ.get("OPENAI_API_KEY"):
                sys.exit("ERROR: OPENAI_API_KEY not set" + _NO_KEY)
            raw = openai.OpenAI(**opts)
        client = instrument_client(limit_client(raw, limiter) if limiter is not None else raw, meter)
    judge_client = claude = None
    if args.oracle == "llm" and is_claude_code(args.judge_model):
        claude = judge_client = ClaudeCodeChatClient(cli_model(args.judge_model), json_schema=VERDICT_SCHEMA)
    elif args.oracle == "llm" and not is_stub(args.judge_model):
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
    return client, judge_client, meter, limiter, claude


def _guards(args: argparse.Namespace, limiter: RateLimiter | None, claude: ClaudeCodeChatClient | None):
    """run_suite's before_pair / after_pair hooks: stay inside the agents' request
    budget and rate limits (waiting between tasks, never inside one) and the judge's
    call budget; keep a task's account with its result; discard a task during which
    the budget ran out or the judge failed (it would measure that, not the monitor)."""
    if limiter is None and claude is None:
        return None, None
    state: dict = {"reserve": args.task_reserve}

    def before() -> str | None:
        if limiter is not None:
            if limiter.remaining is not None and limiter.remaining < state["reserve"]:
                return (f"agent request budget: {limiter.used} of {limiter.budget} spent, "
                        f"a task may need {state['reserve']}")
            limiter.wait_for_headroom(state["reserve"], on_wait=lambda sec: print(
                f"  waiting {sec / 60:.1f} min for room under the rate limits", flush=True))
        if claude is not None and args.judge_max_calls is not None and claude.usage.calls >= args.judge_max_calls:
            return f"judge call budget: {claude.usage.calls} of {args.judge_max_calls} calls spent"
        state["agent"] = limiter.used if limiter is not None else 0
        state["failures"] = len(limiter.failures) if limiter is not None else 0
        state["judge"] = claude.usage.snapshot() if claude is not None else None
        return None

    def after(r) -> str | None:
        if limiter is not None:
            used = limiter.used - state["agent"]
            r.metrics["agent_requests"] = used
            state["reserve"] = max(state["reserve"], used)
            if limiter.exhausted:
                return f"the agent request budget ran out during the task ({limiter.used} of {limiter.budget})"
            if len(limiter.failures) > state["failures"]:
                return f"the agents' endpoint failed a request: {limiter.failures[-1]}"
        if claude is not None:
            now, then = claude.usage.snapshot(), state["judge"]
            r.metrics["judge_usage"] = {k: round(now[k] - then[k], 4) for k in
                                        ("calls", "input_tokens", "output_tokens", "cost_usd", "seconds")}
            if now["errors"] > then["errors"]:
                return f"the claude-code judge failed: {claude.usage.errors[-1]}"
        return None

    return before, after


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

    client, judge_client, meter, limiter, claude = _clients(args)
    before_pair, after_pair = _guards(args, limiter, claude)
    logdir = Path(args.logdir)
    table = []
    for defense in args.defense:
        for s in suites:
            for layout in args.layout:
                cfg = RunConfig(
                    suite=s, layout=layout, backend=args.backend, defense=defense == "on",
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
                                 progress=not args.quiet, before_pair=before_pair, after_pair=after_pair)
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
    if limiter is not None:
        print(f"agent requests this run: {limiter.used}"
              + (f" of a budget of {limiter.budget}" if limiter.budget is not None else ""))
    if claude is not None:
        print(f"claude-code judge this run: {claude.usage.snapshot()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
