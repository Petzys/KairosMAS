# Kairos: artifact

Code, run records and analysis scripts for the paper *Kairos: Transactional Security Enforcement
at the System Boundary for LLM Agents*.

The evaluation relies on hosted models that providers may change or retire, so this repository
contains the per-task record of every run behind a reported number. Every number can be
recomputed from these records in a few minutes, without API keys (first section below). The
remaining sections describe how to repeat the runs.

## Contents

| Path | What it is |
|---|---|
| `kairos/` | The reference monitor: policy engine, provenance tracking, speculative state machine, oracle, and the benchmark and deployment adapters |
| `deploy/` | The deployed stack: microVM, file channel (OverlayFS, FUSE, write-ahead log), network channel (mitmproxy), control plane, latency benchmarks ([overview](deploy/README.md), [usage](deploy/docs/USAGE.md)) |
| `scripts/run_benchmark.py` | Runs one AgentDojo or AgentDyn suite with or without Kairos |
| `evaluation/` | Driver scripts for every reported run set, the AgentDyn policies, and the analysis scripts |
| `benchmarks/` | Setup script and patches for the three benchmarks, which are fetched rather than copied |
| `policies_used/` | The policy files the archived runs were evaluated with |
| `env/` | Exact package versions of the two Python environments the runs used |
| `tests/` | Unit tests |
| `runs/`, `runs_models/`, `runs_judge/`, `evaluation/*/runs/`, `autodojo_runs/`, `production_runs/` | Run records, listed in [DATA.md](DATA.md) |

## Verify the reported numbers

The analysis scripts use only the Python standard library and read the archived records:

```bash
python3 evaluation/summarize_runs.py main         # tab:agentdojo-main and the per-suite tab:main
python3 evaluation/summarize_runs.py agentdyn     # tab:agentdyn, Kairos row
python3 evaluation/summarize_runs.py autodojo     # tab:autodojo, Kairos row
python3 evaluation/summarize_runs.py strict       # strict monitor
python3 evaluation/summarize_runs.py placement    # tab:model-grid and tab:placement
python3 evaluation/cost_and_decisions.py decisions  # tab:decisions and fig:decisions
python3 evaluation/cost_and_decisions.py tokens     # token overhead
python3 evaluation/cost_and_decisions.py latency    # file-channel and proxy latency
python3 evaluation/cost_and_decisions.py retention  # AgentDyn utility retained after held effects
```

Rates are percentages per suite; a table value is the unweighted mean over the suites, and NRP is
computed from the table values rounded to one decimal, as in the paper. Rows marked with a dagger in the AgentDyn and AutoDojo tables
are values published by those benchmarks and are not recomputed here.

## Repeat the runs

**Setup.** Linux, git, [uv](https://docs.astral.sh/uv/) and Python 3.12:

```bash
./setup.sh                      # benchmarks at pinned commits, .venv and .venv-camel
# fill in the API keys in .env, then
set -a; . ./.env; set +a
```

`setup.sh` fetches AgentDojo, AutoDojo and AgentDyn at the commits the evaluation used and
applies the patches in `benchmarks/patches/` (see [benchmarks/README.md](benchmarks/README.md)).
CaMeL runs in its own environment because it pins conflicting package versions.

**Run sets.** Each driver prints its commands when called without `--go`. Results are stored per
task, so an interrupted run resumes where it stopped.

| Reported in | Run set | Command |
|---|---|---|
| tab:agentdojo-main, tab:decisions | GPT-4.1, Kairos and the undefended agent | `evaluation/run_agentdojo_gpt41.sh main --go` |
| tab:agentdojo-main | GPT-4.1, comparison defenses | `evaluation/baselines/run_baseline.sh`, then `evaluation/baselines/run_progent_benign_gpt41.sh` |
| tab:agentdojo-main | Qwen3.6-35B and Llama-3.3-70B, Kairos and undefended | `evaluation/run_models_sweep.sh` (`resume_models_sweep.sh` to finish failed cells) |
| tab:agentdojo-main | Qwen3.6-35B and Llama-3.3-70B, comparison defenses | `evaluation/baselines/run_defenses_models.sh` (attack), `run_defenses_benign_open_parallel.sh` (benign); `resume_defenses_llama_qwen.sh` and `finish_*.sh` finish interrupted cells |
| tab:model-grid, tab:placement | Qwen3.5 agents and oracles, Banking | `evaluation/run_judge_matrix.sh --go` |
| tab:agentdyn, retention | GPT-4o, Kairos with honest hold notices | `KAIROS_AGENT_MODEL=gpt-4o-2024-08-06 KAIROS_HOLD_NOTICE=honest evaluation/agentdyn/run_agentdyn.sh --go` |
| retention | GPT-4o, undefended, benign | see below |
| tab:autodojo | GPT-4o-mini, injections optimized against Kairos, then replayed | `evaluation/autodojo/run_opt_overnight.sh banking slack travel`, then `evaluation/autodojo/run_replay.sh --go` |
| tab:autodojo | GPT-4o-mini, clean utility | `evaluation/autodojo/run_static_clean_gpt4omini.sh --go` |
| strict monitor, token overhead | GPT-4.1, matched set: undefended, strict, full | `evaluation/run_agentdojo_gpt41.sh matched --go` |
| latency | deployed stack | `deploy/bench/latency.py` on a running stack ([how](deploy/bench/README.md)) |

The undefended AgentDyn benign runs used the runner directly:

```bash
for s in github shopping dailylife; do
  .venv/bin/python scripts/run_benchmark.py --benchmark-src benchmark/agentdyn/src --suite $s \
      --model gpt-4o-2024-08-06 --defense off --no-attack --system-message agentdojo-default \
      --logdir evaluation/agentdyn/runs
done
```

## Tests

```bash
.venv/bin/python -m pytest tests
```
