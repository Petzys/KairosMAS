#!/usr/bin/env bash
#
# AutoDojo replay against Kairos (tab:autodojo, attack success): the injections AutoDojo
# optimized against Kairos (run_opt_overnight.sh, cached in variants_v2) are replayed once per
# injection case with GPT-4o-mini as the agent and the GPT-4.1 oracle with the deployed oracle
# prompt. Results: benchmark/autodojo/agentdojo/variant_generation/runs_v2/ (archived copy:
# autodojo_runs/runs_v2/). Clean utility comes from run_static_clean_gpt4omini.sh.
#
#   evaluation/autodojo/run_replay.sh          # dry run
#   evaluation/autodojo/run_replay.sh --go
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VG="$REPO/benchmark/autodojo/agentdojo/variant_generation"
PY="$REPO/.venv/bin/python"
export PYTHONPATH="$REPO/benchmark/autodojo/agentdojo/src:$REPO${PYTHONPATH:+:$PYTHONPATH}"
export KAIROS_JUDGE_MODEL=gpt-4.1 KAIROS_MODE=full KAIROS_JUDGE=llm KAIROS_COMMIT=auto KAIROS_JUDGE_PROMPT=production
GO=0; [ "${1:-}" = "--go" ] && GO=1
[ -d "$VG" ] || { echo "benchmark/autodojo is missing: run ./setup.sh first" >&2; exit 1; }
cd "$VG" || exit 1
mkdir -p runs_v2
for S in banking slack travel; do
    CMD=(env AUTODOJO_CACHE="$VG/variants_v2/$S/openai/gpt-4o-mini/kairos/injections.json" AUTODOJO_VARIANT=0
         "$PY" -m agentdojo.scripts.benchmark --model openai/gpt-4o-mini --defense kairos --attack autodojo
         --suite "$S" --benchmark-version v1.2.2 --logdir ./runs_v2)
    echo "+ ${CMD[*]}"
    [ "$GO" = 1 ] && "${CMD[@]}" > "runs_v2/$S.log" 2>&1
done
[ "$GO" = 1 ] || echo "(dry run: add --go to run)"
