#!/usr/bin/env bash
#
# AutoDojo re-optimisation for the remaining suites, unattended.
#
#   set -a; . .env; set +a
#   nohup evaluation/autodojo/run_opt_overnight.sh slack travel > /dev/null 2>&1 &
#
# Suites run SEQUENTIALLY on purpose: the optimiser is already serial (kairos is
# not registered parallel-safe) and running two at once only multiplies the rate
# limit pressure against the same OpenRouter key, which is the most likely way an
# unattended run dies.
#
# Every cell is saved to injections.json as it completes, and --resume loads that
# back, so an interruption -- rate limit, credit exhaustion, a dropped connection
# -- costs at most the cell in flight. Re-running this script after a failure
# picks up where it stopped.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
VG="$REPO/benchmark/autodojo/agentdojo/variant_generation"
PY="$REPO/.venv/bin/python"
LOGDIR="$REPO/evaluation/autodojo"

export PYTHONPATH="$REPO/benchmark/autodojo/agentdojo/src:$REPO"
export KAIROS_JUDGE_MODEL=gpt-4.1
export KAIROS_MODE=full KAIROS_JUDGE=llm KAIROS_COMMIT=auto
export KAIROS_JUDGE_PROMPT=production          # the deployed oracle prompt
export AUTODOJO_OUTPUT_DIR="$VG/variants_v2"

for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v is unset — source .env before nohup" >&2; exit 2; }
done

cd "$VG" || exit 1
for S in "$@"; do
    echo "=== $(date -Is)  optimising $S ==="
    "$PY" optimize_variants.py \
        --suite "$S" --defense kairos --run-defense \
        --target-model openai/gpt-4o-mini \
        --model google/gemini-3.1-pro-preview \
        --iterations 6 --n-variants 5 --eval-asr --resume \
        > "$LOGDIR/opt_v2_$S.log" 2>&1
    rc=$?
    echo "=== $(date -Is)  $S finished rc=$rc ==="
    cost="$AUTODOJO_OUTPUT_DIR/$S/openai/gpt-4o-mini/kairos/run_cost.json"
    [ -f "$cost" ] && echo "    cost: $(cat "$cost" | head -c 200)"
    [ "$rc" -ne 0 ] && echo "    !! non-zero exit; re-run this script to resume $S"
done
echo "=== $(date -Is)  all done ==="
