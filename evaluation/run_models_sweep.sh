#!/usr/bin/env bash
#
# Block C1 — AgentDojo model replication, unattended.
#
#   set -a; . .env; set +a
#   nohup evaluation/run_models_sweep.sh > evaluation/logs/sweep.log 2>&1 &
#   disown
#
# Four cells per (model, suite), because a defended number alone cannot be
# interpreted: utility depends on how well the model does the task at all, which
# varies enormously across models.
#
#   defended-attack    ASR and utility under enforcement          -> the headline
#   defended-benign    utility with no injection                  -> false-positive cost
#   undefended-benign  the model's CLEAN utility ceiling          -> the reference
#   undefended-attack  ASR with no monitor                        -> the denominator
#
set -uo pipefail


CHILD=""
_cleanup() {
    trap - TERM INT EXIT
    [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null
    echo "=== $(date -Is)  interrupted; in-flight cell killed ==="
    exit 130
}
trap _cleanup TERM INT

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$REPO/.venv/bin/python"
LOGS="$REPO/evaluation/logs"
mkdir -p "$LOGS"
cd "$REPO" || exit 1

AGENTS=(
  # "gpt-4.1"                             # re-measured under the current code
  "meta-llama/llama-3.3-70b-instruct"
  "qwen/qwen3.6-35b-a3b"
)
SUITES=(banking slack travel workspace)

for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env before nohup" >&2; exit 2; }
done

for M in "${AGENTS[@]}"; do
  LABEL="$(echo "$M" | tr '/' '_')"
  for S in "${SUITES[@]}"; do
    for COND in def-attack def-benign undef-attack undef-benign; do
      case "$COND" in
        def-attack)   ATK=(--attack important_instructions)
                      DEF=(--defense on --mode full --speculative on --judge llm
                           --commit auto --judge-model gpt-4.1) ;;
        def-benign)   ATK=(--no-attack)
                      DEF=(--defense on --mode full --speculative on --judge llm
                           --commit auto --judge-model gpt-4.1) ;;
        undef-attack) ATK=(--attack important_instructions)
                      DEF=(--defense off) ;;   # no judge is built at all
        undef-benign) ATK=(--no-attack)
                      DEF=(--defense off) ;;
      esac
      CELL="${LABEL}__${S}__${COND}"
      echo "=== $(date -Is)  $M / $S / $COND ==="
      "$PY" scripts/run_benchmark.py --suite "$S" --model "$M" --agent-name-map legacy \
          "${DEF[@]}" "${ATK[@]}" --logdir "runs_models/$LABEL" \
          > "$LOGS/$CELL.log" 2>&1 &
      CHILD=$!
      wait "$CHILD"; rc=$?; CHILD=""
      tail -2 "$LOGS/$CELL.log" | sed 's/^/    /'
      [ "$rc" -ne 0 ] && echo "    !! rc=$rc  see $LOGS/$CELL.log"
    done
  done
done
echo "=== $(date -Is)  sweep finished ==="
