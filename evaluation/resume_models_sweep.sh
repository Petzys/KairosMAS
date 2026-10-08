#!/usr/bin/env bash

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
export KAIROS_BENCHMARK_SRC="$REPO/benchmark/autodojo/agentdojo/src"
mkdir -p "$LOGS"
cd "$REPO" || exit 1

for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env before nohup" >&2; exit 2; }
done

# cell <model> <suite> <cond>
run_cell() {
    local M="$1" S="$2" COND="$3" LABEL ATK DEF CELL rc
    LABEL="$(echo "$M" | tr '/' '_')"
    case "$COND" in
      def-attack)   ATK=(--attack important_instructions)
                    DEF=(--defense on --mode full --speculative on --judge llm
                         --commit auto --judge-model gpt-4.1) ;;
      undef-attack) ATK=(--attack important_instructions); DEF=(--defense off) ;;
      undef-benign) ATK=(--no-attack);                     DEF=(--defense off) ;;
      def-benign)   ATK=(--no-attack)
                    DEF=(--defense on --mode full --speculative on --judge llm
                         --commit auto --judge-model gpt-4.1) ;;
    esac
    CELL="${LABEL}__${S}__${COND}"
    echo "=== $(date -Is)  RESUME $M / $S / $COND ==="
    "$PY" scripts/run_benchmark.py --suite "$S" --model "$M" --agent-name-map legacy \
        "${DEF[@]}" "${ATK[@]}" --logdir "runs_models/$LABEL" \
        > "$LOGS/$CELL.resume.log" 2>&1 &
    CHILD=$!; wait "$CHILD"; rc=$?; CHILD=""
    tail -3 "$LOGS/$CELL.resume.log" | sed 's/^/    /'
    [ "$rc" -ne 0 ] && echo "    !! rc=$rc  see $LOGS/$CELL.resume.log"
    return 0
}

# --- DeepSeek: one cell -------------------------------------------------------

# --- Llama: four cells --------------------------------------------------------
run_cell "meta-llama/llama-3.3-70b-instruct" slack     def-attack
run_cell "meta-llama/llama-3.3-70b-instruct" slack     undef-attack
run_cell "meta-llama/llama-3.3-70b-instruct" slack     undef-benign
run_cell "meta-llama/llama-3.3-70b-instruct" workspace def-attack

echo "=== $(date -Is)  resume finished ==="
