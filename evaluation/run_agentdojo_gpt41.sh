#!/usr/bin/env bash
#
# AgentDojo with GPT-4.1 as agent and oracle
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO" || exit 1
PY="$REPO/.venv/bin/python"
WHAT="${1:-}"; GO=0; [ "${2:-}" = "--go" ] && GO=1
case "$WHAT" in main|matched) ;; *) echo "usage: $0 main|matched [--go]" >&2; exit 2 ;; esac
[ "$GO" = 0 ] || [ -n "${OPENAI_API_KEY:-}" ] || { echo "OPENAI_API_KEY not set" >&2; exit 2; }

export KAIROS_BENCHMARK_SRC="$REPO/benchmark/agentdojo/src"
export KAIROS_ABORT_NOTICE=v1
P="$REPO/policies_used"
declare -A POL=([banking]=banking_0921474b.yaml [slack]=slack_71dfa38e.yaml
                [travel]=travel_05c343f8.yaml [workspace]=workspace_13887c83.yaml)
COMMON=(--model gpt-4.1 --agent-name-map legacy)
KAIROS=(--defense on --speculative on --judge llm --judge-model gpt-4.1 --commit auto)

run() { echo "+ scripts/run_benchmark.py $*"; [ "$GO" = 1 ] && "$PY" scripts/run_benchmark.py "$@"; return 0; }

for S in banking slack travel workspace; do
    for C in attack benign; do
        A=(--attack important_instructions); [ "$C" = benign ] && A=(--no-attack)
        if [ "$WHAT" = main ]; then
            # mode as run: 'full' (operator rules on) for Banking, and for Slack under attack;
            # 'baseline' (rules layer off) for Travel, Workspace and benign Slack
            MODE=baseline
            { [ "$S" = banking ] || { [ "$S" = slack ] && [ "$C" = attack ]; }; } && MODE=full
            run --suite "$S" "${COMMON[@]}" "${KAIROS[@]}" --mode "$MODE" --policy "$P/${POL[$S]}" "${A[@]}"
            run --suite "$S" "${COMMON[@]}" --defense off "${A[@]}"
        else
            L=(--logdir "$REPO/runs/run_01")
            run --suite "$S" "${COMMON[@]}" --defense off "${A[@]}" "${L[@]}"
            run --suite "$S" "${COMMON[@]}" --defense on --speculative off --mode baseline \
                --policy "$P/${POL[$S]}" "${A[@]}" "${L[@]}"                       # strict monitor
            run --suite "$S" "${COMMON[@]}" "${KAIROS[@]}" --mode baseline \
                --policy "$P/${POL[$S]}" "${A[@]}" "${L[@]}"                       # full pipeline
        fi
    done
done
[ "$GO" = 1 ] || echo "(dry run: add --go to run)"
