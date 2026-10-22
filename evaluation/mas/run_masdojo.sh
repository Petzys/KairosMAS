#!/usr/bin/env bash
#
# MASDojo: Kairos MAS on the AgentDojo suites lifted to multi-agent systems.
#
#   scripted   deterministic, no API key: worst-case obedient scripted agents, the
#              ideal oracle (gt), its containment variant (gt-contain) and no defense,
#              over every cluster layout, plus the strict-containment and dispatch
#              ablations
#   llm        LLM agents and the lineage-aware LLM oracle (needs OPENAI_API_KEY);
#              MODEL / JUDGE override the models (default gpt-4o-mini)
#
# Results land per task in runs_mas/<config tag>/<suite>/, so an interrupted run resumes.
set -uo pipefail
REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO" || exit 1
PY="$REPO/.venv/bin/python"
WHAT="${1:-}"; GO=0; [ "${2:-}" = "--go" ] && GO=1
case "$WHAT" in scripted|llm) ;; *) echo "usage: $0 scripted|llm [--go]" >&2; exit 2 ;; esac
[ "$GO" = 0 ] || [ "$WHAT" = scripted ] || [ -n "${OPENAI_API_KEY:-}" ] || {
    echo "OPENAI_API_KEY not set" >&2; exit 2; }

LOG=(--logdir "$REPO/runs_mas" --quiet)
ALL=(--suite all --layout one domain singleton)
run() { echo "+ scripts/run_mas_benchmark.py $*"; [ "$GO" = 1 ] && "$PY" scripts/run_mas_benchmark.py "$@"; return 0; }

if [ "$WHAT" = scripted ]; then
    run "${ALL[@]}" --defense off "${LOG[@]}"                         # undefended baseline
    run "${ALL[@]}" --oracle gt "${LOG[@]}"                           # mechanics, ideal oracle
    run "${ALL[@]}" --oracle gt-contain "${LOG[@]}"                   # containment vs utility
    run "${ALL[@]}" --oracle deterministic "${LOG[@]}"                # structural oracle
    run --suite all --layout domain --oracle gt --message-review all "${LOG[@]}"   # strict containment
    run --suite all --layout domain --oracle gt --dispatch stream "${LOG[@]}"      # streamed hand-offs
    run --suite all --layout domain --oracle gt --dispatch parallel "${LOG[@]}"    # parallel specialists
    run --suite all --layout domain --defense off --dispatch parallel "${LOG[@]}"
else
    MODEL="${MODEL:-gpt-4o-mini}"; JUDGE="${JUDGE:-gpt-4o-mini}"
    LLM=(--backend llm --model "$MODEL")
    run "${ALL[@]}" "${LLM[@]}" --defense off "${LOG[@]}"
    run "${ALL[@]}" "${LLM[@]}" --oracle llm --judge-model "$JUDGE" "${LOG[@]}"
    run "${ALL[@]}" "${LLM[@]}" --oracle gt "${LOG[@]}"               # monitor with an ideal oracle
fi
[ "$GO" = 1 ] || echo "(dry run: add --go to run)"
