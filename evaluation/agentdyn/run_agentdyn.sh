#!/usr/bin/env bash
#
# Track D — KAIROS on the AgentDyn suites (github, shopping, dailylife).
# Attack + benign run per suite. Dry-run by default; --go to launch.
#
#   evaluation/agentdyn/run_agentdyn.sh          # print commands
#   evaluation/agentdyn/run_agentdyn.sh --go     # run them
#
# Needs OPENAI_API_KEY (agent + judge). Uses the AgentDyn fork's suites via
# PYTHONPATH and the policies in evaluation/policies/.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
export PYTHONPATH="$REPO/benchmark/agentdyn/src${PYTHONPATH:+:$PYTHONPATH}"

MODEL="${KAIROS_AGENT_MODEL:-gpt-4.1}"
JUDGE="${KAIROS_JUDGE_MODEL:-gpt-4.1}"
ATTACK="${KAIROS_ATTACK:-important_instructions}"
SUITES=(github shopping dailylife)
# v2 hold notice: KAIROS_HOLD_NOTICE=honest (default success; the reported runs use honest and KAIROS_AGENT_MODEL=gpt-4o-2024-08-06).
HOLD_NOTICE="${KAIROS_HOLD_NOTICE:-success}"
LOGDIR="$HERE/runs"
# AgentDyn's published tables were produced with AgentDojo's OWN default system
# prompt (the one naming Emma Johnson / Blue Sparrow Tech), not our short prompt.
# The prompt measurably changes ASR, so match theirs by default here — that is the
# whole point of this track: drop our row into their table. Set
# KAIROS_SYSTEM_MESSAGE= (empty) to fall back to our prompt instead.
SYSMSG_ARG=(--system-message "${KAIROS_SYSTEM_MESSAGE-agentdojo-default}")
[ -z "${KAIROS_SYSTEM_MESSAGE-agentdojo-default}" ] && SYSMSG_ARG=()
# Anything in KAIROS_EXTRA is appended verbatim (e.g. --reasoning-effort none).
read -r -a EXTRA <<< "${KAIROS_EXTRA:-}"

GO=0; [ "${1:-}" = "--go" ] && GO=1
if [ "$GO" = "1" ] && [ -z "${OPENAI_API_KEY:-}" ]; then
    echo "OPENAI_API_KEY not set (agent + judge need it)." >&2; exit 1
fi

run() { echo "+ $*"; [ "$GO" = "1" ] && ( cd "$REPO" && "$@" ); }
PY="$REPO/.venv/bin/python"; [ -x "$PY" ] || PY=python3

mkdir -p "$LOGDIR"
for s in "${SUITES[@]}"; do
    POL="$REPO/evaluation/policies/agentdyn_$s.yaml"
    # Pin the AgentDyn fork explicitly: KAIROS_BENCHMARK_SRC in .env (added for the
    # AgentDojo sweeps) overrides PYTHONPATH inside run_benchmark.py and would
    # otherwise load the AutoDojo copy of the suites with a DIFFERENT default prompt.
    common=(scripts/run_benchmark.py --benchmark-src "$REPO/benchmark/agentdyn/src"
            --suite "$s" --model "$MODEL"
            --defense on --mode full --speculative on --judge llm --commit auto
            --judge-model "$JUDGE" --policy "$POL" --logdir "$LOGDIR"
            --hold-notice "$HOLD_NOTICE"
            "${SYSMSG_ARG[@]}" ${EXTRA+"${EXTRA[@]}"})
    run "$PY" "${common[@]}" --attack "$ATTACK"      # security
    run "$PY" "${common[@]}" --no-attack             # benign utility / FP cost
done

[ "$GO" = "0" ] && echo && echo "dry-run only — re-run with --go ($(( ${#SUITES[@]} * 2 )) runs)."
