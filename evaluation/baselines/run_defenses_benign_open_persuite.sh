#!/usr/bin/env bash
#
# FINISHING PASS for run_defenses_benign_open{,_parallel}.sh: one process per INCOMPLETE
# (model, defense, suite) cell, all started at once. Same commands, same result paths; the
# harness resumes per task (a task whose file is missing or half-written is re-run).
# Written to (a) finish the two Llama PI-detector cells that died on a `null` tool-call
# argument (guard added in agent_pipeline/llms/openai_llm.py::_openai_to_tool_call) and
# (b) run the eight CaMeL cells concurrently instead of one lane per model.
#
#   set -a; . .env; set +a
#   evaluation/baselines/run_defenses_benign_open_persuite.sh          # dry-run: lists the cells
#   nohup evaluation/baselines/run_defenses_benign_open_persuite.sh --go \
#         > evaluation/logs/defenses_benign_open_persuite.log 2>&1 &
#   disown
#
# Stop everything:  kill -- -<pid of this script>
set -uo pipefail

_cleanup() { trap - TERM INT; echo "=== $(date -Is)  interrupted; killing all cells ==="; kill -TERM -- -$$ 2>/dev/null; exit 130; }
trap _cleanup TERM INT

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
FORK="$REPO/benchmark/autodojo/agentdojo"
PY="$REPO/.venv/bin/python"
PY_CAMEL="${KAIROS_CAMEL_PY:-$REPO/.venv-camel/bin/python}"
LOGS="$REPO/evaluation/logs"; mkdir -p "$LOGS"
export PYTHONPATH="$FORK/src${PYTHONPATH:+:$PYTHONPATH}"

GO=0; [ "${1:-}" = "--go" ] && GO=1
BENCH=v1; LOGDIR="$HERE/runs/$BENCH"
SYSMSG="You are a helpful assistant. Use the available tools to solve the user's task."
OR_URL="https://openrouter.ai/api/v1"
MODELS=("meta-llama/llama-3.3-70b-instruct" "qwen/qwen3.6-35b-a3b")
DEFS=(spotlighting repeat_user_prompt transformers_pi_detector progent camel)
SUITES=(banking slack travel workspace)
declare -A EXP=([banking]=16 [slack]=21 [travel]=20 [workspace]=40)

if [ "$GO" = 1 ] && pgrep -f 'run_defenses_benign_open(_parallel)?\.sh --go' >/dev/null; then
    echo "ERROR: another run_defenses_benign_open*.sh is still running; stop it first (kill -- -<its pid>)" >&2; exit 2
fi
for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env first" >&2; exit 2; }
done
[ -x "$PY_CAMEL" ] || { echo "ERROR: $PY_CAMEL missing (CaMeL needs the isolated venv)" >&2; exit 2; }
export SECAGENT_BASE_URL="${SECAGENT_BASE_URL:-https://api.openai.com/v1}"
export SECAGENT_API_KEY="${SECAGENT_API_KEY:-$OPENAI_API_KEY}"

build_cmd() {   # build_cmd <model> <defense> <suite> -> CMD, ENV, SHOW, CELL
    local M="$1" D="$2" S="$3" ML RUNPY
    ML="$(echo "$M" | tr '/' '_')"; CELL="benign__${ML}__${D}__${S}"
    local SYS_ARG=(--system-message "$SYSMSG"); case "$D" in camel*) SYS_ARG=() ;; esac
    local EXTRA=(); [ "$D" = progent ] && EXTRA=(--defense-model gpt-4.1)
    ENV=(); SHOW=(); RUNPY="$PY"
    case "$D" in
        camel*) RUNPY="$PY_CAMEL"
                ENV=(OPENAI_BASE_URL="$OR_URL" OPENAI_API_KEY="$OPENROUTER_API_KEY")
                SHOW=(OPENAI_BASE_URL="$OR_URL" 'OPENAI_API_KEY=$OPENROUTER_API_KEY') ;;
        transformers_pi_detector)
                ENV=(OMP_NUM_THREADS=3 TOKENIZERS_PARALLELISM=false); SHOW=("${ENV[@]}") ;;
    esac
    CMD=("$RUNPY" -m agentdojo.scripts.benchmark --model "$M" --defense "$D" --suite "$S"
         "${SYS_ARG[@]}" "${EXTRA[@]}" --benchmark-version "$BENCH" --logdir "$LOGDIR")
}

have() {   # complete benign result files (utility is a bool); half-written files do not count
    local ML DIR; ML="$(echo "$1" | tr '/' '_')"
    case "$2" in camel*) DIR="$LOGDIR/$ML/$2/$3" ;; *) DIR="$LOGDIR/$1/$2/$3" ;; esac
    "$PY" - "$DIR" <<'PYEOF'
import glob, json, sys
n = 0
for f in glob.glob(sys.argv[1] + "/user_task_*/none/*.json"):
    try:
        n += isinstance(json.load(open(f)).get("utility"), bool)
    except Exception:
        pass
print(n)
PYEOF
}

cell() {   # one incomplete cell, run in the background
    local M="$1" D="$2" S="$3" n="$4" rc TAG
    TAG="[$(echo "$M" | cut -d/ -f2 | cut -d- -f1)/$D/$S]"
    build_cmd "$M" "$D" "$S"
    echo "$TAG $(date +%T)  start (have $n/${EXP[$S]})"
    { echo "===== $(date -Is) resume/start (have $n/${EXP[$S]}) ====="; } >> "$LOGS/$CELL.log"
    ( cd "$FORK" && env "${ENV[@]}" "${CMD[@]}" ) >> "$LOGS/$CELL.log" 2>&1; rc=$?
    echo "$TAG $(date +%T)  done rc=$rc  $(grep -E 'Average utility' "$LOGS/$CELL.log" | tail -1 | sed 's/^ *//')  now $(have "$M" "$D" "$S")/${EXP[$S]}"
    [ "$rc" -ne 0 ] && echo "$TAG    !! see $LOGS/$CELL.log"
    return "$rc"
}

# ---------------------------------------------------------------- plan
TODO=()
for D in "${DEFS[@]}"; do for M in "${MODELS[@]}"; do for S in "${SUITES[@]}"; do
    n=$(have "$M" "$D" "$S")
    if [ "$n" -ge "${EXP[$S]}" ]; then continue; fi
    build_cmd "$M" "$D" "$S"; printf "   %-5s %s\n" "$n/${EXP[$S]}" "${SHOW[*]} ${CMD[*]}"
    TODO+=("$M|$D|$S|$n")
done; done; done
echo "##### ${#TODO[@]} incomplete cells, all started concurrently"
[ "$GO" = 1 ] || { echo "(dry-run: add --go to launch)"; exit 0; }
[ "${#TODO[@]}" -gt 0 ] || { echo "nothing to do"; exit 0; }

# ---------------------------------------------------------------- launch
PIDS=()
for t in "${TODO[@]}"; do IFS='|' read -r M D S n <<<"$t"; cell "$M" "$D" "$S" "$n" & PIDS+=($!); done
echo "=== $(date -Is)  ${#PIDS[@]} cells running (pids ${PIDS[*]})"
rc_all=0; for p in "${PIDS[@]}"; do wait "$p" || rc_all=1; done

# ---------------------------------------------------------------- summary
echo "=== $(date -Is)  all cells finished rc=$rc_all; complete result files per cell:"
for D in "${DEFS[@]}"; do for M in "${MODELS[@]}"; do
    printf "    %-36s %-26s" "$M" "$D"; for S in "${SUITES[@]}"; do printf " %s=%s/%s" "$S" "$(have "$M" "$D" "$S")" "${EXP[$S]}"; done; echo
done; done
echo "(nonzero rc or a short cell: re-run this script, it resumes the missing tasks)"
exit "$rc_all"
