#!/usr/bin/env bash
#
# Finish ONE cell: Llama-3.3-70B / camel / travel (89/140 done; the cell died on the
# CaMeL interpreter TypeError before that patch existed). Identical environment to
# resume_defenses_llama_qwen.sh, so the result files land in the same pipeline
# directory and the fork's cache skips the 89 finished tasks. Safe to run while the
# other two resume scripts are still going: different cell, different directory.
#
#   set -a; . .env; set +a
#   evaluation/baselines/finish_llama_camel_travel.sh          # dry-run: prints the command
#   nohup evaluation/baselines/finish_llama_camel_travel.sh --go > evaluation/logs/finish_llama_travel.log 2>&1 &
#   disown
#
# Do NOT pass --force-rerun. Progress: count result files with
#   ls evaluation/baselines/runs/v1/meta-llama_llama-3.3-70b-instruct/camel/travel/user_task_*/important_instructions/*.json | wc -l
set -uo pipefail

CHILD=""
_cleanup() { trap - TERM INT EXIT; [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; echo "=== $(date -Is)  interrupted ==="; exit 130; }
trap _cleanup TERM INT

HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"
FORK="$REPO/benchmark/autodojo/agentdojo"
PY_CAMEL="${KAIROS_CAMEL_PY:-$REPO/.venv-camel/bin/python}"
LOGS="$REPO/evaluation/logs"; mkdir -p "$LOGS"
export PYTHONPATH="$FORK/src${PYTHONPATH:+:$PYTHONPATH}"

GO=0; [ "${1:-}" = "--go" ] && GO=1
BENCH=v1; ATTACK=important_instructions; LOGDIR="$HERE/runs/$BENCH"
OR_URL="https://openrouter.ai/api/v1"
M="meta-llama/llama-3.3-70b-instruct"; D=camel; S=travel

for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env first" >&2; exit 2; }
done
[ -x "$PY_CAMEL" ] || { echo "ERROR: $PY_CAMEL missing" >&2; exit 2; }
export SECAGENT_BASE_URL="${SECAGENT_BASE_URL:-https://api.openai.com/v1}"
export SECAGENT_API_KEY="${SECAGENT_API_KEY:-$OPENAI_API_KEY}"

CELL="base__$(echo "$M" | tr '/' '_')__${D}__${S}"
CMD=("$PY_CAMEL" -m agentdojo.scripts.benchmark --model "$M" --defense "$D"
     --attack "$ATTACK" --suite "$S" --benchmark-version "$BENCH" --logdir "$LOGDIR")
echo "=== $(date -Is)  FINISH $M / $D / $S"
echo "+ OPENAI_BASE_URL=$OR_URL OPENAI_API_KEY=\$OPENROUTER_API_KEY ${CMD[*]}"
[ "$GO" = 1 ] || exit 0
( cd "$FORK" && env OPENAI_BASE_URL="$OR_URL" OPENAI_API_KEY="$OPENROUTER_API_KEY" "${CMD[@]}" ) > "$LOGS/$CELL.finish.log" 2>&1 &
CHILD=$!; wait "$CHILD"; rc=$?; CHILD=""
tail -3 "$LOGS/$CELL.finish.log" | sed 's/^/    /'
[ "$rc" -ne 0 ] && echo "    !! rc=$rc  see $LOGS/$CELL.finish.log"
echo "=== $(date -Is)  done rc=$rc; result files: $(ls "$LOGDIR"/meta-llama_llama-3.3-70b-instruct/camel/travel/user_task_*/important_instructions/*.json 2>/dev/null | wc -l)/140"
exit "$rc"
