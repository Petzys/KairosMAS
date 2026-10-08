#!/usr/bin/env bash
#
# The two KAIROS cells the AutoDojo comparison table still lacks: CLEAN utility (no injection)
# and STATIC attack success (AgentDojo's important_instructions) for the GPT-4o-mini agent on
# banking, slack and travel, in exactly the configuration of the runs_v2 AutoDojo replay:
# the fork's own benchmark CLI with --defense kairos (kairos/adapters/autodojo/pipeline.py),
# agent openai/gpt-4o-mini via OpenRouter, judge GPT-4.1 on OpenAI with the intent-first
# prompt (KAIROS_JUDGE_PROMPT=production), full mode, LLM judge, auto commit, and the fork's
# default system prompt (the CLI's default when --system-message is not given, which is also
# what the replay recorded). Results: $VG/runs_v2_static/openai/gpt-4o-mini/kairos/<suite>/
# user_task_*/{important_instructions,none}/. 389 attack cases + 57 benign tasks; cached per
# task, re-running resumes.
#
#   set -a; . .env; set +a
#   evaluation/autodojo/run_static_clean_gpt4omini.sh          # dry-run
#   nohup evaluation/autodojo/run_static_clean_gpt4omini.sh --go > evaluation/logs/autodojo_static_clean.log 2>&1 &
#   disown
set -uo pipefail
CHILD=""; _cleanup() { trap - TERM INT; [ -n "$CHILD" ] && kill "$CHILD" 2>/dev/null; echo "=== $(date -Is)  interrupted ==="; exit 130; }; trap _cleanup TERM INT

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
FORK="$REPO/benchmark/autodojo/agentdojo"; VG="$FORK/variant_generation"
PY="$REPO/.venv/bin/python"; LOGS="$REPO/evaluation/logs"; mkdir -p "$LOGS"
export PYTHONPATH="$FORK/src:$REPO${PYTHONPATH:+:$PYTHONPATH}"
export KAIROS_JUDGE_MODEL=gpt-4.1 KAIROS_MODE=full KAIROS_JUDGE=llm KAIROS_COMMIT=auto KAIROS_JUDGE_PROMPT=production
GO=0; [ "${1:-}" = "--go" ] && GO=1
MODEL="openai/gpt-4o-mini"; BENCH=v1; LOGDIR="$VG/runs_v2_static"
for v in OPENAI_API_KEY OPENROUTER_API_KEY; do [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env first" >&2; exit 2; }; done

rc_all=0
for S in banking slack travel; do
  for COND in clean; do
    ATK=(--attack important_instructions); [ "$COND" = clean ] && ATK=()
    CMD=("$PY" -m agentdojo.scripts.benchmark --model "$MODEL" --defense kairos --suite "$S"
         "${ATK[@]}" --benchmark-version "$BENCH" --logdir "$LOGDIR")
    echo "=== $(date -Is)  $COND  $MODEL / kairos / $S"; echo "+ ${CMD[*]}"
    [ "$GO" = 1 ] || continue
    ( cd "$FORK" && "${CMD[@]}" ) > "$LOGS/autodojo_${COND}__gpt-4o-mini__kairos__${S}.log" 2>&1 &
    CHILD=$!; wait "$CHILD"; rc=$?; CHILD=""
    tail -2 "$LOGS/autodojo_${COND}__gpt-4o-mini__kairos__${S}.log" | sed 's/^/    /'
    [ "$rc" -ne 0 ] && { rc_all=1; echo "    !! rc=$rc"; }
  done
done
[ "$GO" = 1 ] || { echo "(dry-run: add --go to launch the six runs)"; exit 0; }
echo "=== $(date -Is)  finished rc_all=$rc_all ==="; exit "$rc_all"
