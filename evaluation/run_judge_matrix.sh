#!/usr/bin/env bash
#
# Judge-placement MATRIX on Banking (paper tab:placement, tab:model-grid)
# ========================================================================================
# Every (agent, judge) pair over one model family, with Kairos in its full configuration,
# attack (144 injection cases) and benign (16 tasks), plus one UNDEFENDED attack + benign
# run per agent. Default family: Qwen3.5 through OpenRouter (all three serve tool calls),
#     agents = judges = qwen/qwen3.5-9b, qwen/qwen3.5-27b, qwen/qwen3.5-35b-a3b
# i.e. 3 x 3 x 2 + 3 x 2 = 24 cells. Override with space-separated lists:
#     KAIROS_AGENTS="qwen/qwen3.5-9b qwen/qwen3.5-27b qwen/qwen3.5-35b-a3b"
#     KAIROS_JUDGES="qwen/qwen3.5-9b qwen/qwen3.5-27b qwen/qwen3.5-35b-a3b"
#
# Configuration: --mode full --speculative on --judge llm
# --commit auto, --agent-name-map correct (the injection addresses the agent as "Qwen"), the
# autodojo checkout, judge served through OpenRouter. Kairos cells land in
# runs_judge/<agent>__judge-<judge>/ (the cache tag does not encode the judge, so each pair
# needs its own logdir root); undefended cells in runs_models/<agent>/nodefense-anm-*.
#
# PARALLEL. Each cell is split into KAIROS_SHARDS shards by user task (user_task_i goes to
# shard i mod SHARDS) and up to KAIROS_JOBS shards run at once, queued round-robin across
# agents and judges so one slow model cannot hold up the rest. Shards of one cell write
# disjoint result files (the injection-task precheck is off in this fork), so they never
# collide. Every request gets a per-request timeout (KAIROS_API_TIMEOUT, default 300 s) and
# KAIROS_API_MAX_RETRIES SDK retries (default 4): a provider that accepts a request and never
# answers costs minutes instead of 10-30 min.
#
# INFRASTRUCTURE FAILURES ARE NOT RESULTS. The oracle fails closed when its API call raises;
# a finished task whose record says "judge unavailable" is moved to
# evaluation/logs/judge_matrix_quarantine/ before each attempt, so it is rerun, not counted.
#
# RESUMABLE. run_benchmark caches per task; a shard whose result files are all present is
# skipped without starting a process, and a half-written file ("utility": null, e.g. from a
# killed run) does not count and is re-run. A shard that crashes is restarted up to
# KAIROS_RETRIES times (it resumes). If OpenRouter answers 402 (credits), no further shard is
# started or restarted; the same for 403 "Key limit exceeded" (the API key's own spending cap).
# Top up or raise the key limit and run this script again, it continues where it stopped.
#
#   set -a; . .env; set +a
#   evaluation/run_judge_matrix.sh                 # dry-run: per cell and shard, what exists
#   nohup evaluation/run_judge_matrix.sh --go > evaluation/logs/judge_matrix.log 2>&1 &
#   disown
#
#   KAIROS_SHARDS 4   KAIROS_JOBS 24   KAIROS_RETRIES 2   KAIROS_API_TIMEOUT 300   KAIROS_API_MAX_RETRIES 4
#   KAIROS_NAME_MAP correct (default) | legacy
#
# Credits: OpenRouter reserves the model's full max_tokens for every request in flight, so
# with ~24 requests in flight keep roughly $10 of balance above what the run will spend, or
# it answers 402 before the money is actually used up.
#
# Stop everything (all shards and their python children):  kill -- -<pid of this script>
# Results:  .venv/bin/python evaluation/placement_table.py
set -uo pipefail

_cleanup() { trap - TERM INT; echo "=== $(date -Is)  interrupted; killing running shards ==="; kill -TERM -- -$$ 2>/dev/null; exit 130; }
trap _cleanup TERM INT

REPO="$(cd "$(dirname "$0")/.." && pwd)"
PY="$REPO/.venv/bin/python"
LOGS="$REPO/evaluation/logs"; mkdir -p "$LOGS"
OR="https://openrouter.ai/api/v1"
SUITE=banking
NUT=16                                  # Banking user tasks: user_task_0 .. user_task_15
NINJ=9                                  # Banking injection tasks per user task
GO=0; [ "${1:-}" = "--go" ] && GO=1
SHARDS="${KAIROS_SHARDS:-4}"
JOBS="${KAIROS_JOBS:-24}"
RETRIES="${KAIROS_RETRIES:-2}"
API=(--api-timeout "${KAIROS_API_TIMEOUT:-300}" --api-max-retries "${KAIROS_API_MAX_RETRIES:-4}")
NAME_MAP="${KAIROS_NAME_MAP:-correct}"
CREDIT_FLAG="$LOGS/.judge_matrix_credits_exhausted"
export KAIROS_BENCHMARK_SRC="$REPO/benchmark/autodojo/agentdojo/src"   # same checkout as the sweep
cd "$REPO" || exit 1

read -r -a AGENTS <<<"${KAIROS_AGENTS:-qwen/qwen3.5-9b qwen/qwen3.5-27b qwen/qwen3.5-35b-a3b}"
read -r -a JUDGES <<<"${KAIROS_JUDGES:-qwen/qwen3.5-9b qwen/qwen3.5-27b qwen/qwen3.5-35b-a3b}"

for v in OPENAI_API_KEY OPENROUTER_API_KEY; do
    [ -n "${!v:-}" ] || { echo "ERROR: \$$v unset — source .env first" >&2; exit 2; }
done
if [ "$GO" = 1 ] && pgrep -f 'run_judge_matrix.sh --go' | grep -qv "^$$\$"; then
    echo "ERROR: another run_judge_matrix.sh --go is running; stop it first (kill -- -<pid>)" >&2; exit 2
fi

# run_benchmark's cache tag for Banking under this configuration (policy hash included)
PHASH="$("$PY" -c "import hashlib;print(hashlib.sha1(open('kairos/config/banking.yaml','rb').read()).hexdigest()[:8])")"
ANM=""; [ "$NAME_MAP" = "correct" ] && ANM="-anm"
tag() {   # tag <kairos|undef> <attack|benign>
    local mode="important_instructions"; [ "$2" = benign ] && mode="noattack"
    if [ "$1" = kairos ]; then echo "full-spec_llm${ANM}-${PHASH}-${mode}"; else echo "nodefense${ANM}-${mode}"; fi
}
shard_tasks() {   # shard_tasks <k> -> "user_task_k user_task_{k+S} ..."
    local i out=""; for ((i=$1; i<NUT; i+=SHARDS)); do out+="user_task_$i "; done; echo "${out% }"
}
expected() {      # expected <attack|benign> <k>
    local n; n=$(shard_tasks "$2" | wc -w); [ "$1" = attack ] && echo $((n * NINJ)) || echo "$n"
}
have() {          # have <cell-dir> <attack|benign> <user tasks...> -> complete result files
    local dir="$1" cond="$2"; shift 2
    "$PY" - "$dir" "$cond" "$@" <<'PYEOF'
import glob, json, sys
d, cond, tasks = sys.argv[1], sys.argv[2], sys.argv[3:]
sub = "important_instructions/injection_task_*.json" if cond == "attack" else "none/none.json"
n = 0
for t in tasks:
    for f in glob.glob(f"{d}/{t}/{sub}"):
        try:
            n += isinstance(json.load(open(f)).get("utility"), bool)
        except Exception:
            pass
print(n)
PYEOF
}
quarantine() {    # quarantine <cell-dir> <attack|benign> <user tasks...>
    # A result whose oracle call raised (credits, timeout, connection) is an infrastructure
    # failure, not a verdict: LLMJudge fails closed with "judge unavailable (...)", and the
    # harness would keep the file as a finished task. Move such files aside (never delete)
    # so the next attempt reruns the task. Only this shard's tasks are touched.
    local dir="$1" cond="$2"; shift 2
    "$PY" - "$dir" "$cond" "$REPO/evaluation/logs/judge_matrix_quarantine" "$REPO" "$@" <<'PYEOF'
import glob, json, os, shutil, sys, time
d, cond, qroot, repo, tasks = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5:]
sub = "important_instructions/injection_task_*.json" if cond == "attack" else "none/none.json"
for t in tasks:
    for f in glob.glob(f"{d}/{t}/{sub}"):
        try:
            j = json.load(open(f))
        except Exception:
            continue
        if not isinstance(j.get("utility"), bool):
            continue
        if "judge unavailable" in json.dumps(j.get("kairos") or {}):
            rel = os.path.relpath(os.path.abspath(f), repo)
            dst = os.path.join(qroot, time.strftime("%Y%m%d-%H%M%S"), rel)
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.move(f, dst)
            print(f"quarantined (oracle call failed, task will rerun): {rel}")
PYEOF
}
cell_paths() {    # cell_paths <agent> <judge|-> <cond> -> ROOT CELLDIR NAME (globals)
    local M="$1" J="$2" C="$3" ML JL
    ML="$(echo "$M" | tr '/' '_')"
    if [ "$J" = "-" ]; then ROOT="runs_models/$ML"; NAME="${ML}__undefended__${C}"; CELLDIR="$ROOT/$(tag undef "$C")/$M/$SUITE"
    else JL="$(echo "$J" | tr '/' '_')"; ROOT="runs_judge/${ML}__judge-${JL}"; NAME="${ML}__judge-${JL}__${C}"; CELLDIR="$ROOT/$(tag kairos "$C")/$M/$SUITE"; fi
}

# unit <agent> <judge|-> <attack|benign> <shard>
unit() {
    local M="$1" J="$2" C="$3" K="$4" n e rc try off LOG
    cell_paths "$M" "$J" "$C"
    local TASKS; read -r -a TASKS <<<"$(shard_tasks "$K")"
    e="$(expected "$C" "$K")"
    local ATK=(--attack important_instructions); [ "$C" = benign ] && ATK=(--no-attack)
    local CMD=("$PY" scripts/run_benchmark.py --suite "$SUITE" --model "$M" --agent-name-map "$NAME_MAP"
               "${ATK[@]}" --logdir "$ROOT" --user-tasks "${TASKS[@]}" "${API[@]}")
    if [ "$J" = "-" ]; then CMD+=(--defense off)
    else CMD+=(--defense on --mode full --speculative on --judge llm --commit auto
               --judge-model "$J" --judge-base-url "$OR" --judge-api-key-env OPENROUTER_API_KEY); fi
    LOG="$LOGS/judge_matrix__${NAME}__s${K}of${SHARDS}.log"
    for ((try=0; try<=RETRIES; try++)); do
        quarantine "$CELLDIR" "$C" "${TASKS[@]}" | sed "s|^|=== $(date -Is)  $NAME s$K |"
        n="$(have "$CELLDIR" "$C" "${TASKS[@]}")"
        [ "$n" -ge "$e" ] && { [ "$try" -gt 0 ] && echo "=== $(date -Is)  END   $NAME s$K now $n/$e"; return 0; }
        [ -e "$CREDIT_FLAG" ] && { echo "=== $(date -Is)  SKIP  $NAME s$K ($n/$e): credits exhausted"; return 3; }
        echo "=== $(date -Is)  $([ "$try" = 0 ] && echo START || echo RETRY) $NAME s$K (have $n/$e)"
        off=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
        { echo "===== $(date -Is) attempt $try (have $n/$e) ====="; } >> "$LOG"
        "${CMD[@]}" >> "$LOG" 2>&1; rc=$?
        # 402 = account credits; 403 "Key limit exceeded" = the API key's own spending cap
        # (OpenRouter -> Settings -> API Keys). Either way nothing more can run: stop cleanly.
        if tail -c +"$((off + 1))" "$LOG" | grep -qE 'Error code: 402|Key limit exceeded'; then
            : > "$CREDIT_FLAG"
            echo "=== $(date -Is)  STOP  $NAME s$K: OpenRouter credits or API-key limit exhausted. No further shards start; raise it and re-run."
            return 3
        fi
        [ "$rc" -ne 0 ] && echo "=== $(date -Is)  FAIL  $NAME s$K rc=$rc (attempt $try; see $LOG)"
    done
    quarantine "$CELLDIR" "$C" "${TASKS[@]}" | sed "s|^|=== $(date -Is)  $NAME s$K |"
    n="$(have "$CELLDIR" "$C" "${TASKS[@]}")"
    echo "=== $(date -Is)  END   $NAME s$K now $n/$e$([ "$n" -lt "$e" ] && echo "  !! incomplete after $RETRIES retries; see $LOG")"
    [ "$n" -ge "$e" ]
}

# ---- the queue: undefended references, then the Kairos matrix, round-robin ---------------
QUEUE=()
for ((k=0; k<SHARDS; k++)); do for C in attack benign; do for M in "${AGENTS[@]}"; do QUEUE+=("$M|-|$C|$k"); done; done; done
for ((k=0; k<SHARDS; k++)); do for C in attack benign; do for J in "${JUDGES[@]}"; do for M in "${AGENTS[@]}"; do
    QUEUE+=("$M|$J|$C|$k"); done; done; done; done

status() {   # one line per cell with its shard counts
    local M J C k line tot got e n
    for C in attack benign; do for J in - "${JUDGES[@]}"; do for M in "${AGENTS[@]}"; do
        cell_paths "$M" "$J" "$C"; line=""; tot=0; got=0
        for ((k=0; k<SHARDS; k++)); do
            local T; read -r -a T <<<"$(shard_tasks "$k")"
            n="$(have "$CELLDIR" "$C" "${T[@]}")"; e="$(expected "$C" "$k")"
            line+=" $n/$e"; got=$((got + n)); tot=$((tot + e))
        done
        printf "   %-6s %-24s %-24s %-6s %3d/%3d  shards:%s\n" "$([ "$got" -ge "$tot" ] && echo done || echo TODO)" \
            "$M" "$([ "$J" = - ] && echo undefended || echo "$J")" "$C" "$got" "$tot" "$line"
    done; done; done
}

echo "##### judge matrix on $SUITE: agents {${AGENTS[*]}} x judges {${JUDGES[*]}}, policy $PHASH, name map $NAME_MAP"
echo "##### ${#QUEUE[@]} shard units ($SHARDS per cell), up to $JOBS at once, $RETRIES restarts per shard, API ${API[*]}"
if [ "$GO" != 1 ]; then
    status
    IFS='|' read -r M J C K <<<"${QUEUE[${#AGENTS[@]}*2*SHARDS]}"
    cell_paths "$M" "$J" "$C"
    echo "   e.g. shard: $PY scripts/run_benchmark.py --suite $SUITE --model $M ... --user-tasks $(shard_tasks "$K") ${API[*]} --judge-model $J ..."
    echo "(dry-run: add --go to launch)"; exit 0
fi

rm -f "$CREDIT_FLAG"
rc_all=0
for q in "${QUEUE[@]}"; do
    IFS='|' read -r M J C K <<<"$q"
    [ -e "$CREDIT_FLAG" ] && break
    while [ "$(jobs -rp | wc -l)" -ge "$JOBS" ]; do wait -n || rc_all=1; done
    unit "$M" "$J" "$C" "$K" &
done
while [ "$(jobs -rp | wc -l)" -gt 0 ]; do wait -n || rc_all=1; done

echo "=== $(date -Is)  matrix finished rc=$rc_all"
[ -e "$CREDIT_FLAG" ] && echo "!!! stopped: OpenRouter credits or API-key limit exhausted. Raise it, then run this script again; it resumes."
status
"$PY" evaluation/placement_table.py 2>/dev/null || true
exit "$rc_all"
