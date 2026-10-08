#!/bin/bash
#
# Operator entrypoint — monitored Claude Code in the microVM
# ==========================================================
# Brings up the host network, the filesystem channel (overlay + FUSE monitor +
# virtiofsd), the network channel (transparent mitmproxy), and the control plane,
# boots the guest, and attaches your terminal to Claude Code over vsock. Run in a
# REAL terminal. Detach with Ctrl-] .
#
#   sudo deploy/run.sh
#
# Everything the agent does is recorded into a per-session AUDIT directory under
# /var/lib/kairos/sessions/<timestamp>/ (network + filesystem event streams, full
# request/response bodies, enforcement decisions, and end-of-session reports).
# On exit the filesystem changes are, by default, MERGED so nothing is lost.
#
# Key env (see deploy/docs/USAGE.md for all):
#   KAIROS_FS_SEED     starter project copied into the agent's /data
#   KAIROS_FS_OUT      on commit, write the result back here (DEFAULT: the seed dir,
#                     so your working directory reflects the agent's changes). Set
#                     to a different path to keep your source untouched, or "" to
#                     leave the result only in /var/lib/kairos/fs/base.
#   KAIROS_FS_ON_EXIT  commit (default, merge changes) | keep | abort
#   KAIROS_FS_RESET    =1 wipe staged changes at START (default 0 — never lose data)
#   KAIROS_BRIDGE_CMD  guest command override (model/flags)
#   KAIROS_UI_PORT     control plane port (default 8090)
#   KAIROS_NET_STRICT  1 = strict network boundary: DNS sinkhole, proxy-only egress,
#                     nothing forwarded, non-HTTP flows refused (deploy/net/*.sh)
#   KAIROS_NO_FS / KAIROS_NO_NET / KAIROS_NO_UI   disable a channel
#
set -euo pipefail
DEPLOY="$(cd "$(dirname "$0")" && pwd)"

export KAIROS_FS_ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
export KAIROS_SESSIONS_ROOT="${KAIROS_SESSIONS_ROOT:-/var/lib/kairos/sessions}"
export KAIROS_FS_RESET="${KAIROS_FS_RESET:-0}"          # safe default: keep staged changes
KAIROS_FS_ON_EXIT="${KAIROS_FS_ON_EXIT:-commit}"        # merge-on-exit by default
UI_PORT="${KAIROS_UI_PORT:-8090}"

# The overlay LOWER = the provided directory, used IN PLACE (no copy → instant
# setup, no duplication). No project given → an empty scratch under the state dir.
if [ -n "${KAIROS_FS_SEED:-}" ]; then
    [ -d "$KAIROS_FS_SEED" ] || { echo "seed dir not found: $KAIROS_FS_SEED"; exit 1; }
    export KAIROS_FS_LOWER="$(cd "$KAIROS_FS_SEED" && pwd)"
else
    export KAIROS_FS_LOWER="$KAIROS_FS_ROOT/base"
fi
# On commit, write the result here. Default = the lower dir itself → merged IN
# PLACE (no second copy). Set to a different path to keep your source pristine.
KAIROS_FS_OUT="${KAIROS_FS_OUT-$KAIROS_FS_LOWER}"
# publish the current lower so the (persistent) control plane always diffs the right base
mkdir -p /run/kairos; printf '%s\n' "$KAIROS_FS_LOWER" > /run/kairos/fs_lower

# Mirror src/ into dst/ (adds, modifies, and DELETES) so dst exactly matches src.
mirror_dir() {
    local src="$1" dst="$2"
    [ -d "$dst" ] || mkdir -p "$dst"
    local own; own="$(stat -c '%u:%g' "$dst" 2>/dev/null || echo 0:0)"
    if command -v rsync >/dev/null 2>&1; then
        rsync -a --delete "$src"/ "$dst"/
    else
        python3 - "$src" "$dst" <<'PY'
import sys, os, shutil
src, dst = sys.argv[1], sys.argv[2]
keep = set()
for dp, dirs, files in os.walk(src):
    rel = os.path.relpath(dp, src)
    tgt = dst if rel == '.' else os.path.join(dst, rel)
    os.makedirs(tgt, exist_ok=True)
    for f in files:
        shutil.copy2(os.path.join(dp, f), os.path.join(tgt, f))
        keep.add(os.path.normpath(os.path.join('' if rel=='.' else rel, f)))
for dp, dirs, files in os.walk(dst, topdown=False):
    rel = os.path.relpath(dp, dst)
    for f in files:
        if os.path.normpath(os.path.join('' if rel=='.' else rel, f)) not in keep:
            try: os.remove(os.path.join(dp, f))
            except OSError: pass
PY
    fi
    chown -R "$own" "$dst" 2>/dev/null || true   # restore original ownership
}

if [ "$EUID" -ne 0 ]; then echo "run as root (sudo)"; exit 1; fi

# M5b/M5c judge: use the real kairos trust chain if the core + its venv are present
# (paper repo); otherwise serve.py falls back to the heuristic (standalone deploy).
# When present we run the control plane ITSELF under the venv python (>=3.12) so it can
# import kairos in-process and reuse one LLM oracle, instead of a subprocess/request.
REPO_ROOT="$(dirname "$DEPLOY")"
UI_PY="python3"
if [ -x "$REPO_ROOT/.venv/bin/python" ] && [ -d "$REPO_ROOT/kairos" ]; then
    export KAIROS_KAIROS_PY="$REPO_ROOT/.venv/bin/python"
    export KAIROS_KAIROS_CWD="$REPO_ROOT"
    UI_PY="$REPO_ROOT/.venv/bin/python"
    export KAIROS_JUDGE_MODEL="${KAIROS_JUDGE_MODEL:-gpt-4o-mini}"
    if [ -n "${OPENAI_API_KEY:-}" ] && [ "${KAIROS_LLM_JUDGE:-1}" != "0" ]; then
        echo "[run] judge: kairos trust chain + LLM oracle ($KAIROS_JUDGE_MODEL)"
    else
        echo "[run] judge: kairos trust chain (deterministic only — set OPENAI_API_KEY for the LLM oracle on REVIEW)"
    fi
else
    echo "[run] judge: heuristic (kairos core/venv not found — standalone mode)"
fi

# ---- per-session audit directory ----
SID="$(date +%Y%m%d-%H%M%S)"
SESSION_DIR="$KAIROS_SESSIONS_ROOT/$SID"
mkdir -p "$SESSION_DIR/bodies"
ln -sfn "$SESSION_DIR" "$KAIROS_SESSIONS_ROOT/latest"
export KAIROS_NET_EVENTS="$SESSION_DIR/net_events.jsonl"
export KAIROS_FS_EVENTS="$SESSION_DIR/fs_events.jsonl"
export KAIROS_TMP_EVENTS="$SESSION_DIR/tmp_fs_events.jsonl"
export KAIROS_BODIES_DIR="$SESSION_DIR/bodies"
export KAIROS_DECISIONS="$SESSION_DIR/decisions.jsonl"
: > "$KAIROS_NET_EVENTS"; : > "$KAIROS_FS_EVENTS"; : > "$KAIROS_DECISIONS"
echo "[run] session $SID -> $SESSION_DIR"


# session metadata (best-effort; jq not required)
cat > "$SESSION_DIR/session.json" <<EOF
{
  "id": "$SID",
  "started": "$(date -Is)",
  "mode": "${KAIROS_MODE:-observe}",
  "net_strict": "${KAIROS_NET_STRICT:-0}",
  "fs_seed": "${KAIROS_FS_SEED:-}",
  "fs_on_exit": "$KAIROS_FS_ON_EXIT",
  "bridge_cmd": "${KAIROS_BRIDGE_CMD:-<image default>}",
  "fs_root": "$KAIROS_FS_ROOT"
}
EOF

echo "[run] host network (bridge + NAT + IPv4-only DNS)..."
bash "$DEPLOY/net/setup_net_nat.sh"

echo "[run] clearing stale VM state..."
for p in $(pgrep -f 'vmlinux-6.2.0' 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
rm -f /tmp/kairos_vsock.sock*

# Wait for the guest to actually let go of the rootfs before touching it.
# The VM survives detach by design, so a previous session is usually still
# running here. Writing the image while a live guest has it mounted rw means two
# independent ext4 writers with separate page caches and journals — which
# silently corrupts file DATA while leaving metadata fsck-clean. The symptom is a
# binary that mmaps a bad page: `claude` dying with SIGBUS at a fixed address,
# 1ms in, 0 page faults. This is why the bake below MUST come after the kill.
for _ in $(seq 1 50); do
    pgrep -f 'vmlinux-6.2.0' >/dev/null 2>&1 || break
    sleep 0.2
done
if pgrep -f 'vmlinux-6.2.0' >/dev/null 2>&1; then
    echo "[run] a guest still holds the rootfs; forcing it down" >&2
    pkill -9 -f 'vmlinux-6.2.0' 2>/dev/null || true
    sleep 1
fi

IMG="$DEPLOY/images/claude-rootfs.ext4"
if [ -n "${KAIROS_BRIDGE_CMD:-}" ]; then
    echo "[run] setting guest bridge command: $KAIROS_BRIDGE_CMD"
    if pgrep -f 'vmlinux-6.2.0' >/dev/null 2>&1; then
        echo "[run] REFUSING to write the rootfs while a guest has it open." >&2
        echo "      Stop it first:  sudo pkill -9 -f vmlinux-6.2.0" >&2
        exit 1
    fi
    MP="$(mktemp -d)"; mount -o loop "$IMG" "$MP"
    mkdir -p "$MP/etc/kairos"; printf '%s\n' "$KAIROS_BRIDGE_CMD" > "$MP/etc/kairos/bridge_cmd"
    sync; umount "$MP"; rmdir "$MP"
fi

FS_UP=0
if [ "${KAIROS_NO_FS:-0}" != "1" ]; then
    echo "[run] filesystem channel (overlay + FUSE monitor + virtiofs)..."
    bash "$DEPLOY/fs/start_fs_stack.sh"
    FS_UP=1
fi

TMP_UP=0
if [ "$FS_UP" = "1" ] && [ "${KAIROS_NO_TMP:-0}" != "1" ]; then
    echo "[run] monitored /tmp channel (captures the agent's scratch scripts)..."
    if bash "$DEPLOY/fs/start_tmp_stack.sh"; then TMP_UP=1; else echo "[run] /tmp channel unavailable (continuing without it)"; fi
fi

NET_UP=0
if [ "${KAIROS_NO_NET:-0}" != "1" ]; then
    echo "[run] network channel (transparent mitmproxy)..."
    bash "$DEPLOY/net/start_net_stack.sh"
    NET_UP=1
fi

if [ "${KAIROS_NO_UI:-0}" != "1" ]; then
    mkdir -p /run/kairos
    # ALWAYS restart the control plane: a persisted old instance would run stale code
    # and diff against a stale base (it wouldn't know this session's lower dir).
    [ -f /run/kairos/ui.pid ] && kill "$(cat /run/kairos/ui.pid)" 2>/dev/null || true
    pkill -f "$DEPLOY/frontend/serve.py" 2>/dev/null || true
    echo "[run] starting control plane on http://localhost:${UI_PORT} ..."
    KAIROS_SESSIONS_ROOT="$KAIROS_SESSIONS_ROOT" KAIROS_FS_ROOT="$KAIROS_FS_ROOT" \
    KAIROS_DECISIONS="$KAIROS_DECISIONS" KAIROS_UI_PORT="$UI_PORT" \
    KAIROS_TASK="${KAIROS_TASK:-}" \
    KAIROS_KAIROS_PY="${KAIROS_KAIROS_PY:-}" KAIROS_KAIROS_CWD="${KAIROS_KAIROS_CWD:-}" \
    KAIROS_JUDGE_MODEL="${KAIROS_JUDGE_MODEL:-}" KAIROS_LLM_JUDGE="${KAIROS_LLM_JUDGE:-1}" \
    OPENAI_API_KEY="${OPENAI_API_KEY:-}" KAIROS_JUDGE_BASE_URL="${KAIROS_JUDGE_BASE_URL:-}" \
      setsid "$UI_PY" "$DEPLOY/frontend/serve.py" >/var/log/kairos-ui.log 2>&1 < /dev/null &
    echo $! > /run/kairos/ui.pid
    echo "[run]   -> open http://localhost:${UI_PORT} in your browser"
fi

finalize() {
    echo; echo "[run] finalizing session $SID ..."
    # 1) stop the VM
    kill "${VMPID:-}" 2>/dev/null || true
    for p in $(pgrep -f 'vmlinux-6.2.0' 2>/dev/null || true); do kill "$p" 2>/dev/null || true; done
    # 2) stop the channels (unmounts the overlay so it can be resolved)
    [ "$NET_UP" = "1" ] && bash "$DEPLOY/net/stop_net_stack.sh" || true
    [ "$TMP_UP" = "1" ] && bash "$DEPLOY/fs/stop_tmp_stack.sh" || true
    [ "$FS_UP" = "1" ] && bash "$DEPLOY/fs/stop_fs_stack.sh" || true

    if [ "$FS_UP" = "1" ]; then
        # 3) SNAPSHOT the reports BEFORE resolving (so the diff is preserved for audit)
        python3 "$DEPLOY/fs/report.py"  --root "$KAIROS_FS_ROOT" --events "$KAIROS_FS_EVENTS" --json \
            > "$SESSION_DIR/fs_report.json" 2>/dev/null || true
        python3 "$DEPLOY/fs/report.py"  --root "$KAIROS_FS_ROOT" --events "$KAIROS_FS_EVENTS" \
            > "$SESSION_DIR/fs_report.txt"  2>/dev/null || true
        # The journal is the per-action record: which agent turn made which change,
        # and what was committed or aborted while the session was still running.
        # The overlay only shows the final state, so without this the audit record
        # cannot say who did what.
        [ -f "$KAIROS_FS_ROOT/wal/journal.jsonl" ] && \
            cp "$KAIROS_FS_ROOT/wal/journal.jsonl" "$SESSION_DIR/wal_journal.jsonl" 2>/dev/null || true
        # 3b) ask the judge which staged changes the request actually called for.
        #     BEFORE resolution, because resolving clears upper/ and the question
        #     becomes unanswerable. Advisory: recorded, never auto-applied — the
        #     exit policy below still decides (§4.8, commit.py is the authority).
        if [ "${KAIROS_NO_UI:-0}" != "1" ]; then
            curl -s --max-time 120 "http://127.0.0.1:${UI_PORT}/api/fs/adjudicate" \
                > "$SESSION_DIR/fs_recommendation.json" 2>/dev/null || true
            if [ -s "$SESSION_DIR/fs_recommendation.json" ]; then
                echo "[run] judge recommendation on staged files:"
                python3 - "$SESSION_DIR/fs_recommendation.json" <<'PYEOF' 2>/dev/null || true
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception:
    sys.exit(0)
if d.get("available") is False:
    print(f"        unavailable: {d.get('reason','')}")
    sys.exit(0)
for f in d.get("per_file") or []:
    print(f"        {'KEEP   ' if f['consistent'] else 'DISCARD'} {f['path']}")
if d.get("rationale"):
    print(f"        why: {d['rationale'][:160]}")
PYEOF
            fi
        fi

        # 4) resolve staged changes per policy
        case "$KAIROS_FS_ON_EXIT" in
          commit)
              if [ "${KAIROS_FS_OUT:-}" = "$KAIROS_FS_LOWER" ]; then
                  # in place: merge the changes straight into the provided dir (no copy)
                  echo "[run] merge-on-exit: committing changes in place -> $KAIROS_FS_LOWER"
                  python3 "$DEPLOY/fs/resolve.py" --root "$KAIROS_FS_ROOT" --base "$KAIROS_FS_LOWER" commit || true
                  printf '{"ts":"%s","by":"exit-policy","action":"commit-inplace","dest":"%s"}\n' "$(date -Is)" "$KAIROS_FS_LOWER" >> "$KAIROS_DECISIONS"
              elif [ -n "${KAIROS_FS_OUT:-}" ]; then
                  # keep source pristine: copy it to OUT, then apply the changes there
                  echo "[run] commit to $KAIROS_FS_OUT (source $KAIROS_FS_LOWER left untouched)"
                  mirror_dir "$KAIROS_FS_LOWER" "$KAIROS_FS_OUT"
                  python3 "$DEPLOY/fs/resolve.py" --root "$KAIROS_FS_ROOT" --base "$KAIROS_FS_OUT" commit || true
                  printf '{"ts":"%s","by":"exit-policy","action":"commit-copy","dest":"%s"}\n' "$(date -Is)" "$KAIROS_FS_OUT" >> "$KAIROS_DECISIONS"
              else
                  echo "[run] commit: KAIROS_FS_OUT empty — leaving changes staged in overlay upper/"
              fi ;;
          abort)  echo "[run] exit policy: aborting all staged changes";
                  python3 "$DEPLOY/fs/resolve.py" --root "$KAIROS_FS_ROOT" abort || true
                  printf '{"ts":"%s","by":"exit-policy","action":"abort-all"}\n' "$(date -Is)" >> "$KAIROS_DECISIONS" ;;
          *)      echo "[run] exit policy: keeping staged changes (unresolved in overlay upper/)" ;;
        esac
    fi
    if [ "$NET_UP" = "1" ]; then
        python3 "$DEPLOY/net/net_report.py" --events "$KAIROS_NET_EVENTS" \
            > "$SESSION_DIR/net_report.txt" 2>/dev/null || true
    fi

    # 5) stamp end + write-protect the audit record (immutable-ish; see docs for chattr +i)
    python3 - "$SESSION_DIR/session.json" <<'PY' 2>/dev/null || true
import json,sys,datetime
p=sys.argv[1]
try:
    d=json.load(open(p)); d["ended"]=datetime.datetime.now().astimezone().isoformat()
    json.dump(d,open(p,"w"),indent=2)
except Exception: pass
PY
    find "$SESSION_DIR" -type f -exec chmod a-w {} + 2>/dev/null || true

    echo
    echo "===================  SESSION FILESYSTEM REPORT  ==================="
    [ -f "$SESSION_DIR/fs_report.txt" ] && cat "$SESSION_DIR/fs_report.txt" || echo "(no fs channel)"
    echo
    echo "====================  SESSION NETWORK REPORT  ===================="
    [ -f "$SESSION_DIR/net_report.txt" ] && cat "$SESSION_DIR/net_report.txt" || echo "(no net channel)"
    echo
    echo "[run] audit record : $SESSION_DIR   (write-protected)"
    if [ "$KAIROS_FS_ON_EXIT" = "commit" ] && [ -n "${KAIROS_FS_OUT:-}" ]; then
        echo "[run] result        : $KAIROS_FS_OUT   (updated in place with the agent's changes)"
    else
        echo "[run] changes staged in overlay upper/ (resolve via POST /api/fs/resolve)"
    fi
    echo "[run] control plane    : http://localhost:${UI_PORT}  (still running)"
}
trap finalize EXIT

echo "[run] booting guest (serial -> /tmp/kairos_vm_serial.log)..."
python3 "$DEPLOY/host/launch_vm.py" --serial-log /tmp/kairos_vm_serial.log \
    --memory "${KAIROS_VM_MEMORY:-1024M}" &
VMPID=$!

echo "[run] attaching terminal to Claude Code (Ctrl-] to detach)..."
python3 "$DEPLOY/host/attach_terminal.py"
