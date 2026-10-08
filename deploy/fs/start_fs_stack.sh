#!/bin/bash
#
# Bring up the filesystem channel  (M2)
# =====================================
# overlay (base+upper) -> fs_monitor (FUSE, logs every op to JSONL) -> virtiofsd
# The VM launcher then attaches the virtiofsd socket as /data in the guest.
#
# Env:
#   KAIROS_FS_ROOT   state dir           (default /var/lib/kairos/fs)
#   KAIROS_FS_SEED   starter project     (optional; seeds base/)
#   KAIROS_FS_RESET  =1 fresh session    (wipe upper/, keep base/)
#   KAIROS_FS_EVENTS event log path      (default /tmp/kairos_fs_events.jsonl)
#
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
EVENTS="${KAIROS_FS_EVENTS:-/tmp/kairos_fs_events.jsonl}"
VIOFS_SOCK="/tmp/kairos_virtiofs.sock"
RUN="/run/kairos"; mkdir -p "$RUN"

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi

VIRTIOFSD="$(command -v virtiofsd || echo /usr/local/bin/virtiofsd)"
[ -x "$VIRTIOFSD" ] || { echo "virtiofsd not found"; exit 1; }

# 1) overlay
KAIROS_FS_ROOT="$ROOT" bash "$HERE/setup_overlay.sh"

# 2) FUSE content monitor over the merged view
#    --wal enables the write-ahead log: per-action before-images, so an individual
#    action can be undone WHILE the session runs. The overlay still does the
#    end-of-run disposition (merge / partial merge / abort); the WAL is what makes
#    everything before that point resolvable. KAIROS_FS_WAL=0 turns it off.
: > "$EVENTS" 2>/dev/null || true
WAL_ARGS=()
if [ "${KAIROS_FS_WAL:-1}" != "0" ]; then
    WAL_ARGS=(--wal "$ROOT/wal")
    [ "${KAIROS_FS_RESET:-0}" = "1" ] && rm -rf "${ROOT:?}/wal"
fi
setsid python3 "$HERE/fs_monitor.py" "$ROOT/merged" "$ROOT/logged" --events "$EVENTS" \
    "${WAL_ARGS[@]}" \
    >/var/log/kairos-fs_monitor.log 2>&1 < /dev/null &
echo $! > "$RUN/fs_monitor.pid"
for i in $(seq 1 40); do mountpoint -q "$ROOT/logged" && break; sleep 0.1; done
mountpoint -q "$ROOT/logged" || { echo "fs_monitor failed to mount; see /var/log/kairos-fs_monitor.log"; exit 1; }
echo "[fs] monitor mounted at $ROOT/logged (events -> $EVENTS)"

# 3) virtiofsd sharing the monitored view into the guest
rm -f "$VIOFS_SOCK"
setsid "$VIRTIOFSD" --socket-path="$VIOFS_SOCK" --shared-dir="$ROOT/logged" \
    --sandbox none --cache auto --log-level warn \
    >/var/log/kairos-virtiofsd.log 2>&1 < /dev/null &
echo $! > "$RUN/virtiofsd.pid"
for i in $(seq 1 40); do [ -S "$VIOFS_SOCK" ] && break; sleep 0.1; done
[ -S "$VIOFS_SOCK" ] || { echo "virtiofsd failed to create socket; see /var/log/kairos-virtiofsd.log"; exit 1; }
echo "[fs] virtiofsd serving $ROOT/logged on $VIOFS_SOCK (guest tag=kairosfs -> /data)"
echo "[fs] filesystem channel up."
