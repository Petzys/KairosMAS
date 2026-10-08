#!/bin/bash
#
# Monitored /tmp channel  (observe-only)
# ======================================
# Claude Code likes to write scratch scripts in /tmp. This shares a host-backed
# directory into the guest as /tmp through the SAME FUSE content-logger, so those
# writes are captured to the audit log. There is NO overlay and NO write-back —
# /tmp is ephemeral scratch; the source dir is wiped each run.
#
#   guest /tmp  --virtio-fs(tag=kairostmp)-->  tmp_logged (FUSE) --> tmp_src (host)
#
# Env: KAIROS_FS_ROOT, KAIROS_TMP_EVENTS (default /tmp/kairos_tmp_events.jsonl)
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
EVENTS="${KAIROS_TMP_EVENTS:-/tmp/kairos_tmp_events.jsonl}"
SRC="$ROOT/tmp_src"; LOGGED="$ROOT/tmp_logged"
SOCK="/tmp/kairos_virtiofs_tmp.sock"
RUN="/run/kairos"; mkdir -p "$RUN"

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi
VIRTIOFSD="$(command -v virtiofsd || echo /usr/local/bin/virtiofsd)"

# fresh scratch (ephemeral)
mountpoint -q "$LOGGED" 2>/dev/null && fusermount3 -u "$LOGGED" 2>/dev/null || true
rm -rf "$SRC" 2>/dev/null || true
mkdir -p "$SRC" "$LOGGED"; chmod 1777 "$SRC"
: > "$EVENTS" 2>/dev/null || true

# FUSE content-logger over the scratch dir (label events as the /tmp mount)
setsid python3 "$HERE/fs_monitor.py" "$SRC" "$LOGGED" --events "$EVENTS" --mount tmp \
    >/var/log/kairos-tmp_monitor.log 2>&1 < /dev/null &
echo $! > "$RUN/tmp_monitor.pid"
for i in $(seq 1 40); do mountpoint -q "$LOGGED" && break; sleep 0.1; done
mountpoint -q "$LOGGED" || { echo "[tmp] fs_monitor failed; see /var/log/kairos-tmp_monitor.log"; exit 1; }

# virtiofsd sharing it into the guest as tag=kairostmp
rm -f "$SOCK"
setsid "$VIRTIOFSD" --socket-path="$SOCK" --shared-dir="$LOGGED" \
    --sandbox none --cache auto --log-level warn \
    >/var/log/kairos-tmp_virtiofsd.log 2>&1 < /dev/null &
echo $! > "$RUN/tmp_virtiofsd.pid"
for i in $(seq 1 40); do [ -S "$SOCK" ] && break; sleep 0.1; done
[ -S "$SOCK" ] || { echo "[tmp] virtiofsd failed; see /var/log/kairos-tmp_virtiofsd.log"; exit 1; }
echo "[tmp] monitored /tmp channel up (guest tag=kairostmp, events -> $EVENTS)"
