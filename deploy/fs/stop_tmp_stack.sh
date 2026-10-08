#!/bin/bash
# Tear down the monitored /tmp channel. Event log is kept for the audit.
set -uo pipefail
ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
SOCK="/tmp/kairos_virtiofs_tmp.sock"; RUN="/run/kairos"
for n in tmp_virtiofsd tmp_monitor; do
    [ -f "$RUN/$n.pid" ] && { kill "$(cat "$RUN/$n.pid")" 2>/dev/null || true; rm -f "$RUN/$n.pid"; }
done
pkill -f "fs_monitor.py $ROOT/tmp_src" 2>/dev/null || true
pkill -f "virtiofs_tmp.sock" 2>/dev/null || true
rm -f "$SOCK"; sleep 0.3
mountpoint -q "$ROOT/tmp_logged" && fusermount3 -u "$ROOT/tmp_logged" 2>/dev/null || true
echo "[tmp] channel down (event log kept)"
