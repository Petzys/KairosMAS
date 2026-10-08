#!/bin/bash
#
# Tear down the filesystem channel  (M2)
# ======================================
# Stops virtiofsd + fs_monitor and unmounts the FUSE + overlay layers. The
# overlay upper/ and the event log are LEFT IN PLACE so `report.py` can produce
# the session diff afterwards.
#
set -uo pipefail
ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
VIOFS_SOCK="/tmp/kairos_virtiofs.sock"
RUN="/run/kairos"

for name in virtiofsd fs_monitor; do
    if [ -f "$RUN/$name.pid" ]; then
        kill "$(cat "$RUN/$name.pid")" 2>/dev/null || true
        rm -f "$RUN/$name.pid"
    fi
done
# belt-and-suspenders (match by path, not the reaper-sensitive binary name)
pkill -f "fs_monitor.py $ROOT/merged" 2>/dev/null || true
pkill -f "virtiofs.sock" 2>/dev/null || true
rm -f "$VIOFS_SOCK"
sleep 0.3

mountpoint -q "$ROOT/logged" && fusermount3 -u "$ROOT/logged" 2>/dev/null || true
mountpoint -q "$ROOT/merged" && umount "$ROOT/merged" 2>/dev/null || true
echo "[fs] channel down (upper/ + event log kept for report.py)"
