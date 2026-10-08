#!/bin/bash
#
# Filesystem channel — OverlayFS setup  (M2)
# ==========================================
# The overlay's LOWER layer is the provided directory used DIRECTLY (no copy),
# so setup is instant even for large projects and there is no duplication. The
# UPPER layer holds only the agent's changes; on commit they are merged back
# into the lower (the provided dir) in place. The lower is read-only through the
# overlay during the run, so an abort leaves it pristine.
#
# Layout under $KAIROS_FS_ROOT (default /var/lib/kairos/fs):
#   upper/   changes           — every create/modify/delete lands here (the diff)
#   work/    overlay scratch
#   merged/  overlay mount     — lower + upper, what fs_monitor mirrors
#   logged/  FUSE mountpoint    — virtiofsd shares THIS into the guest
#
# Env:
#   KAIROS_FS_ROOT    state dir (default /var/lib/kairos/fs)
#   KAIROS_FS_LOWER   the lower/base dir to overlay (default $ROOT/base — an empty
#                    scratch used when no project is provided). run.sh sets this
#                    to your KAIROS_FS_SEED directory, used in place (no copy).
#   KAIROS_FS_RESET   =1 wipe upper/work (discard staged changes at start)
#
set -euo pipefail
ROOT="${KAIROS_FS_ROOT:-/var/lib/kairos/fs}"
LOWER="${KAIROS_FS_LOWER:-$ROOT/base}"
RESET="${KAIROS_FS_RESET:-0}"

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi

UPPER="$ROOT/upper"; WORK="$ROOT/work"; MERGED="$ROOT/merged"; LOGGED="$ROOT/logged"

# tear down a previous mount cleanly
mountpoint -q "$LOGGED" 2>/dev/null && fusermount3 -u "$LOGGED" 2>/dev/null || true
mountpoint -q "$MERGED" 2>/dev/null && umount "$MERGED" 2>/dev/null || true

mkdir -p "$UPPER" "$WORK" "$MERGED" "$LOGGED"
[ -d "$LOWER" ] || mkdir -p "$LOWER"     # empty scratch lower when no project given

if [ "$RESET" = "1" ]; then
    echo "[overlay] resetting upper/ + work/ (discarding staged changes)"
    rm -rf "${UPPER:?}/"* "${UPPER:?}"/.[!.]* 2>/dev/null || true
    rm -rf "${WORK:?}/"*  "${WORK:?}"/.[!.]*  2>/dev/null || true
fi

mount -t overlay overlay \
    -o "lowerdir=$LOWER,upperdir=$UPPER,workdir=$WORK" \
    "$MERGED"

echo "[overlay] mounted $MERGED (lower=$LOWER used in place, upper=upper)"
echo "[overlay] FUSE mountpoint ready: $LOGGED"
echo "KAIROS_FS_ROOT=$ROOT KAIROS_FS_LOWER=$LOWER"
