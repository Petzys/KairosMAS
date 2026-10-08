#!/usr/bin/env python3
"""
Filesystem channel — resolution (commit / abort)  (M5)
======================================================
The overlay is the transaction: every change the agent made is staged in the
`upper` layer, `base` is untouched. Resolving a file means:

  commit  -> merge upper/<path> into base/<path> (the change becomes the new
             baseline) and clear it from upper. A staged DELETE (overlay
             whiteout) commits by removing the file from base.
  abort   -> discard upper/<path> (and any whiteout) so base shows through
             again — the change never happened.

Operates on the overlay's `base`/`upper` directories directly, so it must run
while the overlay is NOT mounted (i.e. after the session's stop_fs_stack). That
matches the demo flow: run → detach (overlay torn down) → review + resolve.

Importable (used by the control plane) and runnable as a CLI.
"""

import os
import sys
import stat
import shutil
import argparse


def is_whiteout(p):
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == 0 and os.minor(st.st_rdev) == 0


def _rm(path):
    if os.path.islink(path) or os.path.isfile(path) or is_whiteout(path):
        os.unlink(path)
    elif os.path.isdir(path):
        shutil.rmtree(path)


def base_dir(root):
    """The lower/base directory changes merge into (the provided dir, in place)."""
    return os.environ.get("KAIROS_FS_LOWER") or os.path.join(root, "base")


def resolve_file(root, rel, action, base_root=None):
    """Resolve one staged change. Returns a short status string."""
    rel = rel.lstrip("/")
    base_root = base_root or base_dir(root)
    base = os.path.join(base_root, rel)
    upper = os.path.join(root, "upper", rel)

    if not os.path.lexists(upper):
        return f"skip (no staged change): {rel}"

    if action == "abort":
        _rm(upper)
        return f"aborted (reverted): {rel}"

    if action == "commit":
        if is_whiteout(upper):
            # staged deletion -> apply it to base
            if os.path.lexists(base):
                _rm(base)
            os.unlink(upper)
            return f"committed (deleted): {rel}"
        # staged create/modify -> copy into base, clear from upper
        os.makedirs(os.path.dirname(base) or ".", exist_ok=True)
        if os.path.lexists(base):
            _rm(base)
        shutil.copy2(upper, base, follow_symlinks=False)
        _rm(upper)
        return f"committed (merged): {rel}"

    raise ValueError(f"unknown action: {action}")


def list_changes(root):
    """Relative paths of all staged changes (files + whiteouts) in upper/."""
    upper = os.path.join(root, "upper")
    out = []
    for dirpath, dirs, files in os.walk(upper):
        for name in files + dirs:
            full = os.path.join(dirpath, name)
            if os.path.isfile(full) or is_whiteout(full):
                out.append(os.path.relpath(full, upper))
    # dedupe, stable
    seen, res = set(), []
    for p in out:
        if p not in seen:
            seen.add(p); res.append(p)
    return sorted(res)


def resolve_all(root, action, base_root=None):
    return [resolve_file(root, rel, action, base_root) for rel in list_changes(root)]


# ---------------------------------------------------------------------------
# WAL path — resolution DURING the session
# ---------------------------------------------------------------------------
# The overlay functions above are the end-of-run disposition: they merge or
# discard the upper layer once the agent has finished and the mount is gone. The
# journal covers everything before that. It works while mounted (undo is ordinary
# file I/O through the same merged view) and it is per-action rather than
# per-file, so two changes to one file made in different branches can be resolved
# differently — which one upper layer cannot express.

def wal_for(root, target=None):
    """The session's Wal, or None when the WAL was not enabled for this run."""
    import wal as wal_mod
    d = os.path.join(root, "wal")
    if not os.path.isdir(d):
        return None
    return wal_mod.Wal(d, target_root=target or os.path.join(root, "merged"))


def wal_changes(root, target=None):
    """Pending records grouped for the control plane: one entry per (branch, path)."""
    w = wal_for(root, target)
    if w is None:
        return []
    seen, out = set(), []
    for r in w.select(status="pending"):
        key = (r.get("branch", ""), r["path"])
        if key in seen:
            continue
        seen.add(key)
        out.append({"path": r["path"], "branch": r.get("branch", ""),
                    "op": r["op"], "seq": r["seq"], "ts": r.get("ts")})
    return out


def resolve_records(root, action, *, branch=None, paths=None, target=None,
                    force=False):
    """Commit or abort pending records, live. Returns (results, conflicts).

    commit  marks the records committed — the bytes are already in place, so
            there is nothing to replay; the overlay merges them at exit.
    abort   replays the before-images, newest first, so the effect is gone from
            the agent's view immediately and never reaches the merge.
    """
    w = wal_for(root, target)
    if w is None:
        return ["wal not enabled for this session"], []
    recs = []
    for p in (paths or [None]):
        recs.extend(w.select(branch=branch, path=p, status="pending"))
    recs = list({r["seq"]: r for r in recs}.values())
    if not recs:
        return ["no pending records match"], []
    if action == "abort":
        conflicts = w.conflicts(recs)
        if conflicts and not force:
            return [], conflicts
        results = w.undo(recs)
        w.mark(recs, "aborted")
        return results, []
    w.mark(recs, "committed")
    return [f"committed {len(recs)} record(s) (already in place)"], []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.environ.get("KAIROS_FS_ROOT", "/var/lib/kairos/fs"))
    ap.add_argument("--base", default=None, help="dir to merge into (default: KAIROS_FS_LOWER or root/base)")
    ap.add_argument("action", choices=["commit", "abort"])
    ap.add_argument("paths", nargs="*", help="relative paths; empty = all staged changes")
    args = ap.parse_args()

    if os.path.ismount(os.path.join(args.root, "merged")):
        sys.exit("refusing to resolve while overlay is mounted — stop the FS stack first")

    base_root = args.base or base_dir(args.root)
    targets = args.paths or list_changes(args.root)
    if not targets:
        print("no staged changes to resolve")
        return
    for rel in targets:
        print(resolve_file(args.root, rel, args.action, base_root))


if __name__ == "__main__":
    main()
