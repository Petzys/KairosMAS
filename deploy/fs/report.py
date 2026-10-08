#!/usr/bin/env python3
"""
Filesystem channel — session diff + timeline report  (M2)
=========================================================
Turns the two artifacts of a monitored session into a human/JSON report:

  1. the OverlayFS *upper* layer  -> the authoritative change set (added /
     modified / deleted files, with a unified diff for text files), and
  2. the fs_monitor JSONL event stream -> the timeline (per-op, per-file, and a
     coarse segmentation into "turns" by idle gaps).

This is the data the frontend (M4) will render. Deletions are detected via
OverlayFS whiteouts (a 0/0 char device in upper/).

Usage:
    report.py [--root /var/lib/kairos/fs] [--events FILE] [--json] [--gap SECONDS]
"""

import os
import sys
import json
import stat
import time
import argparse
import difflib


def is_whiteout(p):
    try:
        st = os.lstat(p)
        return stat.S_ISCHR(st.st_mode) and os.major(st.st_rdev) == 0 and os.minor(st.st_rdev) == 0
    except OSError:
        return False


def walk_rel(base):
    for dirpath, _dirs, files in os.walk(base):
        for name in files:
            full = os.path.join(dirpath, name)
            yield os.path.relpath(full, base), full
        # also surface whiteouts (char devices show up as files in os.walk? no) —
        # handle separately below


def collect_changes(root, base=None):
    """Compare the lower/base dir vs upper to classify each changed path."""
    base = base or os.environ.get("KAIROS_FS_LOWER") or os.path.join(root, "base")
    upper = os.path.join(root, "upper")
    changes = []
    for dirpath, _dirs, files in os.walk(upper):
        for name in files + _dirs:  # include names that may be whiteouts (chardev) or dirs
            up = os.path.join(dirpath, name)
            rel = os.path.relpath(up, upper)
            bp = os.path.join(base, rel)
            if is_whiteout(up):
                changes.append({"path": rel, "kind": "deleted"})
            elif os.path.isfile(up):
                kind = "modified" if os.path.exists(bp) else "added"
                changes.append({"path": rel, "kind": kind,
                                "before": bp if os.path.exists(bp) else None, "after": up})
    # dedupe (a path can appear once)
    seen, out = set(), []
    for c in changes:
        if c["path"] in seen:
            continue
        seen.add(c["path"])
        out.append(c)
    return sorted(out, key=lambda c: c["path"])


# Per-file cap for change tracking. Beyond this we record only metadata
# (name/path/operation), not the exact diff — keeps the audit log bounded.
DIFF_CAP = int(os.environ.get("KAIROS_FS_MAX_BYTES", str(100 * 1024 * 1024)))


def read_text(p, cap=DIFF_CAP + 1):
    try:
        with open(p, "rb") as f:
            data = f.read(cap)
        return data.decode("utf-8"), False
    except (UnicodeDecodeError, OSError):
        return None, True


def unified(before_path, after_path, rel):
    # cap: if either side exceeds the limit, don't diff — just note it
    for p in (before_path, after_path):
        try:
            if p and os.path.getsize(p) > DIFF_CAP:
                mb = os.path.getsize(p) / (1024 * 1024)
                return f"  (large file {rel}: {mb:.0f} MB — content not tracked, only the change was recorded)\n"
        except OSError:
            pass
    a = read_text(before_path)[0].splitlines(keepends=True) if before_path else []
    b_text, binary = read_text(after_path)
    if binary:
        return f"  (binary file {rel} changed)\n"
    b = b_text.splitlines(keepends=True)
    diff = difflib.unified_diff(a, b, fromfile=f"a/{rel}", tofile=f"b/{rel}")
    return "".join(diff)


def load_events(path):
    evs = []
    if not os.path.exists(path):
        return evs
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                evs.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return evs


def segment_turns(events, gap):
    """Coarse turn segmentation: a gap > `gap` seconds starts a new turn."""
    turns, cur, last = [], [], None
    for e in events:
        if e.get("op") == "mount":
            continue
        ts = e.get("ts", 0)
        if last is not None and ts - last > gap and cur:
            turns.append(cur)
            cur = []
        cur.append(e)
        last = ts
    if cur:
        turns.append(cur)
    return turns


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=os.environ.get("KAIROS_FS_ROOT", "/var/lib/kairos/fs"))
    ap.add_argument("--events", default="/tmp/kairos_fs_events.jsonl")
    ap.add_argument("--gap", type=float, default=8.0, help="idle seconds => new turn")
    ap.add_argument("--json", action="store_true", help="emit JSON instead of text")
    args = ap.parse_args()

    changes = collect_changes(args.root)
    events = load_events(args.events)
    data_ops = [e for e in events if e.get("op") in
                ("read", "write", "create", "unlink", "rename", "truncate", "mkdir", "rmdir")]
    turns = segment_turns(events, args.gap)

    if args.json:
        for c in changes:
            if c["kind"] in ("added", "modified"):
                c["diff"] = unified(c.get("before"), c.get("after"), c["path"])
        print(json.dumps({
            "root": args.root,
            "changes": changes,
            "event_count": len(events),
            "turns": [{"n": i + 1, "ops": len(t),
                       "files": sorted({e["path"] for e in t if "path" in e}),
                       "start": t[0].get("ts"), "end": t[-1].get("ts")}
                      for i, t in enumerate(turns)],
        }, indent=2))
        return

    print("=" * 64)
    print("  Kairos filesystem session report")
    print("=" * 64)
    print(f"state root : {args.root}")
    print(f"events     : {len(events)} ({len(data_ops)} data ops)  file={args.events}")
    print(f"turns      : {len(turns)} (idle-gap {args.gap:.0f}s segmentation)")
    print()

    if not changes:
        print("No filesystem changes recorded (upper layer empty).")
    else:
        print(f"Changed files ({len(changes)}):")
        for c in changes:
            tag = {"added": "A", "modified": "M", "deleted": "D"}[c["kind"]]
            print(f"  {tag}  {c['path']}")
        print()
        for c in changes:
            print("-" * 64)
            print(f"[{c['kind'].upper()}] {c['path']}")
            if c["kind"] == "deleted":
                continue
            d = unified(c.get("before"), c.get("after"), c["path"])
            print(d if d.strip() else "  (no textual diff / metadata-only change)")

    print("=" * 64)
    print("Timeline (per turn):")
    for i, t in enumerate(turns):
        files = sorted({e["path"] for e in t if "path" in e})
        span = (t[-1].get("ts", 0) - t[0].get("ts", 0))
        print(f"  turn {i+1}: {len(t)} ops, {len(files)} files, {span:.1f}s")
        for fp in files[:12]:
            ops = sorted({e["op"] for e in t if e.get("path") == fp})
            print(f"       {fp}  [{','.join(ops)}]")


if __name__ == "__main__":
    main()
