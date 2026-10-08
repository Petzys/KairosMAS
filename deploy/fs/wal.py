#!/usr/bin/env python3
"""Filesystem write-ahead log — per-action undo while the session is live.

Why this exists
---------------
OverlayFS gives the session ONE upper layer. That is the right shape for the
end-of-run disposition (merge / partly merge / abort against a pristine lower),
but it cannot express anything finer:

  * `upper/` holds each file's FINAL state, so two writes to one file cannot be
    separately committed and aborted;
  * resolution needs the overlay unmounted, so nothing can be resolved while the
    agent is still working;
  * nothing records WHICH action produced which write, so attribution cannot
    survive into a later session.

The journal supplies exactly that, and the two mechanisms divide the work:

    during the run   the WAL is authoritative — per-action attribution, and undo
                     of an individual action without unmounting anything
    at the end       OverlayFS does the disposition — merge, partial merge, or
                     abort of whatever survived

Layout, mirroring the network channel's content-addressed `bodies/<sha256>`:

    <root>/journal.jsonl     append-only; op records and status records
    <root>/blobs/<sha256>    before-images

Undo is whole-file, not block-level. A `write` snapshots the entire file, so
undoing a run of partial writes is order-independent: replaying records
newest-first leaves the earliest before-image in place, which is the state the
branch began with. The cost is one file read per mutating op, which is the right
trade for source trees and is capped by `max_bytes`.

The honest limitation that comes with file-level undo is overlap: aborting an
older change to a path that a LATER, surviving branch also wrote would roll back
that later work too. `conflicts()` detects this and the resolver refuses rather
than silently clobbering.
"""
from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import stat
import time
from threading import Lock

DEFAULT_MAX_BYTES = int(os.environ.get("KAIROS_MAX_LOG_BYTES", str(100 * 1024 * 1024)))

# ops whose undo restores file CONTENT from a before-image
CONTENT_OPS = ("write", "truncate", "create", "unlink")
MUTATING_OPS = CONTENT_OPS + ("rename", "mkdir", "rmdir", "symlink", "link", "chmod")


class Wal:
    """Append-only journal over a target tree.

    `target_root` is the directory the recorded paths are relative to — the
    overlay's merged view, so both capture and undo go through the same mount the
    agent sees and neither needs the overlay taken down.
    """

    def __init__(self, root: str, target_root: str | None = None,
                 max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.root = os.path.abspath(root)
        self.target_root = os.path.abspath(target_root or os.path.join(self.root, "..", "merged"))
        self.blobs = os.path.join(self.root, "blobs")
        self.journal = os.path.join(self.root, "journal.jsonl")
        self.max_bytes = max_bytes
        self._lock = Lock()
        self._seq = 0
        os.makedirs(self.blobs, exist_ok=True)
        self._seq = max((r.get("seq", 0) for r in self._raw()), default=0)

    # ---- paths ------------------------------------------------------------
    def _full(self, rel: str) -> str:
        return os.path.join(self.target_root, rel.lstrip("/"))

    # ---- blob store -------------------------------------------------------
    def _put_blob(self, data: bytes) -> str:
        sha = hashlib.sha256(data).hexdigest()
        p = os.path.join(self.blobs, sha)
        if not os.path.exists(p):
            tmp = p + ".tmp"
            with open(tmp, "wb") as f:
                f.write(data)
            os.replace(tmp, p)
        return sha

    def _get_blob(self, sha: str) -> bytes:
        with open(os.path.join(self.blobs, sha), "rb") as f:
            return f.read()

    # ---- capture ----------------------------------------------------------
    def snapshot(self, rel: str) -> dict:
        """Before-image of `rel`, taken BEFORE the op is performed.

        Returns one of: {"absent": True} (nothing there yet), {"oversize": True}
        (too large to keep — recorded so the record is explicitly non-undoable
        rather than appearing undoable and failing later), {"dir": True},
        {"symlink": target}, or {"sha", "size", "mode"}."""
        full = self._full(rel)
        try:
            st = os.lstat(full)
        except OSError:
            return {"absent": True}
        if stat.S_ISDIR(st.st_mode):
            return {"dir": True, "mode": st.st_mode}
        if stat.S_ISLNK(st.st_mode):
            return {"symlink": os.readlink(full), "mode": st.st_mode}
        if st.st_size > self.max_bytes:
            return {"oversize": True, "size": st.st_size, "mode": st.st_mode}
        try:
            with open(full, "rb") as f:
                data = f.read()
        except OSError as e:
            return {"error": errno.errorcode.get(e.errno, str(e.errno))}
        return {"sha": self._put_blob(data), "size": len(data), "mode": st.st_mode}

    def record(self, op: str, rel: str, before: dict, *, branch: str = "",
               to: str | None = None, mode: int | None = None) -> dict:
        """Append one op record. Returns it."""
        with self._lock:
            self._seq += 1
            rec = {"kind": "op", "seq": self._seq, "ts": round(time.time(), 6),
                   "branch": branch or "", "op": op, "path": rel.lstrip("/"),
                   "before": before, "status": "pending"}
            if to is not None:
                rec["to"] = to.lstrip("/")
            if mode is not None:
                rec["mode"] = mode
            self._append(rec)
        return rec

    def _append(self, rec: dict) -> None:
        with open(self.journal, "a", buffering=1) as f:
            f.write(json.dumps(rec, separators=(",", ":"), ensure_ascii=False) + "\n")

    # ---- read ------------------------------------------------------------
    def _raw(self) -> list[dict]:
        out: list[dict] = []
        try:
            with open(self.journal, encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            out.append(json.loads(line))
                        except ValueError:
                            pass
        except OSError:
            pass
        return out

    def load(self) -> list[dict]:
        """Op records with status folded in.

        Status changes are appended rather than rewritten in place, so the log
        stays append-only and a crash mid-resolution cannot corrupt earlier
        records — replaying it is what reconstructs the current state."""
        ops: dict[int, dict] = {}
        for r in self._raw():
            if r.get("kind") == "op":
                ops[r["seq"]] = dict(r)
            elif r.get("kind") == "status" and r.get("ref") in ops:
                ops[r["ref"]]["status"] = r.get("status", "pending")
        return [ops[k] for k in sorted(ops)]

    def select(self, *, branch: str | None = None, path: str | None = None,
               status: str | None = "pending") -> list[dict]:
        out = self.load()
        if branch is not None:
            out = [r for r in out if r.get("branch") == branch]
        if path is not None:
            p = path.lstrip("/")
            out = [r for r in out if r.get("path") == p or r.get("to") == p]
        if status is not None:
            out = [r for r in out if r.get("status") == status]
        return out

    def branches(self) -> list[str]:
        seen, out = set(), []
        for r in self.load():
            b = r.get("branch") or ""
            if b not in seen:
                seen.add(b)
                out.append(b)
        return out

    def mark(self, records: list[dict], status: str) -> None:
        with self._lock:
            for r in records:
                self._seq += 1
                self._append({"kind": "status", "seq": self._seq, "ref": r["seq"],
                              "status": status, "ts": round(time.time(), 6)})

    # ---- resolution -------------------------------------------------------
    def conflicts(self, records: list[dict]) -> list[dict]:
        """Records that cannot be safely undone because a LATER pending record
        from a different branch touched the same path.

        Whole-file undo would roll that later work back too, so the caller must
        refuse. Reporting it beats silently discarding someone else's change."""
        chosen = {r["seq"] for r in records}
        by_path: dict[str, list[dict]] = {}
        for r in self.load():
            if r.get("status") != "pending":
                continue
            by_path.setdefault(r["path"], []).append(r)
        out = []
        for r in records:
            later = [o for o in by_path.get(r["path"], [])
                     if o["seq"] > r["seq"] and o["seq"] not in chosen]
            if later:
                out.append({"record": r, "blocked_by": [o["seq"] for o in later],
                            "branches": sorted({o.get("branch", "") for o in later})})
        return out

    def undo(self, records: list[dict]) -> list[str]:
        """Revert `records`, newest first. Returns one status line per action taken.

        One agent edit produces several content records — `create` then `write`,
        or `truncate` then `write` — all carrying the same before-image. Restoring
        each in turn is harmless but does the work repeatedly and reports the same
        file reverted several times. Only the OLDEST content record per path is
        applied: its before-image is the state the branch started from, which is
        exactly what the others would converge to anyway."""
        oldest: dict[str, int] = {}
        for r in records:
            if r["op"] in CONTENT_OPS:
                p = r["path"]
                oldest[p] = min(oldest.get(p, r["seq"]), r["seq"])
        out = []
        for r in sorted(records, key=lambda x: -x["seq"]):
            if r["op"] in CONTENT_OPS and oldest.get(r["path"]) != r["seq"]:
                continue                        # superseded by an older snapshot
            try:
                out.append(self._undo_one(r))
            except OSError as e:
                out.append(f"error {r['op']} {r['path']}: {e}")
        return out

    def _restore(self, rel: str, before: dict) -> str:
        full = self._full(rel)
        if before.get("oversize"):
            return f"SKIP (before-image too large to keep): {rel}"
        if before.get("error"):
            return f"SKIP (before-image unreadable): {rel}"
        if before.get("absent"):
            if os.path.lexists(full):
                if os.path.isdir(full) and not os.path.islink(full):
                    shutil.rmtree(full)
                else:
                    os.unlink(full)
            return f"reverted (removed, did not exist before): {rel}"
        if before.get("dir"):
            os.makedirs(full, exist_ok=True)
            return f"reverted (directory restored): {rel}"
        if before.get("symlink") is not None:
            if os.path.lexists(full):
                os.unlink(full)
            os.symlink(before["symlink"], full)
            return f"reverted (symlink restored): {rel}"
        data = self._get_blob(before["sha"])
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        if os.path.lexists(full) and os.path.isdir(full) and not os.path.islink(full):
            shutil.rmtree(full)
        with open(full, "wb") as f:
            f.write(data)
        if before.get("mode"):
            try:
                os.chmod(full, stat.S_IMODE(before["mode"]))
            except OSError:
                pass
        return f"reverted ({len(data)} bytes restored): {rel}"

    def _undo_one(self, r: dict) -> str:
        op, rel, before = r["op"], r["path"], r.get("before") or {}
        full = self._full(rel)
        if op == "rename":
            new = self._full(r.get("to", ""))
            if os.path.lexists(new):
                os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
                os.rename(new, full)
                return f"reverted (renamed back): {r.get('to')} -> {rel}"
            return f"skip (renamed file gone): {rel}"
        if op in ("mkdir",):
            try:
                os.rmdir(full)
                return f"reverted (dir removed): {rel}"
            except OSError:
                return f"skip (dir not empty): {rel}"
        if op in ("rmdir",):
            os.makedirs(full, exist_ok=True)
            return f"reverted (dir recreated): {rel}"
        if op in ("symlink", "link"):
            if os.path.lexists(full):
                os.unlink(full)
            return f"reverted (link removed): {rel}"
        if op == "chmod":
            if before.get("mode"):
                os.chmod(full, stat.S_IMODE(before["mode"]))
                return f"reverted (mode restored): {rel}"
            return f"skip (no prior mode): {rel}"
        return self._restore(rel, before)          # write / truncate / create / unlink


# ---- branch attribution ---------------------------------------------------
# The FUSE layer has no notion of an agent turn, and there is no IPC between it
# and the control plane. Reuse the file handoff run.sh already uses for
# /run/kairos/fs_lower: the control plane writes the current branch id, the FUSE
# layer reads it. One stat per op, no socket, and it survives either side
# restarting.
BRANCH_FILE = os.environ.get("KAIROS_BRANCH_FILE", "/run/kairos/current_branch")
_branch_cache: tuple[float, str] = (0.0, "")


def current_branch(path: str = BRANCH_FILE) -> str:
    global _branch_cache
    try:
        mtime = os.stat(path).st_mtime
    except OSError:
        return ""
    if mtime != _branch_cache[0]:
        try:
            with open(path) as f:
                _branch_cache = (mtime, f.read().strip())
        except OSError:
            _branch_cache = (mtime, "")
    return _branch_cache[1]


def set_branch(value: str, path: str = BRANCH_FILE) -> None:
    try:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            f.write(value)
        os.replace(tmp, path)
    except OSError:
        pass


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="inspect / resolve the filesystem WAL")
    ap.add_argument("--root", default=os.path.join(
        os.environ.get("KAIROS_FS_ROOT", "/var/lib/kairos/fs"), "wal"))
    ap.add_argument("--target", default=None, help="tree the paths are relative to")
    sub = ap.add_subparsers(dest="cmd", required=True)
    ls = sub.add_parser("list"); ls.add_argument("--branch", default=None)
    ls.add_argument("--status", default="pending")
    for name in ("commit", "abort"):
        s = sub.add_parser(name)
        s.add_argument("--branch", default=None)
        s.add_argument("--path", default=None)
        s.add_argument("--force", action="store_true", help="ignore overlap conflicts")
    a = ap.parse_args()

    w = Wal(a.root, a.target)
    recs = w.select(branch=a.branch, path=getattr(a, "path", None),
                    status=None if a.cmd == "list" else "pending")
    if a.cmd == "list":
        recs = [r for r in recs if a.status in (None, "", r.get("status"))]
        for r in recs:
            print(f"{r['seq']:>5} {r['status']:<9} [{r.get('branch') or '-'}] "
                  f"{r['op']:<9} {r['path']}")
        print(f"({len(recs)} records; branches: {', '.join(w.branches()) or '-'})")
        return 0
    if not recs:
        print("no pending records match")
        return 0
    if a.cmd == "abort":
        conf = w.conflicts(recs)
        if conf and not a.force:
            print("refusing: later pending changes to the same paths would be lost")
            for c in conf:
                print(f"  seq {c['record']['seq']} {c['record']['path']} "
                      f"blocked by {c['blocked_by']} (branches {c['branches']})")
            print("re-run with --force to override")
            return 2
        for line in w.undo(recs):
            print(line)
        w.mark(recs, "aborted")
    else:
        w.mark(recs, "committed")
        print(f"committed {len(recs)} record(s) (data already in place)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
