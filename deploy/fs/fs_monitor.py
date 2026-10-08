#!/usr/bin/env python3
"""
Filesystem channel monitor — FUSE content-logger  (M2, observe-only)
====================================================================

A FUSE passthrough filesystem that mirrors an underlying directory (the
OverlayFS *merged* view) and records every operation — with content — as a
structured JSONL event stream. It sits in the data path:

    guest /data  (virtio-fs)
        -> virtiofsd  --shared-dir = <this FUSE mountpoint>
            -> fs_monitor (FUSE, logs every op)     [YOU ARE HERE]
                -> OverlayFS merged  (lower=base, upper=changes)
                    -> real files

Because writes copy-up into the overlay *upper* layer, the upper directory is
the authoritative "what changed" set; this monitor adds the *timeline* (when,
which op, what bytes). Together they let the frontend reconstruct a per-turn
diff later. This milestone is OBSERVE-ONLY: every op is passed through, nothing
is denied.

Usage:
    fs_monitor.py <merged_dir> <mountpoint> [--events FILE] [--max-bytes N]

Events are one JSON object per line in --events (default /tmp/kairos_fs_events.jsonl):
    {"ts":.., "op":"write", "path":"/README.md", "off":0, "len":42,
     "sha256":"..", "preview":"..", "binary":false}
"""

import os
import sys
import json
import errno
import time
import hashlib
import argparse
from threading import Lock

try:
    from fuse import FUSE, FuseOSError, Operations
except ImportError:
    sys.stderr.write("ERROR: fusepy not installed (pip3 install fusepy)\n")
    sys.exit(1)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import wal as wal_mod  # noqa: E402  (write-ahead log: per-action undo, §4.7)


class EventLog:
    """Thread-safe JSONL sink, one event per line, flushed per write."""

    def __init__(self, path, mount=None):
        self._f = open(path, "a", buffering=1)  # line-buffered
        self._lock = Lock()
        self._mount = mount

    def emit(self, **event):
        event["ts"] = round(time.time(), 6)
        if self._mount:
            event["mount"] = self._mount
        line = json.dumps(event, separators=(",", ":"), ensure_ascii=False)
        with self._lock:
            self._f.write(line + "\n")

    def close(self):
        try:
            self._f.close()
        except OSError:
            pass


def _preview(data, max_bytes):
    """(sha256, preview_text_or_None, is_binary) for a bytes chunk."""
    sha = hashlib.sha256(data).hexdigest()
    chunk = data[:max_bytes]
    try:
        text = chunk.decode("utf-8")
        # keep it single-line-ish; the UI can re-expand
        return sha, text, False
    except UnicodeDecodeError:
        return sha, chunk[:32].hex(), True


class MonitorFS(Operations):
    def __init__(self, root, events, max_bytes=512, wal=None):
        self.root = os.path.realpath(root)
        self.ev = events
        self.max_bytes = max_bytes
        self.fd_paths = {}
        self._mutex = Lock()
        self.wal = wal
        # path -> before-image already captured for the CURRENT branch.
        # A whole-file snapshot per write would re-read the file on every 4 KiB
        # chunk; since undo restores the EARLIEST image for the branch anyway,
        # the first capture is the only one that matters. Blobs are
        # content-addressed, so reusing the descriptor costs nothing.
        self._snapped = {}
        self._branch = None

    def _full(self, partial):
        return os.path.join(self.root, partial.lstrip("/"))

    # ---------------- write-ahead log ----------------
    def _before(self, path):
        """Before-image for `path` in the current branch, captured once."""
        if self.wal is None:
            return None
        branch = wal_mod.current_branch()
        if branch != self._branch:             # new branch: snapshot afresh
            self._branch, self._snapped = branch, {}
        if path not in self._snapped:
            try:
                self._snapped[path] = self.wal.snapshot(path)
            except Exception as e:             # noqa: BLE001
                self.ev.emit(op="wal_error", path=path, error=str(e)[:200])
                return None
        return self._snapped[path]

    def _journal(self, op, path, before, **kw):
        """Append the op record. Journaling must never break the agent's I/O:
        the filesystem channel is observe-and-record, and a monitor that makes
        writes fail is worse than one that misses a journal entry."""
        if self.wal is None or before is None:
            return
        try:
            self.wal.record(op, path, before, branch=wal_mod.current_branch(), **kw)
        except Exception as e:                 # noqa: BLE001
            self.ev.emit(op="wal_error", path=path, error=str(e)[:200])

    # ---------------- data-path ops (logged with content) ----------------

    def open(self, path, flags):
        # O_TRUNC destroys content at open() time, before any write handler runs,
        # so the before-image has to be taken here or it is already lost.
        if flags & (os.O_WRONLY | os.O_RDWR | os.O_TRUNC | os.O_APPEND):
            before = self._before(path)
            if flags & os.O_TRUNC:
                self._journal("truncate", path, before)
        fd = os.open(self._full(path), flags)
        with self._mutex:
            self.fd_paths[fd] = path
        names = []
        if flags & os.O_WRONLY:
            names.append("WRITE")
        elif flags & os.O_RDWR:
            names.append("RDWR")
        else:
            names.append("READ")
        for bit, nm in ((os.O_APPEND, "APPEND"), (os.O_CREAT, "CREAT"), (os.O_TRUNC, "TRUNC")):
            if flags & bit:
                names.append(nm)
        self.ev.emit(op="open", path=path, flags=",".join(names))
        return fd

    def create(self, path, mode, fi=None):
        before = self._before(path)
        fd = os.open(self._full(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        self._journal("create", path, before, mode=mode)
        with self._mutex:
            self.fd_paths[fd] = path
        self.ev.emit(op="create", path=path, mode=oct(mode))
        return fd

    def read(self, path, length, offset, fh):
        os.lseek(fh, offset, os.SEEK_SET)
        data = os.read(fh, length)
        sha, prev, binary = _preview(data, self.max_bytes)
        self.ev.emit(op="read", path=path, off=offset, len=len(data),
                     sha256=sha, preview=prev, binary=binary)
        return data

    def write(self, path, data, offset, fh):
        before = self._before(path)
        os.lseek(fh, offset, os.SEEK_SET)
        n = os.write(fh, data)
        self._journal("write", path, before)
        sha, prev, binary = _preview(data, self.max_bytes)
        self.ev.emit(op="write", path=path, off=offset, len=len(data),
                     sha256=sha, preview=prev, binary=binary)
        return n

    def truncate(self, path, length, fh=None):
        before = self._before(path)
        with open(self._full(path), "r+") as f:
            f.truncate(length)
        self._journal("truncate", path, before)
        self.ev.emit(op="truncate", path=path, size=length)

    def ftruncate(self, path, length, fh):
        before = self._before(path)
        os.ftruncate(fh, length)
        self._journal("truncate", path, before)
        self.ev.emit(op="truncate", path=path, size=length)

    # ---------------- namespace ops (logged, no content) ----------------

    def unlink(self, path):
        before = self._before(path)
        self.ev.emit(op="unlink", path=path)
        r = os.unlink(self._full(path))
        self._journal("unlink", path, before)
        return r

    def rename(self, old, new):
        before = self._before(old)
        self.ev.emit(op="rename", path=old, to=new)
        r = os.rename(self._full(old), self._full(new))
        self._journal("rename", old, before, to=new)
        return r

    def mkdir(self, path, mode):
        before = self._before(path)
        self.ev.emit(op="mkdir", path=path, mode=oct(mode))
        r = os.mkdir(self._full(path), mode)
        self._journal("mkdir", path, before, mode=mode)
        return r

    def rmdir(self, path):
        before = self._before(path)
        self.ev.emit(op="rmdir", path=path)
        r = os.rmdir(self._full(path))
        self._journal("rmdir", path, before)
        return r

    def symlink(self, target, name):
        before = self._before(name)
        self.ev.emit(op="symlink", path=name, to=target)
        r = os.symlink(target, self._full(name))
        self._journal("symlink", name, before, to=target)
        return r

    def link(self, target, name):
        before = self._before(name)
        self.ev.emit(op="link", path=name, to=target)
        r = os.link(self._full(target), self._full(name))
        self._journal("link", name, before, to=target)
        return r

    def chmod(self, path, mode):
        before = self._before(path)
        self.ev.emit(op="chmod", path=path, mode=oct(mode))
        r = os.chmod(self._full(path), mode)
        self._journal("chmod", path, before, mode=mode)
        return r

    def chown(self, path, uid, gid):
        return os.chown(self._full(path), uid, gid)

    def mknod(self, path, mode, dev):
        try:
            os.mknod(self._full(path), mode, dev)
        except OSError as e:
            raise FuseOSError(e.errno)
        self.ev.emit(op="mknod", path=path, mode=oct(mode))

    # ---------------- passthrough (not logged) ----------------

    def release(self, path, fh):
        with self._mutex:
            self.fd_paths.pop(fh, None)
        return os.close(fh)

    def flush(self, path, fh):
        return os.fsync(fh)

    def fsync(self, path, fdatasync, fh):
        return os.fsync(fh)

    def lock(self, path, fh, cmd, lock):
        return 0

    def readdir(self, path, fh):
        full = self._full(path)
        yield "."
        yield ".."
        if os.path.isdir(full):
            for name in os.listdir(full):
                yield name

    def opendir(self, path):
        if not os.path.isdir(self._full(path)):
            raise FuseOSError(errno.ENOTDIR)
        return 0

    def releasedir(self, path, fh):
        return 0

    def getattr(self, path, fh=None):
        try:
            st = os.lstat(self._full(path))
        except OSError as e:
            raise FuseOSError(e.errno)
        return {k: getattr(st, k) for k in (
            "st_atime", "st_ctime", "st_gid", "st_mode",
            "st_mtime", "st_nlink", "st_size", "st_uid")}

    def fgetattr(self, path, fh):
        return self.getattr(path, fh)

    def access(self, path, mode):
        if not os.access(self._full(path), mode):
            raise FuseOSError(errno.EACCES)

    def readlink(self, path):
        return os.readlink(self._full(path))

    def utimens(self, path, times=None):
        return os.utime(self._full(path), times)

    def statfs(self, path):
        stv = os.statvfs(self._full(path))
        return {k: getattr(stv, k) for k in (
            "f_bavail", "f_bfree", "f_blocks", "f_bsize", "f_favail",
            "f_ffree", "f_files", "f_flag", "f_frsize", "f_namemax")}

    # xattrs (git and editors poke these; pass through quietly)
    def getxattr(self, path, name, position=0):
        try:
            return os.getxattr(self._full(path), name)
        except OSError as e:
            raise FuseOSError(e.errno)

    def listxattr(self, path):
        try:
            return os.listxattr(self._full(path))
        except OSError as e:
            raise FuseOSError(e.errno)

    def setxattr(self, path, name, value, options, position=0):
        try:
            os.setxattr(self._full(path), name, value, options or 0)
        except OSError as e:
            raise FuseOSError(e.errno)

    def removexattr(self, path, name):
        try:
            os.removexattr(self._full(path), name)
        except OSError as e:
            raise FuseOSError(e.errno)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("source", help="OverlayFS merged dir to mirror")
    ap.add_argument("mountpoint", help="FUSE mountpoint (virtiofsd shares this)")
    ap.add_argument("--events", default="/tmp/kairos_fs_events.jsonl")
    ap.add_argument("--max-bytes", type=int, default=512,
                    help="max content bytes recorded per op")
    ap.add_argument("--mount", default=None,
                    help="label events with this mount name (e.g. tmp)")
    ap.add_argument("--wal", default=None,
                    help="write-ahead log directory (enables per-action undo)")
    args = ap.parse_args()

    if not os.path.isdir(args.source):
        sys.exit(f"source not a dir: {args.source}")
    if not os.path.isdir(args.mountpoint):
        sys.exit(f"mountpoint not a dir: {args.mountpoint}")

    # The WAL records against the SOURCE (the overlay merged view), not the FUSE
    # mountpoint: undo must not re-enter this filesystem and re-journal itself.
    wal = None
    if args.wal:
        wal = wal_mod.Wal(args.wal, target_root=args.source)
        sys.stderr.write(f"[fs_monitor] WAL at {args.wal} (target {args.source})\n")

    ev = EventLog(args.events, mount=args.mount)
    ev.emit(op="mount", path="/", source=os.path.realpath(args.source))
    fs = MonitorFS(args.source, ev, max_bytes=args.max_bytes, wal=wal)
    sys.stderr.write(f"[fs_monitor] {args.source} -> {args.mountpoint}  events={args.events}\n")
    sys.stderr.flush()
    try:
        # single-threaded => ordered event stream; allow_other => virtiofsd can read it
        FUSE(fs, args.mountpoint, nothreads=True, foreground=True, allow_other=True)
    finally:
        ev.close()


if __name__ == "__main__":
    main()
