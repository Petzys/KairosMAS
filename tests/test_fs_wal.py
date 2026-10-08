# tests/test_fs_wal.py — deploy/fs/wal.py
#
# The WAL is what lets a single action be undone while the session is live, so
# these tests are about one question per op: after undo, is the tree exactly as it
# was before the op? Plus the two properties that make it safe to expose in the
# dashboard mid-run — append-only status, and refusing to clobber a later branch.
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "deploy", "fs"))
from wal import Wal  # noqa: E402


@pytest.fixture()
def w(tmp_path):
    target = tmp_path / "merged"
    target.mkdir()
    return Wal(str(tmp_path / "wal"), str(target))


def _write(w, rel, data):
    p = os.path.join(w.target_root, rel)
    os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
    with open(p, "w") as f:
        f.write(data)


def _read(w, rel):
    with open(os.path.join(w.target_root, rel)) as f:
        return f.read()


def test_write_undo_restores_previous_content(w):
    _write(w, "a.py", "original")
    before = w.snapshot("a.py")
    _write(w, "a.py", "modified")
    r = w.record("write", "a.py", before, branch="t1")
    w.undo([r])
    assert _read(w, "a.py") == "original"


def test_create_undo_removes_the_file(w):
    before = w.snapshot("new.py")            # absent
    _write(w, "new.py", "hello")
    r = w.record("create", "new.py", before, branch="t1")
    w.undo([r])
    assert not os.path.exists(os.path.join(w.target_root, "new.py"))


def test_unlink_undo_recreates_the_file(w):
    _write(w, "gone.py", "content")
    before = w.snapshot("gone.py")
    os.unlink(os.path.join(w.target_root, "gone.py"))
    r = w.record("unlink", "gone.py", before, branch="t1")
    w.undo([r])
    assert _read(w, "gone.py") == "content"


def test_rename_undo_moves_it_back(w):
    _write(w, "old.py", "x")
    before = w.snapshot("old.py")
    os.rename(os.path.join(w.target_root, "old.py"), os.path.join(w.target_root, "new.py"))
    r = w.record("rename", "old.py", before, branch="t1", to="new.py")
    w.undo([r])
    assert _read(w, "old.py") == "x"
    assert not os.path.exists(os.path.join(w.target_root, "new.py"))


def test_mkdir_and_rmdir_undo(w):
    d = os.path.join(w.target_root, "sub")
    before = w.snapshot("sub")
    os.mkdir(d)
    w.undo([w.record("mkdir", "sub", before, branch="t1")])
    assert not os.path.exists(d)

    os.mkdir(d)
    before = w.snapshot("sub")
    os.rmdir(d)
    w.undo([w.record("rmdir", "sub", before, branch="t1")])
    assert os.path.isdir(d)


def test_chmod_undo_restores_mode(w):
    _write(w, "s.sh", "#!/bin/sh\n")
    p = os.path.join(w.target_root, "s.sh")
    os.chmod(p, 0o644)
    before = w.snapshot("s.sh")
    os.chmod(p, 0o777)
    w.undo([w.record("chmod", "s.sh", before, branch="t1")])
    assert oct(os.stat(p).st_mode)[-3:] == "644"


def test_successive_writes_undo_to_the_branch_start(w):
    """Whole-file snapshots make undo order-independent: replaying newest-first
    leaves the EARLIEST before-image in place, i.e. the state the branch began
    with. This is the property that lets one action be undone mid-session."""
    _write(w, "f.py", "v0")
    recs = []
    for v in ("v1", "v2", "v3"):
        before = w.snapshot("f.py")
        _write(w, "f.py", v)
        recs.append(w.record("write", "f.py", before, branch="t1"))
    assert _read(w, "f.py") == "v3"
    w.undo(recs)
    assert _read(w, "f.py") == "v0"


def test_commit_one_branch_abort_the_other(w):
    """The case OverlayFS cannot express: two branches touch DIFFERENT files;
    one is kept, the other reverted, without unmounting anything."""
    _write(w, "fix.py", "buggy")
    _write(w, "ci.yml", "clean")

    b1 = w.snapshot("fix.py"); _write(w, "fix.py", "fixed")
    r1 = w.record("write", "fix.py", b1, branch="t1")
    b2 = w.snapshot("ci.yml"); _write(w, "ci.yml", "poisoned")
    r2 = w.record("write", "ci.yml", b2, branch="t2")

    w.mark([r1], "committed")
    w.undo([r2]); w.mark([r2], "aborted")

    assert _read(w, "fix.py") == "fixed"        # the user's change survives
    assert _read(w, "ci.yml") == "clean"        # the injected one is gone
    assert {r["seq"]: r["status"] for r in w.load()} == {r1["seq"]: "committed",
                                                         r2["seq"]: "aborted"}


def test_status_is_append_only_and_replayed(w):
    """Status changes are appended, never rewritten, so a crash mid-resolution
    cannot corrupt earlier records."""
    _write(w, "a", "1")
    r = w.record("write", "a", w.snapshot("a"), branch="t1")
    w.mark([r], "committed")
    reopened = Wal(w.root, w.target_root)
    assert reopened.load()[0]["status"] == "committed"
    assert reopened.select(status="pending") == []


def test_conflict_detected_when_a_later_branch_touched_the_same_path(w):
    """Whole-file undo of an older change would roll back a newer surviving one.
    That must be reported, not silently done."""
    _write(w, "shared.py", "v0")
    b1 = w.snapshot("shared.py"); _write(w, "shared.py", "v1")
    r1 = w.record("write", "shared.py", b1, branch="t1")
    b2 = w.snapshot("shared.py"); _write(w, "shared.py", "v2")
    w.record("write", "shared.py", b2, branch="t2")

    conf = w.conflicts([r1])
    assert len(conf) == 1 and "t2" in conf[0]["branches"]
    # aborting BOTH is unambiguous, so no conflict is reported
    assert w.conflicts(w.select(status="pending")) == []


def test_oversize_before_image_is_marked_not_silently_lost(w):
    small = Wal(w.root, w.target_root, max_bytes=8)
    _write(small, "big.bin", "x" * 64)
    before = small.snapshot("big.bin")
    assert before.get("oversize") is True
    _write(small, "big.bin", "y")
    out = small.undo([small.record("write", "big.bin", before, branch="t1")])
    assert "SKIP" in out[0]                     # explicitly non-undoable
    assert _read(small, "big.bin") == "y"       # and it did NOT pretend to revert


def test_select_filters_by_branch_and_path(w):
    _write(w, "a", "1"); _write(w, "b", "1")
    w.record("write", "a", w.snapshot("a"), branch="t1")
    w.record("write", "b", w.snapshot("b"), branch="t2")
    assert len(w.select(branch="t1")) == 1
    assert w.select(path="/b")[0]["branch"] == "t2"
    assert sorted(w.branches()) == ["t1", "t2"]


def test_undo_restores_each_path_once(w):
    """One agent edit journals create+write (or truncate+write), all carrying the
    same before-image. Undo must do the work once and say so once — repeating it
    is wasted I/O and reports the same file reverted several times."""
    _write(w, "a.txt", "original")
    recs = []
    for op in ("truncate", "write", "write"):
        recs.append(w.record(op, "a.txt", w.snapshot("a.txt"), branch="t1"))
        _write(w, "a.txt", "modified")
    lines = w.undo(recs)
    assert len(lines) == 1, lines
    assert _read(w, "a.txt") == "original"


def test_undo_uses_the_oldest_snapshot_not_the_newest(w):
    """Deduping must keep the EARLIEST before-image; keeping the latest would
    revert to a mid-branch state and silently lose the branch's first change."""
    _write(w, "f", "v0")
    r1 = w.record("write", "f", w.snapshot("f"), branch="t1"); _write(w, "f", "v1")
    r2 = w.record("write", "f", w.snapshot("f"), branch="t1"); _write(w, "f", "v2")
    w.undo([r1, r2])
    assert _read(w, "f") == "v0"
