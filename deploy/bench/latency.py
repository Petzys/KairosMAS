#!/usr/bin/env python3
"""Latency microbenchmarks of the isolation boundary (paper: Cost) -- indicative, single host.

  fs    cost of the FUSE monitor on the file channel: timed create, write, fsync, read and
        unlink cycles through the monitored mount against the same overlay without it.
  net   cost of the transparent proxy on requests it releases: timed requests from the host
        through the proxy against the same requests sent directly.
  task  end-to-end wall time of a session under enforcement against observe mode, read from
        two session directories (not reported).
  held  latency of held requests (not reported: it is dominated by the oracle's model call).

    deploy/bench/latency.py fs   --root /var/lib/kairos/fs
    deploy/bench/latency.py net  --url http://status.internal.local/notify
    deploy/bench/latency.py task --enforced <session> --observe <session>
    deploy/bench/latency.py held --session <session>
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import subprocess
import sys
import tempfile
import time


def _stats(samples: list[float]) -> dict:
    s = sorted(samples)
    return {"n": len(s), "mean_ms": statistics.mean(s) * 1e3,
            "median_ms": statistics.median(s) * 1e3,
            "p95_ms": s[int(0.95 * (len(s) - 1))] * 1e3,
            "min_ms": s[0] * 1e3, "max_ms": s[-1] * 1e3}


def _fs_batch(root: str, n: int, size: int) -> list[float]:
    """One timed create+write+read+unlink cycle per iteration."""
    payload = b"x" * size
    out = []
    for i in range(n):
        p = os.path.join(root, f".kairos_lat_{i}")
        t0 = time.perf_counter()
        with open(p, "wb") as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        with open(p, "rb") as f:
            f.read()
        os.unlink(p)
        out.append(time.perf_counter() - t0)
    return out


def cmd_fs(a) -> int:
    logged = os.path.join(a.root, "logged")      # through fs_monitor (FUSE)
    merged = os.path.join(a.root, "merged")      # the overlay directly, no FUSE
    if not os.path.isdir(logged) or not os.path.isdir(merged):
        print(f"need both {logged} and {merged} — start the fs stack first", file=sys.stderr)
        return 2
    print(f"warming up ({a.warmup} iterations each)…")
    _fs_batch(merged, a.warmup, a.size)
    _fs_batch(logged, a.warmup, a.size)
    direct = _stats(_fs_batch(merged, a.n, a.size))
    through = _stats(_fs_batch(logged, a.n, a.size))
    overhead = through["mean_ms"] - direct["mean_ms"]
    out = {"kind": "fs", "size_bytes": a.size, "direct": direct, "monitored": through,
           "added_ms_per_cycle": overhead,
           "factor": through["mean_ms"] / direct["mean_ms"] if direct["mean_ms"] else None}
    _report(out, a)
    return 0


def _curl(url: str, proxy: str | None, n: int) -> list[float]:
    out = []
    for _ in range(n):
        cmd = ["curl", "-s", "-o", "/dev/null", "-w", "%{time_total}", "-X", "POST",
               "-d", "latency-probe", url]
        if proxy:
            cmd[1:1] = ["-x", proxy]
        t = subprocess.run(cmd, capture_output=True, text=True)
        try:
            out.append(float(t.stdout.strip()))
        except ValueError:
            pass
    return out


def cmd_net(a) -> int:
    """The proxy's cost on a request that is allowed straight through.

    Run from the HOST: with --proxy the request goes via mitmproxy exactly as the
    guest's redirected traffic does; without it, straight to the destination."""
    direct = _curl(a.url, None, a.n)
    viaproxy = _curl(a.url, a.proxy, a.n)
    if not direct or not viaproxy:
        print("no samples — is the sink up and the proxy listening?", file=sys.stderr)
        return 2
    d, p = _stats(direct), _stats(viaproxy)
    out = {"kind": "net", "url": a.url, "direct": d, "through_proxy": p,
           "added_ms_per_request": p["mean_ms"] - d["mean_ms"]}
    _report(out, a)
    return 0


def _session_seconds(sess: str) -> float | None:
    try:
        with open(os.path.join(sess, "session.json")) as f:
            d = json.load(f)
    except OSError:
        return None
    import datetime
    try:
        a = datetime.datetime.fromisoformat(d["started"])
        b = datetime.datetime.fromisoformat(d["ended"])
        return (b - a).total_seconds()
    except (KeyError, ValueError):
        return None


def cmd_task(a) -> int:
    e, o = _session_seconds(a.enforced), _session_seconds(a.observe)
    if e is None or o is None:
        print("need session.json with both started and ended in each dir", file=sys.stderr)
        return 2
    out = {"kind": "task", "enforced_s": e, "observe_s": o,
           "added_s": e - o, "factor": e / o if o else None}
    _report(out, a)
    return 0


def cmd_held(a) -> int:
    """How long held requests actually waited — the judge's cost, not the monitor's.

    Derived from the decision records, so it includes the trust-chain evaluation
    and the oracle round-trip together."""
    recs = []
    try:
        with open(os.path.join(a.session, "decisions.jsonl")) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        recs.append(json.loads(line))
                    except ValueError:
                        pass
    except OSError:
        print(f"no decisions.jsonl under {a.session}", file=sys.stderr)
        return 2
    judged = [r for r in recs if (r.get("verdict") or {}).get("llm")]
    out = {"kind": "held", "decisions": len(recs), "with_llm_verdict": len(judged),
           "note": "wall-clock per hold is the proxy poll interval (0.4s) plus the "
                   "judge round-trip; see net_monitor_addon.POLL_S"}
    _report(out, a)
    return 0


def _report(out: dict, a) -> None:
    print(json.dumps(out, indent=2))
    if getattr(a, "json", None):
        with open(a.json, "w") as f:
            json.dump(out, f, indent=2)
        print(f"wrote {a.json}", file=sys.stderr)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--json", default=None)
    sub = ap.add_subparsers(dest="cmd", required=True)

    f = sub.add_parser("fs");   f.set_defaults(fn=cmd_fs)
    f.add_argument("--root", default=os.environ.get("KAIROS_FS_ROOT", "/var/lib/kairos/fs"))
    f.add_argument("-n", type=int, default=200)
    f.add_argument("--warmup", type=int, default=20)
    f.add_argument("--size", type=int, default=4096)

    n = sub.add_parser("net");  n.set_defaults(fn=cmd_net)
    n.add_argument("--url", default="http://status.internal.local/notify")
    n.add_argument("--proxy", default="http://127.0.0.1:8080")
    n.add_argument("-n", type=int, default=50)

    t = sub.add_parser("task"); t.set_defaults(fn=cmd_task)
    t.add_argument("--enforced", required=True)
    t.add_argument("--observe", required=True)

    h = sub.add_parser("held"); h.set_defaults(fn=cmd_held)
    h.add_argument("--session", required=True)

    a = ap.parse_args()
    return a.fn(a)


if __name__ == "__main__":
    raise SystemExit(main())
