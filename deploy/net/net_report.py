#!/usr/bin/env python3
"""
Network channel — session report  (M3, observe-only)
====================================================
Summarizes the mitmproxy JSONL event stream: per-host request counts, the full
outbound request table (method/host/path/status/size), and — for the actions
that matter to a reference monitor — the bodies of state-changing requests
(POST/PUT/PATCH/DELETE), which is where injection-driven exfil shows up.

Passthrough (cleared) hosts appear as tunnels (host + byte counts) since their
TLS was never decrypted.

Usage: net_report.py [--events FILE] [--json] [--bodies]
"""

import os
import sys
import json
import argparse
from collections import defaultdict

STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}


def load(path):
    evs = []
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        evs.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return evs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--events", default="/tmp/kairos_net_events.jsonl")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--bodies", action="store_true", help="print state-changing request bodies")
    args = ap.parse_args()

    evs = load(args.events)
    reqs = [e for e in evs if e.get("kind") == "request"]
    resps = {e["flow"]: e for e in evs if e.get("kind") == "response"}
    tunnels = [e for e in evs if e.get("kind") == "tunnel_close"]
    snis = sorted({e["sni"] for e in evs if e.get("kind") == "tls_sni" and e.get("sni")})
    refused = [e for e in evs if e.get("kind") == "sinkhole_refused"]   # strict boundary only

    per_host = defaultdict(lambda: {"count": 0, "methods": set(), "bytes_out": 0})
    for r in reqs:
        h = per_host[r.get("host", "?")]
        h["count"] += 1
        h["methods"].add(r.get("method"))
        h["bytes_out"] += r.get("body_len", 0) or 0

    if args.json:
        out = {
            "requests": [{
                "method": r.get("method"), "host": r.get("host"), "path": r.get("path"),
                "url": r.get("url"), "body_len": r.get("body_len"),
                "status": resps.get(r.get("flow"), {}).get("status"),
                "state_changing": r.get("method") in STATE_CHANGING,
            } for r in reqs],
            "tunnels": [{"host": t.get("host"), "bytes_out": t.get("bytes_out"),
                         "bytes_in": t.get("bytes_in")} for t in tunnels],
            "passthrough_sni": snis,
            "strict_refused": [{"stage": e.get("stage"), "host": e.get("host") or e.get("sni"),
                                "port": e.get("port"), "reason": e.get("reason")} for e in refused],
        }
        print(json.dumps(out, indent=2))
        return

    print("=" * 64)
    print("  Kairos network session report")
    print("=" * 64)
    print(f"events        : {len(evs)}  file={args.events}")
    print(f"HTTP requests : {len(reqs)} (decrypted)   tunnels: {len(tunnels)} (passthrough)")
    if refused:
        print(f"strict boundary: {len(refused)} connection(s) refused")
        for e in refused:
            print(f"  [{e.get('stage')}] {e.get('host') or e.get('sni') or '?'}:{e.get('port')}  {e.get('reason')}")
    print()

    if per_host:
        print("Per-host (decrypted):")
        for host, s in sorted(per_host.items(), key=lambda kv: -kv[1]["count"]):
            print(f"  {host:<40} {s['count']:>3} req  [{','.join(sorted(m for m in s['methods'] if m))}]  {s['bytes_out']}B out")
        print()

    if tunnels:
        print("Passthrough tunnels (cleared hosts, not decrypted):")
        for t in tunnels:
            print(f"  {t.get('host'):<40} out={t.get('bytes_out')}B in={t.get('bytes_in')}B")
        print()

    print("Outbound request table:")
    print(f"  {'METHOD':<7} {'STATUS':<6} {'HOST':<32} PATH")
    for r in reqs:
        st = resps.get(r.get("flow"), {}).get("status", "-")
        flag = " *" if r.get("method") in STATE_CHANGING else ""
        print(f"  {r.get('method',''):<7} {str(st):<6} {r.get('host',''):<32} {r.get('path','')}{flag}")
    print("  (* = state-changing request — the class KAIROS will hold in M5)")

    if args.bodies:
        sc = [r for r in reqs if r.get("method") in STATE_CHANGING and r.get("body_len")]
        if sc:
            print()
            print("State-changing request bodies:")
            for r in sc:
                print("-" * 64)
                print(f"{r.get('method')} {r.get('url')}  ({r.get('body_len')} bytes)")
                print(f"  {r.get('body_preview')}")


if __name__ == "__main__":
    main()
