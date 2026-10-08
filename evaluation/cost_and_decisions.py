#!/usr/bin/env python3
"""Recompute the remaining reported numbers that are not success/utility rates.

    .venv/bin/python evaluation/cost_and_decisions.py decisions   # tab:decisions and fig:decisions
    .venv/bin/python evaluation/cost_and_decisions.py tokens      # token overhead (Cost)
    .venv/bin/python evaluation/cost_and_decisions.py latency     # filesystem and proxy latency (Cost)
    .venv/bin/python evaluation/cost_and_decisions.py retention   # AgentDyn utility retained after held effects
    .venv/bin/python evaluation/cost_and_decisions.py             # all four

"""
from __future__ import annotations

import glob
import json
import os
import statistics
import sys
from collections import Counter

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOJO = ["banking", "slack", "travel", "workspace"]
KAIROS = {"banking": ("full-spec_llm-0921474b", "full-spec_llm-0921474b"),
          "slack": ("full-spec_llm-71dfa38e", "baseline-spec_llm-71dfa38e"),
          "travel": ("baseline-spec_llm-05c343f8", "baseline-spec_llm-05c343f8"),
          "workspace": ("baseline-spec_llm-13887c83", "baseline-spec_llm-13887c83")}


def records(pattern):
    for f in sorted(glob.glob(os.path.join(ROOT, pattern))):
        d = json.load(open(f))
        if str(d.get("user_task_id", "")).startswith("injection_task_") or not isinstance(d.get("utility"), bool):
            continue
        yield d


def decisions():
    print("=== tab:decisions: where effects are decided (Kairos, GPT-4.1, AgentDojo) ===")
    print(f"{'':16s}{'effects':>8s}{'policy rel. %':>15s}{'deferred':>10s}{'oracle rel.':>12s}{'oracle ref.':>12s}")
    reasons = Counter()
    for label, cond, sub, idx in (("benign", "noattack", "user_task_*/none/none.json", 1),
                                  ("under attack", "important_instructions", "user_task_*/important_instructions/injection_task_*.json", 0)):
        print(f"-- {label}")
        T = Counter()
        for s in DOJO:
            c = Counter()
            for d in records(f"runs/{KAIROS[s][idx]}-{cond}/gpt-4.1/{s}/{sub}"):
                sess = (d.get("kairos") or {}).get("session") or {}
                for k, v in (sess.get("by_layer") or {}).items():
                    if k.startswith("ALLOW"):
                        c["allow"] += v
                    if k.startswith("REVIEW") and cond != "noattack":
                        reasons[k.split(":", 1)[1].split(":")[0] if ":" in k else k] += v
                for r in sess.get("resolutions") or []:
                    c["commit"] += len(r.get("committed") or [])
                    c["abort"] += len(r.get("aborted") or [])
            c["deferred"] = c["commit"] + c["abort"]
            c["effects"] = c["allow"] + c["deferred"]
            T.update(c)
            print(f"   {s:13s}{c['effects']:8d}{100 * c['allow'] / c['effects']:15.1f}{c['deferred']:10d}{c['commit']:12d}{c['abort']:12d}")
        print(f"   {'all four':13s}{T['effects']:8d}{100 * T['allow'] / T['effects']:15.1f}{T['deferred']:10d}{T['commit']:12d}{T['abort']:12d}")
    n = sum(reasons.values())
    print("-- what produced the deferral (REVIEW decisions under attack, by test)")
    for k, v in reasons.most_common():
        print(f"   {k:28s}{v:6d}  {100 * v / n:5.1f}%")


def tokens():
    print("=== token overhead (runs/run_01: undefended vs full pipeline, GPT-4.1) ===")
    full = {"banking": "0921474b", "slack": "18275ef7", "travel": "05c343f8", "workspace": "13887c83"}
    for label, cond, sub in (("benign", "noattack", "user_task_*/none/none.json"),
                             ("under attack", "important_instructions", "user_task_*/important_instructions/injection_task_*.json")):
        deltas = []
        print(f"-- {label}: mean tokens per task (undefended, full, delta)")
        for s in DOJO:
            und = statistics.mean(d["kairos"]["tokens"]["total_tokens"] for d in records(f"runs/run_01/nodefense-{cond}/gpt-4.1/{s}/{sub}"))
            ful = statistics.mean(d["kairos"]["tokens"]["total_tokens"] for d in records(f"runs/run_01/baseline-spec_llm-{full[s]}-{cond}/gpt-4.1/{s}/{sub}"))
            deltas.append(100 * (ful - und) / und)
            print(f"   {s:11s}{und:9.0f}{ful:9.0f}{deltas[-1]:+8.1f}%")
        print(f"   {'mean':11s}{'':18s}{statistics.mean(deltas):+8.1f}%")


def latency():
    print("=== latency of the isolation boundary (deployed stack) ===")
    fs = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(ROOT, "production_runs/latency/rq2_fs_*.json")))]
    net = [json.load(open(f)) for f in sorted(glob.glob(os.path.join(ROOT, "production_runs/latency/rq2_net_*.json")))]
    cyc = statistics.mean(x["added_ms_per_cycle"] for x in fs)
    print(f"   file channel: {cyc:.2f} ms added per cycle ({len(fs)} repetitions of {fs[0]['direct']['n']} cycles, "
          f"{fs[0]['size_bytes']} B files), {cyc / 5:.2f} ms per operation")
    req = statistics.mean(x["added_ms_per_request"] for x in net)
    print(f"   proxy: {req:.2f} ms added per allowed request ({len(net)} repetitions of {net[0]['direct']['n']} requests)")


def retention():
    print("=== AgentDyn: benign utility retained vs held actions the task continued after ===")
    H = {"github": "1bfd0f14", "shopping": "33490784", "dailylife": "c4ecec61"}
    R, M = "evaluation/agentdyn/runs", "gpt-4o-2024-08-06"

    def load(fn):
        out = {}
        for s in H:
            for d in records(f"{fn(s)}/user_task_*/none/none.json"):
                tr = ((d.get("kairos") or {}).get("session") or {}).get("trace") or []
                held = sum(1 for i, t in enumerate(tr) if t.get("decision") == "REVIEW" and i < len(tr) - 1)
                out[(s, d["user_task_id"])] = (bool(d["utility"]), held)
        return out
    K = load(lambda s: f"{R}/full-spec_llm-honest-sys95318c-anm-{H[s]}-noattack/{M}/{s}")
    U = load(lambda s: f"{R}/nodefense-sys95318c-anm-noattack/{M}/{s}")
    for lab, lo, hi in (("0", 0, 0), ("1", 1, 1), ("2+", 2, 10 ** 6)):
        ks = [k for k, v in K.items() if lo <= v[1] <= hi]
        kp, up = sum(K[k][0] for k in ks), sum(U[k][0] for k in ks if k in U)
        print(f"   {lab:3s} held: {len(ks):3d} tasks, passed {kp} with Kairos / {up} without -> {100 * kp / up:.0f}% retained")


PARTS = {"decisions": decisions, "tokens": tokens, "latency": latency, "retention": retention}

if __name__ == "__main__":
    for p in (sys.argv[1:] or list(PARTS)):
        PARTS[p]()
        print()
