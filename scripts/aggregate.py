#!/usr/bin/env python3
"""Consolidate AgentDojo per-task trace JSONs (now carrying the `kairos` block
of decisions + tokens) into one overview.csv + a printed summary.

Standalone: reads only the JSON files on disk, so you can re-aggregate or diff
past runs without re-running the benchmark. Point it at one run dir or a parent
of several runs (each becomes a `run` row, so baseline vs speculative sit in one
CSV and one printed comparison).

    uv run python scripts/aggregate.py runs/banking/gpt-3.5-turbo-0125/baseline-ab12cd34
    uv run python scripts/aggregate.py runs            # everything under runs/
"""
from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

def is_precheck(d):  # AgentDojo injection-achievability setup rows
    return str(d.get("user_task_id", "")).startswith("injection_task_")

def load(p):
    try:
        return json.loads(p.read_text())
    except Exception:
        return None

def _run_label(p: Path, root: Path) -> str:
    """The config identifier for a task file, robust to directory depth/layout.

    Invariant: every task file sits at {config...}/{user_task}/{injection|none}/f.json,
    so parents[2] is the config-identifying directory. Labelling it by the relative
    path from `root` keeps distinct configs in distinct buckets no matter which layout
    ({tag}/{model}/{suite} vs {suite}/{model}/{tag}) or how deep `root` is pointed —
    the old `parents[2].name` collapsed every config to its suite name and merged them.
    """
    try:
        rel = p.parents[2].relative_to(root)
        label = str(rel)
    except (ValueError, IndexError):
        return p.parents[2].name if len(p.parents) > 2 else root.name
    return root.name if label == "." else label


def main(root):
    root = Path(root)
    files = sorted(root.rglob("*.json"))
    rows, errors = [], []
    per_run = defaultdict(lambda: {
        "benign_ok": 0, "benign_n": 0, "atk_ok": 0, "atk_n": 0,
        "succ": 0, "tok": 0, "calls": 0, "tasks": 0})

    for p in files:
        if p.name == "overview.csv":
            continue
        d = load(p)
        if d is None or is_precheck(d):
            continue
        run = _run_label(p, root)   # config identifier (relative path)

        err = d.get("error")
        bif = d.get("kairos") or {}
        tok = (bif.get("tokens") or {})
        sess = (bif.get("session") or {})
        inj = d.get("injection_task_id")
        is_attack = inj is not None and d.get("attack_type") not in (None, "none")
        util = bool(d.get("utility"))
        sec = bool(d.get("security"))   # True == attack succeeded in AgentDojo

        if err:
            errors.append((str(p), repr(err)[:90]))
            # do NOT count broken tasks toward rates
            continue

        rows.append({
            "run": run,
            "user_task": d.get("user_task_id"),
            "injection_task": inj or "",
            "is_attack": is_attack,
            "utility_ok": util,
            "attack_succeeded": sec if is_attack else "",
            "n_blocked": sess.get("n_blocked", ""),
            "llm_calls": tok.get("llm_calls", 0),
            "total_tokens": tok.get("total_tokens", 0),
        })
        r = per_run[run]
        r["tasks"] += 1
        r["tok"] += tok.get("total_tokens", 0)
        r["calls"] += tok.get("llm_calls", 0)
        if is_attack:
            r["atk_n"] += 1
            r["atk_ok"] += int(util)
            r["succ"] += int(sec)
        else:
            r["benign_n"] += 1
            r["benign_ok"] += int(util)

    # write CSV
    out = root / "overview.csv"
    with out.open("w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()) if rows else
                           ["run","user_task","injection_task","is_attack","utility_ok",
                            "attack_succeeded","n_blocked","llm_calls","total_tokens"])
        w.writeheader(); w.writerows(rows)

    # per-run summary
    print(f"\n{'='*70}\nAGGREGATE  ({len(rows)} task records, {len(errors)} errored & excluded)\n{'='*70}")
    for run, r in sorted(per_run.items()):
        bu = 100*r["benign_ok"]/r["benign_n"] if r["benign_n"] else float("nan")
        ua = 100*r["atk_ok"]/r["atk_n"] if r["atk_n"] else float("nan")
        asr = 100*r["succ"]/r["atk_n"] if r["atk_n"] else float("nan")
        mt = r["tok"]/r["tasks"] if r["tasks"] else 0
        mc = r["calls"]/r["tasks"] if r["tasks"] else 0
        print(f"\nRUN: {run}   ({r['tasks']} tasks)")
        if r["benign_n"]: print(f"  benign utility       : {bu:5.1f}%   ({r['benign_n']} tasks)")
        if r["atk_n"]:
            print(f"  utility under attack : {ua:5.1f}%   ({r['atk_n']} attack tasks)")
            print(f"  ASR                  : {asr:5.1f}%   <- lower is better")
        print(f"  tokens               : {r['tok']:,} total | {mt:,.0f} mean/task | {mc:.1f} calls/task")

    if errors:
        print(f"\n{'!'*70}\nEXCLUDED {len(errors)} errored task(s) — re-run these (delete then rerun w/o --force-rerun):")
        for path, e in errors[:40]:
            print(f"  {path}\n    {e}")

if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else ".")