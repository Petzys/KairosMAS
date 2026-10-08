#!/usr/bin/env python3
"""Judge-placement table on Banking 
"""
from __future__ import annotations
import argparse, datetime, glob, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SUITE = "banking"
N = {"attack": 144, "benign": 16}


def score(files):
    sec, ut = [], []
    for f in files:
        try:
            d = json.load(open(f))
        except Exception:
            continue
        if not isinstance(d.get("utility"), bool):
            continue
        ut.append(bool(d["utility"]))
        if d.get("security") is not None:
            sec.append(bool(d["security"]))
    return sec, ut


def measure(root, tag_attack, tag_benign, model):
    att = glob.glob(os.path.join(root, tag_attack, model, SUITE, "user_task_*", "important_instructions", "injection_task_*.json"))
    ben = glob.glob(os.path.join(root, tag_benign, model, SUITE, "user_task_*", "none", "none.json"))
    sec, ut = score(att)
    _, ub = score(ben)
    return {"n_attack": len(sec), "n_benign": len(ub),
            "asr": round(100 * sum(sec) / len(sec), 1) if sec else None,
            "u_attack": round(100 * sum(ut) / len(ut), 1) if ut else None,
            "u_benign": round(100 * sum(ub) / len(ub), 1) if ub else None,
            "complete": len(sec) == N["attack"] and len(ub) == N["benign"],
            "attack_dir": os.path.relpath(os.path.join(root, tag_attack), ROOT) if att else None,
            "benign_dir": os.path.relpath(os.path.join(root, tag_benign), ROOT) if ben else None}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--all", action="store_true", help="include legacy-named (non -anm) runs")
    args = ap.parse_args()
    rows = []
    # Kairos cells: runs_judge/<agent>__judge-<judge>/<tag>/<agent-id>/banking
    for cell in sorted(glob.glob(os.path.join(ROOT, "runs_judge", "*__judge-*"))):
        agent_u, judge_u = os.path.basename(cell).split("__judge-", 1)
        for tag_a in sorted(glob.glob(os.path.join(cell, "full-spec_llm*-important_instructions"))):
            t = os.path.basename(tag_a)
            if not args.all and "-anm-" not in t:
                continue
            tag_b = t.replace("-important_instructions", "-noattack")
            models = [os.path.relpath(p, tag_a) for p in glob.glob(os.path.join(tag_a, "*", "*", SUITE)) + glob.glob(os.path.join(tag_a, "*", SUITE))]
            for mp in sorted(set(os.path.dirname(m) for m in models)):
                r = measure(cell, t, tag_b, mp)
                rows.append({"agent": mp, "judge": judge_u.replace("_", "/", 1) if "_" in judge_u else judge_u,
                             "defense": "kairos", "tag": t, **r})
    # undefended references: runs_models/<agent>/nodefense*-important_instructions/<agent-id>/banking
    for tag_a in sorted(glob.glob(os.path.join(ROOT, "runs_models", "*", "nodefense*-important_instructions"))):
        t = os.path.basename(tag_a)
        if not args.all and "-anm-" not in t:
            continue
        root = os.path.dirname(tag_a)
        tag_b = t.replace("-important_instructions", "-noattack")
        models = [os.path.relpath(p, tag_a) for p in glob.glob(os.path.join(tag_a, "*", "*", SUITE)) + glob.glob(os.path.join(tag_a, "*", SUITE))]
        for mp in sorted(set(os.path.dirname(m) for m in models)):
            r = measure(root, t, tag_b, mp)
            rows.append({"agent": mp, "judge": None, "defense": "none", "tag": t, **r})

    rows.sort(key=lambda r: (r["agent"], r["defense"] != "none", r["judge"] or ""))
    out = {"meta": {"generated": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                    "script": "evaluation/placement_table.py", "suite": SUITE,
                    "metrics": {"asr": "benchmark scoring, % of the 144 injection cases scored as attack achieved",
                                "u_attack": "% of injection cases with the user task completed",
                                "u_benign": "% of the 16 benign tasks completed"},
                    "config": "Kairos full configuration (speculation on, LLM judge, auto commit), injection addresses the agent by its own name (-anm)"},
            "rows": rows}
    os.makedirs(os.path.join(ROOT, "evaluation", "placement_table"), exist_ok=True)
    json.dump(out, open(os.path.join(ROOT, "evaluation", "placement_table", "placement_table.json"), "w"), indent=2)
    f = lambda x: "  ---" if x is None else f"{x:5.1f}"
    print(f"{'agent':28s} {'judge':28s} {'ASR':>6s} {'U':>6s} {'Ub':>6s}   files")
    for r in rows:
        print(f"{r['agent']:28s} {(r['judge'] or 'undefended'):28s} {f(r['asr']):>6s} {f(r['u_attack']):>6s} {f(r['u_benign']):>6s}   "
              f"{r['n_attack']}/{N['attack']} {r['n_benign']}/{N['benign']}{'' if r['complete'] else '  <- incomplete'}")


if __name__ == "__main__":
    main()
