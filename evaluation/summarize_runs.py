#!/usr/bin/env python3
"""Recompute the paper's result tables from the run records in this repository.

Every value is computed from the per-task result files (one JSON per task, written by the
AgentDojo harness): `utility` is whether the user task was completed, `security` whether the
attacker's goal was reached (benchmark scoring). Per suite:
    ASR = % of injection cases with security true      (attack runs)
    U   = % of injection cases with utility true       (attack runs)
    U_b = % of benign tasks with utility true          (runs without injection)
Table values are the unweighted mean over the suites, and NRP = U_b x (1 - ASR), computed from
the table values rounded to one decimal, as in the paper.

    .venv/bin/python evaluation/summarize_runs.py main        # tab:agentdojo-main and tab:main (per suite)
    .venv/bin/python evaluation/summarize_runs.py agentdyn    # tab:agentdyn, Kairos row
    .venv/bin/python evaluation/summarize_runs.py autodojo    # tab:autodojo, Kairos row
    .venv/bin/python evaluation/summarize_runs.py strict      # strict monitor (deferral and oracle off)
    .venv/bin/python evaluation/summarize_runs.py placement   # tab:placement and tab:model-grid
    .venv/bin/python evaluation/summarize_runs.py all
Add --json to print machine-readable output.
"""
from __future__ import annotations

import glob
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOJO = ["banking", "slack", "travel", "workspace"]
BENIGN = "user_task_*/none/none.json"


def score(pattern: str) -> tuple[float | None, float | None, int]:
    sec = ut = n = 0
    for f in glob.glob(os.path.join(ROOT, pattern)):
        d = json.load(open(f))
        if str(d.get("user_task_id", "")).startswith("injection_task_") or not isinstance(d.get("utility"), bool):
            continue                                   # pre-checks and unfinished records are not results
        n += 1
        ut += bool(d["utility"])
        sec += bool(d.get("security"))
    return (100 * sec / n if n else None, 100 * ut / n if n else None, n)


def row(attack_dir, benign_dir, suites, attack="important_instructions"):
    """attack_dir / benign_dir: suite -> directory holding user_task_*/ (None: not reported);
    attack: the attack's directory name inside each user_task_* (AutoDojo: 'autodojo')."""
    per = {}
    for s in suites:
        asr, u, na = score(f"{attack_dir(s)}/user_task_*/{attack}/injection_task_*.json") if attack_dir else (None, None, 0)
        _, ub, nb = score(f"{benign_dir(s)}/{BENIGN}") if benign_dir else (None, None, 0)
        per[s] = {"asr": asr, "u": u, "u_b": ub, "n_attack": na, "n_benign": nb}

    def mean(k):
        v = [per[s][k] for s in suites]
        return sum(v) / len(v) if all(x is not None for x in v) else None
    m = {k: mean(k) for k in ("asr", "u", "u_b")}
    m["nrp"] = (round(m["u_b"], 1) * (1 - round(m["asr"], 1) / 100)
                if m["asr"] is not None and m["u_b"] is not None else None)
    return {"per_suite": per, "mean": m}


# ---------------------------------------------------------------- AgentDojo, three agents
KAIROS_GPT41 = {"banking": ("full-spec_llm-0921474b", "full-spec_llm-0921474b"),
                "slack": ("full-spec_llm-71dfa38e", "baseline-spec_llm-71dfa38e"),
                "travel": ("baseline-spec_llm-05c343f8", "baseline-spec_llm-05c343f8"),
                "workspace": ("baseline-spec_llm-13887c83", "baseline-spec_llm-13887c83")}
KAIROS_OPEN = {"banking": "62761659", "slack": "a8489a49", "travel": "c75a0a35", "workspace": "13887c83"}
AGENTS = [("GPT-4.1", "gpt-4.1", "gpt-4.1"),
          ("Qwen3.6-35B", "qwen/qwen3.6-35b-a3b", "qwen_qwen3.6-35b-a3b"),
          ("Llama-3.3-70B", "meta-llama/llama-3.3-70b-instruct", "meta-llama_llama-3.3-70b-instruct")]
DEFENSES = [("Spotlighting", "spotlighting"), ("Prompt sandwiching", "repeat_user_prompt"),
            ("PI detector", "transformers_pi_detector"), ("Progent", "progent"), ("CaMeL", "camel")]
BASE = "evaluation/baselines/runs/v1"


def main_table():
    out = {}
    for label, mid, mu in AGENTS:
        rows = {}
        if mid == "gpt-4.1":
            rows["No defense"] = row(lambda s: f"runs/nodefense-important_instructions/gpt-4.1/{s}",
                                     lambda s: f"runs/nodefense-noattack/gpt-4.1/{s}", DOJO)
        else:
            rows["No defense"] = row(lambda s: f"runs_models/{mu}/nodefense-important_instructions/{mid}/{s}",
                                     lambda s: f"runs_models/{mu}/nodefense-noattack/{mid}/{s}", DOJO)
        for name, d in DEFENSES:
            base = f"{BASE}/{mu if d == 'camel' else mid}/{d}"
            rows[name] = row(lambda s, b=base: f"{b}/{s}", lambda s, b=base: f"{b}/{s}", DOJO)
        if mid == "gpt-4.1":
            rows["Kairos"] = row(lambda s: f"runs/{KAIROS_GPT41[s][0]}-important_instructions/gpt-4.1/{s}",
                                 lambda s: f"runs/{KAIROS_GPT41[s][1]}-noattack/gpt-4.1/{s}", DOJO)
        else:
            rows["Kairos"] = row(lambda s: f"runs_models/{mu}/full-spec_llm-{KAIROS_OPEN[s]}-important_instructions/{mid}/{s}",
                                 lambda s: f"runs_models/{mu}/full-spec_llm-{KAIROS_OPEN[s]}-noattack/{mid}/{s}", DOJO)
        out[label] = rows
    return out


def agentdyn():
    H = {"github": "1bfd0f14", "shopping": "33490784", "dailylife": "c4ecec61"}
    R, M = "evaluation/agentdyn/runs", "gpt-4o-2024-08-06"
    return {"GPT-4o": {"Kairos": row(lambda s: f"{R}/full-spec_llm-honest-sys95318c-anm-{H[s]}-important_instructions/{M}/{s}",
                                     lambda s: f"{R}/full-spec_llm-honest-sys95318c-anm-{H[s]}-noattack/{M}/{s}", list(H))}}


def autodojo():
    A = "autodojo_runs"
    # ASR and U: replay of the injections AutoDojo optimized against Kairos; U_b: clean utility
    return {"GPT-4o-mini": {"Kairos": row(lambda s: f"{A}/runs_v2/openai/gpt-4o-mini/kairos/{s}",
                                          lambda s: f"{A}/runs_v2_static/openai/gpt-4o-mini/kairos/{s}",
                                          ["banking", "slack", "travel"], attack="autodojo")}}


def strict():
    H = {"banking": "0921474b", "slack": "18275ef7", "travel": "05c343f8", "workspace": "13887c83"}
    return {"GPT-4.1": {"Strict monitor": row(lambda s: f"runs/run_01/baseline-{H[s]}-important_instructions/gpt-4.1/{s}",
                                              lambda s: f"runs/run_01/baseline-{H[s]}-noattack/gpt-4.1/{s}", DOJO)}}


def placement():
    Q = [("Qwen3.5-35B", "qwen/qwen3.5-35b-a3b"), ("Qwen3.5-27B", "qwen/qwen3.5-27b"), ("Qwen3.5-9B", "qwen/qwen3.5-9b")]
    out = {}
    for al, a in Q:
        au = a.replace("/", "_")
        rows = {"None": row(lambda s: f"runs_models/{au}/nodefense-anm-important_instructions/{a}/{s}",
                            lambda s: f"runs_models/{au}/nodefense-anm-noattack/{a}/{s}", ["banking"])}
        for ol, o in Q:
            base = f"runs_judge/{au}__judge-{o.replace('/', '_')}/full-spec_llm-anm-62761659"
            rows[f"oracle {ol}"] = row(lambda s, b=base: f"{b}-important_instructions/{a}/{s}",
                                       lambda s, b=base: f"{b}-noattack/{a}/{s}", ["banking"])
        out[f"agent {al}"] = rows
    return out


PRESETS = {"main": main_table, "agentdyn": agentdyn, "autodojo": autodojo, "strict": strict, "placement": placement}


def fmt(x):
    return "  ---" if x is None else f"{x:5.1f}"


def show(name, res):
    print(f"\n=== {name} ===")
    for group, rows in res.items():
        print(f"-- {group}")
        suites = list(next(iter(rows.values()))["per_suite"])
        head = "".join(f"{s[:9]:>20s}" for s in suites) if len(suites) > 1 else ""
        print(f"   {'':22s}{'ASR':>7s}{'U':>7s}{'U_b':>7s}{'NRP':>7s}{head}")
        for lab, r in rows.items():
            m = r["mean"]
            ps = "".join(f"   {fmt(r['per_suite'][s]['asr'])}/{fmt(r['per_suite'][s]['u'])}/{fmt(r['per_suite'][s]['u_b'])}"[:20].rjust(20)
                         for s in suites) if len(suites) > 1 else ""
            print(f"   {lab:22s}{fmt(m['asr']):>7s}{fmt(m['u']):>7s}{fmt(m['u_b']):>7s}{fmt(m['nrp']):>7s}{ps}")
    if any(len(next(iter(rows.values()))["per_suite"]) > 1 for rows in res.values()):
        print("   (per suite: ASR/U/U_b)")


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    which = list(PRESETS) if not args or args == ["all"] else args
    results = {w: PRESETS[w]() for w in which}
    if "--json" in sys.argv:
        print(json.dumps(results, indent=1))
    else:
        for w, r in results.items():
            show(w, r)
