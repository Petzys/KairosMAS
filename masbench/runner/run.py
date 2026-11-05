"""Run cases and store one `RunRecord` per case.

Records go to `<out>/<defense+options>/<model>/<scenario>/<case id with / -> __>.json`; an
existing record is skipped, so interrupted batches resume.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from masbench.attacks import model_display_name, render_injections
from masbench.env import make_environment
from masbench.runner.brains import Brain, LLMBrain, ReplayOrchestrator, ReplayWorker
from masbench.runner.defense import load_defense
from masbench.runner.mas import MASRun
from masbench.schema import Case, RunRecord, Scenario


@dataclass
class RunConfig:
    brain: str = "llm"  # llm | replay | replay-attack
    model: str = "gpt-4.1-2025-04-14"
    base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    attack: str | None = None  # override the cases' attack template
    injection_model_name: str | None = None
    defense: str = "undefended"
    defense_options: dict[str, Any] = field(default_factory=dict)
    replay_mode: str = "sync"
    extra_body: dict[str, Any] = field(default_factory=dict)


def _brains(scenario: Scenario, case: Case, env, cfg: RunConfig) -> dict[str, Brain]:  # noqa: ANN001
    if cfg.brain == "llm":
        llm = LLMBrain(cfg.model, cfg.base_url, cfg.api_key_env, cfg.temperature, extra_body=cfg.extra_body)
        return {a.id: llm for a in scenario.agents}
    owner = {t: a.id for a in scenario.agents for t in a.tools}
    plan, final = env.ground_truth(case.scoring.utility)
    if cfg.brain == "replay-attack" and case.scoring.security is not None:
        inj_plan, _ = env.ground_truth(case.scoring.security)
        plan = inj_plan + plan
    brains: dict[str, Brain] = {a.id: ReplayWorker() for a in scenario.agents}
    brains[scenario.entry_agent.id] = ReplayOrchestrator(plan, owner, final, cfg.replay_mode)
    return brains


async def run_case(scenario: Scenario, case: Case, cfg: RunConfig) -> RunRecord:
    name = model_display_name(cfg.model, cfg.injection_model_name)
    injections = render_injections(case, user=scenario.principal.name, model_name=name,
                                   attack_override=cfg.attack)
    env = make_environment(scenario, case, injections)
    defense = load_defense(cfg.defense, **cfg.defense_options)
    model = cfg.model if cfg.brain == "llm" else cfg.brain
    run = MASRun(scenario, case, env, defense, _brains(scenario, case, env, cfg), model)
    return await run.execute()


def record_path(out: Path, cfg: RunConfig, case: Case) -> Path:
    model = (cfg.model if cfg.brain == "llm" else cfg.brain).replace("/", "_")
    tag = cfg.defense.replace(":", "_").replace(".", "_")
    for k, v in sorted(cfg.defense_options.items()):
        if "url" not in k and "key" not in k:
            tag += f"-{k}={v}".replace("/", "_")
    if cfg.attack:
        tag += f"-{cfg.attack}"
    return (out / tag / model / case.scenario
            / (case.id.split("/", 1)[1].replace("/", "__") + ".json"))


async def run_batch(scenario: Scenario, cases: list[Case], cfg: RunConfig,
                    out: Path | None, concurrency: int = 4, progress: bool = True) -> list[RunRecord]:
    sem = asyncio.Semaphore(concurrency)
    records: list[RunRecord] = []

    async def one(case: Case) -> None:
        path = record_path(out, cfg, case) if out else None
        if path and path.exists():
            records.append(RunRecord.model_validate_json(path.read_text()))
            return
        async with sem:
            rec = await run_case(scenario, case, cfg)
        records.append(rec)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(rec.model_dump(mode="json"), ensure_ascii=False, indent=1))
        if progress:
            print(f"{case.id}: utility={rec.utility} security={rec.security}"
                  + (f" error={rec.error}" if rec.error else ""), flush=True)

    await asyncio.gather(*(one(c) for c in cases))
    return records
