"""Run cases and store one `RunRecord` per (case, repetition).

Records go to `<out>/<defense+options>/<model>/<scenario>/<case id with / -> __>[__rN].json`;
an existing record is skipped, so interrupted batches resume.
"""
from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from masbench.attacks import model_display_name, render_injections
from masbench.env import make_environment
from masbench.runner.brains import Brain, LLMBrain, ReplayOrchestrator, ReplayWorker, ScriptedBrain, Turn
from masbench.runner.defense import AuxLLM, load_defense
from masbench.runner.mas import MASRun
from masbench.schema import Case, LLMUsage, RunRecord, Scenario


@dataclass
class RunConfig:
    brain: str = "llm"  # llm | replay | replay-attack
    model: str = "gpt-4.1-2025-04-14"
    base_url: str | None = None
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    attack: str | None = None  # override the cases' attack template
    injection_model_name: str | None = None
    defense: str = "none"
    defense_options: dict[str, Any] = field(default_factory=dict)
    replay_mode: str = "sync"
    extra_body: dict[str, Any] = field(default_factory=dict)
    seed: bool = False  # send the repetition number as the request seed


class _MeteredLLM(AuxLLM):
    def __init__(self, brain: LLMBrain, usage: LLMUsage) -> None:
        self.brain, self.usage = brain, usage

    async def complete(self, messages: list[dict[str, Any]],
                       tools: list[dict[str, Any]] | None = None) -> Turn:
        turn = await self.brain.step(messages, tools or [])
        self.usage.calls += 1
        self.usage.prompt_tokens += turn.prompt_tokens
        self.usage.completion_tokens += turn.completion_tokens
        return turn


def _brains(scenario: Scenario, case: Case, env, cfg: RunConfig, repetition: int) -> dict[str, Brain]:  # noqa: ANN001
    if cfg.brain == "llm":
        llm = LLMBrain(cfg.model, cfg.base_url, cfg.api_key_env, cfg.temperature, extra_body=cfg.extra_body,
                       seed=repetition if cfg.seed else None)
        return {a.id: llm for a in scenario.agents}
    if case.script is not None:  # B2: the case's own ground truth
        return {a.id: ScriptedBrain(case.script.get(a.id, [])) for a in scenario.agents}
    owner = {t: a.id for a in scenario.agents for t in a.tools}
    plan, final = env.ground_truth(case.scoring.utility)
    if cfg.brain == "replay-attack" and case.scoring.security is not None:
        inj_plan, _ = env.ground_truth(case.scoring.security)
        plan = inj_plan + plan
    brains: dict[str, Brain] = {a.id: ReplayWorker() for a in scenario.agents}
    brains[scenario.entry_agent.id] = ReplayOrchestrator(plan, owner, final, cfg.replay_mode)
    return brains


async def run_case(scenario: Scenario, case: Case, cfg: RunConfig, repetition: int = 1) -> RunRecord:
    defense = load_defense(cfg.defense, **cfg.defense_options)
    defense.name = cfg.defense  # the name it was loaded by, so records and directories agree
    model = cfg.model if cfg.brain == "llm" else cfg.brain
    reason = defense.supports(scenario)
    if reason:
        return RunRecord(case=case.id, scenario=scenario.id, defense=defense.name,
                         defense_options=dict(defense.options), model=model, variant=case.variant,
                         repetition=repetition, not_applicable=reason,
                         labels=case.labels.model_dump(mode="json", exclude_defaults=True))
    name = model_display_name(cfg.model, cfg.injection_model_name)
    injections = render_injections(case, user=scenario.principal.name, model_name=name,
                                   attack_override=cfg.attack)
    env = make_environment(scenario, case, injections)
    aux = None
    if cfg.brain == "llm":
        def aux(model: str | None, usage: LLMUsage) -> AuxLLM:
            return _MeteredLLM(LLMBrain(model or cfg.model, cfg.base_url, cfg.api_key_env, cfg.temperature,
                                        extra_body=cfg.extra_body), usage)
    run = MASRun(scenario, case, env, defense, _brains(scenario, case, env, cfg, repetition), model,
                 repetition=repetition, aux_llm=aux)
    return await run.execute()


def run_dir(out: Path, cfg: RunConfig) -> Path:
    model = (cfg.model if cfg.brain == "llm" else cfg.brain).replace("/", "_")
    tag = cfg.defense.replace(":", "_").replace(".", "_")
    for k, v in sorted(cfg.defense_options.items()):
        if "url" not in k and "key" not in k:
            tag += f"-{k}={v}".replace("/", "_")
    if cfg.attack:
        tag += f"-{cfg.attack}"
    return out / tag / model


def record_path(out: Path, cfg: RunConfig, case: Case, repetition: int = 1) -> Path:
    name = case.id.split("/", 1)[1].replace("/", "__") + (f"__r{repetition}" if repetition > 1 else "")
    return run_dir(out, cfg) / case.scenario / f"{name}.json"


async def run_batch(scenario: Scenario, cases: list[Case], cfg: RunConfig,
                    out: Path | None, concurrency: int = 4, progress: bool = True,
                    repeat: int = 1) -> list[RunRecord]:
    sem = asyncio.Semaphore(concurrency)
    records: list[RunRecord] = []

    async def one(case: Case, rep: int) -> None:
        path = record_path(out, cfg, case, rep) if out else None
        if path and path.exists():
            records.append(RunRecord.model_validate_json(path.read_text()))
            return
        async with sem:
            rec = await run_case(scenario, case, cfg, rep)
        records.append(rec)
        if path:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(rec.model_dump(mode="json"), ensure_ascii=False, indent=1))
        if progress:
            print(f"{case.id} r{rep}: utility={rec.utility} security={rec.security}"
                  + (f" n/a={rec.not_applicable}" if rec.not_applicable else "")
                  + (f" error={rec.error}" if rec.error else ""), flush=True)

    await asyncio.gather(*(one(c, r) for c in cases for r in range(1, repeat + 1)))
    return records
