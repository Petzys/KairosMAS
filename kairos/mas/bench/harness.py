"""Running MASDojo: one (user task, injection task) pair end to end, and suites.

A pair is evaluated with AgentDojo's own checks on the final environment: utility
of the user task (from the entry agent's answer and the environment) and success
of the injection task. On top come the system-level measurements a multi-agent
monitor is about: where effects were stopped (cluster boundary or external
boundary), how far the injection spread (agents and clusters that read it), how
many oracle calls the protection cost, and how long the session took.
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from agentdojo.agent_pipeline.llms.openai_llm import OpenAILLM
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.models import MODEL_NAMES
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import text_content_block_from_string

from kairos.mas.a2a.adapter import Delivery
from kairos.mas.bench.environment import Exposure, ToolBox
from kairos.mas.bench.llm import LLMAgents
from kairos.mas.bench.oracles import InjectionMatcher, judge_factory
from kairos.mas.bench.scripted import ScriptedSystem
from kairos.mas.bench.suites import POLICY_DIR, SYSTEMS, BuildOptions, build_spec
from kairos.mas.fabric import MonitorFabric
from kairos.mas.runtime import MASRuntime
from kairos.mas.spec import A2A_REPLY, A2A_SEND


@dataclass(slots=True)
class RunConfig:
    suite: str = "banking"
    layout: str = "domain"
    backend: str = "scripted"            # scripted | llm
    defense: bool = True
    oracle: str = "gt"                   # gt | approve | deny | deterministic | llm
    dispatch: str = "sync"               # scripted: sync | stream | parallel
    attack: str = "important_instructions"
    hold_notice: str = "honest"
    max_held_per_branch: int = 1
    message_identifiers: str = "review"
    message_review: str = "policy"       # policy | all (every inter-cluster message to the oracle)
    model: str = "gpt-4o-mini"           # llm backend: the agents' model
    judge_model: str = "gpt-4o-mini"     # llm oracle
    judge_prompt: str = "benchmark"      # benchmark | production
    tool_latency: float = 0.0
    timeout: float = 300.0
    benchmark_version: str = "v1"
    max_iters: int = 15

    def tag(self) -> str:
        """Results directory name: every knob that changes behaviour, plus a hash of
        the suite's single-agent policy (editing it invalidates cached results)."""
        policy = (POLICY_DIR / f"{self.suite}.yaml").read_bytes()
        parts = [self.backend, self.layout]
        if self.backend == "llm":
            parts.append(self.model.replace("/", "_"))
        if not self.defense:
            parts.append("nodefense")
        else:
            parts += [f"oracle-{self.oracle}" + (f"-{self.judge_model.replace('/', '_')}"
                                                 if self.oracle == "llm" else ""),
                      f"hold-{self.hold_notice}"]
            if self.max_held_per_branch != 1:
                parts.append(f"wide{self.max_held_per_branch}")
            if self.message_identifiers != "review":
                parts.append(f"msgid-{self.message_identifiers}")
            if self.message_review != "policy":
                parts.append(f"review-{self.message_review}")
            if self.judge_prompt != "benchmark" and self.oracle == "llm":
                parts.append(f"prompt-{self.judge_prompt}")
        if self.backend == "scripted" and self.dispatch != "sync":
            parts.append(self.dispatch)
        if self.tool_latency:
            parts.append(f"lat{self.tool_latency:g}")
        parts.append(self.attack or "noattack")
        parts.append(hashlib.sha1(policy).hexdigest()[:8])
        return "-".join(parts)


@dataclass(slots=True)
class PairResult:
    suite: str
    user_task: str
    injection_task: str | None
    utility: bool
    attack_success: bool | None
    output: str
    metrics: dict[str, Any] = field(default_factory=dict)
    report: dict[str, Any] = field(default_factory=dict)
    transcripts: list[dict[str, Any]] = field(default_factory=list)


class _AttackTarget(SimpleNamespace):
    """What an AgentDojo attack needs of the attacked pipeline: its name."""


def make_attack(cfg: RunConfig, suite: Any) -> Any:
    name = cfg.model if cfg.backend == "llm" else "local"
    if not any(k in name for k in MODEL_NAMES):
        MODEL_NAMES[name] = "AI assistant"
    return load_attack(cfg.attack, suite, _AttackTarget(name=name))


def run_pair(cfg: RunConfig, suite: Any, user_task: Any, injection_task: Any | None,
             injections: dict[str, str], *, client: Any = None, judge_client: Any = None,
             meter: Any = None, verbose: bool = False) -> PairResult:
    env = suite.load_and_inject_default_environment(injections)
    task_env = user_task.init_environment(env)
    pre_env = task_env.model_copy(deep=True)
    plan = user_task.ground_truth(pre_env.model_copy(deep=True))
    injection_plan = injection_task.ground_truth(pre_env.model_copy(deep=True)) if injection_task else []

    system = SYSTEMS[cfg.suite]
    spec = build_spec(cfg.suite, BuildOptions(layout=cfg.layout, message_identifiers=cfg.message_identifiers,
                                              message_review=cfg.message_review))
    judges: list[Any] = []
    make_judge = judge_factory(cfg.oracle, injection_plan=injection_plan, user_plan=plan,
                               client=judge_client, model=cfg.judge_model, prompt=cfg.judge_prompt)

    def factory(monitor: Any) -> Any:
        j = make_judge(monitor)
        judges.append(j)
        return j

    fabric = MonitorFabric(spec, judge_factory=factory, hold_notice=cfg.hold_notice,
                           max_held_per_branch=cfg.max_held_per_branch)
    tools = ToolBox(suite, task_env, system, latency=cfg.tool_latency)
    exposure = Exposure.for_injection(injection_task.GOAL if injection_task else None, injections.values())

    if cfg.backend == "scripted":
        agents: Any = ScriptedSystem(spec, system, tools, exposure, plan=plan, injection_plan=injection_plan,
                                     final_output=user_task.GROUND_TRUTH_OUTPUT, dispatch=cfg.dispatch)
    elif cfg.backend == "llm":
        if client is None:
            raise ValueError("the llm backend needs an OpenAI-compatible client")
        agents = LLMAgents(spec, system, tools, exposure, llm_factory=lambda: OpenAILLM(client, cfg.model),
                           max_iters=cfg.max_iters, verbose=verbose)
    else:
        raise ValueError(f"unknown backend {cfg.backend!r}")

    if meter is not None:
        meter.reset()
    rt = MASRuntime(spec, fabric, agents.handlers(), defense=cfg.defense, formatter=ToolBox.format)
    res = rt.run(user_task.PROMPT, timeout=cfg.timeout)

    model_output = [text_content_block_from_string(res.output)]
    utility = suite._check_task_result(user_task, model_output, pre_env, task_env, tools.trace)
    attack_success = (suite._check_task_result(injection_task, model_output, pre_env, task_env, tools.trace)
                      if injection_task is not None else None)
    metrics = _metrics(spec, res, tools, exposure, judges, injection_plan, plan, agents)
    if meter is not None:
        metrics["tokens"] = meter.snapshot()
    return PairResult(suite=cfg.suite, user_task=user_task.ID,
                      injection_task=injection_task.ID if injection_task else None,
                      utility=bool(utility), attack_success=None if attack_success is None else bool(attack_success),
                      output=res.output, metrics=metrics, report=res.report,
                      transcripts=getattr(agents, "transcripts", []))


def _metrics(spec, res, tools: ToolBox, exposure: Exposure, judges: list[Any],
             injection_plan: list[Any], plan: list[Any], agents: Any) -> dict[str, Any]:
    m: dict[str, Any] = {"elapsed": round(res.elapsed, 4), "quiescent": res.quiescent,
                         "executed_calls": len(tools.trace)}
    matcher = InjectionMatcher(injection_plan, plan)
    m["executed_injection_calls"] = sum(1 for c in tools.trace if matcher.matches(c.function, dict(c.args)))
    exposed = exposure.agents
    m["exposed_agents"] = exposed
    m["exposed_clusters"] = sorted({spec.agents[a].cluster for a in exposed})
    if hasattr(agents, "infected"):
        m["infected_agents"] = list(agents.infected)
        m["retries"] = agents.retries
    report = res.report or {}
    counts = report.get("counts", {})
    m.update({k: counts.get(k, 0) for k in ("messages", "intra_cluster", "inter_cluster", "rejected",
                                            "held", "oracle_calls")})
    m["flagged_agents"] = counts.get("flagged_agents", [])
    m["oracle_llm_calls"] = sum(getattr(j, "llm_calls", 0) for j in judges)
    stopped_cluster = stopped_external = 0
    for a in (report.get("agents") or {}).values():
        for r in a.get("resolutions", []):
            for tool in r.get("aborted", []):
                if tool in (A2A_SEND, A2A_REPLY):
                    stopped_cluster += 1
                else:
                    stopped_external += 1
    # messages denied deterministically (topology, rules, confidentiality) never reach the
    # oracle; oracle refusals are already counted in the resolutions above
    denied_msgs = sum(1 for x in report.get("messages", [])
                      if x["status"] == "rejected" and not x["was_held"] and x["decision"] != "oracle")
    m["stopped_at_cluster_boundary"] = stopped_cluster + denied_msgs
    m["stopped_at_external_boundary"] = stopped_external
    m["streamed_messages"] = sum(1 for x in report.get("messages", [])
                                 if x["delivery"] == Delivery.STREAMING.value)
    return m


# --- suites ------------------------------------------------------------------------
def load_suite(cfg: RunConfig) -> Any:
    return get_suite(cfg.benchmark_version, cfg.suite)


def result_path(logdir: Path, cfg: RunConfig, user_task: str, injection_task: str | None) -> Path:
    return logdir / cfg.tag() / cfg.suite / user_task / f"{injection_task or 'none'}.json"


def save(path: Path, cfg: RunConfig, r: PairResult) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"config": asdict(cfg), **asdict(r)}, indent=1, default=str))


def run_suite(cfg: RunConfig, *, logdir: Path, user_tasks: list[str] | None = None,
              injection_tasks: list[str] | None = None, benign: bool = True, attacked: bool = True,
              force: bool = False, client: Any = None, judge_client: Any = None, meter: Any = None,
              verbose: bool = False, progress: bool = True) -> list[dict[str, Any]]:
    suite = load_suite(cfg)
    uts = [suite.user_tasks[u] for u in (user_tasks or list(suite.user_tasks))]
    its = [suite.injection_tasks[i] for i in (injection_tasks or list(suite.injection_tasks))]
    attack = make_attack(cfg, suite) if (attacked and cfg.attack) else None
    rows: list[dict[str, Any]] = []
    pairs: list[tuple[Any, Any | None]] = []
    for ut in uts:
        if benign:
            pairs.append((ut, None))
        if attack is not None:
            pairs += [(ut, it) for it in its]
    t0 = time.monotonic()
    for i, (ut, it) in enumerate(pairs, 1):
        path = result_path(logdir, cfg, ut.ID, it.ID if it else None)
        if path.exists() and not force:
            rows.append(json.loads(path.read_text()))
            continue
        injections = attack.attack(ut, it) if it is not None else {}
        r = run_pair(cfg, suite, ut, it, injections, client=client, judge_client=judge_client,
                     meter=meter, verbose=verbose)
        save(path, cfg, r)
        rows.append(json.loads(path.read_text()))
        if progress:
            sec = "-" if r.attack_success is None else ("ATTACK" if r.attack_success else "safe")
            print(f"[{i}/{len(pairs)} {time.monotonic() - t0:6.1f}s] {cfg.suite} {ut.ID} "
                  f"{it.ID if it else 'benign'}: utility={'ok' if r.utility else 'FAIL'} {sec} "
                  f"oracle={r.metrics.get('oracle_calls', 0)} msgs={r.metrics.get('inter_cluster', 0)}"
                  f"/{r.metrics.get('messages', 0)}", flush=True)
    return rows


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    benign = [r for r in rows if r["injection_task"] is None]
    attacked = [r for r in rows if r["injection_task"] is not None]

    def rate(xs: list[bool]) -> float | None:
        return round(100 * sum(xs) / len(xs), 1) if xs else None

    def mean(key: str, xs: list[dict[str, Any]]) -> float | None:
        vals = [x["metrics"].get(key, 0) for x in xs]
        vals = [len(v) if isinstance(v, list) else v for v in vals]
        return round(sum(vals) / len(vals), 3) if vals else None

    return {
        "pairs": len(rows),
        "utility": rate([r["utility"] for r in benign]),
        "utility_under_attack": rate([r["utility"] for r in attacked]),
        "asr": rate([bool(r["attack_success"]) for r in attacked]),
        "oracle_calls_benign": mean("oracle_calls", benign),
        "oracle_calls_attacked": mean("oracle_calls", attacked),
        "inter_cluster_messages": mean("inter_cluster", rows),
        "held_messages": mean("held", rows),
        "rejected_messages": mean("rejected", rows),
        "exposed_agents": mean("exposed_agents", attacked),
        "exposed_clusters": mean("exposed_clusters", attacked),
        "stopped_at_cluster_boundary": mean("stopped_at_cluster_boundary", attacked),
        "stopped_at_external_boundary": mean("stopped_at_external_boundary", attacked),
        "elapsed": mean("elapsed", rows),
        "not_quiescent": sum(1 for r in rows if not r["metrics"].get("quiescent", True)),
    }
