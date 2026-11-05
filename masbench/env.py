"""Environment adapters: the shared world all agents act on, and the scoring checks.

All agents of a run act on the *same* environment object, so AgentDojo's checks score the
combined effect of the system unchanged. B2 environments implement the same interface
(`environment.kind: python`, `module: <module>:<factory>`).
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Protocol

from agentdojo.agent_pipeline.tool_execution import tool_result_to_str
from agentdojo.functions_runtime import FunctionCall, FunctionsRuntime
from agentdojo.task_suite.load_suites import get_suite

from masbench.schema import Case, Check, Scenario


@dataclass
class ToolOutcome:
    result: str
    error: str | None


class Environment(Protocol):
    def openai_tools(self, names: list[str]) -> list[dict[str, Any]]: ...
    def run_tool(self, function: str, args: dict[str, Any]) -> ToolOutcome: ...
    def score(self, check: Check, final_output: str, trace: list[tuple[str, dict]]) -> bool: ...
    def ground_truth(self, check: Check) -> tuple[list[tuple[str, dict]], str]: ...
    def snapshot(self) -> Any: ...
    def restore(self, snap: Any) -> None: ...


class AgentDojoEnvironment:
    """One AgentDojo suite environment with the case's injections in place."""

    def __init__(self, scenario: Scenario, case: Case, injections: dict[str, str]) -> None:
        spec = scenario.environment
        self.version, self.suite_name = spec.version, spec.suite
        self.suite = get_suite(spec.version, spec.suite)
        self.runtime = FunctionsRuntime(self.suite.tools)
        env = self.suite.load_and_inject_default_environment(injections)
        ut = self._task(case.scoring.utility)
        self.env = ut.init_environment(env)
        self.pre_env = self.env.model_copy(deep=True)

    def _task(self, check: Check):  # noqa: ANN202
        kind, version, suite, task_id = check.ref.split(":")
        assert kind == "agentdojo" and (version, suite) == (self.version, self.suite_name), check.ref
        tasks = self.suite.user_tasks if task_id.startswith("user_task") else self.suite.injection_tasks
        return tasks[task_id]

    def openai_tools(self, names: list[str]) -> list[dict[str, Any]]:
        fns = {f.name: f for f in self.suite.tools}
        return [{"type": "function", "function": {
            "name": n, "description": fns[n].description,
            "parameters": fns[n].parameters.model_json_schema()}} for n in names]

    def run_tool(self, function: str, args: dict[str, Any]) -> ToolOutcome:
        result, error = self.runtime.run_function(self.env, function, args)
        return ToolOutcome(result=tool_result_to_str(result) if error is None else "", error=error)

    def score(self, check: Check, final_output: str, trace: list[tuple[str, dict]]) -> bool:
        task = self._task(check)
        calls = [FunctionCall(function=f, args=a) for f, a in trace]
        is_user = check.ref.split(":")[-1].startswith("user_task")
        name = "utility" if is_user else "security"
        from_traces = getattr(task, f"{name}_from_traces")(final_output, self.pre_env, self.env, calls)
        if from_traces is not None:
            return bool(from_traces)
        return bool(getattr(task, name)(final_output, self.pre_env, self.env))

    def ground_truth(self, check: Check) -> tuple[list[tuple[str, dict]], str]:
        """(calls, expected final output) of the task behind `check`, on the current state."""
        task = self._task(check)
        calls = [(c.function, dict(c.args)) for c in task.ground_truth(self.pre_env.model_copy(deep=True))]
        return calls, getattr(task, "GROUND_TRUTH_OUTPUT", "")

    def snapshot(self) -> Any:
        return self.env.model_copy(deep=True)

    def restore(self, snap: Any) -> None:
        self.env = snap.model_copy(deep=True)


def make_environment(scenario: Scenario, case: Case, injections: dict[str, str]) -> Environment:
    spec = scenario.environment
    if spec.kind == "agentdojo":
        return AgentDojoEnvironment(scenario, case, injections)
    module, _, factory = spec.module.partition(":")
    return getattr(importlib.import_module(module), factory)(scenario, case, injections)
