"""Environment adapters: the shared world all agents act on.

All agents of a run act on the *same* environment object, so checks score the combined
effect of the system. Two kinds:

* `agentdojo`: an AgentDojo suite (B1, and the B2 cases built on the B1 suites). AgentDojo
  is imported only when such an environment is made.
* `python`: `module: <module>:<factory>` returning an environment, normally a
  `masbench.sim.SimEnvironment` subclass (B2).

Scoring goes through `masbench.checks.score`: `python:` checks work on every kind,
`agentdojo:` checks are native to the AgentDojo adapter.
"""
from __future__ import annotations

import importlib
from ast import literal_eval
from dataclasses import dataclass
from typing import Any, Protocol

from masbench.schema import Case, Check, Scenario


@dataclass
class ToolOutcome:
    result: str
    error: str | None


class Environment(Protocol):
    def openai_tools(self, names: list[str]) -> list[dict[str, Any]]: ...
    def run_tool(self, function: str, args: dict[str, Any], agent: str = "") -> ToolOutcome: ...
    def score(self, check: Check, final_output: str, trace: list[tuple[str, dict]]) -> bool: ...
    def ground_truth(self, check: Check) -> tuple[list[tuple[str, dict]], str]: ...
    def snapshot(self) -> Any: ...
    def restore(self, snap: Any) -> None: ...


class AgentDojoEnvironment:
    """One AgentDojo suite environment with the case's injections in place.

    `case.setup` may carry `init_task` (a user task whose `init_environment` prepares the
    state) for cases that are scored by python checks."""

    def __init__(self, scenario: Scenario, case: Case, injections: dict[str, str]) -> None:
        from agentdojo.functions_runtime import FunctionsRuntime
        from agentdojo.task_suite.load_suites import get_suite

        spec = scenario.environment
        self.version, self.suite_name = spec.version, spec.suite
        self.suite = get_suite(spec.version, spec.suite)
        self.runtime = FunctionsRuntime(self.suite.tools)
        self.sink: list[dict[str, Any]] = []
        env = self.suite.load_and_inject_default_environment(injections)
        init = case.scoring.utility.ref if case.scoring.utility.ref.startswith("agentdojo:") else None
        if init is not None:
            env = self._task(case.scoring.utility).init_environment(env)
        elif case.setup.get("init_task"):
            env = self.suite.user_tasks[case.setup["init_task"]].init_environment(env)
        self.env = env
        self.pre_env = self.env.model_copy(deep=True)

    @property
    def state(self) -> Any:
        return self.env

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

    def run_tool(self, function: str, args: dict[str, Any], agent: str = "") -> ToolOutcome:
        from agentdojo.agent_pipeline.tool_execution import is_string_list, tool_result_to_str

        args = dict(args)
        for k, v in list(args.items()):  # as AgentDojo's ToolsExecutor: "['a', 'b']" -> list
            if isinstance(v, str) and is_string_list(v):
                args[k] = literal_eval(v)
        result, error = self.runtime.run_function(self.env, function, args)
        return ToolOutcome(result=tool_result_to_str(result) if error is None else "", error=error)

    def score(self, check: Check, final_output: str, trace: list[tuple[str, dict]]) -> bool:
        from agentdojo.functions_runtime import FunctionCall

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
