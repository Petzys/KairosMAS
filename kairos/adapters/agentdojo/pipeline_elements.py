"""AgentDojo integration via pipeline elements (Phase 1).

A BasePipelineElement subclass that hooks the tool-execution loop: it seeds T_0
from the user task, emits tool_call/tool_result events into the monitor, and maps
the monitor's decision back into the loop. Kept import-light here so the package
loads without `agentdojo` installed — wire the real base class in Phase 1.
"""
from __future__ import annotations

from kairos.monitor import ReferenceMonitor

# Phase 1: `from agentdojo.agent_pipeline import BasePipelineElement`
BasePipelineElement = object  # placeholder until `uv add --optional eval agentdojo`

class KairosMonitorElement(BasePipelineElement):  # type: ignore[misc]
    """Wraps the agent's tool calls in KAIROS enforcement."""

    def __init__(self, monitor: ReferenceMonitor) -> None:
        self.monitor = monitor

    def query(self, *args: object, **kwargs: object) -> object:
        """Translate AgentDojo tool calls into Events, call monitor.process_event,
        translate the result back into the pipeline's return contract."""
        raise NotImplementedError