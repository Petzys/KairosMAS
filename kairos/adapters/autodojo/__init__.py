"""KAIROS as an AutoDojo/AgentDojo-fork defense (`--defense kairos`).

The AutoDojo optimizer builds its target agent pipeline from a fork-registered
defense name. KAIROS's reference monitor is already an AgentDojo pipeline element
(`kairos.adapters.agentdojo.PolicyEnforcer`), so this module is wiring, not new
logic: `build_kairos_pipeline(cls, config)` returns a fork `AgentPipeline` with
the KAIROS elements composed the same way `scripts/run_benchmark.py` does.

All KAIROS knowledge (policy map, judge model, mode) lives here so the edit to
the fork's `agent_pipeline.py` is a three-line branch.
"""

from kairos.adapters.autodojo.pipeline import build_kairos_pipeline

__all__ = ["build_kairos_pipeline"]
