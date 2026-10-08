# tests/test_imports.py
"""Phase 0 gate: every module imports cleanly (the seam holds, no cycles)."""
import importlib

MODULES = [
    "kairos", "kairos.monitor", "kairos.cli",
    "kairos.core.events", "kairos.core.tokens", "kairos.core.matching",
    "kairos.core.extract", "kairos.core.store", "kairos.core.flowgraph",
    "kairos.policy.schema", "kairos.policy.parser", "kairos.policy.contact_book",
    "kairos.policy.rules", "kairos.policy.ratelimit",
    "kairos.engine.decision", "kairos.engine.action_class", "kairos.engine.integrity",
    "kairos.engine.confidentiality", "kairos.engine.pipeline",
    "kairos.speculative.branch", "kairos.speculative.triggers",
    "kairos.speculative.machine", "kairos.speculative.stubs", "kairos.speculative.rollback",
    "kairos.judge.oracle", "kairos.judge.commit",
    "kairos.adapters.base", "kairos.adapters.agentdojo.pipeline_elements",
    "kairos.adapters.agentdojo.effector", "kairos.adapters.production",
]


def test_all_modules_import() -> None:
    for name in MODULES:
        importlib.import_module(name)