# tests/test_skeleton.py
"""Phase 0 gate: the vocabulary is real (types construct, enums and priority hold)."""
import pytest
import yaml

from kairos.core.events import Channel, Event, ToolOp
from kairos.core.tokens import Level, TrustToken
from kairos.engine.decision import Decision, resolve


def test_event_is_frozen_and_metadata_copies() -> None:
    e = Event(0.0, Channel.TOOL, ToolOp.CALL.value, "agent", "send_money", {"recipient": "X"})
    with pytest.raises(Exception):
        e.timestamp = 1.0  # type: ignore[misc]
    assert e.with_metadata(branch_id="b1").branch_id == "b1"
    assert e.branch_id is None  # original unchanged


def test_level_ordering() -> None:
    assert Level.LOW < Level.HIGH < Level.CRITICAL
    assert Level.from_str("high") is Level.HIGH


def test_decision_priority() -> None:
    assert resolve([None, Decision.ALLOW, Decision.REVIEW]) is Decision.REVIEW
    assert resolve([Decision.ALLOW, Decision.DENY, Decision.REVIEW]) is Decision.DENY
    assert resolve([None, None]) is None


def test_trust_token_hashable() -> None:
    assert len({TrustToken("v", "src"), TrustToken("v", "src")}) == 1


def test_example_policy_is_valid_yaml(banking_policy_path) -> None:
    raw = yaml.safe_load(banking_policy_path.read_text())
    assert raw["context"]["name"] == "banking-demo"