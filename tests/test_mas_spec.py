"""The system specification: parsing, validation (incl. agent/cluster policy
disjointness), clearance lookup, the effective per-agent policy, round trip."""
import copy
from pathlib import Path

import pytest
import yaml

from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.mas.spec import endpoint_origin
from kairos.mas.spec_parser import SpecError, dump_spec, load_spec, parse_spec

BANKING = Path(__file__).parent.parent / "kairos" / "mas" / "config" / "banking.yaml"


@pytest.fixture
def raw() -> dict:
    return yaml.safe_load(BANKING.read_text())


def test_example_spec_loads() -> None:
    spec = load_spec(BANKING)
    assert spec.entry == "assistant"
    assert sorted(spec.members("finance")) == ["accounts", "payments"]
    assert spec.same_cluster("accounts", "payments") and not spec.same_cluster("assistant", "payments")
    assert spec.agents["payments"].endpoint == "http://payments.finance.mas.local/a2a"
    assert spec.agent_at("http://payments.finance.mas.local/a2a/") == "payments"
    assert spec.agent_at("https://evil.example/a2a") is None


def test_peer_clearance_default_and_override() -> None:
    spec = load_spec(BANKING)
    # front lists finance without max_level -> finance's declared clearance
    assert spec.peer_clearance("assistant", "payments") == (Level.HIGH, True)
    assert spec.peer_clearance("assistant", "documents") == (Level.LOW, True)
    # docs only lists front
    assert spec.peer_clearance("documents", "payments") == (None, False)


def test_agent_override_beats_cluster_entry(raw) -> None:
    raw["clusters"]["front"]["policy"]["contact_book"]["peers"]["entries"].append(
        {"agent": "payments", "max_level": "medium"})
    spec = parse_spec(raw)
    assert spec.peer_clearance("assistant", "payments") == (Level.MEDIUM, True)
    assert spec.peer_clearance("assistant", "accounts") == (Level.HIGH, True)


def test_effective_agent_policy_joins_labels_and_release() -> None:
    spec = load_spec(BANKING)
    p = spec.agent_policy("accounts")
    assert {t.source for t in p.resources.taints} >= {"get_balance", "get_iban"}
    assert p.resources.contact_book is not None and p.resources.contact_book.lookup_fields == ["recipient"]
    assert [r.id for r in p.rules] == ["review-send-with-sensitive-payload"]
    assert p.context.default_action is Decision.REVIEW and "update_password" in p.context.non_revertable
    assert spec.agent_policy("assistant").resources.contact_book is None


@pytest.mark.parametrize("misplaced", ["contact_book", "rules", "default_action"])
def test_agent_policy_cannot_carry_release_decisions(raw, misplaced) -> None:
    raw["agents"]["payments"]["policy"][misplaced] = {} if misplaced != "rules" else []
    with pytest.raises(SpecError, match="belongs to the cluster policy"):
        parse_spec(raw)


def test_validation_problems_are_reported(raw) -> None:
    bad = copy.deepcopy(raw)
    bad["system"]["entry"] = "nobody"
    bad["agents"]["documents"]["cluster"] = "nowhere"
    bad["clusters"]["finance"]["policy"]["contact_book"]["peers"]["entries"].append({"cluster": "finance"})
    bad["clusters"]["finance"]["policy"]["rules"].append(
        {"id": "x", "match": {"action": "teleport"}, "decision": "DENY"})
    with pytest.raises(SpecError) as e:
        parse_spec(bad)
    msg = str(e.value)
    for needle in ("unknown agent 'nobody'", "unknown cluster 'nowhere'", "its own cluster",
                   "teleport", "at least one member"):
        assert needle in msg, needle


def test_peer_entry_names_exactly_one_target(raw) -> None:
    raw["clusters"]["docs"]["policy"]["contact_book"]["peers"]["entries"] = [
        {"cluster": "front", "agent": "assistant"}]
    with pytest.raises(SpecError, match="exactly one"):
        parse_spec(raw)


def test_duplicate_endpoints_rejected(raw) -> None:
    raw["agents"]["payments"]["endpoint"] = raw["agents"]["accounts"].get(
        "endpoint", "http://accounts.finance.mas.local/a2a")
    with pytest.raises(SpecError, match="already used"):
        parse_spec(raw)


def test_a2a_rules_validate(raw) -> None:
    raw["clusters"]["front"]["policy"]["rules"] = [
        {"id": "no-docs", "match": {"action": "a2a.send", "params": {"to_cluster": {"equals": "docs"}}},
         "decision": "DENY"}]
    spec = parse_spec(raw)
    assert spec.clusters["front"].policy.rules[0].match.action == "a2a.send"


def test_knobs_accept_yaml_booleans(raw) -> None:
    raw["clusters"]["front"]["policy"]["message_identifiers"] = False      # YAML `off`
    raw["clusters"]["front"]["policy"]["embedded_identifiers"] = True      # YAML `on`
    spec = parse_spec(raw)
    assert spec.clusters["front"].policy.message_identifiers == "allow"
    assert spec.clusters["front"].policy.embedded_identifiers == "review"


def test_dump_round_trip() -> None:
    spec = load_spec(BANKING)
    again = parse_spec(yaml.safe_load(dump_spec(spec)))
    assert again.entry == spec.entry and set(again.agents) == set(spec.agents)
    for a in spec.agents:
        assert again.agents[a].labels.actions == spec.agents[a].labels.actions
        assert [t.source for t in again.agents[a].labels.taints] == [t.source for t in spec.agents[a].labels.taints]
        assert endpoint_origin(again.agents[a].endpoint) == endpoint_origin(spec.agents[a].endpoint)
    for c in spec.clusters:
        assert again.clusters[c].clearance == spec.clusters[c].clearance
        assert again.peer_clearance  # noqa: B018
    assert [r.id for r in again.clusters["finance"].policy.rules] == ["review-send-with-sensitive-payload"]
    assert again.clusters["finance"].policy.external.lookup_fields == ["recipient"]


def test_agent_policy_from_file(tmp_path, raw) -> None:
    (tmp_path / "payments.yaml").write_text(yaml.safe_dump(raw["agents"]["payments"]["policy"]))
    raw["agents"]["payments"]["policy"] = "payments.yaml"
    (tmp_path / "spec.yaml").write_text(yaml.safe_dump(raw))
    spec = load_spec(tmp_path / "spec.yaml")
    assert "send_money" in spec.agents["payments"].labels.non_revertable
