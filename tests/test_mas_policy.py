"""Release decisions for messages: intra-cluster pass, topology, integrity of the
destination, confidentiality against the sending cluster's clearances, payload
identifiers, rules over a2a.send, replies, and the intra-cluster annotation."""
from kairos.core.extract import ExtractConfig
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.mas.policy import annotate_intra_cluster, build_engines, evaluate_message

from tests.mas_util import ATTACKER_IBAN, BILL_IBAN, banking_spec


def _engines(spec, agent, prompt=None):
    store = TokenStore(owner=agent)
    if prompt:
        store.seed(prompt)
    return build_engines(spec, agent, store), store


def test_intra_cluster_is_released_without_evaluation() -> None:
    spec = banking_spec()
    eng, _ = _engines(spec, "accounts")
    r = evaluate_message(spec, eng, "accounts", "payments", f"pay {ATTACKER_IBAN}")
    assert r.decision is Decision.ALLOW and r.produced_by == "intra_cluster"


def test_topology_denies_unlisted_peer() -> None:
    spec = banking_spec()
    eng, _ = _engines(spec, "documents")
    r = evaluate_message(spec, eng, "documents", "payments", "hello")
    assert r.decision is Decision.DENY and r.produced_by == "topology"


def test_unlisted_peer_is_reviewed_under_on_miss_review() -> None:
    def m(raw):
        raw["clusters"]["docs"]["policy"]["contact_book"]["peers"]["on_miss"] = "REVIEW"
    spec = banking_spec(m)
    eng, _ = _engines(spec, "documents")
    r = evaluate_message(spec, eng, "documents", "payments", "hello")
    assert r.decision is Decision.REVIEW and r.produced_by == "integrity"


def test_plain_message_to_listed_peer_is_released() -> None:
    spec = banking_spec()
    eng, _ = _engines(spec, "assistant", "pay the bill in bill.txt")
    r = evaluate_message(spec, eng, "assistant", "documents", "Please read bill.txt")
    assert r.decision is Decision.ALLOW


def test_payload_identifier_from_outside_the_closure_is_reviewed() -> None:
    spec = banking_spec()
    eng, _ = _engines(spec, "assistant", "pay the bill in bill.txt")
    r = evaluate_message(spec, eng, "assistant", "payments", f"Send 98.70 to {BILL_IBAN}")
    assert r.decision is Decision.REVIEW and r.produced_by == "embedded_identifiers"


def test_payload_identifier_from_the_user_prompt_passes() -> None:
    spec = banking_spec()
    eng, _ = _engines(spec, "assistant", f"send 10 to {BILL_IBAN}")
    r = evaluate_message(spec, eng, "assistant", "payments", f"Send 10 to {BILL_IBAN}")
    assert r.decision is Decision.ALLOW


def test_message_identifier_check_can_be_disabled() -> None:
    def m(raw):
        raw["clusters"]["front"]["policy"]["message_identifiers"] = "allow"
    spec = banking_spec(m)
    eng, _ = _engines(spec, "assistant", "pay the bill")
    assert evaluate_message(spec, eng, "assistant", "payments", f"to {BILL_IBAN}").decision is Decision.ALLOW


def test_confidentiality_uses_the_sending_clusters_clearance() -> None:
    spec = banking_spec()
    eng, store = _engines(spec, "assistant", "what is my balance")
    store.admit("balance: 1810.55", "get_balance", trusted=False, level=Level.HIGH,
                branch_origin=None, extract_cfg=ExtractConfig())
    to_docs = evaluate_message(spec, eng, "assistant", "documents", "the balance is 1810.55")
    to_fin = evaluate_message(spec, eng, "assistant", "payments", "the balance is 1810.55")
    assert to_docs.decision is Decision.REVIEW and to_docs.produced_by == "confidentiality"
    assert to_fin.decision is Decision.ALLOW              # finance is cleared for HIGH


def test_agent_names_are_not_scanned_as_content() -> None:
    spec = banking_spec()
    eng, store = _engines(spec, "assistant", "hello")
    store.admit("monthly payments to Spotify", "get_most_recent_transactions", trusted=False,
                level=Level.HIGH, branch_origin=None, extract_cfg=ExtractConfig())
    assert evaluate_message(spec, eng, "assistant", "payments", "hello").decision is Decision.ALLOW


def test_reply_to_requester_needs_no_topology_but_keeps_confidentiality() -> None:
    def m(raw):
        raw["clusters"]["docs"]["policy"]["contact_book"]["peers"]["on_miss"] = "REVIEW"
    spec = banking_spec(m)
    eng, store = _engines(spec, "accounts", "hi")
    plain = evaluate_message(spec, eng, "accounts", "documents", "done", reply=True)
    assert plain.decision is Decision.ALLOW
    # ... but answering documents once does not make a NEW request to it known
    def m2(raw):
        raw["clusters"]["finance"]["policy"]["contact_book"]["peers"]["on_miss"] = "REVIEW"
    spec2 = banking_spec(m2)
    eng2, _ = _engines(spec2, "accounts", "hi")
    assert evaluate_message(spec2, eng2, "accounts", "documents", "x", reply=True).decision is Decision.ALLOW
    assert evaluate_message(spec2, eng2, "accounts", "documents", "x").decision is Decision.REVIEW
    store.admit("balance 9876.54", "get_balance", trusted=False, level=Level.HIGH,
                branch_origin=None, extract_cfg=ExtractConfig())
    secret = evaluate_message(spec, eng, "accounts", "documents", "balance 9876.54", reply=True)
    assert secret.decision is Decision.REVIEW and "no clearance" in secret.reason


def test_cluster_rule_over_messages() -> None:
    def m(raw):
        raw["clusters"]["front"]["policy"]["rules"] = [
            {"id": "no-docs", "match": {"action": "a2a.send", "params": {"to_cluster": {"equals": "docs"}}},
             "decision": "DENY"}]
    spec = banking_spec(m)
    eng, _ = _engines(spec, "assistant", "x")
    r = evaluate_message(spec, eng, "assistant", "documents", "read it")
    assert r.decision is Decision.DENY and r.produced_by == "rule:no-docs"
    assert evaluate_message(spec, eng, "assistant", "payments", "hi").decision is Decision.ALLOW


def test_intra_cluster_annotation() -> None:
    spec = banking_spec()
    eng, store = _engines(spec, "accounts", "hi")
    store.admit("balance 4321.09", "get_balance", trusted=False, level=Level.HIGH,
                branch_origin=None, extract_cfg=ExtractConfig())
    ann = annotate_intra_cluster(spec, eng, "accounts", "payments", f"send 4321.09 to {ATTACKER_IBAN}")
    assert ATTACKER_IBAN in ann["identifiers"] and ann["sensitivity"] == "HIGH"
    assert annotate_intra_cluster(spec, eng, "accounts", "payments", "all good") == {}
