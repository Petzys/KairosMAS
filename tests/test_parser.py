# tests/test_parser.py
"""Phase 1: policy parser — grammar coverage, coercion, strictness, references."""
import textwrap

import pytest
import yaml

from kairos.core.extract import STRUCTURED_PATTERNS, ExtractMode
from kairos.core.matching import Strategy
from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.policy.parser import PolicyError, load_policy, parse_policy
from kairos.policy.schema import SequenceRule, SimpleRule


def _parse(*parts: str):
    # Dedent each part independently: MINIMAL and the appended fragments are
    # indented differently in-source, so a single dedent of the concatenation
    # would misalign them. Per-part dedent lands every top-level key at col 0.
    src = "".join(textwrap.dedent(p) for p in parts)
    return parse_policy(yaml.safe_load(src))


MINIMAL = """
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: [read_file, get_balance]
        non_revertable: [send_money]
"""


# --- canonical example ------------------------------------------------------
def test_banking_demo_loads(banking_policy_path) -> None:
    p = load_policy(banking_policy_path)
    assert p.context.name == "banking-demo"
    assert "send_money" in p.context.non_revertable
    assert {ts.source for ts in p.resources.trusted_sources} >= {"read_file", "get_balance"}
    assert any(isinstance(r, SimpleRule) for r in p.rules)
    assert any(isinstance(r, SequenceRule) for r in p.rules)


# --- version + coercion -----------------------------------------------------
def test_version_float_coerces() -> None:
    p = parse_policy({"version": 0.1, "context": yaml.safe_load(textwrap.dedent(MINIMAL))["context"]})
    assert p.version == "0.1"


def test_bad_version_rejected() -> None:
    with pytest.raises(PolicyError, match="version"):
        _parse(MINIMAL.replace('"0.1"', '"0.2"'))


def test_decision_and_level_coercion() -> None:
    p = _parse(MINIMAL,"""
        resources:
          contact_book:
            lookup_fields: [recipient]
            on_miss: review
            entries:
              - match: "DE89"
                max_level: HIGH
    """)
    assert p.resources.contact_book.on_miss is Decision.REVIEW
    assert p.resources.contact_book.entries[0].max_level is Level.HIGH


# --- strictness -------------------------------------------------------------
def test_unknown_key_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown key"):
        _parse(MINIMAL.replace("default_action: REVIEW", "defualt_action: REVIEW\n      default_action: REVIEW"))


def test_missing_required_rejected() -> None:
    with pytest.raises(PolicyError, match="missing required 'name'"):
        _parse("""
            version: "0.1"
            context:
              default_action: ALLOW
              actions: {revertable: [], non_revertable: []}
        """)


# --- durations --------------------------------------------------------------
@pytest.mark.parametrize("text,seconds", [("session", None), ("30s", 30), ("5m", 300), ("2h", 7200)])
def test_duration_parsing(text, seconds) -> None:
    p = _parse(MINIMAL,f"""
        resources:
          rate_limits:
            - id: r
              actions: [send_money]
              group_by: recipient
              max_count: 3
              window: {text}
              on_exceed: REVIEW
    """)
    assert p.resources.rate_limits[0].window.seconds == seconds


def test_bad_duration_rejected() -> None:
    with pytest.raises(PolicyError, match="invalid duration"):
        _parse(MINIMAL,"""
            resources:
              rate_limits:
                - {id: r, actions: [send_money], group_by: x, max_count: 1, window: 5d, on_exceed: DENY}
        """)


# --- trusted_sources: both forms + the strategy gap fix ---------------------
def test_trusted_sources_bare_and_enriched() -> None:
    p = _parse(MINIMAL,"""
        resources:
          trusted_sources:
            - read_file
            - source: get_balance
              scan_strategy: normalized
              extract:
                mode: specific_fields
                fields: [balance]
    """)
    by = {ts.source: ts for ts in p.resources.trusted_sources}
    assert by["read_file"].scan_strategy is None        # bare -> defaults
    assert by["get_balance"].scan_strategy is Strategy.NORMALIZED
    assert by["get_balance"].extract.mode is ExtractMode.SPECIFIC_FIELDS


# --- keep: -> preserve_patterns --------------------------------------------
def test_keep_maps_to_preserve_patterns() -> None:
    p = _parse(MINIMAL,"""
        resources:
          taints:
            - name: tx
              source: read_file
              level: high
              extract:
                mode: all_tokens
                keep: [iban, filename]
    """)
    pats = p.resources.taints[0].extract.preserve_patterns
    assert STRUCTURED_PATTERNS["iban"] in pats and STRUCTURED_PATTERNS["filename"] in pats


def test_unknown_keep_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown pattern 'creditcard'"):
        _parse(MINIMAL,"""
            resources:
              taints:
                - {name: t, source: read_file, level: low, extract: {keep: [creditcard]}}
        """)


# --- taints: §4.4 nameless form defaults name to source ---------------------
def test_taint_name_defaults_to_source() -> None:
    p = _parse(MINIMAL,"""
        resources:
          taints:
            - source: get_balance
              level: high
    """.replace("get_balance", "read_file"))   # keep it declared
    assert p.resources.taints[0].name == "read_file"


# --- rules ------------------------------------------------------------------
def test_simple_rule_origin_and_sequence_constraint() -> None:
    p = _parse(MINIMAL,"""
        resources:
          contact_book:
            lookup_fields: [recipient]
            on_miss: REVIEW
            entries: [{match: "DE89", max_level: high}]
        rules:
          - id: named
            match:
              action: send_money
              origin: {param_in_user_prompt: {key: recipient, required: true}}
            decision: ALLOW
          - id: exfil
            sequence:
              - action: read_file
              - action: send_money
                params: {recipient: {not_in: contacts.recipient}}
            window: session
            decision: REVIEW
    """)
    simple = next(r for r in p.rules if isinstance(r, SimpleRule))
    assert simple.match.origin.param_in_user_prompt_key == "recipient"
    seq = next(r for r in p.rules if isinstance(r, SequenceRule))
    assert seq.sequence[1].params["recipient"].op == "not_in"
    assert seq.sequence[1].params["recipient"].value == "contacts.recipient"


def test_rule_with_both_match_and_sequence_rejected() -> None:
    with pytest.raises(PolicyError, match="either 'match' or 'sequence'"):
        _parse(MINIMAL,"""
            rules:
              - {id: bad, match: {action: send_money}, sequence: [{action: read_file}], window: session, decision: DENY}
        """)


def test_bad_constraint_op_rejected() -> None:
    with pytest.raises(PolicyError, match="unknown constraint op 'startswith'"):
        _parse(MINIMAL,"""
            rules:
              - {id: r, match: {action: send_money, params: {recipient: {startswith: "DE"}}}, decision: DENY}
        """)


# --- reference validation ---------------------------------------------------
def test_undeclared_action_rejected() -> None:
    with pytest.raises(PolicyError, match="undeclared action"):
        _parse(MINIMAL,"""
            resources:
              trusted_sources: [wire_transfer]
        """)   # wire_transfer not in context.actions