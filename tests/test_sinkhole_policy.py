# tests/test_sinkhole_policy.py — deploy/net/sinkhole_policy.py (strict network boundary)
#
# The policy behind the DNS sinkhole: which upstream the proxy may connect to for a
# connection the guest addressed by name (SNI / Host) or by address. Pure Python, no
# mitmproxy needed.
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "deploy", "net"))
from sinkhole_policy import (  # noqa: E402
    DEAD, CachedResolver, Refusal, Upstream, check_address, decide_upstream,
    is_global_ip, is_sinkhole, parse_authority,
)

GW = "192.168.100.1"
PINNED = {"hooks.attacker.external", "status.internal.local"}
PORTS = {80, 443}


def resolver_of(table):
    def _r(name, port):
        if name not in table:
            raise OSError("NXDOMAIN")
        return table[name]
    return _r


def decide(name, port, table=None):
    return decide_upstream(name, port, pinned=PINNED, target=GW, pinned_ports=PORTS,
                           resolver=resolver_of(table or {}))


# ---- addresses -----------------------------------------------------------------

def test_is_sinkhole():
    assert is_sinkhole((GW, 443), GW)
    assert not is_sinkhole(("93.184.216.34", 443), GW)
    assert not is_sinkhole(None, GW)


@pytest.mark.parametrize("ip,ok", [
    ("93.184.216.34", True), ("8.8.8.8", True),
    ("127.0.0.1", False), ("10.0.0.5", False), ("192.168.100.1", False),
    ("169.254.169.254", False), ("0.0.0.0", False), ("224.0.0.1", False),
    ("::1", False), ("2606:2800:220:1:248:1893:25c8:1946", True), ("not-an-ip", False),
])
def test_is_global_ip(ip, ok):
    assert is_global_ip(ip) is ok


# ---- Host header parsing -------------------------------------------------------

@pytest.mark.parametrize("auth,default,expect", [
    ("example.com", 80, ("example.com", 80)),
    ("Example.COM.", 443, ("example.com", 443)),
    ("example.com:8443", 443, ("example.com", 8443)),
    ("1.2.3.4:80", 443, ("1.2.3.4", 80)),
    ("[::1]:80", 443, ("::1", 80)),
    ("[::1]", 443, ("::1", 443)),
    ("", 80, None), ("   ", 80, None),
    ("example.com:abc", 80, None), ("example.com:70000", 80, None), ("[::1", 80, None),
])
def test_parse_authority(auth, default, expect):
    assert parse_authority(auth, default) == expect


# ---- decide_upstream: by name --------------------------------------------------

def test_pinned_name_goes_to_target_on_permitted_port():
    d = decide("hooks.attacker.external", 80)
    assert d == Upstream(GW, 80, "pinned")


def test_pinned_name_refused_on_other_port():
    d = decide("hooks.attacker.external", 8090)      # the control plane port
    assert isinstance(d, Refusal) and "8090" in d.reason


def test_resolved_name_uses_first_global_address():
    d = decide("example.com", 443, {"example.com": ["93.184.216.34", "93.184.216.35"]})
    assert d == Upstream("93.184.216.34", 443, "resolved")


def test_rebinding_name_refused_if_any_address_is_local():
    d = decide("evil.example", 443, {"evil.example": ["93.184.216.34", "127.0.0.1"]})
    assert isinstance(d, Refusal) and "127.0.0.1" in d.reason


def test_name_resolving_to_bridge_subnet_refused():
    d = decide("lan.example", 80, {"lan.example": ["192.168.100.1"]})
    assert isinstance(d, Refusal)


def test_unresolvable_name_refused():
    d = decide("nope.invalid", 443)
    assert isinstance(d, Refusal) and "cannot resolve" in d.reason


def test_empty_answer_refused():
    d = decide("empty.example", 443, {"empty.example": []})
    assert isinstance(d, Refusal)


def test_missing_name_refused():
    assert isinstance(decide("", 443), Refusal)
    assert isinstance(decide(None, 443), Refusal)


def test_global_literal_allowed_local_literal_refused():
    assert decide("93.184.216.34", 80) == Upstream("93.184.216.34", 80, "literal")
    assert isinstance(decide("127.0.0.1", 8090), Refusal)
    assert isinstance(decide("192.168.100.1", 8090), Refusal)


def test_resolver_is_never_asked_for_pinned_or_literal():
    calls = []
    def spy(name, port):
        calls.append(name); return ["93.184.216.34"]
    decide_upstream("hooks.attacker.external", 80, pinned=PINNED, target=GW, pinned_ports=PORTS, resolver=spy)
    decide_upstream("8.8.8.8", 80, pinned=PINNED, target=GW, pinned_ports=PORTS, resolver=spy)
    assert calls == []


# ---- check_address: by address -------------------------------------------------

def test_check_address():
    assert check_address(GW, 80, target=GW, pinned_ports=PORTS) == Upstream(GW, 80, "pinned")
    assert isinstance(check_address(GW, 8090, target=GW, pinned_ports=PORTS), Refusal)
    assert check_address("8.8.8.8", 443, target=GW, pinned_ports=PORTS) == Upstream("8.8.8.8", 443, "literal")
    assert isinstance(check_address(*DEAD, target=GW, pinned_ports=PORTS), Refusal)
    assert isinstance(check_address("10.1.2.3", 22, target=GW, pinned_ports=PORTS), Refusal)


# ---- resolver cache ------------------------------------------------------------

def test_cached_resolver_ttl():
    calls = []
    now = [0.0]
    def r(name, port):
        calls.append(name); return ["93.184.216.34"]
    c = CachedResolver(r, ttl_s=10.0, clock=lambda: now[0])
    assert c("a.example", 443) == ["93.184.216.34"]
    assert c("a.example", 443) == ["93.184.216.34"]
    assert calls == ["a.example"]
    now[0] = 11.0
    c("a.example", 443)
    assert calls == ["a.example", "a.example"]
