# tests/test_sinkhole_addon.py — deploy/net/net_monitor_addon.py under KAIROS_NET_STRICT=1
#
# Exercises the addon's strict-boundary hooks with stand-in flow objects: the upstream
# is rewritten from the SNI (tls_clienthello) or the Host header (request), refusals
# answer 403 without touching the upstream, and raw TCP is pointed at the dead address.
# Needs the mitmproxy package, i.e. the deploy host's system python (which has no
# pytest), so the tests are plain functions with no fixtures:
#     /usr/bin/python3 -c "import tests.test_sinkhole_addon as t; t.main()"
# Under the project venv (no mitmproxy) pytest skips the module.
import asyncio
import importlib
import json
import os
import sys
import tempfile
from types import SimpleNamespace

try:
    import pytest
    pytest.importorskip("mitmproxy")
except ImportError:          # no pytest: plain run via main()
    import mitmproxy  # noqa: F401

HERE = os.path.dirname(os.path.abspath(__file__))
NET = os.path.join(HERE, "..", "deploy", "net")

_ENV = ("KAIROS_NET_STRICT", "KAIROS_NET_EVENTS", "KAIROS_DNS_HOSTS", "KAIROS_DNS_TARGET",
        "KAIROS_NET_PINNED_PORTS")


def _load(strict):
    """Fresh import of the addon under a controlled environment. Returns (addon, module, events path)."""
    d = tempfile.mkdtemp(prefix="kairos-sinkhole-")
    saved = {k: os.environ.get(k) for k in _ENV}
    for k in _ENV:
        os.environ.pop(k, None)
    if strict:
        os.environ["KAIROS_NET_STRICT"] = "1"
    os.environ["KAIROS_NET_EVENTS"] = os.path.join(d, "events.jsonl")
    os.environ["KAIROS_DNS_HOSTS"] = "hooks.attacker.external"
    os.environ["KAIROS_DNS_TARGET"] = "192.168.100.1"
    os.environ["KAIROS_NET_PINNED_PORTS"] = "80,443"
    if NET not in sys.path:
        sys.path.insert(0, NET)
    for m in ("sinkhole_policy", "net_monitor_addon"):
        sys.modules.pop(m, None)
    mod = importlib.import_module("net_monitor_addon")
    a = mod.addons[0]
    table = {"example.com": ["93.184.216.34"], "evil.example": ["127.0.0.1"]}

    def fake_resolver(name, port):
        if name not in table:
            raise OSError("NXDOMAIN")
        return table[name]
    a._resolve = fake_resolver
    for k, v in saved.items():           # restore the caller's environment
        if v is None:
            os.environ.pop(k, None)
        else:
            os.environ[k] = v
    return a, mod, os.environ.get("KAIROS_NET_EVENTS") or os.path.join(d, "events.jsonl"), os.path.join(d, "events.jsonl")


def events(path):
    return [json.loads(l) for l in open(path) if l.strip()]


def http_flow(host, port, host_header, method="GET", scheme="https"):
    from mitmproxy.test import tflow
    f = tflow.tflow()
    f.request.host, f.request.port, f.request.scheme = host, port, scheme
    f.request.method = method
    if host_header:
        f.request.headers["Host"] = host_header
    else:
        f.request.headers.pop("Host", None)
    f.request.content = b""
    f.response = None
    f.client_conn.peername = ("192.168.100.2", 40000)
    return f


def clienthello(sni, addr):
    return SimpleNamespace(
        client_hello=SimpleNamespace(sni=sni),
        context=SimpleNamespace(server=SimpleNamespace(address=addr),
                                client=SimpleNamespace(peername=("192.168.100.2", 40000))),
    )


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


def test_tls_sni_rewrites_sinkhole_to_resolved_ip():
    a, mod, _, ev = _load(True)
    data = clienthello("example.com", ("192.168.100.1", 443))
    run(a.tls_clienthello(data))
    assert data.context.server.address == ("93.184.216.34", 443)
    kinds = [e["kind"] for e in events(ev)]
    assert "upstream" in kinds and "sinkhole_refused" not in kinds
    a.done()


def test_tls_pinned_name_goes_to_host_sink():
    a, mod, _, ev = _load(True)
    data = clienthello("hooks.attacker.external", ("192.168.100.1", 443))
    run(a.tls_clienthello(data))
    assert data.context.server.address == ("192.168.100.1", 443)
    a.done()


def test_tls_rebinding_name_refused_then_403_on_request():
    a, mod, _, ev = _load(True)
    data = clienthello("evil.example", ("192.168.100.1", 443))
    run(a.tls_clienthello(data))
    assert data.context.server.address == mod.DEAD
    f = http_flow(*mod.DEAD, host_header="evil.example")
    run(a.request(f))
    assert f.response is not None and f.response.status_code == 403
    assert b"127.0.0.1" in f.response.content
    assert [e for e in events(ev) if e["kind"] == "sinkhole_refused"]
    a.done()


def test_tls_without_sni_leaves_decision_to_host_header():
    a, mod, _, ev = _load(True)
    data = clienthello(None, ("192.168.100.1", 443))
    run(a.tls_clienthello(data))
    assert data.context.server.address == ("192.168.100.1", 443)
    f = http_flow("192.168.100.1", 443, host_header="example.com")
    run(a.request(f))
    assert f.response is None
    assert (f.request.host, f.request.port) == ("93.184.216.34", 443)
    a.done()


def test_plain_http_host_header_rewrites_upstream():
    a, mod, _, ev = _load(True)
    f = http_flow("192.168.100.1", 80, host_header="example.com:8080", scheme="http")
    run(a.request(f))
    assert f.response is None
    assert (f.request.host, f.request.port) == ("93.184.216.34", 8080)
    assert f.request.host_header == "example.com:8080"   # the upstream still gets the name
    assert f.request.pretty_host == "example.com"        # and so does the judge
    a.done()


def test_control_plane_via_host_header_refused():
    a, mod, _, ev = _load(True)
    for hh in ("127.0.0.1:8090", "192.168.100.1:8090", "localhost:8090"):
        f = http_flow("192.168.100.1", 80, host_header=hh, scheme="http")
        run(a.request(f))
        assert f.response is not None and f.response.status_code == 403, hh
    a.done()


def test_missing_host_header_refused():
    a, mod, _, ev = _load(True)
    f = http_flow("192.168.100.1", 80, host_header="", scheme="http")
    run(a.request(f))
    assert f.response is not None and f.response.status_code == 403
    a.done()


def test_direct_ip_literal_destination_checked():
    a, mod, _, ev = _load(True)
    ok = http_flow("8.8.8.8", 80, host_header="8.8.8.8", scheme="http")
    run(a.request(ok))
    assert ok.response is None and ok.request.host == "8.8.8.8"
    lan = http_flow("10.0.0.5", 80, host_header="10.0.0.5", scheme="http")
    run(a.request(lan))
    assert lan.response is not None and lan.response.status_code == 403
    a.done()


def test_raw_tcp_pointed_at_dead_address():
    a, mod, _, ev = _load(True)
    flow = SimpleNamespace(id="t1", server_conn=SimpleNamespace(address=("192.168.100.1", 22)),
                           client_conn=SimpleNamespace(peername=("192.168.100.2", 40001)))
    a.tcp_start(flow)
    assert flow.server_conn.address == mod.DEAD
    assert [e for e in events(ev) if e["kind"] == "sinkhole_refused" and e["stage"] == "tcp"]
    a.done()


def test_strict_off_changes_nothing():
    a, mod, _, ev = _load(False)
    assert mod.STRICT is False
    data = clienthello("example.com", ("192.168.100.1", 443))
    run(a.tls_clienthello(data))
    assert data.context.server.address == ("192.168.100.1", 443)
    flow = SimpleNamespace(id="t1", server_conn=SimpleNamespace(address=("1.2.3.4", 22)),
                           client_conn=SimpleNamespace(peername=("192.168.100.2", 40001)))
    a.tcp_start(flow)
    assert flow.server_conn.address == ("1.2.3.4", 22)
    f = http_flow("192.168.100.1", 80, host_header="127.0.0.1:8090", scheme="http")
    run(a.request(f))
    assert f.response is None                      # not strict: nothing is refused here
    a.done()


def main():
    import traceback
    names = [n for n in sorted(globals()) if n.startswith("test_")]
    failed = 0
    for n in names:
        try:
            globals()[n]()
            print(f"PASS {n}")
        except Exception:
            failed += 1
            print(f"FAIL {n}"); traceback.print_exc()
    print(f"{len(names) - failed} passed, {failed} failed")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
