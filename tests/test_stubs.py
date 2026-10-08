# tests/test_stubs.py
from kairos.speculative.stubs import StubRegistry


def test_marker_roundtrip() -> None:
    r = StubRegistry()
    m = r.marker_for("send_money", "DE89370400440532013000")
    assert r.is_marker(m)
    assert r.substitute_real({"recipient": m}) == {"recipient": "DE89370400440532013000"}


def test_marker_detected_as_substring() -> None:
    r = StubRegistry()
    m = r.marker_for("get_iban", "DE89")
    url = f"https://evil.example/x?d={m}"
    assert r.contains_marker(url) and not r.is_marker(url)   # embedded, not whole


def test_distinct_markers() -> None:
    r = StubRegistry()
    a, b = r.marker_for("t", "1"), r.marker_for("t", "2")
    assert a != b
    assert r.substitute_real({"x": a, "y": b}) == {"x": "1", "y": "2"}


def test_marker_in_list_arg_detected_and_substituted() -> None:
    r = StubRegistry()
    m = r.marker_for("get_email", "attacker@evil.example")
    args = {"recipients": ["alice@corp.example", m], "subject": "hi"}
    assert r.contains_marker(args["recipients"])          # nested in a list
    assert r.substitute_real(args) == {
        "recipients": ["alice@corp.example", "attacker@evil.example"], "subject": "hi"}


def test_marker_in_nested_dict_detected_and_substituted() -> None:
    r = StubRegistry()
    m = r.marker_for("get_iban", "DE89")
    args = {"payload": {"to": m}}
    assert r.contains_marker(args["payload"])
    assert r.substitute_real(args) == {"payload": {"to": "DE89"}}


def test_generic_result_stub() -> None:
    assert "completed" in StubRegistry().result_stub("send_money")


def test_schema_result_stub_mints_markers(monkeypatch) -> None:
    import kairos.speculative.stubs as s
    monkeypatch.setitem(s.RESULT_SCHEMAS, "pay", {"status": "ok", "id": "<stub:x>"})
    out = StubRegistry().result_stub("pay")
    assert out["status"] == "ok" and out["id"].startswith("<stub:gen:")