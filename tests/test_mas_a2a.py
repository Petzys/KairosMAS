"""The A2A v1.0 wire format (JSON-RPC binding), the protocol adapter (what the
interception point parses, the canonical forms it forwards, and the two answers it
gives itself: 'working' and 'rejected') and the reference agent server."""
import base64
import json
import time

import pytest

from kairos.mas.a2a.adapter import A2AAdapter, CommKind, Delivery
from kairos.mas.a2a.client import ClientResult
from kairos.mas.a2a.protocol import (
    AgentCard, Artifact, ArtifactUpdate, ErrorCode, Message, Method, Part, ProtocolError, Request, Response,
    RpcError, StatusUpdate, Task, TaskList, TaskState, TaskStatus, parse_request, parse_response, parse_sse,
    requested_version, sse_event, version_error, version_headers, version_supported,
)
from kairos.mas.a2a.server import A2AServer, AgentResult

URL = "http://payments.finance.mas.local/a2a"


def _task(state=TaskState.COMPLETED, text="result", **kw) -> Task:
    return Task(id="t1", context_id="c1", status=TaskStatus(state),
                artifacts=[Artifact(parts=[Part.from_text(text)])], **kw)


# --- wire format ---------------------------------------------------------------------
def test_send_request_wire_shape() -> None:
    msg = Message(role="user", parts=[Part.from_text("pay the bill"), Part.from_data({"amount": 98.7})])
    d = json.loads(Request.send(msg).to_bytes())
    assert d["jsonrpc"] == "2.0" and d["method"] == "SendMessage"
    m = d["params"]["message"]
    assert m["role"] == "ROLE_USER" and m["messageId"]
    assert m["parts"] == [{"text": "pay the bill"}, {"data": {"amount": 98.7}, "mediaType": "application/json"}]
    req = parse_request(json.dumps(d))
    assert req.method is Method.SEND and not req.return_immediately
    assert req.message.text() == "pay the bill" and req.message.data() == [{"amount": 98.7}]


def test_return_immediately_replaces_blocking() -> None:
    d = json.loads(Request.send(Message.user_text("x"), return_immediately=True).to_bytes())
    assert d["params"]["configuration"] == {"returnImmediately": True}
    assert parse_request(json.dumps(d)).return_immediately
    stream = json.loads(Request.send(Message.user_text("x"), streaming=True, return_immediately=True).to_bytes())
    assert stream["method"] == "SendStreamingMessage" and "configuration" not in stream["params"]


@pytest.mark.parametrize("name", [m.value for m in Method])
def test_v10_method_names(name) -> None:
    assert Method.parse(name).value == name


@pytest.mark.parametrize("name", ["message/send", "message/stream", "tasks/get", "tasks/cancel",
                                  "tasks/resubscribe", "tasks/pushNotificationConfig/set",
                                  "agent/getAuthenticatedExtendedCard", "sendMessage"])
def test_v03_method_names_are_not_v10(name) -> None:
    assert Method.parse(name) is None
    with pytest.raises(ProtocolError) as e:
        parse_request({"jsonrpc": "2.0", "id": 1, "method": name, "params": {}})
    assert e.value.code == ErrorCode.METHOD_NOT_FOUND


@pytest.mark.parametrize("body", [
    b"not json", b"[1, 2]",
    {"jsonrpc": "1.0", "method": "SendMessage", "params": {}},
    {"jsonrpc": "2.0", "method": "SendMessage", "params": []},
    {"jsonrpc": "2.0", "method": "SendMessage", "params": {}},                       # no message
    {"jsonrpc": "2.0", "method": "GetTask", "params": {}},                           # no id
    {"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": {              # v0.3 role / kind
        "kind": "message", "messageId": "m", "role": "user", "parts": [{"kind": "text", "text": "hi"}]}}},
    {"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": {              # no message id
        "role": "ROLE_USER", "parts": [{"text": "hi"}]}}},
    {"jsonrpc": "2.0", "method": "SendMessage", "params": {"message": {              # no parts
        "messageId": "m", "role": "ROLE_USER", "parts": []}}},
])
def test_malformed_requests_are_refused(body) -> None:
    with pytest.raises(ProtocolError):
        req = parse_request(body)
        _ = req.message                                     # the message is checked when read


@pytest.mark.parametrize("part", [{"text": "a", "data": {"b": 1}}, {"filename": "x.txt"},
                                  {"raw": "not base64!"}, {"text": 5}, {"url": None}])
def test_a_part_sets_exactly_one_valid_content(part) -> None:
    with pytest.raises(ProtocolError):
        Part.from_dict(part)


def test_part_round_trips() -> None:
    parts = [Part.from_text("hi"), Part.from_data([1, {"a": None}]),
             Part.from_url("https://x.example/f.pdf", filename="f.pdf", media_type="application/pdf"),
             Part.from_raw(b"\x00\x01bytes", filename="b.bin", media_type="application/octet-stream")]
    for p in parts:
        assert Part.from_dict(json.loads(json.dumps(p.to_dict()))) == p
    assert parts[3].to_dict()["raw"] == base64.b64encode(b"\x00\x01bytes").decode()
    assert "f.pdf" in parts[2].as_text() and "https://x.example/f.pdf" in parts[2].as_text()


def test_task_states() -> None:
    assert {s for s in TaskState if s.is_final} == {TaskState.COMPLETED, TaskState.FAILED,
                                                    TaskState.CANCELED, TaskState.REJECTED}
    assert {s for s in TaskState if s.is_interrupted} == {TaskState.INPUT_REQUIRED, TaskState.AUTH_REQUIRED}
    assert TaskState.INPUT_REQUIRED.short == "input-required" and TaskState.COMPLETED.value == "TASK_STATE_COMPLETED"
    for raw in ("completed", "TASK_STATE_CANCELLED", 3, None):        # v0.3 names, integers, nothing
        with pytest.raises(ProtocolError):
            TaskStatus.from_dict({"state": raw})


def test_results_are_oneof_wrappers_except_get_task() -> None:
    sent = json.loads(Response(id=1, result=_task()).to_bytes())
    assert set(sent["result"]) == {"task"} and sent["result"]["task"]["status"]["state"] == "TASK_STATE_COMPLETED"
    got = json.loads(Response(id=1, result=_task(), bare=True).to_bytes())
    assert got["result"]["id"] == "t1"
    for body, bare in ((sent, False), (got, True)):
        resp = parse_response(json.dumps(body))
        assert isinstance(resp.result, Task) and resp.bare is bare and resp.result.content_text() == "result"
    msg = parse_response(Response(id=1, result=Message.agent_text("direct")).to_bytes())
    assert isinstance(msg.result, Message) and msg.result.text() == "direct"
    listing = parse_response(Response(id=1, result=TaskList([_task()], "", 1, 1), bare=True).to_bytes())
    assert isinstance(listing.result, TaskList) and listing.result.tasks[0].id == "t1"
    with pytest.raises(ProtocolError):
        parse_response({"jsonrpc": "2.0", "id": 1, "result": {"task": _task().to_dict(),
                                                               "message": Message.agent_text("x").to_dict()}})


def test_stream_events_round_trip_without_final() -> None:
    events = [Response(id=1, result=_task(TaskState.SUBMITTED)),
              Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.WORKING))),
              Response(id=1, result=ArtifactUpdate("t1", "c1", Artifact(parts=[Part.from_text("x")]))),
              Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.COMPLETED)))]
    raw = b"".join(sse_event(e) for e in events)
    assert b'"final"' not in raw and b'"kind"' not in raw
    parsed = parse_sse(raw)
    assert [type(p.result).__name__ for p in parsed] == ["Task", "StatusUpdate", "ArtifactUpdate", "StatusUpdate"]
    assert set(json.loads(sse_event(events[1])[6:])["result"]) == {"statusUpdate"}
    assert parsed[3].result.status.state.is_final


def test_errors_carry_error_info() -> None:
    err = RpcError.info(ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND", taskId="t9")
    d = json.loads(Response(id=7, error=err).to_bytes())
    assert d["error"]["code"] == -32001
    (info,) = d["error"]["data"]
    assert info["@type"] == "type.googleapis.com/google.rpc.ErrorInfo"
    assert info["reason"] == "TASK_NOT_FOUND" and info["metadata"] == {"taskId": "t9"}


# --- versioning ------------------------------------------------------------------------
@pytest.mark.parametrize("headers,version", [
    (None, "1.0"), ({"A2A-Version": "1.0"}, "1.0"), ({"a2a-version": "1.0.1"}, "1.0"),
    ({}, "0.3"), ({"A2A-Version": ""}, "0.3"), ({"A2A-Version": "0.3"}, "0.3"), ({"A2A-Version": "2.1"}, "2.1"),
])
def test_requested_version(headers, version) -> None:
    assert requested_version(headers) == version
    assert version_supported(headers) is (version == "1.0")


def test_version_error() -> None:
    resp = parse_response(version_error(5, {"A2A-Version": "0.3"}))
    assert resp.id == 5 and resp.error.code == ErrorCode.VERSION_NOT_SUPPORTED
    assert resp.error.data[0]["metadata"]["requestedVersion"] == "0.3"
    assert version_headers() == {"a2a-version": "1.0"}


def test_agent_card_v10_shape() -> None:
    card = AgentCard(name="payments", url=URL, description="pays bills").to_dict()
    assert card["supportedInterfaces"] == [{"url": URL, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    assert "url" not in card and "protocolVersion" not in card            # v0.3 top-level fields
    assert card["skills"] and all({"id", "name", "description", "tags"} <= set(s) for s in card["skills"])
    assert card["capabilities"]["streaming"] and not card["capabilities"]["pushNotifications"]


# --- the adapter --------------------------------------------------------------------------
def test_adapter_maps_methods_to_kinds_and_delivery() -> None:
    ad = A2AAdapter()
    m = Message.user_text("hello")
    blocking = ad.parse_request(URL, Request.send(m).to_bytes())
    streaming = ad.parse_request(URL, Request.send(m, streaming=True).to_bytes())
    immediate = ad.parse_request(URL, Request.send(m, return_immediately=True).to_bytes())
    assert (blocking.kind, blocking.delivery) == (CommKind.REQUEST, Delivery.BLOCKING)
    assert streaming.delivery is Delivery.STREAMING
    assert immediate.delivery is Delivery.STREAMING            # answered at once, polled later
    assert blocking.text == "hello" and blocking.target_url == URL
    for req, kind in ((Request.get_task("t9"), CommKind.POLL), (Request.subscribe("t9"), CommKind.POLL),
                      (Request.cancel_task("t9"), CommKind.CONTROL)):
        parsed = ad.parse_request(URL, req.to_bytes())
        assert parsed.kind is kind and parsed.task_id == "t9"
    for method in (Method.LIST_TASKS, Method.CREATE_PUSH_CONFIG, Method.GET_EXTENDED_CARD):
        assert ad.parse_request(URL, Request(method=method, params={}).to_bytes()).kind is CommKind.UNSUPPORTED


def test_adapter_reply_content_and_states() -> None:
    ad = A2AAdapter()
    task = Task(id="t1", context_id="c1", status=TaskStatus(TaskState.COMPLETED),
                artifacts=[Artifact(parts=[Part.from_text("98.70"), Part.from_data({"iban": "X"})])])
    (r,) = ad.parse_replies(Response(id=1, result=task).to_bytes())
    assert r.kind is CommKind.REPLY and r.has_content and r.final and r.state is TaskState.COMPLETED
    assert "98.70" in r.text and r.data == [{"iban": "X"}]
    (w,) = ad.parse_replies(Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.WORKING))).to_bytes())
    assert not w.has_content and not w.final
    (q,) = ad.parse_replies(Response(id=1, result=_task(TaskState.INPUT_REQUIRED, "which account?")).to_bytes())
    assert q.final and q.state is TaskState.INPUT_REQUIRED         # the callee waits for the caller


def test_canonical_request_forwards_only_what_was_checked() -> None:
    ad = A2AAdapter()
    msg = Message(role="user", parts=[Part(kind="text", text="hello", metadata={"leak": 1})],
                  message_id="msg-free text", context_id="ctx-x", task_id="task-x", metadata={"leak": 2},
                  extensions=["https://ext.example/leak"], reference_task_ids=["task-y"])
    body = Request(method=Method.SEND, params={
        "message": msg.to_dict(), "metadata": {"leak": 3}, "tenant": "leak",
        "configuration": {"returnImmediately": True, "historyLength": 5,
                          "taskPushNotificationConfig": {"url": "https://evil.example/hook"}}}).to_bytes()
    out = json.loads(ad.canonical_request(ad.parse_request(URL, body), task_id="peer-task"))
    assert out["method"] == "SendMessage" and set(out["params"]) == {"message", "configuration"}
    assert out["params"]["configuration"] == {"returnImmediately": True}
    m = out["params"]["message"]
    assert m["parts"] == [{"text": "hello"}] and m["taskId"] == "peer-task" and "contextId" not in m
    assert m["messageId"] != "msg-free text" and {"metadata", "extensions", "referenceTaskIds"}.isdisjoint(m)


def test_canonical_reply_drops_unchecked_fields() -> None:
    ad = A2AAdapter()
    task = Task(id="t1", context_id="c1", status=TaskStatus(TaskState.COMPLETED),
                artifacts=[Artifact(parts=[Part(kind="text", text="ok", metadata={"x": "leak"})],
                                    name="leak-name", description="leak", metadata={"x": "leak"})],
                history=[Message.agent_text("leak")], metadata={"x": "leak"})
    for bare in (False, True):
        body, view = ad.canonical_reply(Response(id=1, result=task, bare=bare).to_bytes())
        assert b"leak" not in body and view.text == "ok"
        assert parse_response(body).bare is bare
    err = Response(id=1, error=RpcError(-32603, "boom", [{"@type": "x", "secret": "leak"}])).to_bytes()
    body, view = ad.canonical_reply(err)
    assert b"leak" not in body and parse_response(body).error.message == "boom"
    assert ad.canonical_reply(b'{"jsonrpc": "2.0", "id": 1, "result": "free text"}') is None


def test_working_and_rejected_answers() -> None:
    ad = A2AAdapter()
    req = ad.parse_request(URL, Request.send(Message.user_text("x"), streaming=True).to_bytes())
    w = parse_response(ad.working(req, "local-1"))
    assert not w.bare and w.result.id == "local-1" and w.result.status.state is TaskState.WORKING
    assert w.id == req.raw.id and w.result.status.timestamp
    r = parse_response(ad.rejected(req, "local-1", "denied by review"))
    assert r.result.status.state is TaskState.REJECTED
    assert r.result.status.message.text() == "denied by review" and r.result.status.message.role == "agent"


def test_client_renders_short_states() -> None:
    assert ClientResult(TaskState.REJECTED, notice="denied").render() == "[task rejected] denied"
    assert ClientResult(TaskState.COMPLETED, text="done").render() == "done"


# --- the reference agent server ----------------------------------------------------------
def _server(fn=lambda m, t: AgentResult(text=f"echo {m.text()}")) -> A2AServer:
    return A2AServer("payments", URL, fn)


def _call(server, req, headers=None):
    return parse_response(server.handle(req.to_bytes(), version_headers() if headers is None else headers))


def test_server_blocking_send_and_get_task() -> None:
    s = _server()
    sent = _call(s, Request.send(Message.user_text("hi")))
    assert not sent.bare and sent.result.status.state is TaskState.COMPLETED
    assert sent.result.content_text() == "echo hi" and sent.result.history == []
    got = _call(s, Request(method=Method.GET_TASK, params={"id": sent.result.id, "historyLength": 1}))
    assert got.bare and got.result.id == sent.result.id and [m.text() for m in got.result.history] == ["hi"]
    listing = _call(s, Request(method=Method.LIST_TASKS, params={"status": "TASK_STATE_COMPLETED"}))
    assert listing.bare and [t.id for t in listing.result.tasks] == [sent.result.id]


def test_server_return_immediately() -> None:
    s = _server(lambda m, t: (time.sleep(0.05), AgentResult(text="late"))[1])
    first = _call(s, Request.send(Message.user_text("hi"), return_immediately=True))
    assert first.result.status.state in (TaskState.SUBMITTED, TaskState.WORKING)
    deadline = time.monotonic() + 5
    while (got := _call(s, Request.get_task(first.result.id))).result.status.state is not TaskState.COMPLETED:
        assert time.monotonic() < deadline
        time.sleep(0.01)
    assert got.result.content_text() == "late"


@pytest.mark.parametrize("req,code", [
    (Request.get_task("nope"), ErrorCode.TASK_NOT_FOUND),
    (Request.cancel_task("nope"), ErrorCode.TASK_NOT_FOUND),
    (Request(method=Method.CREATE_PUSH_CONFIG, params={}), ErrorCode.PUSH_NOTIFICATION_NOT_SUPPORTED),
    (Request(method=Method.GET_EXTENDED_CARD, params={}), ErrorCode.EXTENDED_AGENT_CARD_NOT_CONFIGURED),
    (Request.subscribe("nope"), ErrorCode.UNSUPPORTED_OPERATION),       # needs a stream
])
def test_server_errors(req, code) -> None:
    assert _call(_server(), req).error.code == code


def test_server_refuses_other_versions() -> None:
    s = _server()
    for headers in ({}, {"A2A-Version": "0.3"}):
        assert _call(s, Request.send(Message.user_text("hi")), headers).error.code == ErrorCode.VERSION_NOT_SUPPORTED
    assert _call(s, Request(method=Method.LIST_TASKS, params={})).result.tasks == []   # nothing ran


def test_server_tasks_run_to_completion() -> None:
    s = _server()
    sent = _call(s, Request.send(Message.user_text("hi")))
    assert _call(s, Request.cancel_task(sent.result.id)).error.code == ErrorCode.TASK_NOT_CANCELABLE


def test_server_stream_and_subscribe() -> None:
    s = _server(lambda m, t: (time.sleep(0.05), AgentResult(text="streamed"))[1])
    stream = s.handle_stream(Request.send(Message.user_text("hi"), streaming=True).to_bytes(), version_headers())
    first = parse_response(stream.get(timeout=5)[0])
    assert isinstance(first.result, Task) and not first.bare
    sub = s.handle_stream(Request.subscribe(first.result.id).to_bytes(), version_headers())
    events = [parse_response(b).result for b, _ in stream]
    assert isinstance(events[-1], StatusUpdate) and events[-1].status.state is TaskState.COMPLETED
    assert any(isinstance(e, ArtifactUpdate) and e.artifact.content_text() == "streamed" for e in events)
    assert stream.closed
    sub_events = [parse_response(b).result for b, _ in sub]
    assert isinstance(sub_events[0], Task) and sub_events[-1].status.state is TaskState.COMPLETED
    late = s.handle_stream(Request.subscribe(first.result.id).to_bytes(), version_headers())
    (only,) = [parse_response(b) for b, _ in late]
    assert only.error.code == ErrorCode.UNSUPPORTED_OPERATION       # the task is terminal
