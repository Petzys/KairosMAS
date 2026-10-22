"""The A2A wire format and the protocol adapter (what the interception point
parses, and the two answers it gives itself: 'working' and 'rejected')."""
import json

import pytest

from kairos.mas.a2a.adapter import A2AAdapter, CommKind, Delivery
from kairos.mas.a2a.protocol import (
    Artifact, ArtifactUpdate, Message, Method, Part, ProtocolError, Request, Response, StatusUpdate,
    Task, TaskState, TaskStatus, parse_request, parse_response, parse_sse, sse_event,
)

URL = "http://payments.finance.mas.local/a2a"


def test_send_request_round_trip() -> None:
    msg = Message(role="user", parts=[Part.from_text("pay the bill"), Part.from_data({"amount": 98.7})])
    body = Request.send(msg).to_bytes()
    d = json.loads(body)
    assert d["jsonrpc"] == "2.0" and d["method"] == "message/send"
    assert d["params"]["message"]["parts"][0] == {"kind": "text", "text": "pay the bill"}
    req = parse_request(body)
    assert req.method is Method.SEND
    assert req.message.text() == "pay the bill" and req.message.data() == [{"amount": 98.7}]


@pytest.mark.parametrize("name,method", [
    ("SendMessage", Method.SEND), ("SendStreamingMessage", Method.STREAM),
    ("message/stream", Method.STREAM), ("GetTask", Method.GET_TASK), ("tasks/get", Method.GET_TASK),
    ("tasks/resubscribe", Method.RESUBSCRIBE), ("CancelTask", Method.CANCEL_TASK),
])
def test_method_aliases_v03_and_v10(name, method) -> None:
    assert Method.parse(name) is method


def test_parse_rejects_non_a2a() -> None:
    with pytest.raises(ProtocolError):
        parse_request(b"not json")
    with pytest.raises(ProtocolError):
        parse_request({"jsonrpc": "2.0", "method": "eth_call", "params": {}})
    with pytest.raises(ProtocolError):
        parse_request({"jsonrpc": "1.0", "method": "message/send", "params": {}})


@pytest.mark.parametrize("raw,state", [
    ("completed", TaskState.COMPLETED), ("TASK_STATE_COMPLETED", TaskState.COMPLETED),
    ("input_required", TaskState.INPUT_REQUIRED), ("TASK_STATE_INPUT_REQUIRED", TaskState.INPUT_REQUIRED),
    ("cancelled", TaskState.CANCELED), ("bogus", TaskState.UNKNOWN), (None, TaskState.UNKNOWN),
])
def test_task_state_normalisation(raw, state) -> None:
    assert TaskState.parse(raw) is state


def test_parts_without_kind_discriminator_v10() -> None:
    m = Message.from_dict({"role": "ROLE_USER", "parts": [{"text": "hi"}, {"data": {"a": 1}}]})
    assert m.role == "user" and m.text() == "hi" and m.data() == [{"a": 1}]


def test_response_and_sse_round_trip() -> None:
    task = Task(id="t1", context_id="c1", status=TaskStatus(TaskState.COMPLETED),
                artifacts=[Artifact(parts=[Part.from_text("result")])])
    resp = parse_response(Response(id=1, result=task).to_bytes())
    assert isinstance(resp.result, Task) and resp.result.content_text() == "result"
    events = [Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.WORKING))),
              Response(id=1, result=ArtifactUpdate("t1", "c1", Artifact(parts=[Part.from_text("x")]))),
              Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.COMPLETED), final=True))]
    parsed = parse_sse(b"".join(sse_event(e) for e in events))
    assert [type(p.result).__name__ for p in parsed] == ["StatusUpdate", "ArtifactUpdate", "StatusUpdate"]
    assert parsed[2].result.final


def test_adapter_maps_send_methods_to_delivery() -> None:
    ad = A2AAdapter()
    m = Message.user_text("hello")
    blocking = ad.parse_request(URL, Request.send(m).to_bytes())
    streaming = ad.parse_request(URL, Request.send(m, streaming=True).to_bytes())
    nonblocking = ad.parse_request(URL, Request.send(m, blocking=False).to_bytes())
    assert (blocking.kind, blocking.delivery) == (CommKind.REQUEST, Delivery.BLOCKING)
    assert streaming.delivery is Delivery.STREAMING
    assert nonblocking.delivery is Delivery.STREAMING          # returns at once, polled later
    assert blocking.text == "hello" and blocking.target_url == URL
    poll = ad.parse_request(URL, Request.get_task("t9").to_bytes())
    assert poll.kind is CommKind.POLL and poll.task_id == "t9"


def test_adapter_reply_content_and_states() -> None:
    ad = A2AAdapter()
    task = Task(id="t1", context_id="c1", status=TaskStatus(TaskState.COMPLETED),
                artifacts=[Artifact(parts=[Part.from_text("98.70"), Part.from_data({"iban": "X"})])])
    (r,) = ad.parse_replies(Response(id=1, result=task).to_bytes())
    assert r.kind is CommKind.REPLY and r.has_content and r.final and r.state is TaskState.COMPLETED
    assert "98.70" in r.text and r.data == [{"iban": "X"}]
    working = Response(id=1, result=StatusUpdate("t1", "c1", TaskStatus(TaskState.WORKING)))
    (w,) = ad.parse_replies(working.to_bytes())
    assert not w.has_content and not w.final


def test_working_and_rejected_answers() -> None:
    ad = A2AAdapter()
    req = ad.parse_request(URL, Request.send(Message.user_text("x"), streaming=True).to_bytes())
    w = parse_response(ad.working(req, "local-1"))
    assert w.result.id == "local-1" and w.result.status.state is TaskState.WORKING
    assert w.id == req.raw.id
    r = parse_response(ad.rejected(req, "local-1", "denied by review"))
    assert r.result.status.state is TaskState.REJECTED
    assert r.result.status.message.text() == "denied by review"
