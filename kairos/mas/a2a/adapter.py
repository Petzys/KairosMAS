"""The protocol seam of the inter-agent channel.

The monitor reasons about inter-agent communication in protocol-neutral terms
(`InterAgentMessage`): a REQUEST to another agent, delivered BLOCKING (the caller
waits for the answer) or STREAMING (the caller continues and collects the answer
later), a REPLY travelling back, a POLL for a task's state, a CONTROL call, or an
operation the monitor does not relay. A protocol adapter maps wire traffic onto
these, renders the two answers the monitor itself has to give -- "still working"
while a message is stalled, "rejected" when it is denied -- and the CANONICAL form
of what it checked, which is what leaves.

A2A v1.0 (JSON-RPC binding) is the prototype's protocol; another protocol only needs
another adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from kairos.mas.a2a.protocol import (
    Artifact, ArtifactUpdate, Message, Method, Part, ProtocolError, Request, Response, Result,
    RpcError, StatusUpdate, Task, TaskList, TaskState, TaskStatus, new_id, parse_request,
    parse_response, parse_sse, result_text, utc_now,
)


class CommKind(str, Enum):
    REQUEST = "request"         # content to another agent (new work or a continuation)
    REPLY = "reply"             # content travelling back to the requester
    POLL = "poll"               # GetTask / SubscribeToTask for a task the caller started
    CONTROL = "control"         # CancelTask
    UNSUPPORTED = "unsupported"  # ListTasks, push notification configs, extended card


class Delivery(str, Enum):
    BLOCKING = "blocking"    # SendMessage: a KAIROS blocking effect (resolve before sending)
    STREAMING = "streaming"  # SendStreamingMessage / returnImmediately: a stallable effect


@dataclass(slots=True)
class InterAgentMessage:
    kind: CommKind
    delivery: Delivery
    text: str = ""                                   # all content, as text
    data: list[Any] = field(default_factory=list)    # structured (data) parts
    target_url: str | None = None                    # REQUEST / POLL
    task_id: str | None = None
    context_id: str | None = None
    protocol_message_id: str | None = None
    final: bool = True                               # REPLY: the task is terminal or waits for input
    state: TaskState | None = None                   # REPLY: the task state it reports
    raw: Any = None

    @property
    def has_content(self) -> bool:
        return bool(self.text.strip()) or bool(self.data)


class ProtocolAdapter(Protocol):
    name: str

    def parse_request(self, url: str, body: bytes | str | dict[str, Any]) -> InterAgentMessage: ...
    def parse_replies(self, body: bytes | str | dict[str, Any], *,
                      streaming: bool = False) -> list[InterAgentMessage]: ...
    def canonical_request(self, msg: InterAgentMessage, *, task_id: str | None = None,
                          context_id: str | None = None) -> bytes: ...
    def canonical_reply(self, body: bytes | str | dict[str, Any]) -> tuple[bytes, InterAgentMessage] | None: ...
    def working(self, request: InterAgentMessage, task_id: str, *, context_id: str | None = None) -> bytes: ...
    def rejected(self, request: InterAgentMessage, task_id: str, notice: str, *,
                 context_id: str | None = None) -> bytes: ...


def _canonical_part(p: Part) -> Part:
    """A part as forwarded: its content, filename and media type (all checked as
    text); its free-form metadata is not forwarded (it was not checked)."""
    return Part(kind=p.kind, text=p.text, raw=p.raw, url=p.url, data=p.data,
                filename=p.filename, media_type=p.media_type)


def _canonical_message(m: Message) -> Message:
    return Message(role=m.role, parts=[_canonical_part(p) for p in m.parts], message_id=m.message_id,
                   context_id=m.context_id, task_id=m.task_id)


def _canonical_status(s: TaskStatus) -> TaskStatus:
    return TaskStatus(s.state, message=_canonical_message(s.message) if s.message else None,
                      timestamp=s.timestamp)


def _canonical_artifact(a: Artifact) -> Artifact:
    return Artifact(parts=[_canonical_part(p) for p in a.parts], artifact_id=a.artifact_id)


def _canonical_task(t: Task) -> Task:
    return Task(id=t.id, context_id=t.context_id, status=_canonical_status(t.status),
                artifacts=[_canonical_artifact(a) for a in t.artifacts])


class A2AAdapter:
    """A2A v1.0 JSON-RPC <-> InterAgentMessage."""

    name = "a2a/1.0"

    def parse_request(self, url: str, body: bytes | str | dict[str, Any]) -> InterAgentMessage:
        req = parse_request(body)
        if req.method in (Method.SEND, Method.STREAM):
            msg = req.message
            assert msg is not None                     # parse_request requires it
            # SendMessage with returnImmediately answers at once with a task in
            # progress: for the caller that is a task it polls later
            blocking = req.method is Method.SEND and not req.return_immediately
            return InterAgentMessage(
                kind=CommKind.REQUEST,
                delivery=Delivery.BLOCKING if blocking else Delivery.STREAMING,
                text=msg.content_text(), data=msg.data(), target_url=url,
                task_id=msg.task_id, context_id=msg.context_id,
                protocol_message_id=msg.message_id, raw=req)
        if req.method in (Method.GET_TASK, Method.SUBSCRIBE):
            return InterAgentMessage(kind=CommKind.POLL, delivery=Delivery.STREAMING,
                                     target_url=url, task_id=req.task_id, raw=req)
        if req.method is Method.CANCEL_TASK:
            return InterAgentMessage(kind=CommKind.CONTROL, delivery=Delivery.BLOCKING,
                                     target_url=url, task_id=req.task_id, raw=req)
        return InterAgentMessage(kind=CommKind.UNSUPPORTED, delivery=Delivery.BLOCKING,
                                 target_url=url, raw=req)

    def parse_replies(self, body: bytes | str | dict[str, Any], *,
                      streaming: bool = False) -> list[InterAgentMessage]:
        responses = parse_sse(body) if streaming else [parse_response(body)]
        return [self._reply(r) for r in responses]

    def reply_from_result(self, result: Result) -> InterAgentMessage:
        return self._reply(Response(id=None, result=result))

    @staticmethod
    def _reply(resp: Response) -> InterAgentMessage:
        res = resp.result
        if res is None:
            return InterAgentMessage(kind=CommKind.REPLY, delivery=Delivery.BLOCKING,
                                     text=resp.error.message if resp.error else "",
                                     state=TaskState.FAILED, raw=resp)
        task_id = context_id = None
        state: TaskState | None = None
        final = True
        data: list[Any] = []
        if isinstance(res, Task):
            task_id, context_id, state = res.id, res.context_id, res.status.state
            final = state.is_final or state.is_interrupted
            for a in res.artifacts:
                data += [p.data for p in a.parts if p.kind == "data"]
        elif isinstance(res, StatusUpdate):
            task_id, context_id, state = res.task_id, res.context_id, res.status.state
            final = state.is_final or state.is_interrupted
        elif isinstance(res, ArtifactUpdate):
            task_id, context_id, final = res.task_id, res.context_id, False
            data = [p.data for p in res.artifact.parts if p.kind == "data"]
        elif isinstance(res, Message):
            task_id, context_id = res.task_id, res.context_id
            data = res.data()
        elif isinstance(res, TaskList):
            for t in res.tasks:
                for a in t.artifacts:
                    data += [p.data for p in a.parts if p.kind == "data"]
        return InterAgentMessage(kind=CommKind.REPLY, delivery=Delivery.BLOCKING,
                                 text=result_text(res), data=data, task_id=task_id,
                                 context_id=context_id, final=final, state=state, raw=resp)

    # --- canonical forms: forward exactly what was decided --------------------
    def canonical_request(self, msg: InterAgentMessage, *, task_id: str | None = None,
                          context_id: str | None = None) -> bytes:
        """The request re-serialized from what the monitor checked: the message parts
        and the delivery mode. Agent-chosen free fields -- request, message and part
        metadata, extensions, unknown params, its own message id, task and context ids
        the monitor cannot map -- are not forwarded: they would carry content past the
        decision. `task_id` / `context_id` are the PEER's ids the monitor mapped."""
        req = msg.raw
        assert isinstance(req, Request)
        m = req.message
        parts = [_canonical_part(p) for p in m.parts] if m is not None else []
        out = Message(role="user", parts=parts, message_id=new_id("msg-"),
                      context_id=context_id, task_id=task_id)
        params: dict[str, Any] = {"message": out.to_dict()}
        if req.method is Method.SEND and msg.delivery is Delivery.STREAMING:
            params["configuration"] = {"returnImmediately": True}
        return Request(method=req.method, params=params, id=req.id).to_bytes()

    @staticmethod
    def canonical_poll(msg: InterAgentMessage, remote_task_id: str) -> bytes:
        req = msg.raw
        assert isinstance(req, Request)
        return Request(method=req.method, params={"id": remote_task_id}, id=req.id).to_bytes()

    def canonical_reply(self, body: bytes | str | dict[str, Any]) -> tuple[bytes, InterAgentMessage] | None:
        """A reply re-serialized from its checked view (artifact parts, status and its
        message, update fields; no history, no metadata, no artifact names), with that
        view. None when the body is not a well-formed A2A v1.0 response: fail closed,
        never pass it on."""
        try:
            resp = parse_response(body)
        except ProtocolError:
            return None
        res = resp.result
        canon: Response
        if resp.error is not None:
            canon = Response(id=resp.id, error=RpcError(resp.error.code, resp.error.message))
        elif isinstance(res, Task):
            canon = Response(id=resp.id, result=_canonical_task(res), bare=resp.bare)
        elif isinstance(res, Message):
            canon = Response(id=resp.id, result=_canonical_message(res))
        elif isinstance(res, StatusUpdate):
            canon = Response(id=resp.id, result=StatusUpdate(res.task_id, res.context_id,
                                                             _canonical_status(res.status)))
        elif isinstance(res, ArtifactUpdate):
            canon = Response(id=resp.id, result=ArtifactUpdate(
                res.task_id, res.context_id, _canonical_artifact(res.artifact), res.append, res.last_chunk))
        elif isinstance(res, TaskList):
            canon = Response(id=resp.id, result=TaskList([_canonical_task(t) for t in res.tasks],
                                                         res.next_page_token, res.page_size, res.total_size),
                             bare=True)
        else:
            return None
        return canon.to_bytes(), self._reply(canon)

    # --- what the monitor answers itself -----------------------------------
    def working(self, request: InterAgentMessage, task_id: str, *, context_id: str | None = None) -> bytes:
        """A stalled message: the native A2A TASK_STATE_WORKING, nothing else. The
        caller sees a task in progress, exactly as if the callee were busy."""
        rpc_id = request.raw.id if isinstance(request.raw, Request) else None
        task = Task(id=task_id, context_id=context_id or request.context_id or new_id("ctx-"),
                    status=TaskStatus(TaskState.WORKING, timestamp=utc_now()))
        return Response(id=rpc_id, result=task).to_bytes()

    def rejected(self, request: InterAgentMessage, task_id: str, notice: str, *,
                 context_id: str | None = None) -> bytes:
        """A denied message: TASK_STATE_REJECTED plus the monitor's notice to the sender."""
        rpc_id = request.raw.id if isinstance(request.raw, Request) else None
        task = Task(id=task_id, context_id=context_id or request.context_id or new_id("ctx-"),
                    status=TaskStatus(TaskState.REJECTED, message=Message.agent_text(notice),
                                      timestamp=utc_now()))
        return Response(id=rpc_id, result=task).to_bytes()
