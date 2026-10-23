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
    """One message on the inter-agent channel, in protocol-neutral terms: what the
    monitor reasons about. `raw` keeps the parsed protocol object it came from."""
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
        """Does it carry anything to decide about? (A bare "working" status does not.)"""
        return bool(self.text.strip()) or bool(self.data)


class ProtocolAdapter(Protocol):
    """What the monitor needs from a protocol: parse traffic into InterAgentMessages,
    render canonical forms, and render its own two answers."""
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


# --- canonical forms: what is kept of each type --------------------------------
def _canonical_part(part: Part) -> Part:
    """A part as forwarded: its content, filename and media type (all checked as
    text); its free-form metadata is not forwarded (it was not checked)."""
    return Part(kind=part.kind, text=part.text, raw=part.raw, url=part.url, data=part.data,
                filename=part.filename, media_type=part.media_type)


def _canonical_message(message: Message) -> Message:
    """Role, parts and ids; no metadata, extensions or task references."""
    return Message(role=message.role, parts=[_canonical_part(part) for part in message.parts],
                   message_id=message.message_id, context_id=message.context_id, task_id=message.task_id)


def _canonical_status(status: TaskStatus) -> TaskStatus:
    return TaskStatus(status.state, message=_canonical_message(status.message) if status.message else None,
                      timestamp=status.timestamp)


def _canonical_artifact(artifact: Artifact) -> Artifact:
    """Parts and id; no name, description or metadata."""
    return Artifact(parts=[_canonical_part(part) for part in artifact.parts], artifact_id=artifact.artifact_id)


def _canonical_task(task: Task) -> Task:
    """Id, context, status and artifacts; no history and no metadata."""
    return Task(id=task.id, context_id=task.context_id, status=_canonical_status(task.status),
                artifacts=[_canonical_artifact(artifact) for artifact in task.artifacts])


class A2AAdapter:
    """A2A v1.0 JSON-RPC <-> InterAgentMessage."""

    name = "a2a/1.0"

    def parse_request(self, url: str, body: bytes | str | dict[str, Any]) -> InterAgentMessage:
        """What an outgoing request is, in the monitor's terms. Raises ProtocolError
        for anything that is not a well-formed A2A v1.0 request."""
        request = parse_request(body)
        if request.method in (Method.SEND, Method.STREAM):
            message = request.message
            assert message is not None                     # parse_request requires it
            # SendMessage with returnImmediately answers at once with a task in
            # progress: for the caller that is a task it polls later
            blocking = request.method is Method.SEND and not request.return_immediately
            return InterAgentMessage(
                kind=CommKind.REQUEST,
                delivery=Delivery.BLOCKING if blocking else Delivery.STREAMING,
                text=message.content_text(), data=message.data(), target_url=url,
                task_id=message.task_id, context_id=message.context_id,
                protocol_message_id=message.message_id, raw=request)
        if request.method in (Method.GET_TASK, Method.SUBSCRIBE):
            return InterAgentMessage(kind=CommKind.POLL, delivery=Delivery.STREAMING,
                                     target_url=url, task_id=request.task_id, raw=request)
        if request.method is Method.CANCEL_TASK:
            return InterAgentMessage(kind=CommKind.CONTROL, delivery=Delivery.BLOCKING,
                                     target_url=url, task_id=request.task_id, raw=request)
        return InterAgentMessage(kind=CommKind.UNSUPPORTED, delivery=Delivery.BLOCKING,
                                 target_url=url, raw=request)

    def parse_replies(self, body: bytes | str | dict[str, Any], *,
                      streaming: bool = False) -> list[InterAgentMessage]:
        """A response (or, with `streaming`, a complete SSE body) as REPLY messages."""
        responses = parse_sse(body) if streaming else [parse_response(body)]
        return [self._reply(response) for response in responses]

    def reply_from_result(self, result: Result) -> InterAgentMessage:
        return self._reply(Response(id=None, result=result))

    @staticmethod
    def _reply(resp: Response) -> InterAgentMessage:
        """The monitor's view of one response: its content as text and data, the task
        it belongs to, and whether the task has settled (`final`: terminal, or waiting
        for the caller)."""
        result = resp.result
        if result is None:
            return InterAgentMessage(kind=CommKind.REPLY, delivery=Delivery.BLOCKING,
                                     text=resp.error.message if resp.error else "",
                                     state=TaskState.FAILED, raw=resp)
        task_id = context_id = None
        state: TaskState | None = None
        final = True
        data: list[Any] = []
        if isinstance(result, Task):
            task_id, context_id, state = result.id, result.context_id, result.status.state
            final = state.is_final or state.is_interrupted
            for artifact in result.artifacts:
                data += [part.data for part in artifact.parts if part.kind == "data"]
        elif isinstance(result, StatusUpdate):
            task_id, context_id, state = result.task_id, result.context_id, result.status.state
            final = state.is_final or state.is_interrupted
        elif isinstance(result, ArtifactUpdate):
            task_id, context_id, final = result.task_id, result.context_id, False
            data = [part.data for part in result.artifact.parts if part.kind == "data"]
        elif isinstance(result, Message):
            task_id, context_id = result.task_id, result.context_id
            data = result.data()
        elif isinstance(result, TaskList):
            for task in result.tasks:
                for artifact in task.artifacts:
                    data += [part.data for part in artifact.parts if part.kind == "data"]
        return InterAgentMessage(kind=CommKind.REPLY, delivery=Delivery.BLOCKING,
                                 text=result_text(result), data=data, task_id=task_id,
                                 context_id=context_id, final=final, state=state, raw=resp)

    # --- canonical forms: forward exactly what was decided --------------------
    def canonical_request(self, msg: InterAgentMessage, *, task_id: str | None = None,
                          context_id: str | None = None) -> bytes:
        """The request re-serialized from what the monitor checked: the message parts
        and the delivery mode. Agent-chosen free fields -- request, message and part
        metadata, extensions, unknown params, its own message id, task and context ids
        the monitor cannot map -- are not forwarded: they would carry content past the
        decision. `task_id` / `context_id` are the PEER's ids the monitor mapped."""
        request = msg.raw
        assert isinstance(request, Request)
        original = request.message
        parts = [_canonical_part(part) for part in original.parts] if original is not None else []
        # A fresh message id: the agent's own id is free text it chose.
        canonical = Message(role="user", parts=parts, message_id=new_id("msg-"),
                            context_id=context_id, task_id=task_id)
        params: dict[str, Any] = {"message": canonical.to_dict()}
        if request.method is Method.SEND and msg.delivery is Delivery.STREAMING:
            params["configuration"] = {"returnImmediately": True}
        return Request(method=request.method, params=params, id=request.id).to_bytes()

    @staticmethod
    def canonical_poll(msg: InterAgentMessage, remote_task_id: str) -> bytes:
        """A GetTask / SubscribeToTask / CancelTask that carries nothing but the peer's
        task id."""
        request = msg.raw
        assert isinstance(request, Request)
        return Request(method=request.method, params={"id": remote_task_id}, id=request.id).to_bytes()

    def canonical_reply(self, body: bytes | str | dict[str, Any]) -> tuple[bytes, InterAgentMessage] | None:
        """A reply re-serialized from its checked view (artifact parts, status and its
        message, update fields; no history, no metadata, no artifact names), with that
        view. None when the body is not a well-formed A2A v1.0 response: fail closed,
        never pass it on."""
        try:
            response = parse_response(body)
        except ProtocolError:
            return None
        result = response.result
        canonical: Response
        if response.error is not None:
            # An error keeps its code and message; its structured `data` could carry
            # anything, so it is dropped.
            canonical = Response(id=response.id, error=RpcError(response.error.code, response.error.message))
        elif isinstance(result, Task):
            canonical = Response(id=response.id, result=_canonical_task(result), bare=response.bare)
        elif isinstance(result, Message):
            canonical = Response(id=response.id, result=_canonical_message(result))
        elif isinstance(result, StatusUpdate):
            canonical = Response(id=response.id, result=StatusUpdate(result.task_id, result.context_id,
                                                                     _canonical_status(result.status)))
        elif isinstance(result, ArtifactUpdate):
            canonical = Response(id=response.id, result=ArtifactUpdate(
                result.task_id, result.context_id, _canonical_artifact(result.artifact), result.append,
                result.last_chunk))
        elif isinstance(result, TaskList):
            canonical = Response(id=response.id,
                                 result=TaskList([_canonical_task(task) for task in result.tasks],
                                                 result.next_page_token, result.page_size, result.total_size),
                                 bare=True)
        else:
            return None
        # The view is taken from the canonical form: the decision is made on exactly
        # what will be sent.
        return canonical.to_bytes(), self._reply(canonical)

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
