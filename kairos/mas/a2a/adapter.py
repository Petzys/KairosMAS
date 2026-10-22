"""The protocol seam of the inter-agent channel.

The monitor reasons about inter-agent communication in protocol-neutral terms
(`InterAgentMessage`): a REQUEST to another agent, delivered BLOCKING (the caller
waits for the answer) or STREAMING (the caller continues and collects the answer
later), a REPLY travelling back, or a POLL for a task's state. A protocol adapter
maps wire traffic onto these and renders the two answers the monitor itself has to
give: "still working" while a message is stalled, and "rejected" when it is denied.

A2A is the prototype's protocol; another protocol only needs another adapter.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from kairos.mas.a2a.protocol import (
    ArtifactUpdate, Message, Method, ProtocolError, Request, Response, Result,
    StatusUpdate, Task, TaskState, TaskStatus, new_id, parse_request, parse_response,
    parse_sse, result_text,
)


class CommKind(str, Enum):
    REQUEST = "request"     # content to another agent (new work or a continuation)
    REPLY = "reply"         # content travelling back to the requester
    POLL = "poll"           # the requester asks for a task's state / resubscribes
    CONTROL = "control"     # cancel and similar, no content


class Delivery(str, Enum):
    BLOCKING = "blocking"    # SendMessage: a KAIROS blocking effect (resolve before sending)
    STREAMING = "streaming"  # SendStreamingMessage: a stallable effect (held in scope)


@dataclass(slots=True)
class InterAgentMessage:
    kind: CommKind
    delivery: Delivery
    text: str = ""                                   # all content, as text
    data: list[dict[str, Any]] = field(default_factory=list)
    target_url: str | None = None                    # REQUEST / POLL
    task_id: str | None = None
    context_id: str | None = None
    protocol_message_id: str | None = None
    final: bool = True                               # REPLY: last content of the task
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
    def working(self, request: InterAgentMessage, task_id: str) -> bytes: ...
    def rejected(self, request: InterAgentMessage, task_id: str, notice: str) -> bytes: ...


class A2AAdapter:
    """A2A JSON-RPC <-> InterAgentMessage."""

    name = "a2a"

    def parse_request(self, url: str, body: bytes | str | dict[str, Any]) -> InterAgentMessage:
        req = parse_request(body)
        if req.method in (Method.SEND, Method.STREAM):
            msg = req.message
            if msg is None:
                raise ProtocolError(f"{req.method.value} without a message")
            # message/send with configuration.blocking=false returns at once with a
            # task in progress: for the caller that is a stream it polls later.
            blocking = req.method is Method.SEND and (req.params.get("configuration") or {}).get(
                "blocking", True) is not False
            return InterAgentMessage(
                kind=CommKind.REQUEST,
                delivery=Delivery.BLOCKING if blocking else Delivery.STREAMING,
                text=msg.content_text(), data=msg.data(), target_url=url,
                task_id=msg.task_id, context_id=msg.context_id,
                protocol_message_id=msg.message_id, raw=req)
        if req.method in (Method.GET_TASK, Method.RESUBSCRIBE):
            return InterAgentMessage(kind=CommKind.POLL, delivery=Delivery.STREAMING,
                                     target_url=url, task_id=req.task_id, raw=req)
        return InterAgentMessage(kind=CommKind.CONTROL, delivery=Delivery.BLOCKING,
                                 target_url=url, task_id=req.task_id, raw=req)

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
        data: list[dict[str, Any]] = []
        if isinstance(res, Task):
            task_id, context_id, state = res.id, res.context_id, res.status.state
            final = state.is_final or state is TaskState.INPUT_REQUIRED
            for a in res.artifacts:
                data += [p.data or {} for p in a.parts if p.kind == "data"]
        elif isinstance(res, StatusUpdate):
            task_id, context_id, state, final = res.task_id, res.context_id, res.status.state, res.final
        elif isinstance(res, ArtifactUpdate):
            task_id, context_id, final = res.task_id, res.context_id, False
            data = [p.data or {} for p in res.artifact.parts if p.kind == "data"]
        elif isinstance(res, Message):
            task_id, context_id = res.task_id, res.context_id
            data = res.data()
        return InterAgentMessage(kind=CommKind.REPLY, delivery=Delivery.BLOCKING,
                                 text=result_text(res), data=data, task_id=task_id,
                                 context_id=context_id, final=final, state=state, raw=resp)

    # --- what the monitor answers itself -----------------------------------
    def working(self, request: InterAgentMessage, task_id: str) -> bytes:
        """A stalled message: the native A2A 'working' state, nothing else. The
        caller sees a task in progress, exactly as if the callee were busy."""
        rpc_id = request.raw.id if isinstance(request.raw, Request) else None
        task = Task(id=task_id, context_id=request.context_id or new_id("ctx-"),
                    status=TaskStatus(TaskState.WORKING))
        return Response(id=rpc_id, result=task).to_bytes()

    def rejected(self, request: InterAgentMessage, task_id: str, notice: str) -> bytes:
        """A denied message: A2A 'rejected' plus the monitor's notice to the sender."""
        rpc_id = request.raw.id if isinstance(request.raw, Request) else None
        task = Task(id=task_id, context_id=request.context_id or new_id("ctx-"),
                    status=TaskStatus(TaskState.REJECTED, message=Message.agent_text(notice)))
        return Response(id=rpc_id, result=task).to_bytes()
