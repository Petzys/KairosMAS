"""A minimal A2A v1.0 server for an agent (JSON-RPC binding).

This is the AGENT's side of the protocol -- untrusted and unmodified by the
monitor. It turns an incoming message into a task, runs the agent's handler on it
and reports the result as an artifact. The monitor sits in front of it (the
enforcement point), never inside it.

Supported: SendMessage (blocking, or returnImmediately), SendStreamingMessage,
GetTask (historyLength), CancelTask (tasks run to completion: not cancelable),
ListTasks, SubscribeToTask. A message with a taskId continues that task if it waits
for input; an unknown task, a finished one, one still working or a mismatching
contextId is refused (spec 3.1.1, 3.4). Push notifications and the extended agent
card are not offered and answer with their spec errors. Requests must carry
`A2A-Version: 1.0`.

How a task runs: `_task_for` creates (or continues) the task, `_run` calls the
agent's handler, and every change of the task is published to the open streams of
that task (`_publish`). Streams close when the task reaches a terminal state.
"""
from __future__ import annotations

import threading
import traceback
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from kairos.mas.a2a.protocol import (
    AgentCard, Artifact, ArtifactUpdate, ErrorCode, Message, Method, Part, ProtocolError, Request, Response,
    RpcError, StatusUpdate, Task, TaskList, TaskState, TaskStatus, new_id, parse_request, rpc_id_of, utc_now,
    version_error, version_supported,
)
from kairos.mas.transport import EventStream


@dataclass(slots=True)
class AgentResult:
    """What the agent's handler returns for one task (or one turn of it)."""
    text: str
    data: list[Any] = field(default_factory=list)
    state: TaskState = TaskState.COMPLETED     # INPUT_REQUIRED: the task waits for the caller


Handler = Callable[[Message, str], AgentResult]     # (incoming message, task id) -> result


def _error(rpc_id: Any, code: ErrorCode, message: str, reason: str, **meta: str) -> bytes:
    return Response(id=rpc_id, error=RpcError.info(code, message, reason, **meta)).to_bytes()


def _closed(body: bytes) -> EventStream:
    """A stream with exactly one event."""
    stream = EventStream()
    stream.put(body)
    stream.close()
    return stream


class A2AServer:
    """The A2A endpoint of one agent: `handle` for request/response methods,
    `handle_stream` for the streaming ones.

    `_lock` protects the task table and the subscriber lists; the agent's handler
    runs outside it."""

    def __init__(self, name: str, url: str, handler: Handler, description: str = "") -> None:
        self.name = name
        self.url = url
        self.handler = handler
        self.card = AgentCard(name=name, url=url, description=description)
        self._tasks: dict[str, Task] = {}
        # task id -> the open streams of that task, each with the JSON-RPC id to answer under
        self._subscribers: dict[str, list[tuple[Any, EventStream]]] = {}
        self._lock = threading.Lock()

    # --- request/response methods -------------------------------------------
    def handle(self, body: bytes, headers: Mapping[str, str] | None = None) -> bytes:
        if not version_supported(headers):
            return version_error(rpc_id_of(body), headers)
        try:
            request = parse_request(body)
        except ProtocolError as e:
            return Response(id=rpc_id_of(body), error=RpcError(e.code, str(e))).to_bytes()

        if request.method is Method.SEND:
            message = request.message
            assert message is not None
            task = self._task_for(request, message)
            if isinstance(task, bytes):                 # refused: the error response
                return task
            if request.return_immediately:
                # Answer at once with the task in progress; the caller polls for the rest.
                threading.Thread(target=self._run, args=(task, message), daemon=True).start()
            else:
                self._run(task, message)
            return Response(id=request.id, result=self._snapshot(task.id, history=0)).to_bytes()

        if request.method is Method.GET_TASK:
            history_length = request.params.get("historyLength")
            snapshot = self._snapshot(request.task_id or "",
                                      history=history_length if isinstance(history_length, int) else None)
            if snapshot is None:
                return _error(request.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                              taskId=request.task_id or "")
            return Response(id=request.id, result=snapshot, bare=True).to_bytes()

        if request.method is Method.CANCEL_TASK:
            if self._snapshot(request.task_id or "") is None:
                return _error(request.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                              taskId=request.task_id or "")
            return _error(request.id, ErrorCode.TASK_NOT_CANCELABLE, "Task cannot be canceled: this agent "
                          "runs every task to completion", "TASK_NOT_CANCELABLE", taskId=request.task_id or "")

        if request.method is Method.LIST_TASKS:
            return Response(id=request.id, result=self._list(request.params), bare=True).to_bytes()
        if request.method.push_config:
            return _error(request.id, ErrorCode.PUSH_NOTIFICATION_NOT_SUPPORTED,
                          "Push notifications are not supported", "PUSH_NOTIFICATION_NOT_SUPPORTED")
        if request.method is Method.GET_EXTENDED_CARD:
            return _error(request.id, ErrorCode.EXTENDED_AGENT_CARD_NOT_CONFIGURED,
                          "No extended agent card is configured", "EXTENDED_AGENT_CARD_NOT_CONFIGURED")
        return _error(request.id, ErrorCode.UNSUPPORTED_OPERATION, f"{request.method.value} needs a stream",
                      "UNSUPPORTED_OPERATION")

    # --- streaming methods --------------------------------------------------
    def handle_stream(self, body: bytes, headers: Mapping[str, str] | None = None) -> EventStream:
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        try:
            request = parse_request(body)
        except ProtocolError as e:
            return _closed(Response(id=rpc_id_of(body), error=RpcError(e.code, str(e))).to_bytes())

        if request.method is Method.STREAM:
            message = request.message
            assert message is not None
            task = self._task_for(request, message)
            if isinstance(task, bytes):
                return _closed(task)
            # The stream begins with the Task; the handler's progress follows as events.
            stream = EventStream()
            stream.put(Response(id=request.id, result=self._snapshot(task.id, history=0)).to_bytes())
            with self._lock:
                self._subscribers.setdefault(task.id, []).append((request.id, stream))
            threading.Thread(target=self._run, args=(task, message), daemon=True).start()
            return stream

        if request.method is Method.SUBSCRIBE:
            snapshot = self._snapshot(request.task_id or "", history=0)
            if snapshot is None:
                return _closed(_error(request.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                                      taskId=request.task_id or ""))
            stream = EventStream()
            with self._lock:
                if snapshot.status.state.is_final:
                    return _closed(_error(request.id, ErrorCode.UNSUPPORTED_OPERATION,
                                          "The task is in a terminal state", "UNSUPPORTED_OPERATION",
                                          taskId=snapshot.id))
                stream.put(Response(id=request.id, result=snapshot).to_bytes())
                self._subscribers.setdefault(snapshot.id, []).append((request.id, stream))
            return stream

        return _closed(_error(request.id, ErrorCode.UNSUPPORTED_OPERATION,
                              f"{request.method.value} is not a streaming method", "UNSUPPORTED_OPERATION"))

    # --- internals ----------------------------------------------------------
    def _task_for(self, req: Request, msg: Message) -> Task | bytes:
        """The task a message starts, or the one it continues; an error response if
        it can do neither."""
        if not msg.task_id:
            task = Task(id=new_id("task-"), context_id=msg.context_id or new_id("ctx-"),
                        status=TaskStatus(TaskState.SUBMITTED, timestamp=utc_now()), history=[msg])
            with self._lock:
                self._tasks[task.id] = task
            return task
        with self._lock:
            task = self._tasks.get(msg.task_id)
            if task is None:
                return _error(req.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                              taskId=msg.task_id)
            if msg.context_id and msg.context_id != task.context_id:
                return Response(id=req.id, error=RpcError(
                    ErrorCode.INVALID_PARAMS, "contextId does not match the task's context")).to_bytes()
            # Only a task that waits for the caller takes another message.
            if not task.status.state.is_interrupted:
                why = "is in a terminal state" if task.status.state.is_final else "is still working"
                return _error(req.id, ErrorCode.UNSUPPORTED_OPERATION, f"The task {why}",
                              "UNSUPPORTED_OPERATION", taskId=task.id)
            task.history.append(msg)
            # claimed: a second message for the same turn finds it working
            task.status = TaskStatus(TaskState.WORKING, timestamp=utc_now())
        return task

    def _run(self, task: Task, msg: Message) -> AgentResult:
        """Run the agent's handler on one message of the task and publish the result:
        WORKING, then the artifact, then the final state."""
        self._set_status(task, TaskStatus(TaskState.WORKING, timestamp=utc_now()))
        try:
            result = self.handler(msg, task.id)
        except Exception as e:                          # the agent crashed: a failed task
            traceback.print_exc()
            result = AgentResult(text=f"agent error: {type(e).__name__}: {e}", state=TaskState.FAILED)
        artifact = Artifact(parts=self._parts(result))
        with self._lock:
            task.artifacts.append(artifact)
        self._publish(task, lambda rpc_id: Response(id=rpc_id,
                                                    result=ArtifactUpdate(task.id, task.context_id, artifact)))
        self._set_status(task, TaskStatus(result.state, timestamp=utc_now()))
        return result

    def _set_status(self, task: Task, status: TaskStatus) -> None:
        with self._lock:
            task.status = status
        self._publish(task, lambda rpc_id: Response(id=rpc_id,
                                                    result=StatusUpdate(task.id, task.context_id, status)))

    def _publish(self, task: Task, event: Callable[[Any], Response]) -> None:
        """An event to every open stream of the task; streams close at a terminal state.
        `event` builds the response for one stream's JSON-RPC id."""
        with self._lock:
            subscribers = list(self._subscribers.get(task.id, []))
            if task.status.state.is_final:
                self._subscribers.pop(task.id, None)
        for rpc_id, stream in subscribers:
            stream.put(event(rpc_id).to_bytes())
            if task.status.state.is_final:
                stream.close()

    @staticmethod
    def _parts(result: AgentResult) -> list[Part]:
        return [Part.from_text(result.text)] + [Part.from_data(data) for data in result.data]

    def _snapshot(self, task_id: str, history: int | None = None) -> Task | None:
        """A copy of the task, with at most `history` messages of its history
        (None: all of them)."""
        with self._lock:
            task = self._tasks.get(task_id)
            if task is None:
                return None
            if history is None:
                kept = list(task.history)
            elif history > 0:
                kept = list(task.history[-history:])
            else:
                kept = []
            return Task(id=task.id, context_id=task.context_id, status=task.status,
                        artifacts=list(task.artifacts), history=kept, metadata=dict(task.metadata))

    def _list(self, params: dict[str, Any]) -> TaskList:
        """ListTasks: filtered by context and state, one page (no paging tokens)."""
        context_filter = params.get("contextId")
        status_filter = params.get("status")
        requested = params.get("pageSize")
        page_size = requested if isinstance(requested, int) and 0 < requested <= 100 else 50
        with self._lock:
            tasks = [task for task in self._tasks.values()
                     if (not context_filter or task.context_id == context_filter)
                     and (not status_filter or task.status.state.value == status_filter)]
        page = tasks[:page_size]
        return TaskList(tasks=[Task(id=task.id, context_id=task.context_id, status=task.status,
                                    artifacts=list(task.artifacts) if params.get("includeArtifacts") else [])
                               for task in page],
                        next_page_token="", page_size=len(page), total_size=len(tasks))


__all__ = ["A2AServer", "AgentResult", "Handler"]
