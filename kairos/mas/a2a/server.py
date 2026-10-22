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
    text: str
    data: list[Any] = field(default_factory=list)
    state: TaskState = TaskState.COMPLETED


Handler = Callable[[Message, str], AgentResult]     # (incoming message, task id) -> result


def _error(rpc_id: Any, code: ErrorCode, message: str, reason: str, **meta: str) -> bytes:
    return Response(id=rpc_id, error=RpcError.info(code, message, reason, **meta)).to_bytes()


def _closed(body: bytes) -> EventStream:
    s = EventStream()
    s.put(body)
    s.close()
    return s


class A2AServer:
    def __init__(self, name: str, url: str, handler: Handler, description: str = "") -> None:
        self.name = name
        self.url = url
        self.handler = handler
        self.card = AgentCard(name=name, url=url, description=description)
        self._tasks: dict[str, Task] = {}
        self._subscribers: dict[str, list[tuple[Any, EventStream]]] = {}
        self._lock = threading.Lock()

    # --- request/response methods -------------------------------------------
    def handle(self, body: bytes, headers: Mapping[str, str] | None = None) -> bytes:
        if not version_supported(headers):
            return version_error(rpc_id_of(body), headers)
        try:
            req = parse_request(body)
        except ProtocolError as e:
            return Response(id=rpc_id_of(body), error=RpcError(e.code, str(e))).to_bytes()
        if req.method is Method.SEND:
            msg = req.message
            assert msg is not None
            task = self._task_for(req, msg)
            if isinstance(task, bytes):
                return task
            if req.return_immediately:
                threading.Thread(target=self._run, args=(task, msg), daemon=True).start()
            else:
                self._run(task, msg)
            return Response(id=req.id, result=self._snapshot(task.id, history=0)).to_bytes()
        if req.method is Method.GET_TASK:
            hl = req.params.get("historyLength")
            snap = self._snapshot(req.task_id or "", history=hl if isinstance(hl, int) else None)
            if snap is None:
                return _error(req.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                              taskId=req.task_id or "")
            return Response(id=req.id, result=snap, bare=True).to_bytes()
        if req.method is Method.CANCEL_TASK:
            if self._snapshot(req.task_id or "") is None:
                return _error(req.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                              taskId=req.task_id or "")
            return _error(req.id, ErrorCode.TASK_NOT_CANCELABLE, "Task cannot be canceled: this agent "
                          "runs every task to completion", "TASK_NOT_CANCELABLE", taskId=req.task_id or "")
        if req.method is Method.LIST_TASKS:
            return Response(id=req.id, result=self._list(req.params), bare=True).to_bytes()
        if req.method.push_config:
            return _error(req.id, ErrorCode.PUSH_NOTIFICATION_NOT_SUPPORTED,
                          "Push notifications are not supported", "PUSH_NOTIFICATION_NOT_SUPPORTED")
        if req.method is Method.GET_EXTENDED_CARD:
            return _error(req.id, ErrorCode.EXTENDED_AGENT_CARD_NOT_CONFIGURED,
                          "No extended agent card is configured", "EXTENDED_AGENT_CARD_NOT_CONFIGURED")
        return _error(req.id, ErrorCode.UNSUPPORTED_OPERATION, f"{req.method.value} needs a stream",
                      "UNSUPPORTED_OPERATION")

    # --- streaming methods --------------------------------------------------
    def handle_stream(self, body: bytes, headers: Mapping[str, str] | None = None) -> EventStream:
        if not version_supported(headers):
            return _closed(version_error(rpc_id_of(body), headers))
        try:
            req = parse_request(body)
        except ProtocolError as e:
            return _closed(Response(id=rpc_id_of(body), error=RpcError(e.code, str(e))).to_bytes())
        if req.method is Method.STREAM:
            msg = req.message
            assert msg is not None
            task = self._task_for(req, msg)
            if isinstance(task, bytes):
                return _closed(task)
            out = EventStream()
            out.put(Response(id=req.id, result=self._snapshot(task.id, history=0)).to_bytes())
            with self._lock:
                self._subscribers.setdefault(task.id, []).append((req.id, out))
            threading.Thread(target=self._run, args=(task, msg), daemon=True).start()
            return out
        if req.method is Method.SUBSCRIBE:
            snap = self._snapshot(req.task_id or "", history=0)
            if snap is None:
                return _closed(_error(req.id, ErrorCode.TASK_NOT_FOUND, "Task not found", "TASK_NOT_FOUND",
                                      taskId=req.task_id or ""))
            out = EventStream()
            with self._lock:
                if snap.status.state.is_final:
                    return _closed(_error(req.id, ErrorCode.UNSUPPORTED_OPERATION,
                                          "The task is in a terminal state", "UNSUPPORTED_OPERATION",
                                          taskId=snap.id))
                out.put(Response(id=req.id, result=snap).to_bytes())
                self._subscribers.setdefault(snap.id, []).append((req.id, out))
            return out
        return _closed(_error(req.id, ErrorCode.UNSUPPORTED_OPERATION,
                              f"{req.method.value} is not a streaming method", "UNSUPPORTED_OPERATION"))

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
            if not task.status.state.is_interrupted:
                why = "is in a terminal state" if task.status.state.is_final else "is still working"
                return _error(req.id, ErrorCode.UNSUPPORTED_OPERATION, f"The task {why}",
                              "UNSUPPORTED_OPERATION", taskId=task.id)
            task.history.append(msg)
            # claimed: a second message for the same turn finds it working
            task.status = TaskStatus(TaskState.WORKING, timestamp=utc_now())
        return task

    def _run(self, task: Task, msg: Message) -> AgentResult:
        self._set_status(task, TaskStatus(TaskState.WORKING, timestamp=utc_now()))
        try:
            result = self.handler(msg, task.id)
        except Exception as e:                          # the agent crashed: a failed task
            traceback.print_exc()
            result = AgentResult(text=f"agent error: {type(e).__name__}: {e}", state=TaskState.FAILED)
        art = Artifact(parts=self._parts(result))
        with self._lock:
            task.artifacts.append(art)
        self._publish(task, lambda rid: Response(id=rid, result=ArtifactUpdate(task.id, task.context_id, art)))
        self._set_status(task, TaskStatus(result.state, timestamp=utc_now()))
        return result

    def _set_status(self, task: Task, status: TaskStatus) -> None:
        with self._lock:
            task.status = status
        self._publish(task, lambda rid: Response(id=rid, result=StatusUpdate(task.id, task.context_id, status)))

    def _publish(self, task: Task, event: Callable[[Any], Response]) -> None:
        """An event to every open stream of the task; streams close at a terminal state."""
        with self._lock:
            subs = list(self._subscribers.get(task.id, []))
            if task.status.state.is_final:
                self._subscribers.pop(task.id, None)
        for rid, stream in subs:
            stream.put(event(rid).to_bytes())
            if task.status.state.is_final:
                stream.close()

    @staticmethod
    def _parts(result: AgentResult) -> list[Part]:
        return [Part.from_text(result.text)] + [Part.from_data(d) for d in result.data]

    def _snapshot(self, task_id: str, history: int | None = None) -> Task | None:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return None
            hist = list(t.history) if history is None else (list(t.history[-history:]) if history > 0 else [])
            return Task(id=t.id, context_id=t.context_id, status=t.status,
                        artifacts=list(t.artifacts), history=hist, metadata=dict(t.metadata))

    def _list(self, params: dict[str, Any]) -> TaskList:
        ctx = params.get("contextId")
        status = params.get("status")
        size = params.get("pageSize")
        size = size if isinstance(size, int) and 0 < size <= 100 else 50
        with self._lock:
            tasks = [t for t in self._tasks.values()
                     if (not ctx or t.context_id == ctx) and (not status or t.status.state.value == status)]
        page = tasks[:size]
        return TaskList(tasks=[Task(id=t.id, context_id=t.context_id, status=t.status,
                                    artifacts=list(t.artifacts) if params.get("includeArtifacts") else [])
                               for t in page],
                        next_page_token="", page_size=len(page), total_size=len(tasks))


__all__ = ["A2AServer", "AgentResult", "Handler"]
