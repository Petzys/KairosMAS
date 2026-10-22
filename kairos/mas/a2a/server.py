"""A minimal A2A server for an agent: tasks, blocking and streaming sends, polls.

This is the AGENT's side of the protocol -- untrusted and unmodified by the
monitor. It turns an incoming message into a task, runs the agent's handler on it
and reports the result as an artifact. The monitor sits in front of it (the
enforcement point), never inside it.
"""
from __future__ import annotations

import threading
import traceback
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kairos.mas.a2a.protocol import (
    AgentCard, Artifact, ArtifactUpdate, ErrorCode, Message, Method, Part, ProtocolError, Request,
    Response, RpcError, StatusUpdate, Task, TaskState, TaskStatus, new_id, parse_request,
)
from kairos.mas.transport import EventStream


@dataclass(slots=True)
class AgentResult:
    text: str
    data: list[dict[str, Any]] = field(default_factory=list)
    state: TaskState = TaskState.COMPLETED


Handler = Callable[[Message, str], AgentResult]     # (incoming message, task id) -> result


class A2AServer:
    def __init__(self, name: str, url: str, handler: Handler, description: str = "") -> None:
        self.name = name
        self.url = url
        self.handler = handler
        self.card = AgentCard(name=name, url=url, description=description)
        self._tasks: dict[str, Task] = {}
        self._lock = threading.Lock()

    # --- blocking methods ---------------------------------------------------
    def handle(self, body: bytes) -> bytes:
        try:
            req = parse_request(body)
        except ProtocolError as e:
            return Response(id=None, error=RpcError(ErrorCode.INVALID_REQUEST, str(e))).to_bytes()
        if req.method is Method.SEND:
            msg = req.message
            if msg is None:
                return self._error(req, ErrorCode.INVALID_PARAMS, "missing message")
            task = self._new_task(msg)
            if (req.params.get("configuration") or {}).get("blocking", True) is False:
                threading.Thread(target=self._run, args=(task, msg), daemon=True).start()
                return Response(id=req.id, result=self._snapshot(task.id)).to_bytes()
            self._run(task, msg)
            return Response(id=req.id, result=self._snapshot(task.id)).to_bytes()
        if req.method is Method.GET_TASK:
            snap = self._snapshot(req.task_id or "")
            if snap is None:
                return self._error(req, ErrorCode.TASK_NOT_FOUND, f"task {req.task_id} not found")
            return Response(id=req.id, result=snap).to_bytes()
        if req.method is Method.CANCEL_TASK:
            return self._error(req, ErrorCode.TASK_NOT_CANCELABLE, "tasks run to completion")
        return self._error(req, ErrorCode.UNSUPPORTED_OPERATION, f"{req.method.value} needs a stream")

    # --- streaming methods --------------------------------------------------
    def handle_stream(self, body: bytes) -> EventStream:
        out = EventStream()
        try:
            req = parse_request(body)
        except ProtocolError as e:
            out.put(Response(id=None, error=RpcError(ErrorCode.INVALID_REQUEST, str(e))).to_bytes())
            out.close()
            return out
        if req.method is Method.STREAM and req.message is not None:
            msg = req.message
            task = self._new_task(msg)
            out.put(Response(id=req.id, result=self._snapshot(task.id)).to_bytes())

            def run() -> None:
                result = self._run(task, msg)
                art = Artifact(parts=self._parts(result))
                out.put(Response(id=req.id, result=ArtifactUpdate(task.id, task.context_id, art)).to_bytes())
                out.put(Response(id=req.id, result=StatusUpdate(
                    task.id, task.context_id, TaskStatus(result.state), final=True)).to_bytes())
                out.close()

            threading.Thread(target=run, daemon=True).start()
            return out
        if req.method is Method.RESUBSCRIBE:
            snap = self._snapshot(req.task_id or "")
            if snap is None:
                out.put(self._error(req, ErrorCode.TASK_NOT_FOUND, f"task {req.task_id} not found"))
            else:
                out.put(Response(id=req.id, result=snap).to_bytes())
            out.close()
            return out
        out.put(self._error(req, ErrorCode.INVALID_PARAMS, "not a streaming request"))
        out.close()
        return out

    # --- internals ----------------------------------------------------------
    def _new_task(self, msg: Message) -> Task:
        task = Task(id=new_id("task-"), context_id=msg.context_id or new_id("ctx-"),
                    status=TaskStatus(TaskState.WORKING), history=[msg])
        with self._lock:
            self._tasks[task.id] = task
        return task

    def _run(self, task: Task, msg: Message) -> AgentResult:
        try:
            result = self.handler(msg, task.id)
        except Exception as e:                          # the agent crashed: a failed task
            traceback.print_exc()
            result = AgentResult(text=f"agent error: {type(e).__name__}: {e}", state=TaskState.FAILED)
        with self._lock:
            task.artifacts = [Artifact(parts=self._parts(result))]
            task.status = TaskStatus(result.state)
        return result

    @staticmethod
    def _parts(result: AgentResult) -> list[Part]:
        return [Part.from_text(result.text)] + [Part.from_data(d) for d in result.data]

    def _snapshot(self, task_id: str) -> Task | None:
        with self._lock:
            t = self._tasks.get(task_id)
            if t is None:
                return None
            return Task(id=t.id, context_id=t.context_id, status=t.status,
                        artifacts=list(t.artifacts), metadata=dict(t.metadata))

    @staticmethod
    def _error(req: Request, code: int, message: str) -> bytes:
        return Response(id=req.id, error=RpcError(int(code), message)).to_bytes()
