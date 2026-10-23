"""A minimal A2A v1.0 client for an agent: send and wait, or start a task and collect it.

The agent's side of the protocol, used by benchmark agents as their messaging
tools. Its two transport functions are whatever the agent's host provides; on a
monitored host they lead into the host's enforcement point, which the client
cannot tell apart from the network. Every request carries `A2A-Version: 1.0`.

Two ways to talk to another agent:
  * `send_message`: SendMessage, wait for the answer;
  * `start_task` + `wait_task` / `poll`: SendStreamingMessage, return as soon as the
    task exists, and collect the rest of the stream in the background.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kairos.mas.a2a.protocol import (
    ArtifactUpdate, Message, Part, ProtocolError, Request, StatusUpdate, Task, TaskState,
    parse_response, version_headers,
)
from kairos.mas.transport import EventStream, Headers

SendFn = Callable[[str, bytes, Headers], bytes]           # (url, body, headers) -> response body
StreamFn = Callable[[str, bytes, Headers], EventStream]   # (url, body, headers) -> event stream


@dataclass(slots=True)
class ClientResult:
    """What the agent learns about a task: its state and the content so far."""
    state: TaskState
    text: str = ""
    data: list[Any] = field(default_factory=list)
    task_id: str | None = None
    notice: str = ""                       # a status message (rejection notice etc.)

    @property
    def ok(self) -> bool:
        return self.state is TaskState.COMPLETED

    def render(self) -> str:
        """What an agent's messaging tool returns."""
        if self.state is TaskState.COMPLETED:
            return self.text
        body = self.notice or self.text
        return f"[task {self.state.short}] {body}".strip()


@dataclass(slots=True)
class _Tracked:
    """A task started with `start_task`, as the client has seen it so far."""
    url: str
    task_id: str
    state: TaskState = TaskState.SUBMITTED
    texts: list[str] = field(default_factory=list)
    data: list[Any] = field(default_factory=list)
    notice: str = ""
    done: threading.Event = field(default_factory=threading.Event)   # set once settled


def _settled(state: TaskState) -> bool:
    """No further progress without the caller: terminal, or waiting for its input."""
    return state.is_final or state.is_interrupted


class A2AClient:
    def __init__(self, send: SendFn, send_stream: StreamFn) -> None:
        self._send = send
        self._send_stream = send_stream
        self._tasks: dict[str, _Tracked] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _message(text: str, data: list[Any] | None) -> Message:
        return Message(role="user", parts=[Part.from_text(text)] + [Part.from_data(d) for d in data or []])

    # --- blocking -----------------------------------------------------------
    def send_message(self, url: str, text: str, data: list[Any] | None = None) -> ClientResult:
        """SendMessage: wait for the other agent's answer."""
        body = Request.send(self._message(text, data)).to_bytes()
        try:
            response = parse_response(self._send(url, body, version_headers()))
        except (ProtocolError, ConnectionError) as e:
            return ClientResult(TaskState.FAILED, notice=f"transport error: {e}")
        if response.error is not None:
            return ClientResult(TaskState.FAILED, notice=response.error.message)
        return self._from_result(response.result)

    @staticmethod
    def _from_result(res: Any) -> ClientResult:
        if isinstance(res, Task):
            texts, data = [], []
            for artifact in res.artifacts:
                texts += [part.text or "" for part in artifact.parts if part.kind == "text"]
                data += [part.data for part in artifact.parts if part.kind == "data"]
            notice = res.status.message.text() if res.status.message else ""
            return ClientResult(res.status.state, "\n".join(texts), data, res.id, notice)
        if isinstance(res, Message):                       # a direct answer, no task
            return ClientResult(TaskState.COMPLETED, res.text(), res.data(), res.task_id)
        return ClientResult(TaskState.UNSPECIFIED)

    # --- streaming ------------------------------------------------------------
    def start_task(self, url: str, text: str, data: list[Any] | None = None,
                   timeout: float = 30.0) -> ClientResult:
        """SendStreamingMessage; return as soon as the task exists (working, or already
        settled). The rest of the stream is collected in the background."""
        body = Request.send(self._message(text, data), streaming=True).to_bytes()
        try:
            stream = self._send_stream(url, body, version_headers())
        except ConnectionError as e:
            return ClientResult(TaskState.FAILED, notice=f"transport error: {e}")
        first = stream.get(timeout=timeout)
        if first is None:
            return ClientResult(TaskState.FAILED, notice="no response")
        tracked = self._apply(None, url, first[0])
        if tracked is None:
            return ClientResult(TaskState.FAILED, notice="malformed response")
        threading.Thread(target=self._pump, args=(tracked, stream), daemon=True).start()
        return self._snapshot(tracked)

    def _pump(self, tracked: _Tracked, stream: EventStream) -> None:
        """Background thread: apply every further event of the task's stream."""
        for body, _headers in stream:
            self._apply(tracked, tracked.url, body)
        if not _settled(tracked.state):
            # the stream ended before the task settled: ask once more
            self.poll(tracked.task_id)
        tracked.done.set()

    def _apply(self, tracked: _Tracked | None, url: str, body: bytes) -> _Tracked | None:
        """Update what is known about a task from one response or event. With
        `tracked` None (the first event), the task is created from the event."""
        try:
            response = parse_response(body)
        except ProtocolError:
            return tracked
        result = response.result
        if response.error is not None:
            if tracked is not None:
                tracked.state, tracked.notice = TaskState.FAILED, response.error.message
                tracked.done.set()
            return tracked
        if isinstance(result, Task):
            with self._lock:
                tracked = tracked or self._tasks.get(result.id) or _Tracked(url=url, task_id=result.id)
                self._tasks[result.id] = tracked
            tracked.state = result.status.state
            for artifact in result.artifacts:
                self._collect(tracked, artifact.parts)
            if result.status.message is not None:
                tracked.notice = result.status.message.text()
        elif isinstance(result, Message):                     # a message-only stream
            with self._lock:
                tracked = tracked or _Tracked(url=url, task_id=result.task_id or result.message_id)
                self._tasks[tracked.task_id] = tracked
            tracked.state = TaskState.COMPLETED
            self._collect(tracked, result.parts)
        elif isinstance(result, StatusUpdate) and tracked is not None:
            tracked.state = result.status.state
            if result.status.message is not None:
                tracked.notice = result.status.message.text()
        elif isinstance(result, ArtifactUpdate) and tracked is not None:
            self._collect(tracked, result.artifact.parts)
        if tracked is not None and _settled(tracked.state):
            tracked.done.set()
        return tracked

    @staticmethod
    def _collect(tracked: _Tracked, parts: list[Part]) -> None:
        """Add new content (a snapshot repeats what came before, so skip duplicates)."""
        for part in parts:
            if part.kind == "text" and part.text and part.text not in tracked.texts:
                tracked.texts.append(part.text)
            elif part.kind == "data" and part.data not in tracked.data:
                tracked.data.append(part.data)

    def poll(self, task_id: str) -> ClientResult:
        """GetTask: the task's current state (an explicit dependency on it)."""
        with self._lock:
            tracked = self._tasks.get(task_id)
        if tracked is None:
            return ClientResult(TaskState.UNSPECIFIED, task_id=task_id, notice=f"unknown task {task_id}")
        try:
            self._apply(tracked, tracked.url,
                        self._send(tracked.url, Request.get_task(task_id).to_bytes(), version_headers()))
        except ConnectionError:
            pass
        return self._snapshot(tracked)

    def wait_task(self, task_id: str, timeout: float = 60.0) -> ClientResult:
        """Wait (up to `timeout`) until the task has settled; return what is known."""
        with self._lock:
            tracked = self._tasks.get(task_id)
        if tracked is None:
            return ClientResult(TaskState.UNSPECIFIED, task_id=task_id, notice=f"unknown task {task_id}")
        if not tracked.done.is_set():
            # Asking is an explicit dependency on the task: on a monitored host, a held
            # task is resolved now rather than when its stall budget runs out.
            self.poll(task_id)
        deadline = time.monotonic() + timeout
        while not tracked.done.wait(timeout=0.25):
            if time.monotonic() > deadline:
                break
        return self._snapshot(tracked)

    @staticmethod
    def _snapshot(t: _Tracked) -> ClientResult:
        return ClientResult(t.state, "\n".join(t.texts), list(t.data), t.task_id, t.notice)
