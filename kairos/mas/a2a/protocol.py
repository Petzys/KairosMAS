"""A2A (Agent2Agent) wire types: the subset the monitor has to understand.

A2A is JSON-RPC 2.0 over HTTP. The monitor never interprets an agent's intent from
these messages; it needs to know three things about every request it intercepts:
who it goes to (the URL), whether the caller blocks on the answer (SendMessage) or
streams it (SendStreamingMessage), and what content leaves (the message parts).
Responses and stream events are the callee's content travelling back.

Serialization follows the v0.3 JSON-RPC binding (`message/send`, `kind`-tagged
parts, lowercase task states). Parsing is lenient towards the v1.0 naming
(`SendMessage`, `SendStreamingMessage`, `TASK_STATE_*`, parts without `kind`), so
the interception point works for agents on either version.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

JSONRPC = "2.0"


class Method(str, Enum):
    SEND = "message/send"                 # SendMessage: caller blocks
    STREAM = "message/stream"             # SendStreamingMessage: SSE stream of updates
    GET_TASK = "tasks/get"
    CANCEL_TASK = "tasks/cancel"
    RESUBSCRIBE = "tasks/resubscribe"

    @classmethod
    def parse(cls, name: str) -> "Method | None":
        return _METHOD_ALIASES.get(name)


_METHOD_ALIASES: dict[str, Method] = {
    "message/send": Method.SEND, "SendMessage": Method.SEND,
    "message/stream": Method.STREAM, "SendStreamingMessage": Method.STREAM,
    "tasks/get": Method.GET_TASK, "GetTask": Method.GET_TASK,
    "tasks/cancel": Method.CANCEL_TASK, "CancelTask": Method.CANCEL_TASK,
    "tasks/resubscribe": Method.RESUBSCRIBE, "SubscribeToTask": Method.RESUBSCRIBE,
    "TaskSubscription": Method.RESUBSCRIBE,
}


class TaskState(str, Enum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    FAILED = "failed"
    REJECTED = "rejected"
    AUTH_REQUIRED = "auth-required"
    UNKNOWN = "unknown"

    @classmethod
    def parse(cls, raw: str | None) -> "TaskState":
        if not raw:
            return cls.UNKNOWN
        s = str(raw).strip()
        if s.upper().startswith("TASK_STATE_"):
            s = s[len("TASK_STATE_"):]
        s = s.lower().replace("_", "-")
        if s == "cancelled":
            s = "canceled"
        try:
            return cls(s)
        except ValueError:
            return cls.UNKNOWN

    @property
    def is_final(self) -> bool:
        return self in _FINAL_STATES


_FINAL_STATES = {TaskState.COMPLETED, TaskState.CANCELED, TaskState.FAILED, TaskState.REJECTED}


class ErrorCode(int, Enum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    TASK_NOT_FOUND = -32001
    TASK_NOT_CANCELABLE = -32002
    UNSUPPORTED_OPERATION = -32004


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


# --- content ---------------------------------------------------------------
@dataclass(slots=True)
class Part:
    kind: str                       # "text" | "data" | "file"
    text: str | None = None
    data: dict[str, Any] | None = None
    file: dict[str, Any] | None = None

    @classmethod
    def from_text(cls, text: str) -> "Part":
        return cls(kind="text", text=text)

    @classmethod
    def from_data(cls, data: dict[str, Any]) -> "Part":
        return cls(kind="data", data=data)

    def to_dict(self) -> dict[str, Any]:
        if self.kind == "text":
            return {"kind": "text", "text": self.text or ""}
        if self.kind == "data":
            return {"kind": "data", "data": self.data or {}}
        return {"kind": "file", "file": self.file or {}}

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Part":
        kind = d.get("kind") or d.get("type")
        if kind is None:   # v1.0: a oneof without a discriminator
            kind = "text" if "text" in d else "data" if "data" in d else "file"
        if kind == "text":
            return cls(kind="text", text=str(d.get("text", "")))
        if kind == "data":
            data = d.get("data")
            return cls(kind="data", data=data if isinstance(data, dict) else {"value": data})
        return cls(kind="file", file=d.get("file") or {})

    def as_text(self) -> str:
        """Everything this part carries, as text (what leaves the boundary)."""
        if self.kind == "text":
            return self.text or ""
        if self.kind == "data":
            return json.dumps(self.data or {}, ensure_ascii=False, sort_keys=True)
        f = self.file or {}
        return " ".join(str(f[k]) for k in ("name", "uri", "bytes") if f.get(k))


@dataclass(slots=True)
class Message:
    role: str                                  # "user" (caller) | "agent" (callee)
    parts: list[Part]
    message_id: str = field(default_factory=lambda: new_id("msg-"))
    context_id: str | None = None
    task_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def user_text(cls, text: str, **kw: Any) -> "Message":
        return cls(role="user", parts=[Part.from_text(text)], **kw)

    @classmethod
    def agent_text(cls, text: str, **kw: Any) -> "Message":
        return cls(role="agent", parts=[Part.from_text(text)], **kw)

    def text(self) -> str:
        return "\n".join(p.text or "" for p in self.parts if p.kind == "text")

    def data(self) -> list[dict[str, Any]]:
        return [p.data or {} for p in self.parts if p.kind == "data"]

    def content_text(self) -> str:
        return "\n".join(p.as_text() for p in self.parts)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": "message", "role": self.role,
                             "parts": [p.to_dict() for p in self.parts],
                             "messageId": self.message_id}
        if self.context_id:
            d["contextId"] = self.context_id
        if self.task_id:
            d["taskId"] = self.task_id
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Message":
        role = str(d.get("role", "user")).lower().removeprefix("role_")
        return cls(
            role="agent" if role in ("agent", "assistant") else "user",
            parts=[Part.from_dict(p) for p in d.get("parts") or d.get("content") or []],
            message_id=str(d.get("messageId") or d.get("message_id") or new_id("msg-")),
            context_id=d.get("contextId") or d.get("context_id"),
            task_id=d.get("taskId") or d.get("task_id"),
            metadata=dict(d.get("metadata") or {}),
        )


@dataclass(slots=True)
class TaskStatus:
    state: TaskState
    message: Message | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"state": self.state.value}
        if self.message is not None:
            d["message"] = self.message.to_dict()
        if self.timestamp:
            d["timestamp"] = self.timestamp
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "TaskStatus":
        m = d.get("message") or d.get("update")
        return cls(state=TaskState.parse(d.get("state")),
                   message=Message.from_dict(m) if isinstance(m, dict) else None,
                   timestamp=d.get("timestamp"))


@dataclass(slots=True)
class Artifact:
    parts: list[Part]
    artifact_id: str = field(default_factory=lambda: new_id("art-"))
    name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"artifactId": self.artifact_id, "parts": [p.to_dict() for p in self.parts]}
        if self.name:
            d["name"] = self.name
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Artifact":
        return cls(parts=[Part.from_dict(p) for p in d.get("parts") or []],
                   artifact_id=str(d.get("artifactId") or d.get("artifact_id") or new_id("art-")),
                   name=d.get("name"))

    def content_text(self) -> str:
        return "\n".join(p.as_text() for p in self.parts)


@dataclass(slots=True)
class Task:
    id: str
    context_id: str
    status: TaskStatus
    artifacts: list[Artifact] = field(default_factory=list)
    history: list[Message] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"kind": "task", "id": self.id, "contextId": self.context_id,
                             "status": self.status.to_dict()}
        if self.artifacts:
            d["artifacts"] = [a.to_dict() for a in self.artifacts]
        if self.history:
            d["history"] = [m.to_dict() for m in self.history]
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Task":
        return cls(id=str(d.get("id", "")), context_id=str(d.get("contextId") or d.get("context_id") or ""),
                   status=TaskStatus.from_dict(d.get("status") or {}),
                   artifacts=[Artifact.from_dict(a) for a in d.get("artifacts") or []],
                   history=[Message.from_dict(m) for m in d.get("history") or []],
                   metadata=dict(d.get("metadata") or {}))

    def content_text(self) -> str:
        """The callee's content: artifacts plus the final status message."""
        chunks = [a.content_text() for a in self.artifacts]
        if self.status.message is not None:
            chunks.append(self.status.message.content_text())
        return "\n".join(c for c in chunks if c)


@dataclass(slots=True)
class StatusUpdate:
    task_id: str
    context_id: str
    status: TaskStatus
    final: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "status-update", "taskId": self.task_id, "contextId": self.context_id,
                "status": self.status.to_dict(), "final": self.final}


@dataclass(slots=True)
class ArtifactUpdate:
    task_id: str
    context_id: str
    artifact: Artifact
    last_chunk: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {"kind": "artifact-update", "taskId": self.task_id, "contextId": self.context_id,
                "artifact": self.artifact.to_dict(), "lastChunk": self.last_chunk}


Result = Task | Message | StatusUpdate | ArtifactUpdate


def result_from_dict(d: dict[str, Any]) -> Result:
    kind = d.get("kind")
    if kind == "task" or (kind is None and "status" in d and "id" in d):
        return Task.from_dict(d)
    if kind == "status-update":
        return StatusUpdate(task_id=str(d.get("taskId", "")), context_id=str(d.get("contextId", "")),
                            status=TaskStatus.from_dict(d.get("status") or {}),
                            final=bool(d.get("final", False)))
    if kind == "artifact-update":
        return ArtifactUpdate(task_id=str(d.get("taskId", "")), context_id=str(d.get("contextId", "")),
                              artifact=Artifact.from_dict(d.get("artifact") or {}),
                              last_chunk=bool(d.get("lastChunk", True)))
    return Message.from_dict(d)


def result_text(result: Result) -> str:
    """The content a result carries back to the caller (empty for a bare status)."""
    if isinstance(result, Task):
        return result.content_text()
    if isinstance(result, Message):
        return result.content_text()
    if isinstance(result, ArtifactUpdate):
        return result.artifact.content_text()
    return result.status.message.content_text() if result.status.message else ""


# --- JSON-RPC envelopes -----------------------------------------------------
@dataclass(slots=True)
class Request:
    method: Method
    params: dict[str, Any]
    id: str | int | None = field(default_factory=lambda: new_id("rpc-"))
    raw_method: str | None = None

    @property
    def message(self) -> Message | None:
        m = self.params.get("message") or self.params.get("request")
        return Message.from_dict(m) if isinstance(m, dict) else None

    @property
    def task_id(self) -> str | None:
        v = self.params.get("id") or self.params.get("taskId") or self.params.get("name")
        return str(v).removeprefix("tasks/") if v else None

    def to_dict(self) -> dict[str, Any]:
        return {"jsonrpc": JSONRPC, "id": self.id, "method": self.raw_method or self.method.value,
                "params": self.params}

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=False).encode()

    @classmethod
    def send(cls, message: Message, *, streaming: bool = False, blocking: bool = True) -> "Request":
        params: dict[str, Any] = {"message": message.to_dict()}
        if not streaming:
            params["configuration"] = {"blocking": blocking}
        return cls(method=Method.STREAM if streaming else Method.SEND, params=params)

    @classmethod
    def get_task(cls, task_id: str) -> "Request":
        return cls(method=Method.GET_TASK, params={"id": task_id})


@dataclass(slots=True)
class RpcError:
    code: int
    message: str
    data: Any = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data is not None:
            d["data"] = self.data
        return d


@dataclass(slots=True)
class Response:
    id: str | int | None
    result: Result | None = None
    error: RpcError | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": JSONRPC, "id": self.id}
        if self.error is not None:
            d["error"] = self.error.to_dict()
        else:
            d["result"] = self.result.to_dict() if self.result is not None else None
        return d

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=False).encode()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Response":
        err = d.get("error")
        res = d.get("result")
        return cls(id=d.get("id"),
                   result=result_from_dict(res) if isinstance(res, dict) else None,
                   error=RpcError(int(err.get("code", ErrorCode.INTERNAL_ERROR)), str(err.get("message", "")),
                                  err.get("data")) if isinstance(err, dict) else None)


class ProtocolError(ValueError):
    """The body is not a well-formed A2A JSON-RPC message."""


def parse_request(body: bytes | str | dict[str, Any]) -> Request:
    d = _load(body)
    if d.get("jsonrpc") != JSONRPC or "method" not in d:
        raise ProtocolError("not a JSON-RPC 2.0 request")
    raw = str(d["method"])
    method = Method.parse(raw)
    if method is None:
        raise ProtocolError(f"unknown A2A method {raw!r}")
    params = d.get("params")
    if not isinstance(params, dict):
        raise ProtocolError("params must be an object")
    return Request(method=method, params=params, id=d.get("id"), raw_method=raw)


def parse_response(body: bytes | str | dict[str, Any]) -> Response:
    d = _load(body)
    if d.get("jsonrpc") != JSONRPC or ("result" not in d and "error" not in d):
        raise ProtocolError("not a JSON-RPC 2.0 response")
    return Response.from_dict(d)


def _load(body: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(body, dict):
        return body
    try:
        d = json.loads(body)
    except (ValueError, TypeError) as e:
        raise ProtocolError(f"invalid JSON: {e}") from None
    if not isinstance(d, dict):
        raise ProtocolError("JSON-RPC message must be an object")
    return d


def sse_event(response: Response) -> bytes:
    """One server-sent event carrying a JSON-RPC response (streaming methods)."""
    return b"data: " + response.to_bytes() + b"\n\n"


def parse_sse(stream: bytes | str) -> list[Response]:
    text = stream.decode() if isinstance(stream, bytes) else stream
    out: list[Response] = []
    for block in text.split("\n\n"):
        data = "".join(line[5:].strip() for line in block.splitlines() if line.startswith("data:"))
        if data:
            out.append(parse_response(data))
    return out


@dataclass(slots=True)
class AgentCard:
    """Discovery document (`/.well-known/agent-card.json`)."""
    name: str
    url: str
    description: str = ""
    version: str = "0.1.0"
    streaming: bool = True
    skills: list[dict[str, Any]] = field(default_factory=list)
    protocol_version: str = "0.3.0"

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "description": self.description, "url": self.url,
                "version": self.version, "protocolVersion": self.protocol_version,
                "capabilities": {"streaming": self.streaming},
                "defaultInputModes": ["text/plain", "application/json"],
                "defaultOutputModes": ["text/plain", "application/json"],
                "skills": self.skills}
