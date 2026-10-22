"""A2A (Agent2Agent) protocol v1.0 wire types, JSON-RPC binding (specification 1.0.1).

A2A is JSON-RPC 2.0 over HTTP. The monitor never interprets an agent's intent from
these messages; it needs to know three things about every request it intercepts:
who it goes to (the URL), whether the caller blocks on the answer (SendMessage) or
streams it (SendStreamingMessage), and what content leaves (the message parts).
Responses and stream events are the callee's content travelling back.

The data model follows the normative `specification/a2a.proto` of A2A v1.0.1
(package lf.a2a.v1) in its ProtoJSON form: camelCase fields, enums as their names
(TASK_STATE_COMPLETED, ROLE_USER), one `Part` with exactly one of text / raw / url /
data, and oneof wrappers for results (SendMessageResponse: {"task"} | {"message"};
StreamResponse additionally {"statusUpdate"} | {"artifactUpdate"}; GetTask and
CancelTask return the Task itself). Every request carries the service parameter
`A2A-Version: 1.0`; a request without it is a v0.3 request (spec 3.6.2), which this
implementation does not speak (VersionNotSupportedError).

Parsing is strict on purpose: the enforcement point decides on what it parsed, so
it must parse exactly what the receiving agent will.
"""
from __future__ import annotations

import base64
import binascii
import json
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

JSONRPC = "2.0"
A2A_VERSION = "1.0"                 # Major.Minor of the specification (patch versions are not negotiated)
VERSION_HEADER = "a2a-version"      # service parameter, as an HTTP header (case-insensitive)
PROTOCOL_BINDING = "JSONRPC"
ERROR_DOMAIN = "a2a-protocol.org"


class Method(str, Enum):
    SEND = "SendMessage"                         # caller blocks (unless returnImmediately)
    STREAM = "SendStreamingMessage"              # SSE stream of StreamResponse events
    GET_TASK = "GetTask"
    LIST_TASKS = "ListTasks"
    CANCEL_TASK = "CancelTask"
    SUBSCRIBE = "SubscribeToTask"                # SSE stream for an existing task
    CREATE_PUSH_CONFIG = "CreateTaskPushNotificationConfig"
    GET_PUSH_CONFIG = "GetTaskPushNotificationConfig"
    LIST_PUSH_CONFIGS = "ListTaskPushNotificationConfigs"
    DELETE_PUSH_CONFIG = "DeleteTaskPushNotificationConfig"
    GET_EXTENDED_CARD = "GetExtendedAgentCard"

    @classmethod
    def parse(cls, name: str) -> "Method | None":
        try:
            return cls(name)
        except ValueError:
            return None

    @property
    def streams(self) -> bool:
        return self in (Method.STREAM, Method.SUBSCRIBE)

    @property
    def push_config(self) -> bool:
        return self in (Method.CREATE_PUSH_CONFIG, Method.GET_PUSH_CONFIG, Method.LIST_PUSH_CONFIGS,
                        Method.DELETE_PUSH_CONFIG)


class TaskState(str, Enum):
    UNSPECIFIED = "TASK_STATE_UNSPECIFIED"
    SUBMITTED = "TASK_STATE_SUBMITTED"
    WORKING = "TASK_STATE_WORKING"
    COMPLETED = "TASK_STATE_COMPLETED"
    FAILED = "TASK_STATE_FAILED"
    CANCELED = "TASK_STATE_CANCELED"
    INPUT_REQUIRED = "TASK_STATE_INPUT_REQUIRED"
    REJECTED = "TASK_STATE_REJECTED"
    AUTH_REQUIRED = "TASK_STATE_AUTH_REQUIRED"

    @classmethod
    def parse(cls, raw: Any) -> "TaskState":
        try:
            return cls(str(raw))
        except ValueError:
            return cls.UNSPECIFIED

    @property
    def is_final(self) -> bool:
        """Terminal: the task accepts no further messages; a stream closes."""
        return self in _TERMINAL

    @property
    def is_interrupted(self) -> bool:
        """The agent waits for the caller; a blocking SendMessage returns."""
        return self in (TaskState.INPUT_REQUIRED, TaskState.AUTH_REQUIRED)

    @property
    def short(self) -> str:
        """For people and models: 'completed', 'input-required'."""
        return self.value.removeprefix("TASK_STATE_").lower().replace("_", "-")


_TERMINAL = {TaskState.COMPLETED, TaskState.FAILED, TaskState.CANCELED, TaskState.REJECTED}
_STATES = {s.value for s in TaskState}


class Role(str, Enum):
    UNSPECIFIED = "ROLE_UNSPECIFIED"
    USER = "ROLE_USER"
    AGENT = "ROLE_AGENT"


class ErrorCode(int, Enum):
    PARSE_ERROR = -32700
    INVALID_REQUEST = -32600
    METHOD_NOT_FOUND = -32601
    INVALID_PARAMS = -32602
    INTERNAL_ERROR = -32603
    TASK_NOT_FOUND = -32001
    TASK_NOT_CANCELABLE = -32002
    PUSH_NOTIFICATION_NOT_SUPPORTED = -32003
    UNSUPPORTED_OPERATION = -32004
    CONTENT_TYPE_NOT_SUPPORTED = -32005
    INVALID_AGENT_RESPONSE = -32006
    EXTENDED_AGENT_CARD_NOT_CONFIGURED = -32007
    EXTENSION_SUPPORT_REQUIRED = -32008
    VERSION_NOT_SUPPORTED = -32009


def new_id(prefix: str = "") -> str:
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def utc_now() -> str:
    """ISO 8601, UTC, millisecond precision (spec 5.6.1)."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ProtocolError(ValueError):
    """The body is not a well-formed A2A v1.0 JSON-RPC message."""

    def __init__(self, message: str, code: int = ErrorCode.INVALID_REQUEST) -> None:
        super().__init__(message)
        self.code = int(code)


# --- content ---------------------------------------------------------------
_CONTENT = ("text", "raw", "url", "data")


@dataclass(slots=True)
class Part:
    """One content part. `kind` names the member of the proto oneof that is set."""
    kind: str                                    # "text" | "raw" | "url" | "data"
    text: str | None = None
    raw: bytes | None = None
    url: str | None = None
    data: Any = None                             # any JSON value
    filename: str | None = None
    media_type: str | None = None
    metadata: dict[str, Any] | None = None

    @classmethod
    def from_text(cls, text: str) -> "Part":
        return cls(kind="text", text=text)

    @classmethod
    def from_data(cls, data: Any) -> "Part":
        return cls(kind="data", data=data, media_type="application/json")

    @classmethod
    def from_url(cls, url: str, *, filename: str | None = None, media_type: str | None = None) -> "Part":
        return cls(kind="url", url=url, filename=filename, media_type=media_type)

    @classmethod
    def from_raw(cls, raw: bytes, *, filename: str | None = None, media_type: str | None = None) -> "Part":
        return cls(kind="raw", raw=raw, filename=filename, media_type=media_type)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any]
        if self.kind == "text":
            d = {"text": self.text or ""}
        elif self.kind == "raw":
            d = {"raw": base64.b64encode(self.raw or b"").decode("ascii")}
        elif self.kind == "url":
            d = {"url": self.url or ""}
        else:
            d = {"data": self.data}
        if self.filename:
            d["filename"] = self.filename
        if self.media_type:
            d["mediaType"] = self.media_type
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: Any) -> "Part":
        if not isinstance(d, dict):
            raise ProtocolError("a part must be an object", ErrorCode.INVALID_PARAMS)
        present = [k for k in _CONTENT if k in d]
        if len(present) != 1:
            raise ProtocolError(f"a part sets exactly one of {', '.join(_CONTENT)} (got {present or 'none'})",
                                ErrorCode.INVALID_PARAMS)
        kind = present[0]
        p = cls(kind=kind, filename=_opt_str(d.get("filename")), media_type=_opt_str(d.get("mediaType")),
                metadata=d.get("metadata") if isinstance(d.get("metadata"), dict) else None)
        if kind == "text":
            p.text = _str_field(d["text"], "part.text")
        elif kind == "url":
            p.url = _str_field(d["url"], "part.url")
        elif kind == "raw":
            try:
                p.raw = base64.b64decode(_str_field(d["raw"], "part.raw"), validate=True)
            except (binascii.Error, ValueError):
                raise ProtocolError("part.raw is not valid base64", ErrorCode.INVALID_PARAMS) from None
        else:
            p.data = d["data"]
        return p

    def as_text(self) -> str:
        """Everything this part carries, as text (what leaves the boundary)."""
        if self.kind == "text":
            return self.text or ""
        if self.kind == "data":
            return json.dumps(self.data, ensure_ascii=False, sort_keys=True)
        label = " ".join(x for x in (self.filename, self.media_type) if x)
        if self.kind == "url":
            return f"{label} {self.url or ''}".strip()
        return f"{label} {(self.raw or b'').decode('utf-8', errors='replace')}".strip()


def _opt_str(v: Any) -> str | None:
    return v if isinstance(v, str) and v else None


def _str_field(v: Any, name: str) -> str:
    if not isinstance(v, str):
        raise ProtocolError(f"{name} must be a string", ErrorCode.INVALID_PARAMS)
    return v


def _parts(v: Any, where: str, *, required: bool = True) -> list[Part]:
    if v is None and not required:
        return []
    if not isinstance(v, list) or (required and not v):
        raise ProtocolError(f"{where}.parts must be a non-empty list", ErrorCode.INVALID_PARAMS)
    return [Part.from_dict(p) for p in v]


@dataclass(slots=True)
class Message:
    role: str                                  # "user" (the caller) | "agent" (the callee)
    parts: list[Part]
    message_id: str = field(default_factory=lambda: new_id("msg-"))
    context_id: str | None = None
    task_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    extensions: list[str] = field(default_factory=list)
    reference_task_ids: list[str] = field(default_factory=list)

    @classmethod
    def user_text(cls, text: str, **kw: Any) -> "Message":
        return cls(role="user", parts=[Part.from_text(text)], **kw)

    @classmethod
    def agent_text(cls, text: str, **kw: Any) -> "Message":
        return cls(role="agent", parts=[Part.from_text(text)], **kw)

    def text(self) -> str:
        return "\n".join(p.text or "" for p in self.parts if p.kind == "text")

    def data(self) -> list[Any]:
        return [p.data for p in self.parts if p.kind == "data"]

    def content_text(self) -> str:
        return "\n".join(p.as_text() for p in self.parts)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"messageId": self.message_id,
                             "role": (Role.AGENT if self.role == "agent" else Role.USER).value,
                             "parts": [p.to_dict() for p in self.parts]}
        if self.context_id:
            d["contextId"] = self.context_id
        if self.task_id:
            d["taskId"] = self.task_id
        if self.metadata:
            d["metadata"] = self.metadata
        if self.extensions:
            d["extensions"] = list(self.extensions)
        if self.reference_task_ids:
            d["referenceTaskIds"] = list(self.reference_task_ids)
        return d

    @classmethod
    def from_dict(cls, d: Any, *, strict: bool = True) -> "Message":
        """`strict` (a request's message): role and messageId must be set, as the proto
        requires. Messages inside a response (a status message, task history) are
        read leniently: other implementations' examples omit the id there."""
        if not isinstance(d, dict):
            raise ProtocolError("a message must be an object", ErrorCode.INVALID_PARAMS)
        try:
            role = Role(d.get("role", Role.AGENT.value if not strict else None))
        except ValueError:
            raise ProtocolError(f"message.role must be ROLE_USER or ROLE_AGENT, got {d.get('role')!r}",
                                ErrorCode.INVALID_PARAMS) from None
        if role is Role.UNSPECIFIED and strict:
            raise ProtocolError("message.role is unspecified", ErrorCode.INVALID_PARAMS)
        mid = d.get("messageId")
        if not isinstance(mid, str) or not mid:
            if strict:
                raise ProtocolError("message.messageId is required", ErrorCode.INVALID_PARAMS)
            mid = new_id("msg-")
        return cls(role="agent" if role is Role.AGENT else "user",
                   parts=_parts(d.get("parts"), "message"), message_id=mid,
                   context_id=_opt_str(d.get("contextId")), task_id=_opt_str(d.get("taskId")),
                   metadata=dict(d.get("metadata") or {}),
                   extensions=[str(x) for x in d.get("extensions") or []],
                   reference_task_ids=[str(x) for x in d.get("referenceTaskIds") or []])


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
    def from_dict(cls, d: Any) -> "TaskStatus":
        if not isinstance(d, dict):
            raise ProtocolError("a task status must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        state, m = d.get("state"), d.get("message")
        if not isinstance(state, str) or state not in _STATES:
            # enum names only (ProtoJSON's canonical form): an unknown or v0.3 state
            # ("completed") is not a v1.0 response
            raise ProtocolError(f"unknown task state {state!r}", ErrorCode.INVALID_AGENT_RESPONSE)
        return cls(state=TaskState(state),
                   message=Message.from_dict(m, strict=False) if isinstance(m, dict) else None,
                   timestamp=_opt_str(d.get("timestamp")))


@dataclass(slots=True)
class Artifact:
    parts: list[Part]
    artifact_id: str = field(default_factory=lambda: new_id("art-"))
    name: str | None = None
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    extensions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"artifactId": self.artifact_id, "parts": [p.to_dict() for p in self.parts]}
        if self.name:
            d["name"] = self.name
        if self.description:
            d["description"] = self.description
        if self.metadata:
            d["metadata"] = self.metadata
        if self.extensions:
            d["extensions"] = list(self.extensions)
        return d

    @classmethod
    def from_dict(cls, d: Any) -> "Artifact":
        if not isinstance(d, dict):
            raise ProtocolError("an artifact must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        return cls(parts=_parts(d.get("parts"), "artifact"),
                   artifact_id=str(d.get("artifactId") or new_id("art-")),
                   name=_opt_str(d.get("name")), description=_opt_str(d.get("description")),
                   metadata=dict(d.get("metadata") or {}),
                   extensions=[str(x) for x in d.get("extensions") or []])

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
        d: dict[str, Any] = {"id": self.id, "contextId": self.context_id, "status": self.status.to_dict()}
        if self.artifacts:
            d["artifacts"] = [a.to_dict() for a in self.artifacts]
        if self.history:
            d["history"] = [m.to_dict() for m in self.history]
        if self.metadata:
            d["metadata"] = self.metadata
        return d

    @classmethod
    def from_dict(cls, d: Any) -> "Task":
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or "status" not in d:
            raise ProtocolError("a task needs an id and a status", ErrorCode.INVALID_AGENT_RESPONSE)
        return cls(id=d["id"], context_id=str(d.get("contextId") or ""),
                   status=TaskStatus.from_dict(d["status"]),
                   artifacts=[Artifact.from_dict(a) for a in d.get("artifacts") or []],
                   history=[Message.from_dict(m, strict=False) for m in d.get("history") or []],
                   metadata=dict(d.get("metadata") or {}))

    def content_text(self) -> str:
        """The callee's content: artifacts plus the status message."""
        chunks = [a.content_text() for a in self.artifacts]
        if self.status.message is not None:
            chunks.append(self.status.message.content_text())
        return "\n".join(c for c in chunks if c)


@dataclass(slots=True)
class StatusUpdate:
    """TaskStatusUpdateEvent (v1.0 has no `final`: the stream closes at a terminal state)."""
    task_id: str
    context_id: str
    status: TaskStatus
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"taskId": self.task_id, "contextId": self.context_id,
                             "status": self.status.to_dict()}
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass(slots=True)
class ArtifactUpdate:
    """TaskArtifactUpdateEvent."""
    task_id: str
    context_id: str
    artifact: Artifact
    append: bool = False
    last_chunk: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"taskId": self.task_id, "contextId": self.context_id,
                             "artifact": self.artifact.to_dict()}
        if self.append:
            d["append"] = True
        if self.last_chunk:
            d["lastChunk"] = True
        if self.metadata:
            d["metadata"] = self.metadata
        return d


@dataclass(slots=True)
class TaskList:
    """ListTasksResponse."""
    tasks: list[Task]
    next_page_token: str = ""
    page_size: int = 0
    total_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"tasks": [t.to_dict() for t in self.tasks], "nextPageToken": self.next_page_token,
                "pageSize": self.page_size, "totalSize": self.total_size}


Result = Task | Message | StatusUpdate | ArtifactUpdate | TaskList


def result_to_dict(res: Result, *, bare: bool = False) -> dict[str, Any]:
    """SendMessageResponse / StreamResponse are oneof wrappers; GetTask and CancelTask
    return the Task itself (`bare`), ListTasks a ListTasksResponse."""
    if isinstance(res, Task):
        return res.to_dict() if bare else {"task": res.to_dict()}
    if isinstance(res, Message):
        return {"message": res.to_dict()}
    if isinstance(res, StatusUpdate):
        return {"statusUpdate": res.to_dict()}
    if isinstance(res, ArtifactUpdate):
        return {"artifactUpdate": res.to_dict()}
    return res.to_dict()


def result_from_dict(d: Any) -> tuple[Result, bool]:
    """(result, bare): which payload of the oneof is set, or a bare Task / task list."""
    if not isinstance(d, dict):
        raise ProtocolError("result must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
    payload = [k for k in ("task", "message", "statusUpdate", "artifactUpdate") if k in d]
    if len(payload) > 1:
        raise ProtocolError("result sets more than one payload", ErrorCode.INVALID_AGENT_RESPONSE)
    if payload == ["task"]:
        return Task.from_dict(d["task"]), False
    if payload == ["message"]:
        return Message.from_dict(d["message"], strict=False), False
    if payload == ["statusUpdate"]:
        s = d["statusUpdate"]
        if not isinstance(s, dict):
            raise ProtocolError("statusUpdate must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        return StatusUpdate(task_id=str(s.get("taskId", "")), context_id=str(s.get("contextId", "")),
                            status=TaskStatus.from_dict(s.get("status")),
                            metadata=dict(s.get("metadata") or {})), False
    if payload == ["artifactUpdate"]:
        a = d["artifactUpdate"]
        if not isinstance(a, dict):
            raise ProtocolError("artifactUpdate must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        return ArtifactUpdate(task_id=str(a.get("taskId", "")), context_id=str(a.get("contextId", "")),
                              artifact=Artifact.from_dict(a.get("artifact")),
                              append=bool(a.get("append", False)), last_chunk=bool(a.get("lastChunk", False)),
                              metadata=dict(a.get("metadata") or {})), False
    if "tasks" in d:
        return TaskList(tasks=[Task.from_dict(t) for t in d.get("tasks") or []],
                        next_page_token=str(d.get("nextPageToken", "")),
                        page_size=int(d.get("pageSize") or 0), total_size=int(d.get("totalSize") or 0)), True
    return Task.from_dict(d), True


def result_text(result: Result) -> str:
    """The content a result carries back to the caller (empty for a bare status)."""
    if isinstance(result, (Task, Message)):
        return result.content_text()
    if isinstance(result, ArtifactUpdate):
        return result.artifact.content_text()
    if isinstance(result, TaskList):
        return "\n".join(t.content_text() for t in result.tasks)
    return result.status.message.content_text() if result.status.message else ""


# --- JSON-RPC envelopes -----------------------------------------------------
@dataclass(slots=True)
class Request:
    method: Method
    params: dict[str, Any]
    id: str | int | None = field(default_factory=lambda: new_id("rpc-"))

    @property
    def message(self) -> Message | None:
        m = self.params.get("message")
        return Message.from_dict(m) if isinstance(m, dict) else None

    @property
    def configuration(self) -> dict[str, Any]:
        c = self.params.get("configuration")
        return c if isinstance(c, dict) else {}

    @property
    def return_immediately(self) -> bool:
        return self.method is Method.SEND and self.configuration.get("returnImmediately") is True

    @property
    def task_id(self) -> str | None:
        v = self.params.get("id")
        return v if isinstance(v, str) and v else None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": JSONRPC, "id": self.id, "method": self.method.value}
        if self.params or self.method is not Method.GET_EXTENDED_CARD:
            d["params"] = self.params
        return d

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=False).encode()

    @classmethod
    def send(cls, message: Message, *, streaming: bool = False, return_immediately: bool = False) -> "Request":
        params: dict[str, Any] = {"message": message.to_dict()}
        if return_immediately and not streaming:
            params["configuration"] = {"returnImmediately": True}
        return cls(method=Method.STREAM if streaming else Method.SEND, params=params)

    @classmethod
    def get_task(cls, task_id: str) -> "Request":
        return cls(method=Method.GET_TASK, params={"id": task_id})

    @classmethod
    def cancel_task(cls, task_id: str) -> "Request":
        return cls(method=Method.CANCEL_TASK, params={"id": task_id})

    @classmethod
    def subscribe(cls, task_id: str) -> "Request":
        return cls(method=Method.SUBSCRIBE, params={"id": task_id})


@dataclass(slots=True)
class RpcError:
    code: int
    message: str
    data: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data:
            d["data"] = self.data
        return d

    @classmethod
    def info(cls, code: ErrorCode, message: str, reason: str, **metadata: str) -> "RpcError":
        """With a google.rpc.ErrorInfo detail, as the JSON-RPC binding recommends."""
        detail: dict[str, Any] = {"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                  "reason": reason, "domain": ERROR_DOMAIN}
        if metadata:
            detail["metadata"] = {k: str(v) for k, v in metadata.items()}
        return cls(int(code), message, [detail])


@dataclass(slots=True)
class Response:
    id: str | int | None
    result: Result | None = None
    error: RpcError | None = None
    bare: bool = False            # a GetTask / CancelTask / ListTasks result (no oneof wrapper)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {"jsonrpc": JSONRPC, "id": self.id}
        if self.error is not None:
            d["error"] = self.error.to_dict()
        else:
            d["result"] = result_to_dict(self.result, bare=self.bare) if self.result is not None else None
        return d

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=False).encode()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Response":
        err = d.get("error")
        if err is not None:
            if not isinstance(err, dict) or not isinstance(err.get("code"), int):
                raise ProtocolError("malformed error object", ErrorCode.INVALID_AGENT_RESPONSE)
            data = err.get("data")
            return cls(id=d.get("id"), error=RpcError(int(err["code"]), str(err.get("message", "")),
                                                      data if isinstance(data, list) else None))
        result, bare = result_from_dict(d.get("result"))
        return cls(id=d.get("id"), result=result, bare=bare)


def parse_request(body: bytes | str | dict[str, Any]) -> Request:
    d = _load(body)
    if d.get("jsonrpc") != JSONRPC or not isinstance(d.get("method"), str):
        raise ProtocolError("not a JSON-RPC 2.0 request", ErrorCode.INVALID_REQUEST)
    method = Method.parse(d["method"])
    if method is None:
        raise ProtocolError(f"unknown A2A v1.0 method {d['method']!r}", ErrorCode.METHOD_NOT_FOUND)
    params = d.get("params", {})
    if not isinstance(params, dict):
        raise ProtocolError("params must be an object", ErrorCode.INVALID_PARAMS)
    if method in (Method.SEND, Method.STREAM) and not isinstance(params.get("message"), dict):
        raise ProtocolError(f"{method.value} needs params.message", ErrorCode.INVALID_PARAMS)
    if method in (Method.GET_TASK, Method.CANCEL_TASK, Method.SUBSCRIBE) and not (
            isinstance(params.get("id"), str) and params["id"]):
        raise ProtocolError(f"{method.value} needs params.id", ErrorCode.INVALID_PARAMS)
    return Request(method=method, params=params, id=d.get("id"))


def parse_response(body: bytes | str | dict[str, Any]) -> Response:
    d = _load(body)
    if d.get("jsonrpc") != JSONRPC or ("result" not in d and "error" not in d):
        raise ProtocolError("not a JSON-RPC 2.0 response", ErrorCode.INVALID_AGENT_RESPONSE)
    return Response.from_dict(d)


def _load(body: bytes | str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(body, dict):
        return body
    try:
        d = json.loads(body)
    except (ValueError, TypeError) as e:
        raise ProtocolError(f"invalid JSON: {e}", ErrorCode.PARSE_ERROR) from None
    if not isinstance(d, dict):
        raise ProtocolError("JSON-RPC message must be an object", ErrorCode.INVALID_REQUEST)
    return d


def error_response(rpc_id: Any, code: int, message: str) -> bytes:
    return Response(id=rpc_id, error=RpcError(int(code), message)).to_bytes()


# --- versioning -------------------------------------------------------------
def requested_version(headers: Mapping[str, str] | None) -> str:
    """The Major.Minor a request asks for; an empty value means 0.3 (spec 3.6.2)."""
    if headers is None:
        return A2A_VERSION
    raw = next((v for k, v in headers.items() if k.lower() == VERSION_HEADER), "")
    parts = str(raw).strip().split(".")
    return ".".join(parts[:2]) if raw and str(raw).strip() else "0.3"


def version_supported(headers: Mapping[str, str] | None) -> bool:
    """`headers` None: an in-process call between components of this implementation."""
    return requested_version(headers) == A2A_VERSION


def version_error(rpc_id: Any, headers: Mapping[str, str] | None) -> bytes:
    asked = requested_version(headers)
    return Response(id=rpc_id, error=RpcError.info(
        ErrorCode.VERSION_NOT_SUPPORTED,
        f"A2A protocol version {asked} is not supported; this agent speaks {A2A_VERSION}",
        "VERSION_NOT_SUPPORTED", requestedVersion=asked, supportedVersions=A2A_VERSION)).to_bytes()


def version_headers() -> dict[str, str]:
    return {VERSION_HEADER: A2A_VERSION}


def rpc_id_of(body: bytes | str | dict[str, Any]) -> Any:
    try:
        return _load(body).get("id")
    except ProtocolError:
        return None


# --- streaming --------------------------------------------------------------
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


# --- discovery ----------------------------------------------------------------
@dataclass(slots=True)
class AgentCard:
    """Discovery document (`/.well-known/agent-card.json`), v1.0 shape."""
    name: str
    url: str
    description: str = ""
    version: str = "0.1.0"
    streaming: bool = True
    skills: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        skills = self.skills or [{"id": self.name, "name": self.name,
                                  "description": self.description or self.name, "tags": [self.name]}]
        return {"name": self.name, "description": self.description or self.name,
                "supportedInterfaces": [{"url": self.url, "protocolBinding": PROTOCOL_BINDING,
                                         "protocolVersion": A2A_VERSION}],
                "version": self.version,
                "capabilities": {"streaming": self.streaming, "pushNotifications": False,
                                 "extendedAgentCard": False},
                "defaultInputModes": ["text/plain", "application/json"],
                "defaultOutputModes": ["text/plain", "application/json"],
                "skills": skills}
