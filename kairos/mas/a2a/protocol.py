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

Reading guide: the enums (`Method`, `TaskState`, `Role`, `ErrorCode`) come first, then
the content types from the inside out (`Part` -> `Message` -> `TaskStatus`, `Artifact`
-> `Task`, the two stream events, `TaskList`), then how a result is wrapped
(`result_to_dict` / `result_from_dict`), the JSON-RPC envelopes (`Request`,
`Response`, `RpcError`) with their parsers, version negotiation, SSE framing, and the
agent card. Every type has `to_dict` (to the wire) and, where the monitor reads it,
`from_dict` (from the wire, raising `ProtocolError` on anything malformed).
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
    """The JSON-RPC method names of A2A v1.0."""
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
        """The method of that name, or None (v0.3 names such as `message/send` included)."""
        try:
            return cls(name)
        except ValueError:
            return None

    @property
    def streams(self) -> bool:
        """Answered with a server-sent event stream rather than one response."""
        return self in (Method.STREAM, Method.SUBSCRIBE)

    @property
    def push_config(self) -> bool:
        return self in (Method.CREATE_PUSH_CONFIG, Method.GET_PUSH_CONFIG, Method.LIST_PUSH_CONFIGS,
                        Method.DELETE_PUSH_CONFIG)


class TaskState(str, Enum):
    """The state of a task (proto enum TaskState).

    Terminal states end a task for good. Interrupted states (input or auth required)
    wait for the caller: a blocking SendMessage returns there, and a later message
    with the task's id continues it."""
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
        """Lenient: anything unknown becomes UNSPECIFIED. Reading a response from the
        wire does NOT use this: `TaskStatus.from_dict` refuses unknown states."""
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
_STATES = {state.value for state in TaskState}


class Role(str, Enum):
    """Who wrote a message: the caller (USER) or the callee (AGENT)."""
    UNSPECIFIED = "ROLE_UNSPECIFIED"
    USER = "ROLE_USER"
    AGENT = "ROLE_AGENT"


class ErrorCode(int, Enum):
    """JSON-RPC error codes: the standard ones, then A2A's own (spec 5.4)."""
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
    """A fresh random id, e.g. `task-1a2b3c4d5e6f`."""
    return f"{prefix}{uuid.uuid4().hex[:12]}"


def utc_now() -> str:
    """ISO 8601, UTC, millisecond precision (spec 5.6.1)."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


class ProtocolError(ValueError):
    """The body is not a well-formed A2A v1.0 JSON-RPC message. `code` is the
    JSON-RPC error code to answer with."""

    def __init__(self, message: str, code: int = ErrorCode.INVALID_REQUEST) -> None:
        super().__init__(message)
        self.code = int(code)


# --- content ---------------------------------------------------------------
_CONTENT = ("text", "raw", "url", "data")     # the members of Part's `content` oneof


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
        obj: dict[str, Any]
        if self.kind == "text":
            obj = {"text": self.text or ""}
        elif self.kind == "raw":
            # bytes travel as base64 in ProtoJSON
            obj = {"raw": base64.b64encode(self.raw or b"").decode("ascii")}
        elif self.kind == "url":
            obj = {"url": self.url or ""}
        else:
            obj = {"data": self.data}
        if self.filename:
            obj["filename"] = self.filename
        if self.media_type:
            obj["mediaType"] = self.media_type
        if self.metadata:
            obj["metadata"] = self.metadata
        return obj

    @classmethod
    def from_dict(cls, d: Any) -> "Part":
        """Read a part; exactly one content member must be set (it is a oneof)."""
        if not isinstance(d, dict):
            raise ProtocolError("a part must be an object", ErrorCode.INVALID_PARAMS)
        present = [key for key in _CONTENT if key in d]
        if len(present) != 1:
            raise ProtocolError(f"a part sets exactly one of {', '.join(_CONTENT)} (got {present or 'none'})",
                                ErrorCode.INVALID_PARAMS)
        kind = present[0]
        part = cls(kind=kind, filename=_opt_str(d.get("filename")), media_type=_opt_str(d.get("mediaType")),
                   metadata=d.get("metadata") if isinstance(d.get("metadata"), dict) else None)
        if kind == "text":
            part.text = _str_field(d["text"], "part.text")
        elif kind == "url":
            part.url = _str_field(d["url"], "part.url")
        elif kind == "raw":
            try:
                part.raw = base64.b64decode(_str_field(d["raw"], "part.raw"), validate=True)
            except (binascii.Error, ValueError):
                raise ProtocolError("part.raw is not valid base64", ErrorCode.INVALID_PARAMS) from None
        else:
            part.data = d["data"]
        return part

    def as_text(self) -> str:
        """Everything this part carries, as text (what leaves the boundary)."""
        if self.kind == "text":
            return self.text or ""
        if self.kind == "data":
            return json.dumps(self.data, ensure_ascii=False, sort_keys=True)
        # A file's name and media type are content too: they can carry text.
        label = " ".join(value for value in (self.filename, self.media_type) if value)
        if self.kind == "url":
            return f"{label} {self.url or ''}".strip()
        return f"{label} {(self.raw or b'').decode('utf-8', errors='replace')}".strip()


def _opt_str(v: Any) -> str | None:
    """A non-empty string, else None."""
    return v if isinstance(v, str) and v else None


def _str_field(v: Any, name: str) -> str:
    if not isinstance(v, str):
        raise ProtocolError(f"{name} must be a string", ErrorCode.INVALID_PARAMS)
    return v


def _parts(v: Any, where: str, *, required: bool = True) -> list[Part]:
    """The `parts` list of a message or artifact (non-empty when required)."""
    if v is None and not required:
        return []
    if not isinstance(v, list) or (required and not v):
        raise ProtocolError(f"{where}.parts must be a non-empty list", ErrorCode.INVALID_PARAMS)
    return [Part.from_dict(part) for part in v]


@dataclass(slots=True)
class Message:
    """One turn of a conversation: parts written by the caller or the callee.

    `task_id` continues an existing task; `context_id` groups related tasks. Both
    are free text a sender may choose, which is why the enforcement point forwards
    only ids the peer issued itself."""
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
        """The text parts only."""
        return "\n".join(part.text or "" for part in self.parts if part.kind == "text")

    def data(self) -> list[Any]:
        """The data parts' values."""
        return [part.data for part in self.parts if part.kind == "data"]

    def content_text(self) -> str:
        """Every part as text: all the content the message carries."""
        return "\n".join(part.as_text() for part in self.parts)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"messageId": self.message_id,
                               "role": (Role.AGENT if self.role == "agent" else Role.USER).value,
                               "parts": [part.to_dict() for part in self.parts]}
        if self.context_id:
            obj["contextId"] = self.context_id
        if self.task_id:
            obj["taskId"] = self.task_id
        if self.metadata:
            obj["metadata"] = self.metadata
        if self.extensions:
            obj["extensions"] = list(self.extensions)
        if self.reference_task_ids:
            obj["referenceTaskIds"] = list(self.reference_task_ids)
        return obj

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
        message_id = d.get("messageId")
        if not isinstance(message_id, str) or not message_id:
            if strict:
                raise ProtocolError("message.messageId is required", ErrorCode.INVALID_PARAMS)
            message_id = new_id("msg-")
        return cls(role="agent" if role is Role.AGENT else "user",
                   parts=_parts(d.get("parts"), "message"), message_id=message_id,
                   context_id=_opt_str(d.get("contextId")), task_id=_opt_str(d.get("taskId")),
                   metadata=dict(d.get("metadata") or {}),
                   extensions=[str(x) for x in d.get("extensions") or []],
                   reference_task_ids=[str(x) for x in d.get("referenceTaskIds") or []])


@dataclass(slots=True)
class TaskStatus:
    """A task's state, with an optional message from the callee (e.g. why it failed)."""
    state: TaskState
    message: Message | None = None
    timestamp: str | None = None

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"state": self.state.value}
        if self.message is not None:
            obj["message"] = self.message.to_dict()
        if self.timestamp:
            obj["timestamp"] = self.timestamp
        return obj

    @classmethod
    def from_dict(cls, d: Any) -> "TaskStatus":
        if not isinstance(d, dict):
            raise ProtocolError("a task status must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        state, message = d.get("state"), d.get("message")
        if not isinstance(state, str) or state not in _STATES:
            # enum names only (ProtoJSON's canonical form): an unknown or v0.3 state
            # ("completed") is not a v1.0 response
            raise ProtocolError(f"unknown task state {state!r}", ErrorCode.INVALID_AGENT_RESPONSE)
        return cls(state=TaskState(state),
                   message=Message.from_dict(message, strict=False) if isinstance(message, dict) else None,
                   timestamp=_opt_str(d.get("timestamp")))


@dataclass(slots=True)
class Artifact:
    """An output the callee produced for a task (its parts are the result)."""
    parts: list[Part]
    artifact_id: str = field(default_factory=lambda: new_id("art-"))
    name: str | None = None
    description: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    extensions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"artifactId": self.artifact_id, "parts": [part.to_dict() for part in self.parts]}
        if self.name:
            obj["name"] = self.name
        if self.description:
            obj["description"] = self.description
        if self.metadata:
            obj["metadata"] = self.metadata
        if self.extensions:
            obj["extensions"] = list(self.extensions)
        return obj

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
        return "\n".join(part.as_text() for part in self.parts)


@dataclass(slots=True)
class Task:
    """A unit of work at the callee: its status, its artifacts, and its history."""
    id: str
    context_id: str
    status: TaskStatus
    artifacts: list[Artifact] = field(default_factory=list)
    history: list[Message] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"id": self.id, "contextId": self.context_id, "status": self.status.to_dict()}
        if self.artifacts:
            obj["artifacts"] = [artifact.to_dict() for artifact in self.artifacts]
        if self.history:
            obj["history"] = [message.to_dict() for message in self.history]
        if self.metadata:
            obj["metadata"] = self.metadata
        return obj

    @classmethod
    def from_dict(cls, d: Any) -> "Task":
        if not isinstance(d, dict) or not isinstance(d.get("id"), str) or "status" not in d:
            raise ProtocolError("a task needs an id and a status", ErrorCode.INVALID_AGENT_RESPONSE)
        return cls(id=d["id"], context_id=str(d.get("contextId") or ""),
                   status=TaskStatus.from_dict(d["status"]),
                   artifacts=[Artifact.from_dict(artifact) for artifact in d.get("artifacts") or []],
                   history=[Message.from_dict(message, strict=False) for message in d.get("history") or []],
                   metadata=dict(d.get("metadata") or {}))

    def content_text(self) -> str:
        """The callee's content: artifacts plus the status message."""
        chunks = [artifact.content_text() for artifact in self.artifacts]
        if self.status.message is not None:
            chunks.append(self.status.message.content_text())
        return "\n".join(chunk for chunk in chunks if chunk)


@dataclass(slots=True)
class StatusUpdate:
    """TaskStatusUpdateEvent (v1.0 has no `final`: the stream closes at a terminal state)."""
    task_id: str
    context_id: str
    status: TaskStatus
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"taskId": self.task_id, "contextId": self.context_id,
                               "status": self.status.to_dict()}
        if self.metadata:
            obj["metadata"] = self.metadata
        return obj


@dataclass(slots=True)
class ArtifactUpdate:
    """TaskArtifactUpdateEvent: an artifact (or a chunk of one) produced by the task."""
    task_id: str
    context_id: str
    artifact: Artifact
    append: bool = False
    last_chunk: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"taskId": self.task_id, "contextId": self.context_id,
                               "artifact": self.artifact.to_dict()}
        # ProtoJSON omits fields at their default value.
        if self.append:
            obj["append"] = True
        if self.last_chunk:
            obj["lastChunk"] = True
        if self.metadata:
            obj["metadata"] = self.metadata
        return obj


@dataclass(slots=True)
class TaskList:
    """ListTasksResponse."""
    tasks: list[Task]
    next_page_token: str = ""
    page_size: int = 0
    total_size: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {"tasks": [task.to_dict() for task in self.tasks], "nextPageToken": self.next_page_token,
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
    """(result, bare): which payload of the oneof is set, or a bare Task / task list.

    A result that sets more than one payload is refused: two readers could pick
    different ones, and the monitor must read what the receiver will."""
    if not isinstance(d, dict):
        raise ProtocolError("result must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
    payload = [key for key in ("task", "message", "statusUpdate", "artifactUpdate") if key in d]
    if len(payload) > 1:
        raise ProtocolError("result sets more than one payload", ErrorCode.INVALID_AGENT_RESPONSE)
    if payload == ["task"]:
        return Task.from_dict(d["task"]), False
    if payload == ["message"]:
        return Message.from_dict(d["message"], strict=False), False
    if payload == ["statusUpdate"]:
        update = d["statusUpdate"]
        if not isinstance(update, dict):
            raise ProtocolError("statusUpdate must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        return StatusUpdate(task_id=str(update.get("taskId", "")), context_id=str(update.get("contextId", "")),
                            status=TaskStatus.from_dict(update.get("status")),
                            metadata=dict(update.get("metadata") or {})), False
    if payload == ["artifactUpdate"]:
        update = d["artifactUpdate"]
        if not isinstance(update, dict):
            raise ProtocolError("artifactUpdate must be an object", ErrorCode.INVALID_AGENT_RESPONSE)
        return ArtifactUpdate(task_id=str(update.get("taskId", "")), context_id=str(update.get("contextId", "")),
                              artifact=Artifact.from_dict(update.get("artifact")),
                              append=bool(update.get("append", False)),
                              last_chunk=bool(update.get("lastChunk", False)),
                              metadata=dict(update.get("metadata") or {})), False
    if "tasks" in d:
        return TaskList(tasks=[Task.from_dict(task) for task in d.get("tasks") or []],
                        next_page_token=str(d.get("nextPageToken", "")),
                        page_size=int(d.get("pageSize") or 0), total_size=int(d.get("totalSize") or 0)), True
    # No wrapper: a bare Task (the answer to GetTask or CancelTask).
    return Task.from_dict(d), True


def result_text(result: Result) -> str:
    """The content a result carries back to the caller (empty for a bare status)."""
    if isinstance(result, (Task, Message)):
        return result.content_text()
    if isinstance(result, ArtifactUpdate):
        return result.artifact.content_text()
    if isinstance(result, TaskList):
        return "\n".join(task.content_text() for task in result.tasks)
    return result.status.message.content_text() if result.status.message else ""


# --- JSON-RPC envelopes -----------------------------------------------------
@dataclass(slots=True)
class Request:
    """A JSON-RPC request. `params` is kept as received; the properties read the
    fields the monitor needs."""
    method: Method
    params: dict[str, Any]
    id: str | int | None = field(default_factory=lambda: new_id("rpc-"))

    @property
    def message(self) -> Message | None:
        """The message of a SendMessage / SendStreamingMessage (strictly parsed)."""
        message = self.params.get("message")
        return Message.from_dict(message) if isinstance(message, dict) else None

    @property
    def configuration(self) -> dict[str, Any]:
        configuration = self.params.get("configuration")
        return configuration if isinstance(configuration, dict) else {}

    @property
    def return_immediately(self) -> bool:
        """SendMessage that answers at once with the task in progress (the caller polls)."""
        return self.method is Method.SEND and self.configuration.get("returnImmediately") is True

    @property
    def task_id(self) -> str | None:
        """The task a GetTask / CancelTask / SubscribeToTask is about."""
        task_id = self.params.get("id")
        return task_id if isinstance(task_id, str) and task_id else None

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"jsonrpc": JSONRPC, "id": self.id, "method": self.method.value}
        if self.params or self.method is not Method.GET_EXTENDED_CARD:
            obj["params"] = self.params
        return obj

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
    """A JSON-RPC error object. `data` holds structured details (ErrorInfo)."""
    code: int
    message: str
    data: list[dict[str, Any]] | None = None

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"code": self.code, "message": self.message}
        if self.data:
            obj["data"] = self.data
        return obj

    @classmethod
    def info(cls, code: ErrorCode, message: str, reason: str, **metadata: str) -> "RpcError":
        """With a google.rpc.ErrorInfo detail, as the JSON-RPC binding recommends."""
        detail: dict[str, Any] = {"@type": "type.googleapis.com/google.rpc.ErrorInfo",
                                  "reason": reason, "domain": ERROR_DOMAIN}
        if metadata:
            detail["metadata"] = {key: str(value) for key, value in metadata.items()}
        return cls(int(code), message, [detail])


@dataclass(slots=True)
class Response:
    """A JSON-RPC response: a result or an error."""
    id: str | int | None
    result: Result | None = None
    error: RpcError | None = None
    bare: bool = False            # a GetTask / CancelTask / ListTasks result (no oneof wrapper)

    def to_dict(self) -> dict[str, Any]:
        obj: dict[str, Any] = {"jsonrpc": JSONRPC, "id": self.id}
        if self.error is not None:
            obj["error"] = self.error.to_dict()
        else:
            obj["result"] = result_to_dict(self.result, bare=self.bare) if self.result is not None else None
        return obj

    def to_bytes(self) -> bytes:
        return json.dumps(self.to_dict(), ensure_ascii=False).encode()

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Response":
        error = d.get("error")
        if error is not None:
            if not isinstance(error, dict) or not isinstance(error.get("code"), int):
                raise ProtocolError("malformed error object", ErrorCode.INVALID_AGENT_RESPONSE)
            data = error.get("data")
            return cls(id=d.get("id"), error=RpcError(int(error["code"]), str(error.get("message", "")),
                                                      data if isinstance(data, list) else None))
        result, bare = result_from_dict(d.get("result"))
        return cls(id=d.get("id"), result=result, bare=bare)


def parse_request(body: bytes | str | dict[str, Any]) -> Request:
    """Read a request, refusing anything that is not a well-formed A2A v1.0 call.

    The checks here are the minimum the monitor relies on: a known v1.0 method, an
    object as params, a message for the send methods, a task id for the task methods.
    The message itself is parsed (strictly) when it is read."""
    obj = _load(body)
    if obj.get("jsonrpc") != JSONRPC or not isinstance(obj.get("method"), str):
        raise ProtocolError("not a JSON-RPC 2.0 request", ErrorCode.INVALID_REQUEST)
    method = Method.parse(obj["method"])
    if method is None:
        raise ProtocolError(f"unknown A2A v1.0 method {obj['method']!r}", ErrorCode.METHOD_NOT_FOUND)
    params = obj.get("params", {})
    if not isinstance(params, dict):
        raise ProtocolError("params must be an object", ErrorCode.INVALID_PARAMS)
    if method in (Method.SEND, Method.STREAM) and not isinstance(params.get("message"), dict):
        raise ProtocolError(f"{method.value} needs params.message", ErrorCode.INVALID_PARAMS)
    if method in (Method.GET_TASK, Method.CANCEL_TASK, Method.SUBSCRIBE) and not (
            isinstance(params.get("id"), str) and params["id"]):
        raise ProtocolError(f"{method.value} needs params.id", ErrorCode.INVALID_PARAMS)
    return Request(method=method, params=params, id=obj.get("id"))


def parse_response(body: bytes | str | dict[str, Any]) -> Response:
    """Read a response (or one stream event); anything malformed raises ProtocolError."""
    obj = _load(body)
    if obj.get("jsonrpc") != JSONRPC or ("result" not in obj and "error" not in obj):
        raise ProtocolError("not a JSON-RPC 2.0 response", ErrorCode.INVALID_AGENT_RESPONSE)
    return Response.from_dict(obj)


def _load(body: bytes | str | dict[str, Any]) -> dict[str, Any]:
    """The body as a JSON object (a dict is taken as already parsed)."""
    if isinstance(body, dict):
        return body
    try:
        obj = json.loads(body)
    except (ValueError, TypeError) as e:
        raise ProtocolError(f"invalid JSON: {e}", ErrorCode.PARSE_ERROR) from None
    if not isinstance(obj, dict):
        raise ProtocolError("JSON-RPC message must be an object", ErrorCode.INVALID_REQUEST)
    return obj


def error_response(rpc_id: Any, code: int, message: str) -> bytes:
    return Response(id=rpc_id, error=RpcError(int(code), message)).to_bytes()


# --- versioning -------------------------------------------------------------
def requested_version(headers: Mapping[str, str] | None) -> str:
    """The Major.Minor a request asks for; an empty value means 0.3 (spec 3.6.2)."""
    if headers is None:
        # No headers at all: an in-process call from a component of this implementation.
        return A2A_VERSION
    raw = next((value for key, value in headers.items() if key.lower() == VERSION_HEADER), "")
    parts = str(raw).strip().split(".")
    return ".".join(parts[:2]) if raw and str(raw).strip() else "0.3"


def version_supported(headers: Mapping[str, str] | None) -> bool:
    """`headers` None: an in-process call between components of this implementation."""
    return requested_version(headers) == A2A_VERSION


def version_error(rpc_id: Any, headers: Mapping[str, str] | None) -> bytes:
    """The VersionNotSupportedError answer to a request for another version."""
    asked = requested_version(headers)
    return Response(id=rpc_id, error=RpcError.info(
        ErrorCode.VERSION_NOT_SUPPORTED,
        f"A2A protocol version {asked} is not supported; this agent speaks {A2A_VERSION}",
        "VERSION_NOT_SUPPORTED", requestedVersion=asked, supportedVersions=A2A_VERSION)).to_bytes()


def version_headers() -> dict[str, str]:
    """The service parameter every request of this implementation carries."""
    return {VERSION_HEADER: A2A_VERSION}


def rpc_id_of(body: bytes | str | dict[str, Any]) -> Any:
    """The JSON-RPC id of a body, if it has one (to answer even a malformed request)."""
    try:
        return _load(body).get("id")
    except ProtocolError:
        return None


# --- streaming --------------------------------------------------------------
def sse_event(response: Response) -> bytes:
    """One server-sent event carrying a JSON-RPC response (streaming methods)."""
    return b"data: " + response.to_bytes() + b"\n\n"


def parse_sse(stream: bytes | str) -> list[Response]:
    """All events of a complete SSE body, each parsed as a response."""
    text = stream.decode() if isinstance(stream, bytes) else stream
    responses: list[Response] = []
    for block in text.split("\n\n"):
        data = "".join(line[5:].strip() for line in block.splitlines() if line.startswith("data:"))
        if data:
            responses.append(parse_response(data))
    return responses


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
        # The spec requires at least one skill; without any, the agent itself is one.
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
