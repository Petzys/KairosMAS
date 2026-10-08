"""Uniform event model.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

class Channel(Enum):
    """Channels for events to be emitted on."""
    FS = "FS"
    NET = "NET"
    TOOL = "TOOL"

class FsOp(str, Enum):
    OPEN = "open"
    READ = "read"
    WRITE = "write"
    UNLINK = "unlink"

class HttpMethod(str, Enum):
    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    DELETE = "DELETE"

class ToolOp(str, Enum):
    CALL = "tool_call"
    RESULT = "tool_result"
@dataclass(frozen=True, slots=True)
class Event:
    """e = (timestamp, channel, operation, subject, object, content, metadata).

    Frozen on purpose: events are an immutable record of what crossed the
    boundary. Branch association (`metadata["branch_id"]`) is attached by
    producing a new event via `with_metadata`, not by mutation.

    `object`  — FS: file path · NET: URL · TOOL: tool name
    `content` — FS: file bytes · NET: HTTP body · TOOL: call args / result
    """
    timestamp: float
    channel: Channel
    operation: str                       # value of FsOp | HttpMethod | ToolOp
    subject: str                         # agent process (prod) | dojo simulator (sim)
    object: str
    content: Any = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def with_metadata(self, **kw: Any) -> Event:
        """Return a copy with metadata updated (e.g. branch_id, call<->result link)."""
        return dataclasses.replace(self, metadata={**self.metadata, **kw})

    @property
    def branch_id(self) -> str | None:
        return self.metadata.get("branch_id")