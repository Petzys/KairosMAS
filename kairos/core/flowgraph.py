"""FlowGraph: directed graph of actors/artifacts over a session
"""
from __future__ import annotations

from kairos.core.events import Channel, Event, FsOp, ToolOp

class FlowGraph:
    def __init__(self) -> None:
        self._nodes: set[str] = set()
        self._edges: list[tuple[str, str, Event]] = []   # (src_node, dst_node, event)

    # --- construction ------------------------------------------------------
    def record(self, event: Event) -> None:
        """Add the nodes and edge implied by `event`.

        Direction encodes data flow:
          inbound  (tool_result / FS read): artifact -> agent  (data enters)
          outbound (tool_call / NET / FS write): agent -> artifact (data leaves)
        The agent is the implicit hub; we model the artifact node and the
        subject, and link them in the flow direction.
        """
        artifact = self._artifact_node(event)
        subject = f"actor:{event.subject}"
        self._nodes.add(artifact)
        self._nodes.add(subject)

        if self._is_inbound(event):
            self._edges.append((artifact, subject, event))
        else:
            self._edges.append((subject, artifact, event))

    def _artifact_node(self, event: Event) -> str:
        if event.channel is Channel.TOOL:
            return f"tool:{event.object}"
        if event.channel is Channel.FS:
            return f"file:{event.object}"
        if event.channel is Channel.NET:
            return f"net:{event.object}"
        return f"obj:{event.object}"

    @staticmethod
    def _is_inbound(event: Event) -> bool:
        if event.channel is Channel.TOOL:
            return event.operation == ToolOp.RESULT.value
        if event.channel is Channel.FS:
            return event.operation in (FsOp.OPEN.value, FsOp.READ.value)
        return False

    # --- read accessors (used by tests)
    @property
    def nodes(self) -> set[str]:
        return set(self._nodes)

    def edges(self) -> list[tuple[str, str, Event]]:
        return list(self._edges)

    def events(self) -> list[Event]:
        return [e for _, _, e in self._edges]

    # --- provenance back-walk (deferred to Phase 2) ------------------------
    def trace_to(self, node: str) -> list[Event]:
        """Provenance path feeding `node` — context for branch resolution.

        Deferred: its only consumer is the judge (Phase 2). Implementing it now
        would be untestable against a real need and risks feeding the judge a
        plausible-but-wrong trace. Build it with the judge.
        """
        raise NotImplementedError("trace_to is Phase 2 (judge context); record() is active")