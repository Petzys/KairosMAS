# tests/test_flowgraph.py
"""Phase 1: FlowGraph records structure; trace_to is honestly deferred."""
import pytest

from kairos.core.events import Channel, Event, FsOp, HttpMethod, ToolOp
from kairos.core.flowgraph import FlowGraph


def _result(tool, content):
    return Event(1.0, Channel.TOOL, ToolOp.RESULT.value, "agent", tool, content)


def _call(tool, **args):
    return Event(2.0, Channel.TOOL, ToolOp.CALL.value, "agent", tool, dict(args))


def test_inbound_edge_points_artifact_to_actor() -> None:
    g = FlowGraph()
    g.record(_result("read_file", {"recipient": "X"}))
    src, dst, _ = g.edges()[0]
    assert src == "tool:read_file" and dst == "actor:agent"   # data flows IN


def test_outbound_edge_points_actor_to_artifact() -> None:
    g = FlowGraph()
    g.record(_call("send_money", recipient="X"))
    src, dst, _ = g.edges()[0]
    assert src == "actor:agent" and dst == "tool:send_money"  # data flows OUT


def test_channels_namespace_nodes() -> None:
    g = FlowGraph()
    g.record(Event(1.0, Channel.FS, FsOp.READ.value, "agent", "/data/bill.txt", "..."))
    g.record(Event(2.0, Channel.NET, HttpMethod.GET.value, "agent", "https://x/y", None))
    assert "file:/data/bill.txt" in g.nodes
    assert "net:https://x/y" in g.nodes


def test_events_preserved_on_edges() -> None:
    g = FlowGraph()
    g.record(_call("send_money", recipient="X"))
    assert g.events()[0].object == "send_money"


def test_trace_to_is_deferred() -> None:
    g = FlowGraph()
    with pytest.raises(NotImplementedError, match="Phase 2"):
        g.trace_to("tool:send_money")