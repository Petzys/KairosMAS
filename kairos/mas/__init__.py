"""KAIROS for multi-agent systems.

Opaque agents on separate hosts talk to each other over A2A; every agent host has
an enforcement point, every cluster of agents a decision point. Messages inside a
cluster are logged, never stalled; messages that leave a cluster are released like
external requests; every external effect of every agent passes full KAIROS under
labels joined across the messages its work descends from, and the oracle sees the
effect's lineage across agents.

  spec        the system as the principal declares it (agents, clusters, policies)
  causal      per-agent sequence numbers, vector clocks, causal delivery
  policy      release decisions for messages (built on the single-agent engine)
  agent       AgentMonitor: the per-agent state a decision point keeps
  fabric      decision points and their connection (co-located or distributed)
  enforcement EnforcementPoint: the per-host boundary that applies decisions
  oracle      the lineage-aware oracle
  a2a         the A2A protocol (wire types, adapter, minimal server and client)
"""
from kairos.mas.agent import AgentMonitor, MessageRecord, MsgStatus, Outcome
from kairos.mas.enforcement import EnforcementPoint, ToolOutcome
from kairos.mas.fabric import ClusterDecisionPoint, MonitorFabric
from kairos.mas.spec import MASSpec
from kairos.mas.spec_parser import SpecError, dump_spec, load_spec, parse_spec

__all__ = [
    "AgentMonitor", "MessageRecord", "MsgStatus", "Outcome", "EnforcementPoint", "ToolOutcome",
    "ClusterDecisionPoint", "MonitorFabric", "MASSpec", "SpecError", "dump_spec", "load_spec",
    "parse_spec",
]
