"""The multi-agent system as the principal declares it.

Two kinds of policy, disjoint by construction:

  * the AGENT policy says how the agent's data is LABELED: which of its actions are
    revertable, which sources are sensitive (taints) and which are trusted. It is
    the part of a single-agent KAIROS policy that describes the agent's tools.
  * the CLUSTER policy says WHO MAY RECEIVE WHICH DATA: the contact book (peer
    clusters and agents with their clearance, plus external parties), the rules
    that apply at the cluster and the external boundary, and the release knobs.

A cluster is the unit of containment: messages between its members are logged but
never stalled; messages that leave it are released like external requests. Every
external effect of every member passes full KAIROS under its agent's labels and its
cluster's release policy. Only the sending cluster's policy decides; there is no
inbound check.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ada_url import URL

from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.policy.schema import (
    ContactBook, Context, Policy, Resources, SimpleRule, TaintDef, TrustedSource,
)

# Pseudo-actions under which inter-agent messages are matched by cluster rules.
A2A_SEND = "a2a.send"       # a request to another agent
A2A_REPLY = "a2a.reply"     # content returned to a requester
A2A_ACTIONS = (A2A_SEND, A2A_REPLY)


@dataclass(slots=True)
class AgentLabels:
    """The agent policy (labeling only)."""
    revertable: list[str] = field(default_factory=list)
    non_revertable: list[str] = field(default_factory=list)
    taints: list[TaintDef] = field(default_factory=list)
    trusted_sources: list[TrustedSource] = field(default_factory=list)

    @property
    def actions(self) -> set[str]:
        return set(self.revertable) | set(self.non_revertable)


@dataclass(slots=True)
class AgentSpec:
    id: str
    cluster: str
    endpoint: str
    description: str = ""
    labels: AgentLabels = field(default_factory=AgentLabels)


@dataclass(slots=True)
class PeerEntry:
    """A contact-book entry for agents of the system: a whole cluster (its default
    clearance) or one agent (an override). max_level None = the destination
    cluster's declared clearance."""
    cluster: str | None = None
    agent: str | None = None
    max_level: Level | None = None


@dataclass(slots=True)
class PeerBook:
    """on_miss for a request to an agent the book does not list. DENY makes the
    listed edges the system's effective topology; REVIEW lets the oracle decide."""
    on_miss: Decision = Decision.REVIEW
    entries: list[PeerEntry] = field(default_factory=list)


@dataclass(slots=True)
class ClusterPolicy:
    default_action: Decision = Decision.REVIEW
    navigational_get: str = "allow"
    # payload identifiers of EXTERNAL effects (the single-agent knob, default off)
    embedded_identifiers: str = "allow"
    # payload identifiers of messages LEAVING the cluster: a link, account or address
    # in a message is a destination for whoever receives it (default on)
    message_identifiers: str = "review"
    # deterministic checks on intra-cluster messages: "annotate" records their result
    # in the causal log for the oracle, never stalls; "off" skips them
    intra_cluster_checks: str = "annotate"
    peers: PeerBook = field(default_factory=PeerBook)
    external: ContactBook | None = None
    rules: list[SimpleRule] = field(default_factory=list)


@dataclass(slots=True)
class ClusterSpec:
    id: str
    clearance: Level = Level.LOW          # default clearance of this cluster as a destination
    description: str = ""
    policy: ClusterPolicy = field(default_factory=ClusterPolicy)


def default_endpoint(agent: str, cluster: str) -> str:
    host = f"{agent}.{cluster}.mas.local".replace("_", "-").lower()
    return f"http://{host}/a2a"


def endpoint_origin(url: str) -> str:
    try:
        return URL(url if "://" in url else f"http://{url}").origin
    except Exception:
        return url


@dataclass(slots=True)
class MASSpec:
    name: str
    entry: str
    agents: dict[str, AgentSpec]
    clusters: dict[str, ClusterSpec]
    description: str = ""
    version: str = "0.1"

    # --- topology -------------------------------------------------------------
    def members(self, cluster: str) -> list[str]:
        return [a.id for a in self.agents.values() if a.cluster == cluster]

    def cluster_of(self, agent: str) -> ClusterSpec:
        return self.clusters[self.agents[agent].cluster]

    def same_cluster(self, a: str, b: str) -> bool:
        return self.agents[a].cluster == self.agents[b].cluster

    def agent_at(self, url: str) -> str | None:
        """The agent whose A2A endpoint `url` addresses (None: not part of the system)."""
        origin = endpoint_origin(url)
        for a in self.agents.values():
            if endpoint_origin(a.endpoint) == origin:
                return a.id
        return None

    def peer_clearance(self, sender: str, dest: str) -> tuple[Level | None, bool]:
        """(clearance, listed) of agent `dest` in the contact book of `sender`'s
        cluster. Intra-cluster destinations are not looked up (never gated)."""
        book = self.cluster_of(sender).policy.peers
        dest_cluster = self.agents[dest].cluster
        for e in book.entries:                      # per-agent override first
            if e.agent == dest:
                return (e.max_level or self.clusters[dest_cluster].clearance), True
        for e in book.entries:
            if e.cluster == dest_cluster:
                return (e.max_level or self.clusters[dest_cluster].clearance), True
        return None, False

    # --- effective single-agent policy ----------------------------------------
    def agent_policy(self, agent: str) -> Policy:
        """The KAIROS policy one agent's external effects are evaluated under: its
        own labels joined with its cluster's release policy."""
        a = self.agents[agent]
        c = self.clusters[a.cluster]
        cp = c.policy
        ctx = Context(
            name=agent, default_action=cp.default_action,
            revertable=list(a.labels.revertable), non_revertable=list(a.labels.non_revertable),
            description=a.description, scope=f"mas:{self.name}/{c.id}",
            navigational_get=cp.navigational_get, embedded_identifiers=cp.embedded_identifiers)
        res = Resources(contact_book=cp.external, taints=list(a.labels.taints),
                        trusted_sources=list(a.labels.trusted_sources))
        return Policy(version=self.version, context=ctx, resources=res, rules=list(cp.rules))
