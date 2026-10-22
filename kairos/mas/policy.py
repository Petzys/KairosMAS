"""Release decisions for inter-agent messages, built from the single-agent engine.

A message that leaves its cluster is released like an external request: an HTTP
POST to the peer's A2A endpoint, evaluated by the same PolicyEngine as every other
effect -- integrity (is the destination known?), confidentiality (is it cleared for
the data the message carries?), payload identifiers, and the cluster's rules. Only
the sending cluster's policy decides, but it decides over the sender's JOINED label
sets, so data the sender received from elsewhere keeps its labels.

Two engines per agent share one store: one for external effects (exactly the
single-agent configuration: the cluster's external contact book), one for messages
(a contact book of the system's agents).
"""
from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from kairos.core.events import Channel, Event, HttpMethod
from kairos.core.matching import Strategy, normalize
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.action_class import classify
from kairos.engine.confidentiality import outbound_sensitivity
from kairos.engine.decision import Decision, StageResult
from kairos.engine.integrity import check_embedded_identifiers
from kairos.engine.pipeline import PolicyEngine
from kairos.mas.spec import A2A_REPLY, A2A_SEND, MASSpec, endpoint_origin
from kairos.policy.contact_book import ContactBook
from kairos.policy.rules import SimpleRuleMatcher
from kairos.policy.schema import CbEntry, Policy
from kairos.policy.schema import ContactBook as ContactBookSchema


class PeerContactBook(ContactBook):
    """Destinations inside the system: the A2A endpoints the sending cluster lists,
    with their clearance, plus the requesters this agent currently answers.

    A requester is KNOWN for its reply (it addressed this agent) but has no
    clearance unless the book lists it: a reply carrying sensitive data to an
    uncleared requester is still reviewed. Identifiers the cluster's external book
    knows (a contact's address in a message body) count as known too."""

    def __init__(self, peers: Iterable[tuple[str, Level]], *, on_miss: Decision,
                 external: ContactBook | None = None) -> None:
        super().__init__(ContactBookSchema(
            lookup_fields=[], on_miss=on_miss,
            entries=[CbEntry(match=origin, max_level=level) for origin, level in peers]))
        self._external = external
        self._reply_targets: set[str] = set()

    def add_reply_target(self, endpoint: str) -> None:
        self._reply_targets.add(normalize(endpoint_origin(endpoint)))

    def lookup(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> CbEntry | None:
        e = super().lookup(value, strategy)
        if e is None and self._external is not None:
            e = self._external.lookup(value, strategy)
        return e

    def is_known(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> bool:
        if super().is_known(value, strategy) or normalize(value) in self._reply_targets:
            return True
        return self._external is not None and self._external.is_known(value, strategy)


class MessageRuleMatcher(SimpleRuleMatcher):
    """Cluster rules over messages: `action: a2a.send | a2a.reply`, and params on
    the destination (`to_agent`, `to_cluster`) or the content (`message`)."""

    @staticmethod
    def _arg(event: Event, key: str) -> object | None:
        meta = event.metadata or {}
        if key in ("to_agent", "to_cluster", "from_agent"):
            return meta.get(key)
        return event.content.get(key) if isinstance(event.content, dict) else None


def message_event(spec: MASSpec, sender: str, dest: str, text: str,
                  data: list[dict[str, Any]] | None = None, *, reply: bool = False) -> Event:
    """A message as the boundary sees it: a POST of its content to the peer's
    endpoint. Who it goes to rides in metadata, never in the scanned content (an
    agent name must not match a sensitive word)."""
    content: dict[str, Any] = {"message": text}
    if data:
        content["data"] = json.dumps(data, ensure_ascii=False, sort_keys=True)
    return Event(time.time(), Channel.NET, HttpMethod.POST.value, sender, spec.agents[dest].endpoint,
                 content, {"function": A2A_REPLY if reply else A2A_SEND, "a2a": True,
                           "from_agent": sender, "to_agent": dest,
                           "to_cluster": spec.agents[dest].cluster})


@dataclass(slots=True)
class AgentEngines:
    engine: PolicyEngine          # external effects
    messages: PolicyEngine        # messages leaving the cluster
    peers: PeerContactBook


def build_engines(spec: MASSpec, agent: str, store: TokenStore, *, mode: str = "full") -> AgentEngines:
    policy = spec.agent_policy(agent)
    cp = spec.cluster_of(agent).policy
    external = ContactBook(cp.external) if cp.external is not None else None
    engine = PolicyEngine(policy, store, contact_book=external,
                          simple_rules=SimpleRuleMatcher(list(cp.rules)), mode=mode)  # type: ignore[arg-type]

    sender_cluster = spec.agents[agent].cluster
    peers = []
    for other in spec.agents.values():
        if other.cluster == sender_cluster:
            continue
        level, listed = spec.peer_clearance(agent, other.id)
        if listed and level is not None:
            peers.append((endpoint_origin(other.endpoint), level))
    book = PeerContactBook(peers, on_miss=cp.peers.on_miss, external=external)
    msg_policy = Policy(version=policy.version, context=_message_context(policy, cp.message_identifiers),
                        resources=policy.resources, rules=policy.rules)
    messages = PolicyEngine(msg_policy, store, contact_book=book,
                            simple_rules=MessageRuleMatcher(list(cp.rules)), mode=mode)  # type: ignore[arg-type]
    return AgentEngines(engine=engine, messages=messages, peers=book)


def _message_context(policy: Policy, message_identifiers: str):
    return dataclasses.replace(policy.context, embedded_identifiers=message_identifiers)


def evaluate_message(spec: MASSpec, engines: AgentEngines, sender: str, dest: str, text: str,
                     data: list[dict[str, Any]] | None = None, *, reply: bool = False) -> StageResult:
    """The release decision for one message from `sender` to `dest`.

    Intra-cluster: ALLOW, never evaluated further (logged, never stalled). Leaving
    the cluster: the topology check (a request to an agent the contact book does
    not list, under on_miss DENY), then the message engine. A reply needs no
    topology check: the request it answers established the edge."""
    if spec.same_cluster(sender, dest):
        return StageResult(Decision.ALLOW, stage=1, produced_by="intra_cluster")
    cp = spec.cluster_of(sender).policy
    _level, listed = spec.peer_clearance(sender, dest)
    if not reply and not listed and cp.peers.on_miss is Decision.DENY:
        return StageResult(Decision.DENY, stage=1, produced_by="topology",
                           reason=f"agent {dest!r} (cluster {spec.agents[dest].cluster!r}) is not "
                                  f"in the contact book of cluster {spec.agents[sender].cluster!r}")
    return engines.messages.evaluate(message_event(spec, sender, dest, text, data, reply=reply))


def annotate_intra_cluster(spec: MASSpec, engines: AgentEngines, sender: str, dest: str, text: str,
                           data: list[dict[str, Any]] | None = None, *,
                           reply: bool = False) -> dict[str, Any]:
    """The cheap deterministic check on an intra-cluster message: does its content
    carry identifiers no trusted source vouches for, and at which sensitivity? The
    result annotates the causal log, where the oracle sees it when a later effect's
    lineage passes through this message. It never stalls and never resolves.

    The destination is not checked: inside a cluster every member may talk to every
    other."""
    ev = message_event(spec, sender, dest, text, data, reply=reply)
    eng = engines.messages
    ac = classify(ev, eng.policy)
    probe = dataclasses.replace(eng.policy, context=dataclasses.replace(
        eng.policy.context, embedded_identifiers="review"))
    _dec, reason = check_embedded_identifiers(ev, ac, eng.store, probe, contact_book=engines.peers)
    level = outbound_sensitivity(ev, ac, eng.store)
    out: dict[str, Any] = {}
    if reason:
        out["identifiers"] = reason
    if level is not None:
        out["sensitivity"] = level.name
    return out
