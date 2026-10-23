"""Release decisions for inter-agent messages, built from the single-agent engine.

A message that leaves its cluster is treated like an external request: as an HTTP
POST of its content to the peer's A2A endpoint, evaluated by the same PolicyEngine as
every other effect. The engine checks integrity (is the destination known?),
confidentiality (is the destination cleared for the data the message carries?),
identifiers embedded in the payload, and the cluster's rules. Only the *sending*
cluster's policy decides, but it decides over the sender's JOINED label sets, so data
the sender received from elsewhere keeps its labels.

Each agent gets two engines over one shared label store:

* `engine` for external effects: exactly the single-agent configuration, with the
  cluster's external contact book;
* `messages` for messages that leave the cluster: its "contact book" lists the A2A
  endpoints of the system's agents (`PeerContactBook`).

Messages inside a cluster are never stalled; `annotate_intra_cluster` only records
what a cheap check finds, so that the oracle sees it later in a lineage.
"""
from __future__ import annotations

import dataclasses
import json
import time
from collections.abc import Iterable, Iterator
from contextlib import contextmanager
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
    with their clearance -- and, while its reply is being decided, the requester.

    A requester is KNOWN for the reply it asked for (the request established that
    edge) but for nothing else, and it has no clearance unless the book lists it: a
    reply carrying sensitive data to an uncleared requester is still reviewed, and a
    NEW request to it is judged like any other. Identifiers the cluster's external
    book knows (a contact's address in a message body) count as known too."""

    def __init__(self, peers: Iterable[tuple[str, Level]], *, on_miss: Decision,
                 external: ContactBook | None = None) -> None:
        super().__init__(ContactBookSchema(
            lookup_fields=[], on_miss=on_miss,
            entries=[CbEntry(match=origin, max_level=level) for origin, level in peers]))
        self._external = external
        # The requester whose reply is being decided right now (normalized origin).
        self._answering: str | None = None

    @contextmanager
    def answering(self, endpoint: str) -> Iterator[None]:
        """Scope in which `endpoint` is known: the decision about a reply to it.
        Decisions run under the deciding agent's lock, so the scope is not shared."""
        previous, self._answering = self._answering, normalize(endpoint_origin(endpoint))
        try:
            yield
        finally:
            self._answering = previous

    def lookup(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> CbEntry | None:
        """The entry for `value`: a listed peer first, else the external book's entry."""
        entry = super().lookup(value, strategy)
        if entry is None and self._external is not None:
            entry = self._external.lookup(value, strategy)
        return entry

    def is_known(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> bool:
        """Known: a listed peer, the requester being answered, or an external contact.
        (Being known says nothing about clearance; see `lookup`.)"""
        if super().is_known(value, strategy):
            return True
        if self._answering is not None and normalize(value) == self._answering:
            return True
        return self._external is not None and self._external.is_known(value, strategy)


class MessageRuleMatcher(SimpleRuleMatcher):
    """Cluster rules over messages: `action: a2a.send | a2a.reply`, and params on
    the destination (`to_agent`, `to_cluster`) or the content (`message`)."""

    @staticmethod
    def _arg(event: Event, key: str) -> object | None:
        # Who a message goes to (and comes from) rides in the event's metadata; every
        # other parameter is looked up in the message content.
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
    """The two policy engines of `agent`, sharing its label store `store`."""
    policy = spec.agent_policy(agent)
    cluster_policy = spec.cluster_of(agent).policy
    external = ContactBook(cluster_policy.external) if cluster_policy.external is not None else None
    rules = SimpleRuleMatcher(list(cluster_policy.rules))
    engine = PolicyEngine(policy, store, contact_book=external,
                          simple_rules=rules, mode=mode)  # type: ignore[arg-type]

    # The message engine's contact book: every agent of ANOTHER cluster that the
    # sending cluster lists, with the clearance it grants that agent. (Agents of the
    # sender's own cluster never need it: their messages are not decided.)
    sender_cluster = spec.agents[agent].cluster
    peers = []
    for other in spec.agents.values():
        if other.cluster == sender_cluster:
            continue
        level, listed = spec.peer_clearance(agent, other.id)
        if listed and level is not None:
            peers.append((endpoint_origin(other.endpoint), level))
    book = PeerContactBook(peers, on_miss=cluster_policy.peers.on_miss, external=external)

    # The same policy, except for how identifiers embedded in a message are treated
    # (the cluster's `message_identifiers` setting).
    message_policy = Policy(version=policy.version,
                            context=_message_context(policy, cluster_policy.message_identifiers),
                            resources=policy.resources, rules=policy.rules)
    message_rules = MessageRuleMatcher(list(cluster_policy.rules))
    messages = PolicyEngine(message_policy, store, contact_book=book,
                            simple_rules=message_rules, mode=mode)  # type: ignore[arg-type]
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

    cluster_policy = spec.cluster_of(sender).policy
    _level, listed = spec.peer_clearance(sender, dest)
    if not reply and not listed and cluster_policy.peers.on_miss is Decision.DENY:
        return StageResult(Decision.DENY, stage=1, produced_by="topology",
                           reason=f"agent {dest!r} (cluster {spec.agents[dest].cluster!r}) is not "
                                  f"in the contact book of cluster {spec.agents[sender].cluster!r}")

    event = message_event(spec, sender, dest, text, data, reply=reply)
    if reply:
        # While a reply is decided, its requester counts as a known destination.
        with engines.peers.answering(spec.agents[dest].endpoint):
            return engines.messages.evaluate(event)
    return engines.messages.evaluate(event)


def annotate_intra_cluster(spec: MASSpec, engines: AgentEngines, sender: str, dest: str, text: str,
                           data: list[dict[str, Any]] | None = None, *,
                           reply: bool = False) -> dict[str, Any]:
    """The cheap deterministic check on an intra-cluster message: does its content
    carry identifiers no trusted source vouches for, and at which sensitivity? The
    result annotates the causal log, where the oracle sees it when a later effect's
    lineage passes through this message. It never stalls and never resolves.

    The destination is not checked: inside a cluster every member may talk to every
    other."""
    event = message_event(spec, sender, dest, text, data, reply=reply)
    engine = engines.messages
    action_class = classify(event, engine.policy)
    # Probe with identifier review switched on, whatever the cluster configured: we
    # only want to know what the check would find, not to decide anything.
    probe = dataclasses.replace(engine.policy, context=dataclasses.replace(
        engine.policy.context, embedded_identifiers="review"))
    _decision, reason = check_embedded_identifiers(event, action_class, engine.store, probe,
                                                   contact_book=engines.peers)
    level = outbound_sensitivity(event, action_class, engine.store)
    annotation: dict[str, Any] = {}
    if reason:
        annotation["identifiers"] = reason
    if level is not None:
        annotation["sensitivity"] = level.name
    return annotation
