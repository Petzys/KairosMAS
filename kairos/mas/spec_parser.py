"""YAML -> MASSpec, with validation.

    version: "0.1"
    system:   {name, description, entry}
    agents:
      <id>: {cluster, endpoint?, description?, policy: <inline mapping | path>}
    clusters:
      <id>:
        clearance: low|medium|high|critical     # default clearance as a destination
        policy:
          default_action, navigational_get, embedded_identifiers,
          message_identifiers, intra_cluster_checks,
          contact_book:
            peers:    {on_miss, entries: [{cluster|agent, max_level?}]}
            external: <single-agent contact book: lookup_fields, on_miss, entries, seed>
          rules: [<single-agent simple rules; actions of members or a2a.send/a2a.reply>]

An agent policy has `actions` (revertable / non_revertable), `taints` and
`trusted_sources` -- the labeling half of a single-agent policy. A contact book or
rules in an agent policy is an error: they belong to the cluster.

`parse_spec` reads and checks each part; `validate_spec` then checks the parts
against each other (unknown names, empty clusters, duplicate endpoints, rules about
actions no member has). `spec_to_dict` / `dump_spec` write a spec back as YAML.
The small parsing helpers come from the single-agent policy parser.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from kairos.core.extract import STRUCTURED_PATTERNS
from kairos.core.tokens import Level
from kairos.engine.decision import Decision
from kairos.mas.spec import (
    A2A_ACTIONS, AgentLabels, AgentSpec, ClusterPolicy, ClusterSpec, MASSpec, PeerBook,
    PeerEntry, default_endpoint, endpoint_origin,
)
from kairos.policy.parser import (
    PolicyError, _check_keys, _decision, _level, _list, _mapping, _parse_contact_book,
    _parse_rule, _parse_taint, _parse_trusted_source, _require, _str, _str_list,
)
from kairos.policy.schema import SimpleRule

SUPPORTED_VERSION = "0.1"


class SpecError(PolicyError):
    """A multi-agent system specification is malformed."""


def load_spec(path: str | Path) -> MASSpec:
    """Read a spec file. Agent policies given as paths are resolved relative to it."""
    spec_path = Path(path)
    raw = yaml.safe_load(spec_path.read_text())
    if not isinstance(raw, dict):
        raise SpecError(f"spec root must be a mapping, got {type(raw).__name__}")
    return parse_spec(raw, base_dir=spec_path.parent)


def parse_spec(raw: dict[str, Any], base_dir: Path | None = None) -> MASSpec:
    _check_keys(raw, {"version", "system", "agents", "clusters"}, "<root>")
    version = str(raw.get("version", "")).strip()
    # (an unquoted 0.1 or 0.10 reads as the float 0.1; a quoted "0.10" is accepted too)
    if version not in (SUPPORTED_VERSION, "0.10"):
        raise SpecError(f"<root>.version: expected {SUPPORTED_VERSION!r}, got {raw.get('version')!r}")
    system = _mapping(_require(raw, "system", "<root>"), "system")
    _check_keys(system, {"name", "description", "entry"}, "system")

    clusters_raw = _mapping(_require(raw, "clusters", "<root>"), "clusters")
    agents_raw = _mapping(_require(raw, "agents", "<root>"), "agents")
    clusters = {cluster_id: _parse_cluster(str(cluster_id), _mapping(cluster, f"clusters.{cluster_id}"))
                for cluster_id, cluster in clusters_raw.items()}
    agents = {agent_id: _parse_agent(str(agent_id), _mapping(agent, f"agents.{agent_id}"), base_dir)
              for agent_id, agent in agents_raw.items()}
    spec = MASSpec(name=_str(_require(system, "name", "system"), "system.name"),
                   entry=_str(_require(system, "entry", "system"), "system.entry"),
                   agents=agents, clusters=clusters,
                   description=_str(system.get("description", ""), "system.description"),
                   version=SUPPORTED_VERSION)
    validate_spec(spec)
    return spec


def _parse_agent(aid: str, d: dict[str, Any], base_dir: Path | None) -> AgentSpec:
    path = f"agents.{aid}"
    _check_keys(d, {"cluster", "endpoint", "description", "policy"}, path)
    cluster = _str(_require(d, "cluster", path), f"{path}.cluster")
    policy_raw = d.get("policy", {})
    if isinstance(policy_raw, str):
        # The agent policy lives in its own file (e.g. a single-agent policy).
        file = (base_dir / policy_raw) if base_dir is not None else Path(policy_raw)
        policy_raw = yaml.safe_load(file.read_text()) or {}
    labels = parse_agent_policy(_mapping(policy_raw, f"{path}.policy"), f"{path}.policy")
    return AgentSpec(id=aid, cluster=cluster,
                     endpoint=_str(d.get("endpoint") or default_endpoint(aid, cluster), f"{path}.endpoint"),
                     description=_str(d.get("description", ""), f"{path}.description"),
                     labels=labels)


def parse_agent_policy(d: dict[str, Any], path: str = "policy") -> AgentLabels:
    """The labeling half of a policy. Taints and trusted sources may sit at the top
    level or under `resources` (as in a single-agent policy)."""
    for misplaced in ("contact_book", "rules", "default_action"):
        if misplaced in d or misplaced in (d.get("resources") or {}):
            raise SpecError(f"{path}: '{misplaced}' is a release decision and belongs to the "
                            f"cluster policy; an agent policy only labels data")
    _check_keys(d, {"version", "description", "actions", "taints", "trusted_sources", "resources"}, path)
    resources = _mapping(d.get("resources", {}), f"{path}.resources")
    _check_keys(resources, {"taints", "trusted_sources"}, f"{path}.resources")
    actions = _mapping(d.get("actions", {}), f"{path}.actions")
    _check_keys(actions, {"revertable", "non_revertable"}, f"{path}.actions")
    taints_raw = d.get("taints", resources.get("taints", []))
    trusted_raw = d.get("trusted_sources", resources.get("trusted_sources", []))
    labels = AgentLabels(
        revertable=_str_list(actions.get("revertable", []), f"{path}.actions.revertable"),
        non_revertable=_str_list(actions.get("non_revertable", []), f"{path}.actions.non_revertable"),
        taints=[_parse_taint(_mapping(taint, f"{path}.taints[{i}]"), f"{path}.taints[{i}]")
                for i, taint in enumerate(_list(taints_raw, f"{path}.taints"))],
        trusted_sources=[_parse_trusted_source(source, f"{path}.trusted_sources[{i}]")
                         for i, source in enumerate(_list(trusted_raw, f"{path}.trusted_sources"))],
    )
    # Named on purpose: written inline, `a | b - c` would subtract from `b` only.
    referenced = {taint.source for taint in labels.taints} | {source.source for source in labels.trusted_sources}
    undeclared = sorted(referenced - labels.actions)
    if undeclared:
        raise SpecError(f"{path}: taints/trusted_sources reference undeclared action(s): "
                        f"{', '.join(undeclared)}")
    return labels


def _parse_cluster(cid: str, d: dict[str, Any]) -> ClusterSpec:
    path = f"clusters.{cid}"
    _check_keys(d, {"clearance", "description", "policy"}, path)
    policy_raw = _mapping(d.get("policy", {}), f"{path}.policy")
    _check_keys(policy_raw, {"default_action", "navigational_get", "embedded_identifiers",
                             "message_identifiers", "intra_cluster_checks", "contact_book", "rules"},
                f"{path}.policy")
    contact_book = _mapping(policy_raw.get("contact_book", {}), f"{path}.policy.contact_book")
    _check_keys(contact_book, {"peers", "external"}, f"{path}.policy.contact_book")
    peers_raw = _mapping(contact_book.get("peers", {}), f"{path}.policy.contact_book.peers")
    _check_keys(peers_raw, {"on_miss", "entries"}, f"{path}.policy.contact_book.peers")
    entries = [_parse_peer_entry(_mapping(entry, f"{path}.peers.entries[{i}]"), f"{path}.peers.entries[{i}]")
               for i, entry in enumerate(_list(peers_raw.get("entries", []), f"{path}.peers.entries"))]
    rules = []
    for i, rule_raw in enumerate(_list(policy_raw.get("rules", []), f"{path}.policy.rules")):
        rule = _parse_rule(_mapping(rule_raw, f"{path}.policy.rules[{i}]"), f"{path}.policy.rules[{i}]")
        if not isinstance(rule, SimpleRule):
            raise SpecError(f"{path}.policy.rules[{i}]: sequence rules are not supported")
        rules.append(rule)
    policy = ClusterPolicy(
        default_action=_decision(policy_raw.get("default_action", "REVIEW"), f"{path}.policy.default_action"),
        navigational_get=_knob(policy_raw.get("navigational_get", "allow"), f"{path}.policy.navigational_get"),
        embedded_identifiers=_knob(policy_raw.get("embedded_identifiers", "allow"),
                                   f"{path}.policy.embedded_identifiers"),
        message_identifiers=_knob(policy_raw.get("message_identifiers", "review"),
                                  f"{path}.policy.message_identifiers"),
        intra_cluster_checks=_choice(policy_raw.get("intra_cluster_checks", "annotate"), ("annotate", "off"),
                                     f"{path}.policy.intra_cluster_checks"),
        peers=PeerBook(on_miss=_decision(peers_raw.get("on_miss", "REVIEW"),
                                         f"{path}.policy.contact_book.peers.on_miss"),
                       entries=entries),
        external=(_parse_contact_book(_mapping(contact_book["external"], f"{path}.policy.contact_book.external"))
                  if "external" in contact_book else None),
        rules=rules,
    )
    return ClusterSpec(id=cid, clearance=_level(d.get("clearance", "low"), f"{path}.clearance"),
                       description=_str(d.get("description", ""), f"{path}.description"),
                       policy=policy)


def _parse_peer_entry(d: dict[str, Any], path: str) -> PeerEntry:
    _check_keys(d, {"cluster", "agent", "max_level"}, path)
    if ("cluster" in d) == ("agent" in d):
        raise SpecError(f"{path}: a peer entry names exactly one of 'cluster' or 'agent'")
    return PeerEntry(cluster=_str(d["cluster"], f"{path}.cluster") if "cluster" in d else None,
                     agent=_str(d["agent"], f"{path}.agent") if "agent" in d else None,
                     max_level=_level(d["max_level"], f"{path}.max_level") if "max_level" in d else None)


def _knob(v: Any, path: str) -> str:
    """An allow/review switch; also accepts on/off (and YAML's booleans)."""
    if isinstance(v, bool):              # YAML 1.1: bare on/off parse as booleans
        return "review" if v else "allow"
    text = _str(v, path).strip().lower()
    text = {"off": "allow", "on": "review"}.get(text, text)
    return _choice(text, ("allow", "review"), path)


def _choice(v: Any, allowed: tuple[str, ...], path: str) -> str:
    text = _str(v, path).strip().lower()
    if text not in allowed:
        raise SpecError(f"{path}: expected one of {', '.join(allowed)}, got {v!r}")
    return text


def validate_spec(spec: MASSpec) -> None:
    """Check the parts of a spec against each other; report every problem at once."""
    problems: list[str] = []
    if spec.entry not in spec.agents:
        problems.append(f"system.entry: unknown agent {spec.entry!r}")
    for agent in spec.agents.values():
        if agent.cluster not in spec.clusters:
            problems.append(f"agents.{agent.id}: unknown cluster {agent.cluster!r}")
    for cluster_id in spec.clusters:
        if not spec.members(cluster_id):
            problems.append(f"clusters.{cluster_id}: a cluster needs at least one member")

    # Agents are told apart by their endpoint's origin, so no two may share one.
    origins: dict[str, str] = {}
    for agent in spec.agents.values():
        origin = endpoint_origin(agent.endpoint)
        if origin in origins:
            problems.append(f"agents.{agent.id}: endpoint origin {origin} already used by {origins[origin]}")
        origins[origin] = agent.id

    for cluster in spec.clusters.values():
        for entry in cluster.policy.peers.entries:
            if entry.cluster is not None and entry.cluster not in spec.clusters:
                problems.append(f"clusters.{cluster.id}: peer entry names unknown cluster {entry.cluster!r}")
            if entry.agent is not None and entry.agent not in spec.agents:
                problems.append(f"clusters.{cluster.id}: peer entry names unknown agent {entry.agent!r}")
            if entry.cluster == cluster.id or (entry.agent in spec.agents
                                               and spec.agents[entry.agent].cluster == cluster.id):
                problems.append(f"clusters.{cluster.id}: peer entry for its own cluster (intra-cluster "
                                f"messages are never gated)")
        # A rule may name the messaging actions or an action some member declares.
        known = set(A2A_ACTIONS)
        for member in spec.members(cluster.id) if cluster.id in spec.clusters else []:
            known |= spec.agents[member].labels.actions
        for rule in cluster.policy.rules:
            actions = [rule.match.action] if isinstance(rule.match.action, str) else rule.match.action
            bad = sorted(set(actions) - known)
            if bad:
                problems.append(f"clusters.{cluster.id}: rule {rule.id} references action(s) no member "
                                f"declares: {', '.join(bad)}")
    if problems:
        raise SpecError("invalid multi-agent system specification:\n  - " + "\n  - ".join(problems))


def _level_name(level: Level | None) -> str | None:
    return level.name.lower() if level is not None else None


def spec_to_dict(spec: MASSpec) -> dict[str, Any]:
    """The YAML form of a spec (what load_spec reads back)."""
    def extract(cfg) -> dict[str, Any]:
        keep = [name for name, pattern in STRUCTURED_PATTERNS.items() if pattern in cfg.preserve_patterns]
        obj: dict[str, Any] = {"mode": cfg.mode.value, "min_token_length": cfg.min_token_length,
                               "exclude_stopwords": cfg.exclude_stopwords}
        if cfg.fields:
            obj["fields"] = list(cfg.fields)
        if cfg.pattern:
            obj["pattern"] = cfg.pattern
        if keep:
            obj["keep"] = keep
        return obj

    def taint(t) -> dict[str, Any]:
        obj: dict[str, Any] = {"name": t.name, "source": t.source, "level": _level_name(t.level)}
        if t.params:
            obj["params"] = dict(t.params)
        if t.extract is not None:
            obj["extract"] = extract(t.extract)
        if t.scan_strategy is not None:
            obj["scan_strategy"] = t.scan_strategy.value
        return obj

    def trusted(t) -> Any:
        # A plain trusted source is written as just its name.
        if t.extract is None and t.scan_strategy is None:
            return t.source
        obj: dict[str, Any] = {"source": t.source}
        if t.extract is not None:
            obj["extract"] = extract(t.extract)
        if t.scan_strategy is not None:
            obj["scan_strategy"] = t.scan_strategy.value
        return obj

    def rule(r: SimpleRule) -> dict[str, Any]:
        match: dict[str, Any] = {"action": r.match.action}
        if r.match.params:
            match["params"] = {key: {condition.op: condition.value} for key, condition in r.match.params.items()}
        if r.match.taint is not None and r.match.taint.level_gte is not None:
            match["taint"] = {"level_gte": _level_name(r.match.taint.level_gte)}
        if r.match.origin is not None:
            match["origin"] = {"param_in_user_prompt": {"key": r.match.origin.param_in_user_prompt_key,
                                                        "required": r.match.origin.required}}
        return {"id": r.id, "match": match, "decision": r.decision.value}

    out: dict[str, Any] = {
        "version": spec.version,
        "system": {"name": spec.name, "description": spec.description, "entry": spec.entry},
        "agents": {}, "clusters": {},
    }
    for agent in spec.agents.values():
        policy: dict[str, Any] = {"actions": {"revertable": list(agent.labels.revertable),
                                              "non_revertable": list(agent.labels.non_revertable)}}
        if agent.labels.taints:
            policy["taints"] = [taint(t) for t in agent.labels.taints]
        if agent.labels.trusted_sources:
            policy["trusted_sources"] = [trusted(t) for t in agent.labels.trusted_sources]
        out["agents"][agent.id] = {"cluster": agent.cluster, "endpoint": agent.endpoint,
                                   "description": agent.description, "policy": policy}
    for cluster in spec.clusters.values():
        release = cluster.policy
        contact_book: dict[str, Any] = {"peers": {"on_miss": release.peers.on_miss.value, "entries": [
            {**({"cluster": entry.cluster} if entry.cluster else {"agent": entry.agent}),
             **({"max_level": _level_name(entry.max_level)} if entry.max_level else {})}
            for entry in release.peers.entries]}}
        if release.external is not None:
            contact_book["external"] = {
                "lookup_fields": list(release.external.lookup_fields),
                "on_miss": release.external.on_miss.value,
                "entries": [{"match": entry.match, "max_level": _level_name(entry.max_level),
                             **({"fields": list(entry.fields)} if entry.fields else {})}
                            for entry in release.external.entries],
                "seed": dict(release.external.seed)}
        out["clusters"][cluster.id] = {
            "clearance": _level_name(cluster.clearance), "description": cluster.description,
            "policy": {"default_action": release.default_action.value,
                       "navigational_get": release.navigational_get,
                       "embedded_identifiers": release.embedded_identifiers,
                       "message_identifiers": release.message_identifiers,
                       "intra_cluster_checks": release.intra_cluster_checks,
                       "contact_book": contact_book, "rules": [rule(r) for r in release.rules]}}
    return out


def dump_spec(spec: MASSpec) -> str:
    return yaml.safe_dump(spec_to_dict(spec), sort_keys=False)


__all__ = ["SpecError", "load_spec", "parse_spec", "parse_agent_policy", "validate_spec",
           "spec_to_dict", "dump_spec", "Decision", "Level"]
