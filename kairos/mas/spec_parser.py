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
    p = Path(path)
    raw = yaml.safe_load(p.read_text())
    if not isinstance(raw, dict):
        raise SpecError(f"spec root must be a mapping, got {type(raw).__name__}")
    return parse_spec(raw, base_dir=p.parent)


def parse_spec(raw: dict[str, Any], base_dir: Path | None = None) -> MASSpec:
    _check_keys(raw, {"version", "system", "agents", "clusters"}, "<root>")
    version = str(raw.get("version", "")).strip()
    if version not in (SUPPORTED_VERSION, "0.10"):
        raise SpecError(f"<root>.version: expected {SUPPORTED_VERSION!r}, got {raw.get('version')!r}")
    system = _mapping(_require(raw, "system", "<root>"), "system")
    _check_keys(system, {"name", "description", "entry"}, "system")

    clusters_raw = _mapping(_require(raw, "clusters", "<root>"), "clusters")
    agents_raw = _mapping(_require(raw, "agents", "<root>"), "agents")
    clusters = {cid: _parse_cluster(str(cid), _mapping(c, f"clusters.{cid}"))
                for cid, c in clusters_raw.items()}
    agents = {aid: _parse_agent(str(aid), _mapping(a, f"agents.{aid}"), base_dir)
              for aid, a in agents_raw.items()}
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
    pol = d.get("policy", {})
    if isinstance(pol, str):
        file = (base_dir / pol) if base_dir is not None else Path(pol)
        pol = yaml.safe_load(file.read_text()) or {}
    labels = parse_agent_policy(_mapping(pol, f"{path}.policy"), f"{path}.policy")
    return AgentSpec(id=aid, cluster=cluster,
                     endpoint=_str(d.get("endpoint") or default_endpoint(aid, cluster), f"{path}.endpoint"),
                     description=_str(d.get("description", ""), f"{path}.description"),
                     labels=labels)


def parse_agent_policy(d: dict[str, Any], path: str = "policy") -> AgentLabels:
    for misplaced in ("contact_book", "rules", "default_action"):
        if misplaced in d or misplaced in (d.get("resources") or {}):
            raise SpecError(f"{path}: '{misplaced}' is a release decision and belongs to the "
                            f"cluster policy; an agent policy only labels data")
    _check_keys(d, {"version", "description", "actions", "taints", "trusted_sources", "resources"}, path)
    res = _mapping(d.get("resources", {}), f"{path}.resources")
    _check_keys(res, {"taints", "trusted_sources"}, f"{path}.resources")
    actions = _mapping(d.get("actions", {}), f"{path}.actions")
    _check_keys(actions, {"revertable", "non_revertable"}, f"{path}.actions")
    taints_raw = d.get("taints", res.get("taints", []))
    trusted_raw = d.get("trusted_sources", res.get("trusted_sources", []))
    labels = AgentLabels(
        revertable=_str_list(actions.get("revertable", []), f"{path}.actions.revertable"),
        non_revertable=_str_list(actions.get("non_revertable", []), f"{path}.actions.non_revertable"),
        taints=[_parse_taint(_mapping(t, f"{path}.taints[{i}]"), f"{path}.taints[{i}]")
                for i, t in enumerate(_list(taints_raw, f"{path}.taints"))],
        trusted_sources=[_parse_trusted_source(t, f"{path}.trusted_sources[{i}]")
                         for i, t in enumerate(_list(trusted_raw, f"{path}.trusted_sources"))],
    )
    referenced = {t.source for t in labels.taints} | {t.source for t in labels.trusted_sources}
    undeclared = sorted(referenced - labels.actions)
    if undeclared:
        raise SpecError(f"{path}: taints/trusted_sources reference undeclared action(s): "
                        f"{', '.join(undeclared)}")
    return labels


def _parse_cluster(cid: str, d: dict[str, Any]) -> ClusterSpec:
    path = f"clusters.{cid}"
    _check_keys(d, {"clearance", "description", "policy"}, path)
    pol = _mapping(d.get("policy", {}), f"{path}.policy")
    _check_keys(pol, {"default_action", "navigational_get", "embedded_identifiers",
                      "message_identifiers", "intra_cluster_checks", "contact_book", "rules"},
                f"{path}.policy")
    cb = _mapping(pol.get("contact_book", {}), f"{path}.policy.contact_book")
    _check_keys(cb, {"peers", "external"}, f"{path}.policy.contact_book")
    peers_raw = _mapping(cb.get("peers", {}), f"{path}.policy.contact_book.peers")
    _check_keys(peers_raw, {"on_miss", "entries"}, f"{path}.policy.contact_book.peers")
    entries = [_parse_peer_entry(_mapping(e, f"{path}.peers.entries[{i}]"), f"{path}.peers.entries[{i}]")
               for i, e in enumerate(_list(peers_raw.get("entries", []), f"{path}.peers.entries"))]
    rules = []
    for i, r in enumerate(_list(pol.get("rules", []), f"{path}.policy.rules")):
        rule = _parse_rule(_mapping(r, f"{path}.policy.rules[{i}]"), f"{path}.policy.rules[{i}]")
        if not isinstance(rule, SimpleRule):
            raise SpecError(f"{path}.policy.rules[{i}]: sequence rules are not supported")
        rules.append(rule)
    policy = ClusterPolicy(
        default_action=_decision(pol.get("default_action", "REVIEW"), f"{path}.policy.default_action"),
        navigational_get=_knob(pol.get("navigational_get", "allow"), f"{path}.policy.navigational_get"),
        embedded_identifiers=_knob(pol.get("embedded_identifiers", "allow"),
                                   f"{path}.policy.embedded_identifiers"),
        message_identifiers=_knob(pol.get("message_identifiers", "review"),
                                  f"{path}.policy.message_identifiers"),
        intra_cluster_checks=_choice(pol.get("intra_cluster_checks", "annotate"), ("annotate", "off"),
                                     f"{path}.policy.intra_cluster_checks"),
        peers=PeerBook(on_miss=_decision(peers_raw.get("on_miss", "REVIEW"),
                                         f"{path}.policy.contact_book.peers.on_miss"),
                       entries=entries),
        external=(_parse_contact_book(_mapping(cb["external"], f"{path}.policy.contact_book.external"))
                  if "external" in cb else None),
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
    if isinstance(v, bool):              # YAML 1.1: bare on/off parse as booleans
        return "review" if v else "allow"
    s = _str(v, path).strip().lower()
    s = {"off": "allow", "on": "review"}.get(s, s)
    return _choice(s, ("allow", "review"), path)


def _choice(v: Any, allowed: tuple[str, ...], path: str) -> str:
    s = _str(v, path).strip().lower()
    if s not in allowed:
        raise SpecError(f"{path}: expected one of {', '.join(allowed)}, got {v!r}")
    return s


def validate_spec(spec: MASSpec) -> None:
    problems: list[str] = []
    if spec.entry not in spec.agents:
        problems.append(f"system.entry: unknown agent {spec.entry!r}")
    for a in spec.agents.values():
        if a.cluster not in spec.clusters:
            problems.append(f"agents.{a.id}: unknown cluster {a.cluster!r}")
    for cid in spec.clusters:
        if not spec.members(cid):
            problems.append(f"clusters.{cid}: a cluster needs at least one member")
    origins: dict[str, str] = {}
    for a in spec.agents.values():
        o = endpoint_origin(a.endpoint)
        if o in origins:
            problems.append(f"agents.{a.id}: endpoint origin {o} already used by {origins[o]}")
        origins[o] = a.id
    for c in spec.clusters.values():
        for e in c.policy.peers.entries:
            if e.cluster is not None and e.cluster not in spec.clusters:
                problems.append(f"clusters.{c.id}: peer entry names unknown cluster {e.cluster!r}")
            if e.agent is not None and e.agent not in spec.agents:
                problems.append(f"clusters.{c.id}: peer entry names unknown agent {e.agent!r}")
            if e.cluster == c.id or (e.agent in spec.agents and spec.agents[e.agent].cluster == c.id):
                problems.append(f"clusters.{c.id}: peer entry for its own cluster (intra-cluster "
                                f"messages are never gated)")
        known = set(A2A_ACTIONS)
        for m in spec.members(c.id) if c.id in spec.clusters else []:
            known |= spec.agents[m].labels.actions
        for r in c.policy.rules:
            acts = [r.match.action] if isinstance(r.match.action, str) else r.match.action
            bad = sorted(set(acts) - known)
            if bad:
                problems.append(f"clusters.{c.id}: rule {r.id} references action(s) no member "
                                f"declares: {', '.join(bad)}")
    if problems:
        raise SpecError("invalid multi-agent system specification:\n  - " + "\n  - ".join(problems))


def _level_name(level: Level | None) -> str | None:
    return level.name.lower() if level is not None else None


def spec_to_dict(spec: MASSpec) -> dict[str, Any]:
    """The YAML form of a spec (what load_spec reads back)."""
    def extract(cfg) -> dict[str, Any]:
        keep = [name for name, pat in STRUCTURED_PATTERNS.items() if pat in cfg.preserve_patterns]
        d: dict[str, Any] = {"mode": cfg.mode.value, "min_token_length": cfg.min_token_length,
                             "exclude_stopwords": cfg.exclude_stopwords}
        if cfg.fields:
            d["fields"] = list(cfg.fields)
        if cfg.pattern:
            d["pattern"] = cfg.pattern
        if keep:
            d["keep"] = keep
        return d

    def taint(t) -> dict[str, Any]:
        d: dict[str, Any] = {"name": t.name, "source": t.source, "level": _level_name(t.level)}
        if t.params:
            d["params"] = dict(t.params)
        if t.extract is not None:
            d["extract"] = extract(t.extract)
        if t.scan_strategy is not None:
            d["scan_strategy"] = t.scan_strategy.value
        return d

    def trusted(t) -> Any:
        if t.extract is None and t.scan_strategy is None:
            return t.source
        d: dict[str, Any] = {"source": t.source}
        if t.extract is not None:
            d["extract"] = extract(t.extract)
        if t.scan_strategy is not None:
            d["scan_strategy"] = t.scan_strategy.value
        return d

    def rule(r: SimpleRule) -> dict[str, Any]:
        m: dict[str, Any] = {"action": r.match.action}
        if r.match.params:
            m["params"] = {k: {c.op: c.value} for k, c in r.match.params.items()}
        if r.match.taint is not None and r.match.taint.level_gte is not None:
            m["taint"] = {"level_gte": _level_name(r.match.taint.level_gte)}
        if r.match.origin is not None:
            m["origin"] = {"param_in_user_prompt": {"key": r.match.origin.param_in_user_prompt_key,
                                                    "required": r.match.origin.required}}
        return {"id": r.id, "match": m, "decision": r.decision.value}

    out: dict[str, Any] = {
        "version": spec.version,
        "system": {"name": spec.name, "description": spec.description, "entry": spec.entry},
        "agents": {}, "clusters": {},
    }
    for a in spec.agents.values():
        pol: dict[str, Any] = {"actions": {"revertable": list(a.labels.revertable),
                                           "non_revertable": list(a.labels.non_revertable)}}
        if a.labels.taints:
            pol["taints"] = [taint(t) for t in a.labels.taints]
        if a.labels.trusted_sources:
            pol["trusted_sources"] = [trusted(t) for t in a.labels.trusted_sources]
        out["agents"][a.id] = {"cluster": a.cluster, "endpoint": a.endpoint,
                               "description": a.description, "policy": pol}
    for c in spec.clusters.values():
        cp = c.policy
        cb: dict[str, Any] = {"peers": {"on_miss": cp.peers.on_miss.value, "entries": [
            {**({"cluster": e.cluster} if e.cluster else {"agent": e.agent}),
             **({"max_level": _level_name(e.max_level)} if e.max_level else {})}
            for e in cp.peers.entries]}}
        if cp.external is not None:
            cb["external"] = {"lookup_fields": list(cp.external.lookup_fields),
                              "on_miss": cp.external.on_miss.value,
                              "entries": [{"match": e.match, "max_level": _level_name(e.max_level),
                                           **({"fields": list(e.fields)} if e.fields else {})}
                                          for e in cp.external.entries],
                              "seed": dict(cp.external.seed)}
        out["clusters"][c.id] = {
            "clearance": _level_name(c.clearance), "description": c.description,
            "policy": {"default_action": cp.default_action.value,
                       "navigational_get": cp.navigational_get,
                       "embedded_identifiers": cp.embedded_identifiers,
                       "message_identifiers": cp.message_identifiers,
                       "intra_cluster_checks": cp.intra_cluster_checks,
                       "contact_book": cb, "rules": [rule(r) for r in cp.rules]}}
    return out


def dump_spec(spec: MASSpec) -> str:
    return yaml.safe_dump(spec_to_dict(spec), sort_keys=False)


__all__ = ["SpecError", "load_spec", "parse_spec", "parse_agent_policy", "validate_spec",
           "spec_to_dict", "dump_spec", "Decision", "Level"]
