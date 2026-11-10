"""KAIROS MAS cluster layouts for masbench scenarios, derived from the tool annotations.

Clusters are a KAIROS MAS concept (the principal's security/speed knob), so they live here and
not in masbench. Stored per scenario in `data/<bench>/<suite>/layouts.yaml`.

Named strategies (Benchmark Design §2.3):
* single - every agent its own cluster (full mediation)
* func   - readers vs actors. A reader holds a tool with untrusted output and no high-impact
           tool; everyone else (and the orchestrator) is an actor. If no worker is a reader,
           the orchestrator (the only agent that never reads third-party content itself) is
           separated from all workers.
* crit   - every agent holding a high-impact tool is a singleton; the rest share a cluster.
* one    - all agents in one cluster (only the external boundary is mediated)
* sweep  - every set partition of the agents (Bell number many), for ablation R1.
"""
from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, model_validator

from masbench import io
from masbench.schema import Scenario

DATA = Path(__file__).parent / "data"
FORMAT = "kairos-mas/layouts/0.1"


class Layout(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    strategy: Literal["single", "func", "crit", "one", "org", "sweep"]
    description: str = ""
    clusters: dict[str, list[str]]


class LayoutSet(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["kairos-mas/layouts/0.1"] = FORMAT
    scenario: str
    agents: list[str]
    layouts: list[Layout]

    @model_validator(mode="after")
    def _partitions(self) -> LayoutSet:
        for lay in self.layouts:
            members = [a for ms in lay.clusters.values() for a in ms]
            if sorted(members) != sorted(self.agents):
                raise ValueError(f"layout {lay.id} is not a partition of the agents")
        return self

    def get(self, layout_id: str) -> Layout:
        return next(lay for lay in self.layouts if lay.id == layout_id)

    def cluster_of(self, layout_id: str) -> dict[str, str]:
        return {a: c for c, ms in self.get(layout_id).clusters.items() for a in ms}


def scenario_dir(scenario_id: str) -> Path:
    """`b1.banking` -> data/b1/banking (mirrors masbench's data layout)."""
    bench, _, name = scenario_id.partition(".")
    return DATA / bench / name


def load_layouts(scenario_id: str) -> LayoutSet:
    return LayoutSet.model_validate(io.load_yaml(scenario_dir(scenario_id) / "layouts.yaml"))


def write_layouts(ls: LayoutSet, header: str = "") -> Path:
    path = scenario_dir(ls.scenario) / "layouts.yaml"
    io.dump_yaml(ls.model_dump(mode="json"), path, header)
    return path


def set_partitions(items: list[str]) -> Iterator[list[list[str]]]:
    if not items:
        yield []
        return
    first, rest = items[0], items[1:]
    for part in set_partitions(rest):
        yield [[first], *part]
        for i in range(len(part)):
            yield [*part[:i], [first, *part[i]], *part[i + 1:]]


def _canon(clusters: dict[str, list[str]]) -> frozenset[frozenset[str]]:
    return frozenset(frozenset(m) for m in clusters.values())


def named_layouts(s: Scenario) -> list[Layout]:
    entry = s.entry_agent.id
    workers = [a for a in s.agents if not a.entry]

    def has(a, pred) -> bool:  # noqa: ANN001
        return any(pred(s.tool(t)) for t in a.tools)

    readers = [a.id for a in workers
               if has(a, lambda t: t.output_trust == "untrusted") and not has(a, lambda t: t.impact == "high")]
    if readers:
        func = {"readers": readers, "actors": [a.id for a in s.agents if a.id not in readers]}
        func_desc = "Readers (untrusted input, no high-impact tool) vs actors with the orchestrator"
    else:
        func = {"orchestrator": [entry], "workers": [a.id for a in workers]}
        func_desc = ("No worker is a pure reader; the orchestrator, which never reads third-party "
                     "content itself, is separated from all workers")

    critical = [a.id for a in workers if has(a, lambda t: t.impact == "high")]
    crit = {c: [c] for c in critical}
    rest = [a.id for a in s.agents if a.id not in critical]
    if rest:
        crit["rest"] = rest

    layouts = [
        Layout(id="L-single", strategy="single", description="Every agent its own cluster",
               clusters={a.id: [a.id] for a in s.agents}),
        Layout(id="L-func", strategy="func", description=func_desc, clusters=func),
        Layout(id="L-crit", strategy="crit",
               description="Agents with high-impact tools isolated, the rest grouped", clusters=crit),
        Layout(id="L-one", strategy="one", description="All agents in one cluster",
               clusters={"all": [a.id for a in s.agents]}),
    ]
    seen: dict[frozenset, str] = {}
    for lay in layouts:
        key = _canon(lay.clusters)
        if key in seen:
            lay.description += f" (same partition as {seen[key]})"
        else:
            seen[key] = lay.id
    return layouts


def sweep_layouts(s: Scenario, named: list[Layout]) -> list[Layout]:
    by_key = {_canon(n.clusters): n.id for n in named}
    out = []
    for i, part in enumerate(set_partitions([a.id for a in s.agents]), 1):
        clusters = {f"c{j}": sorted(m) for j, m in enumerate(sorted(part, key=lambda m: (-len(m), m)), 1)}
        alias = by_key.get(_canon(clusters))
        out.append(Layout(id=f"P{i:03d}", strategy="sweep", clusters=clusters,
                          description=f"= {alias}" if alias else ""))
    return out


def build_layouts(s: Scenario) -> LayoutSet:
    named = named_layouts(s)
    return LayoutSet(scenario=s.id, agents=[a.id for a in s.agents],
                     layouts=named + sweep_layouts(s, named))
