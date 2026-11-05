"""Read and write scenario directories (`scenario.yaml`, `cases.jsonl`, `layouts.yaml`)."""
from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path
from typing import Any

import yaml

from masbench.schema import Case, LayoutSet, Scenario

DATA = Path(__file__).parent / "data"


class _Dumper(yaml.SafeDumper):
    pass


def _str(dumper: yaml.SafeDumper, s: str) -> yaml.ScalarNode:
    style = "|" if "\n" in s else None
    return dumper.represent_scalar("tag:yaml.org,2002:str", s, style=style)


def _tuple(dumper: yaml.SafeDumper, t: tuple[Any, ...]) -> yaml.SequenceNode:
    return dumper.represent_sequence("tag:yaml.org,2002:seq", list(t), flow_style=True)


_Dumper.add_representer(str, _str)
_Dumper.add_representer(tuple, _tuple)


def dump_yaml(obj: Any, path: Path, header: str = "") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    text = yaml.dump(obj, Dumper=_Dumper, sort_keys=False, allow_unicode=True, width=100)
    path.write_text((header + "\n" if header else "") + text)


def load_yaml(path: Path) -> Any:
    return yaml.safe_load(path.read_text())


def scenario_dir(scenario_id: str) -> Path:
    """`b1.banking` -> data/b1/banking."""
    bench, _, name = scenario_id.partition(".")
    return DATA / bench / name


def load_scenario(scenario_id: str) -> Scenario:
    return Scenario.model_validate(load_yaml(scenario_dir(scenario_id) / "scenario.yaml"))


def load_layouts(scenario_id: str) -> LayoutSet:
    return LayoutSet.model_validate(load_yaml(scenario_dir(scenario_id) / "layouts.yaml"))


def load_cases(scenario_id: str) -> list[Case]:
    path = scenario_dir(scenario_id) / "cases.jsonl"
    return [Case.model_validate_json(line) for line in path.read_text().splitlines() if line.strip()]


def write_scenario(s: Scenario, header: str = "") -> None:
    dump_yaml(s.model_dump(mode="json", exclude_defaults=False), scenario_dir(s.id) / "scenario.yaml", header)


def write_layouts(ls: LayoutSet, header: str = "") -> None:
    dump_yaml(ls.model_dump(mode="json"), scenario_dir(ls.scenario) / "layouts.yaml", header)


def write_cases(scenario_id: str, cases: Iterable[Case]) -> None:
    path = scenario_dir(scenario_id) / "cases.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w") as f:
        for c in cases:
            f.write(json.dumps(c.model_dump(mode="json", exclude_none=True), ensure_ascii=False) + "\n")
