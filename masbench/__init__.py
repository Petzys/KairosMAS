"""masbench: defense-neutral benchmark for multi-agent systems (B1 AgentDojo-MAS, B2 MAS-unique attacks).

The package knows no defense. A defense is an adapter that subclasses
`masbench.runner.defense.Defense` and lives in the defense's own code base (e.g. KAIROS:
`masbench/defenses/kairos/`); it derives its configuration (policies, layouts, detectors) from
the defense-neutral annotations of a scenario. Load it with `--defense <module>:<Class>` or
register a short name under the `masbench.defenses` entry-point group.

Layout of a scenario directory (format `mascase/0.2`, see `masbench.schema`)::

    data/<benchmark>/<scenario>/scenario.yaml   environment, tools, agents, communication, boards
    data/<benchmark>/<scenario>/cases.jsonl     one case per line (benign or attack)
"""

FORMAT = "mascase/0.2"
