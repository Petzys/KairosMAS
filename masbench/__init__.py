"""masbench: defense-neutral benchmark for multi-agent systems (B1 AgentDojo-MAS, B2 MAS-unique attacks).

The package does not import `kairos`. Defenses (KAIROS MAS, baselines) plug in through
`masbench.runner.defense.Defense`; their policies live next to the cases under
`masbench/data/policies/<defense>/`.

Layout of a scenario directory (format `mascase/0.1`, see `masbench.schema`)::

    data/<benchmark>/<scenario>/scenario.yaml   environment, tools, agents, communication, boards
    data/<benchmark>/<scenario>/cases.jsonl     one case per line (benign or attack)
    data/<benchmark>/<scenario>/layouts.yaml    cluster partitions of the agents
"""

FORMAT = "mascase/0.1"
