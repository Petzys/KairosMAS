"""KAIROS adapter for masbench, the defense-neutral MAS benchmark.

masbench (top-level package) holds scenarios, cases and the runner and knows no defense. This
adapter turns a masbench scenario into KAIROS configuration and plugs KAIROS into the runner:

| Module | What it is |
|---|---|
| `layouts.py` | KAIROS MAS cluster layouts (L-single, L-func, L-crit, L-one, full sweep), derived from the scenario's tool annotations |
| `policies.py` | KAIROS MAS agent and cluster policies, split from the single-agent suite policies in `kairos/config/` |
| `per_agent.py` | Baseline R03: unmodified single-agent KAIROS on every agent (`--defense kairos-per-agent`) |
| `data/<bench>/<suite>/` | Generated `layouts.yaml`, `agents/`, `cluster_template.yaml`, `clusters/<layout>/` |

    .venv/bin/python -m kairos.adapters.masbench        # regenerate layouts and policies
    .venv/bin/python -m masbench.cli run -s b1.banking --defense kairos-per-agent \\
        --defense-options '{"judge_model": "gpt-4.1-2025-04-14"}'

The KAIROS MAS monitor itself (clusters, cross-agent provenance) will plug in here as a further
defense class reading `layouts.yaml` and the cluster policies.
"""
