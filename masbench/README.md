# masbench

Defense-neutral benchmark for multi-agent systems. **B1** lifts AgentDojo v1 to a MAS with the
MultiAgentDojo agent split ("Can CaMeLs talk?", Table I) plus a tool-less orchestrator, so every
task needs inter-agent communication. **B2** (MAS-unique attacks) uses the same format. The package
does not import `kairos`; KAIROS MAS and the baselines plug in through `runner/defense.py`.

| Path | What it is |
|---|---|
| `schema.py` | The `mascase/0.1` format (scenario, case, layouts, run record); JSON Schemas in `schema/` |
| `b1/partition.py` | Agent split and defense-neutral tool annotations (edit here) |
| `b1/generate.py` | Generates `data/b1/<suite>/` from AgentDojo |
| `layouts.py` | L-single, L-func, L-crit, L-one and the full partition sweep |
| `policies/kairos_mas.py` | KAIROS MAS agent and cluster policies, generated from `kairos/config/` |
| `runner/` | Concurrent agents, A2A shim (`send_message`, `send_message_async`), defense hooks, records |
| `env.py`, `attacks.py` | Shared environment and scoring; attack templates rendered at run time |

```bash
.venv/bin/python -m masbench.cli generate      # data/b1/*  (97 benign, 629 attack cases)
.venv/bin/python -m masbench.cli policies      # data/policies/kairos_mas/b1/*
.venv/bin/python -m masbench.cli schema        # schema/*.schema.json
.venv/bin/python -m masbench.cli validate

# offline: replay AgentDojo ground truth through the agents (no model needed)
.venv/bin/python -m masbench.cli run -s b1.banking -l L-func --brain replay --kind benign

# LLM agents on any OpenAI-compatible endpoint
.venv/bin/python -m masbench.cli run -s b1.workspace -l L-func --model gpt-4.1-2025-04-14 --kind attack
.venv/bin/python -m masbench.cli run -s b1.banking --model gemma-4-26b-a4b-it \
    --base-url "$UZL_BASE_URL" --api-key-env UZL_API_KEY
.venv/bin/python -m masbench.cli summarize runs_masbench

.venv/bin/python -m pytest tests/test_masbench.py
```

The format specification is in the thesis notes (`Benchmarking/MAS Case Format.md`).
