# masbench

Defense-neutral benchmark for multi-agent systems. **B1** lifts AgentDojo v1 to a MAS with the
MultiAgentDojo agent split ("Can CaMeLs talk?", Table I) plus a tool-less orchestrator, so every
task needs inter-agent communication. **B2** (MAS-unique attacks) uses the same format.

masbench knows no defense. Scenarios carry defense-neutral tool annotations (effect,
reversibility, external reach, impact, output trust, sensitivity); each defense derives its own
configuration from them in an adapter that lives with the defense and subclasses
`runner/defense.py:Defense`. The KAIROS adapter is `kairos/adapters/masbench/`.

| Path | What it is |
|---|---|
| `schema.py` | The `mascase/0.1` format (scenario, case, run record); JSON Schemas in `schema/` |
| `b1/partition.py` | Agent split and defense-neutral tool annotations (edit here) |
| `b1/generate.py` | Generates `data/b1/<suite>/` from AgentDojo |
| `runner/` | Concurrent agents, A2A shim (`send_message`, `send_message_async`), defense hooks, records |
| `env.py`, `attacks.py` | Shared environment and scoring; attack templates rendered at run time |

## Writing a defense adapter

Subclass `Defense` and override the hooks you need (all async, so a hook may stall a call):
`system_prompt`, `make_brain` (replace an agent's loop), `before_tool`, `after_tool`,
`on_message` (requests and replies), `on_receive`, `on_activation_end`, `drain_notices`,
`on_final`, `finish`. `ctx.execute_tool` runs a call the defense held and later committed;
`ctx.log` ends up in the run record. Constructor keyword arguments are the defense options
(`--defense-options '{...}'`) and are stored in every run record.

Load it as `--defense <module>:<Class>`, or give it a short name in the defense's package:

```toml
[project.entry-points."masbench.defenses"]
my-defense = "my_pkg.masbench_adapter:MyDefense"
```

## Commands

```bash
.venv/bin/python -m masbench.cli generate      # data/b1/*  (97 benign, 629 attack cases)
.venv/bin/python -m masbench.cli schema        # schema/*.schema.json
.venv/bin/python -m masbench.cli validate

# offline: replay AgentDojo ground truth through the agents (no model needed)
.venv/bin/python -m masbench.cli run -s b1.banking --brain replay --kind benign

# LLM agents on any OpenAI-compatible endpoint, with or without a defense
.venv/bin/python -m masbench.cli run -s b1.workspace --model gpt-4.1-2025-04-14 --kind attack
.venv/bin/python -m masbench.cli run -s b1.banking --model gemma-4-26b-a4b-it \
    --base-url "$UZL_BASE_URL" --api-key-env UZL_API_KEY \
    --defense kairos-per-agent --defense-options '{"judge_model": "qwen3.8-27b", ...}'
.venv/bin/python -m masbench.cli summarize runs_masbench

.venv/bin/python -m pytest tests/test_masbench.py
```
