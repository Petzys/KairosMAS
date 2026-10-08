# Benchmarks

The three benchmarks are not copied into this repository. `setup_benchmarks.sh` clones each at the
commit the evaluation used and applies the patch below; checkouts land in `benchmark/`.

| Benchmark | Upstream | Commit | Used for |
|---|---|---|---|
| agentdojo | https://github.com/ethz-spylab/agentdojo | `089ed468cf3e` | GPT-4.1 AgentDojo runs (Kairos, undefended agent, matched set) |
| autodojo | https://github.com/xhOwenMa/AutoDojo | `abbcbd8d59ea` | its AgentDojo fork: comparison defenses, open-weight agents, Qwen3.5 matrix; the AutoDojo attack |
| agentdyn | https://github.com/SaFo-Lab/AgentDyn | `5353cf7615b1` | AgentDyn suites |

## Patches

**agentdojo** (`patches/agentdojo.patch`):

- `src/agentdojo/types.py`: scoring tolerates a final assistant message without content

**autodojo** (`patches/autodojo.patch`):

- `agentdojo/src/agentdojo/agent_pipeline/agent_pipeline.py`: registers `--defense kairos`; routes a vendor-prefixed model id to OpenRouter and a bare id to OpenAI
- `agentdojo/src/agentdojo/agent_pipeline/llms/openai_llm.py`: tool-call arguments: accepts double-encoded JSON, a list of objects, or null
- `agentdojo/src/agentdojo/benchmark.py`: records a task that exceeds the model's context window as failed instead of aborting the suite
- `agentdojo/src/agentdojo/default_suites/v1/slack/user_tasks.py`: one Slack utility check no longer raises when the agent never fetched the page
- `agentdojo/src/agentdojo/defenses/camel/src/camel/interpreter/interpreter.py`: CaMeL interpreter: a failed `in` comparison becomes a program error instead of a crash
- `agentdojo/src/agentdojo/models.py`: the names by which injections address the open-weight agents
- `agentdojo/src/agentdojo/types.py`: same scoring fix as the AgentDojo patch

**agentdyn**: unmodified.

The licenses of the benchmarks apply to the fetched checkouts and to the patches.
