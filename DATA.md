# Run records

Every directory below holds the per-task records behind a reported number, and nothing else:
runs of configurations that the paper does not report are not included. One JSON file per
task, as written by the AgentDojo harness: the conversation, `utility`, `security`, and for
Kairos runs a `kairos` block with the session record (every decision, deferral and oracle
verdict with its rationale) and the exact token usage. Pre-check records named
`injection_task_*` inside `user_task_*` directories are harness checks, not results.

20645 files in 101 directories.

Directory names encode the configuration: `full` (operator rules on) or `baseline` (rules
off), `spec_llm` (deferral with the LLM oracle; absent: deferral off), `anm` (the injection
addresses the agent by its own model name), `honest` (honest hold notices), the policy tag,
and `important_instructions` (attack) or `noattack` (benign).

## AgentDojo, GPT-4.1 agent: Kairos, the undefended agent and the comparison defenses

Reported in: tab:agentdojo-main, tab:main (per suite), tab:decisions, fig:decisions.

| Directory | Files |
|---|---|
| `runs/full-spec_llm-0921474b-important_instructions/gpt-4.1/banking` | 153 |
| `runs/full-spec_llm-0921474b-noattack/gpt-4.1/banking` | 16 |
| `runs/nodefense-important_instructions/gpt-4.1/banking` | 153 |
| `runs/nodefense-noattack/gpt-4.1/banking` | 16 |
| `runs/full-spec_llm-71dfa38e-important_instructions/gpt-4.1/slack` | 110 |
| `runs/baseline-spec_llm-71dfa38e-noattack/gpt-4.1/slack` | 21 |
| `runs/nodefense-important_instructions/gpt-4.1/slack` | 110 |
| `runs/nodefense-noattack/gpt-4.1/slack` | 21 |
| `runs/baseline-spec_llm-05c343f8-important_instructions/gpt-4.1/travel` | 147 |
| `runs/baseline-spec_llm-05c343f8-noattack/gpt-4.1/travel` | 20 |
| `runs/nodefense-important_instructions/gpt-4.1/travel` | 147 |
| `runs/nodefense-noattack/gpt-4.1/travel` | 20 |
| `runs/baseline-spec_llm-13887c83-important_instructions/gpt-4.1/workspace` | 246 |
| `runs/baseline-spec_llm-13887c83-noattack/gpt-4.1/workspace` | 40 |
| `runs/nodefense-important_instructions/gpt-4.1/workspace` | 246 |
| `runs/nodefense-noattack/gpt-4.1/workspace` | 40 |
| `evaluation/baselines/runs/v1/gpt-4.1/spotlighting` | 726 |
| `evaluation/baselines/runs/v1/gpt-4.1/repeat_user_prompt` | 726 |
| `evaluation/baselines/runs/v1/gpt-4.1/transformers_pi_detector` | 726 |
| `evaluation/baselines/runs/v1/gpt-4.1/progent` | 726 |
| `evaluation/baselines/runs/v1/gpt-4.1/camel` | 726 |

## AgentDojo, GPT-4.1 agent, matched set: undefended, strict monitor (deferral and oracle off), full pipeline

Reported in: strict monitor (Oracle and Model Choice); token overhead (Cost).

| Directory | Files |
|---|---|
| `runs/run_01/nodefense-important_instructions/gpt-4.1/banking` | 153 |
| `runs/run_01/baseline-0921474b-important_instructions/gpt-4.1/banking` | 153 |
| `runs/run_01/baseline-spec_llm-0921474b-important_instructions/gpt-4.1/banking` | 153 |
| `runs/run_01/nodefense-noattack/gpt-4.1/banking` | 16 |
| `runs/run_01/baseline-0921474b-noattack/gpt-4.1/banking` | 16 |
| `runs/run_01/baseline-spec_llm-0921474b-noattack/gpt-4.1/banking` | 16 |
| `runs/run_01/nodefense-important_instructions/gpt-4.1/slack` | 110 |
| `runs/run_01/baseline-18275ef7-important_instructions/gpt-4.1/slack` | 110 |
| `runs/run_01/baseline-spec_llm-18275ef7-important_instructions/gpt-4.1/slack` | 110 |
| `runs/run_01/nodefense-noattack/gpt-4.1/slack` | 21 |
| `runs/run_01/baseline-18275ef7-noattack/gpt-4.1/slack` | 21 |
| `runs/run_01/baseline-spec_llm-18275ef7-noattack/gpt-4.1/slack` | 21 |
| `runs/run_01/nodefense-important_instructions/gpt-4.1/travel` | 147 |
| `runs/run_01/baseline-05c343f8-important_instructions/gpt-4.1/travel` | 147 |
| `runs/run_01/baseline-spec_llm-05c343f8-important_instructions/gpt-4.1/travel` | 147 |
| `runs/run_01/nodefense-noattack/gpt-4.1/travel` | 20 |
| `runs/run_01/baseline-05c343f8-noattack/gpt-4.1/travel` | 20 |
| `runs/run_01/baseline-spec_llm-05c343f8-noattack/gpt-4.1/travel` | 20 |
| `runs/run_01/nodefense-important_instructions/gpt-4.1/workspace` | 246 |
| `runs/run_01/baseline-13887c83-important_instructions/gpt-4.1/workspace` | 246 |
| `runs/run_01/baseline-spec_llm-13887c83-important_instructions/gpt-4.1/workspace` | 246 |
| `runs/run_01/nodefense-noattack/gpt-4.1/workspace` | 40 |
| `runs/run_01/baseline-13887c83-noattack/gpt-4.1/workspace` | 40 |
| `runs/run_01/baseline-spec_llm-13887c83-noattack/gpt-4.1/workspace` | 40 |

## AgentDojo, Qwen3.6-35B-A3B and Llama-3.3-70B agents (GPT-4.1 oracle and Progent policy model)

Reported in: tab:agentdojo-main, tab:main (per suite).

| Directory | Files |
|---|---|
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-62761659-important_instructions/meta-llama/llama-3.3-70b-instruct/banking` | 144 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-62761659-noattack/meta-llama/llama-3.3-70b-instruct/banking` | 16 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-a8489a49-important_instructions/meta-llama/llama-3.3-70b-instruct/slack` | 105 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-a8489a49-noattack/meta-llama/llama-3.3-70b-instruct/slack` | 21 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-c75a0a35-important_instructions/meta-llama/llama-3.3-70b-instruct/travel` | 140 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-c75a0a35-noattack/meta-llama/llama-3.3-70b-instruct/travel` | 20 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-13887c83-important_instructions/meta-llama/llama-3.3-70b-instruct/workspace` | 240 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/full-spec_llm-13887c83-noattack/meta-llama/llama-3.3-70b-instruct/workspace` | 40 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/nodefense-important_instructions/meta-llama/llama-3.3-70b-instruct` | 629 |
| `runs_models/meta-llama_llama-3.3-70b-instruct/nodefense-noattack/meta-llama/llama-3.3-70b-instruct` | 97 |
| `evaluation/baselines/runs/v1/meta-llama/llama-3.3-70b-instruct/spotlighting` | 726 |
| `evaluation/baselines/runs/v1/meta-llama/llama-3.3-70b-instruct/repeat_user_prompt` | 726 |
| `evaluation/baselines/runs/v1/meta-llama/llama-3.3-70b-instruct/transformers_pi_detector` | 726 |
| `evaluation/baselines/runs/v1/meta-llama/llama-3.3-70b-instruct/progent` | 726 |
| `evaluation/baselines/runs/v1/meta-llama_llama-3.3-70b-instruct/camel` | 726 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-62761659-important_instructions/qwen/qwen3.6-35b-a3b/banking` | 144 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-62761659-noattack/qwen/qwen3.6-35b-a3b/banking` | 16 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-a8489a49-important_instructions/qwen/qwen3.6-35b-a3b/slack` | 105 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-a8489a49-noattack/qwen/qwen3.6-35b-a3b/slack` | 21 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-c75a0a35-important_instructions/qwen/qwen3.6-35b-a3b/travel` | 140 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-c75a0a35-noattack/qwen/qwen3.6-35b-a3b/travel` | 20 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-13887c83-important_instructions/qwen/qwen3.6-35b-a3b/workspace` | 240 |
| `runs_models/qwen_qwen3.6-35b-a3b/full-spec_llm-13887c83-noattack/qwen/qwen3.6-35b-a3b/workspace` | 40 |
| `runs_models/qwen_qwen3.6-35b-a3b/nodefense-important_instructions/qwen/qwen3.6-35b-a3b` | 629 |
| `runs_models/qwen_qwen3.6-35b-a3b/nodefense-noattack/qwen/qwen3.6-35b-a3b` | 97 |
| `evaluation/baselines/runs/v1/qwen/qwen3.6-35b-a3b/spotlighting` | 726 |
| `evaluation/baselines/runs/v1/qwen/qwen3.6-35b-a3b/repeat_user_prompt` | 726 |
| `evaluation/baselines/runs/v1/qwen/qwen3.6-35b-a3b/transformers_pi_detector` | 726 |
| `evaluation/baselines/runs/v1/qwen/qwen3.6-35b-a3b/progent` | 726 |
| `evaluation/baselines/runs/v1/qwen_qwen3.6-35b-a3b/camel` | 726 |

## AgentDojo Banking, Qwen3.5 agents and oracles

Reported in: tab:model-grid, tab:placement.

| Directory | Files |
|---|---|
| `runs_judge/qwen_qwen3.5-9b__judge-qwen_qwen3.5-9b` | 160 |
| `runs_judge/qwen_qwen3.5-9b__judge-qwen_qwen3.5-27b` | 160 |
| `runs_judge/qwen_qwen3.5-9b__judge-qwen_qwen3.5-35b-a3b` | 160 |
| `runs_models/qwen_qwen3.5-9b/nodefense-anm-important_instructions` | 144 |
| `runs_models/qwen_qwen3.5-9b/nodefense-anm-noattack` | 16 |
| `runs_judge/qwen_qwen3.5-27b__judge-qwen_qwen3.5-9b` | 160 |
| `runs_judge/qwen_qwen3.5-27b__judge-qwen_qwen3.5-27b` | 160 |
| `runs_judge/qwen_qwen3.5-27b__judge-qwen_qwen3.5-35b-a3b` | 160 |
| `runs_models/qwen_qwen3.5-27b/nodefense-anm-important_instructions` | 144 |
| `runs_models/qwen_qwen3.5-27b/nodefense-anm-noattack` | 16 |
| `runs_judge/qwen_qwen3.5-35b-a3b__judge-qwen_qwen3.5-9b` | 160 |
| `runs_judge/qwen_qwen3.5-35b-a3b__judge-qwen_qwen3.5-27b` | 160 |
| `runs_judge/qwen_qwen3.5-35b-a3b__judge-qwen_qwen3.5-35b-a3b` | 160 |
| `runs_models/qwen_qwen3.5-35b-a3b/nodefense-anm-important_instructions` | 144 |
| `runs_models/qwen_qwen3.5-35b-a3b/nodefense-anm-noattack` | 16 |

## AgentDyn, GPT-4o agent, GPT-4.1 oracle: Kairos with honest hold notices; undefended agent (benign)

Reported in: tab:agentdyn (Kairos row); utility retained after held effects (undefended runs as the reference).

| Directory | Files |
|---|---|
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-1bfd0f14-important_instructions` | 189 |
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-1bfd0f14-noattack` | 20 |
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-33490784-important_instructions` | 189 |
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-33490784-noattack` | 20 |
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-c4ecec61-important_instructions` | 210 |
| `evaluation/agentdyn/runs/full-spec_llm-honest-sys95318c-anm-c4ecec61-noattack` | 20 |
| `evaluation/agentdyn/runs/nodefense-sys95318c-anm-noattack` | 60 |

## AutoDojo, GPT-4o-mini agent, GPT-4.1 oracle: injections optimized against Kairos, their replay, clean runs

Reported in: tab:autodojo (Kairos row: attack success from the replay, clean utility from runs_v2_static).

| Directory | Files |
|---|---|
| `autodojo_runs/variants_v2` | 6 |
| `autodojo_runs/runs_v2` | 389 |
| `autodojo_runs/runs_v2_static` | 57 |

## Deployed stack: latency microbenchmarks

Reported in: latency (Cost).

| Directory | Files |
|---|---|
| `production_runs/latency` | 6 |

## Policies

The tag in a run directory name is the SHA-1 prefix of the policy file the run used. The files
are in `policies_used/`; their comments and free-text description were edited for anonymous
review, which changed their hashes; no field the monitor evaluates changed.

| Tag | File | Used by |
|---|---|---|
| `0921474b` | `policies_used/banking_0921474b.yaml` | Banking: GPT-4.1 runs and the matched set |
| `71dfa38e` | `policies_used/slack_71dfa38e.yaml` | Slack: GPT-4.1 runs (the matched set used 18275ef7, not preserved) |
| `05c343f8` | `policies_used/travel_05c343f8.yaml` | Travel: GPT-4.1 runs and the matched set |
| `13887c83` | `policies_used/workspace_13887c83.yaml` | Workspace: all AgentDojo runs |
| `62761659` | `policies_used/banking_62761659.yaml` | Banking: open agent models, Qwen3.5 matrix, AutoDojo |
| `a8489a49` | `policies_used/slack_a8489a49.yaml` | Slack: open agent models, AutoDojo |
| `c75a0a35` | `policies_used/travel_c75a0a35.yaml` | Travel: open agent models, AutoDojo |
| `1bfd0f14` | `policies_used/agentdyn_github_1bfd0f14.yaml` | AgentDyn github |
| `33490784` | `policies_used/agentdyn_shopping_33490784.yaml` | AgentDyn shopping |
| `c4ecec61` | `policies_used/agentdyn_dailylife_c4ecec61.yaml` | AgentDyn dailylife |
| `18275ef7` | not preserved | Slack: matched set |

