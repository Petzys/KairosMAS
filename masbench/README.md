# masbench

A defense-neutral benchmark for multi-agent systems. Attack cases and defenses meet only in
the runner:

```
attack case (data)            runner                               defense adapter
scenario.yaml + cases.jsonl → agents, A2A, tools, boards, sink  ←  masbench/defenses/<name>/
checks (python predicates)  ← committed state + sink + trace       hooks only, no case access
```

- **B1 (AgentDojo-MAS)**: AgentDojo v1 on the MultiAgentDojo agent split, 97 benign and 629
  attack cases (`b1/`).
- **B2 (MAS-unique attacks)**: the cases of `b2/core.csv` (pinned copy of the notes'
  `b2_core.csv`), each with a benign twin and, for Composition, single-fragment controls
  (`b2/`). 43 of the 58 core cases have an attack case; for the other 15 the scenario and twin
  exist and the attacker side is read from a seed file (`b2/seeds/README.md`).

## Layout

| Path | Content |
|---|---|
| `schema.py`, `schema/*.json` | The `mascase/0.2` format: `Scenario`, `Case`, `RunRecord` |
| `data/<bench>/<scenario>/` | Generated `scenario.yaml` and `cases.jsonl` |
| `env.py`, `sim.py` | Environments: AgentDojo suites, and in-process simulations (state, boards, sink, scripted shell) |
| `checks.py` | Scoring: `agentdojo:` task checks and `python:` predicates over committed state, sink and trace |
| `runner/` | Agents on an A2A shim, the defense hooks (`defense.py`), brains (model, replay), batch runs |
| `b1/`, `b2/` | Case generators. `b2/envs/*.py`: one module per environment family with tools, checks, cases |
| `defenses/<name>/` | One adapter per defense |

## How a catalogue row becomes a case

| `b2_core.csv` | Case |
|---|---|
| `core_id`, `primary_class`, `origin`, `adversary`, `sok_*`, `shared_board`, `attack_path`, ... | `labels` (never shown to agents or defenses; copied into each run record) |
| adversary A1 | `attacker.injections[]`: literal text in an injection vector of the environment |
| adversary A3 | `attacker.compromised_agents[]`: instructions appended to, or replacing, an agent's prompt |
| board cases | `scenario.boards[]`, board tools (`ToolSpec.board`), `attacker.board_writes[]` for pre-seeded content |
| `delivery` | `communication.edges` and the split of tools over agents |
| `success_predicate` | `scoring.security`: a python predicate; only committed, externally visible state counts |
| `benign_twin` | the `kind: benign` case `<core_id>/twin` |
| `controls` | `kind: control` cases; their security check must stay False |

`labels.payload_source` says whether the payload is `verbatim` from the seed or `written` for
this benchmark; `labels.impl_note` records every deviation from the catalogue. The column
`expected_mechanism` is specific to one defense and is not part of a case.

Every B2 case carries a ground-truth `script` (the analogue of AgentDojo's ground truth):
`--brain replay` runs it without a model. Attack scripts must reach the attacker's goal along
`labels.path_agents`, twin scripts must complete the task, controls must not reach the goal.

## Defenses

A defense subclasses `runner/defense.py:Defense` and lives in `defenses/<name>/` (its
`DEFENSE` class). It sees the scenario (agents, tool annotations, topology, boards), the
principal's prompt and the traffic; never the attacker, the scoring, the labels or the
environment's internals. It derives its policy from the tool annotations (`effect`,
`reversible`, `external`, `impact`, `output_trust`, `output_sensitivity`, `board`).

| Hook | Use |
|---|---|
| `supports(scenario)` | Reason why the defense cannot run a scenario; such runs are recorded as not applicable |
| `system_prompt`, `before_llm` | Change an agent's prompt, or the conversation and tools of one model call |
| `before_tool` | allow / deny / replace (stub result) / modify (rewrite args) / abort |
| `after_tool`, `on_receive` | New text, or a verdict, for a tool output or a delivered message |
| `on_message` | Verdict on a request or reply before delivery; `Message.meta` carries defense metadata |
| `make_brain(agent, default, handle)` | Replace the agent loop; `handle.llm / call_tool / send` stay on the recorded path |
| `on_activation_end`, `drain_notices`, `on_final`, `finish` | Staging monitors |
| `ctx.messages`, `ctx.tool_calls`, `ctx.isolate`, `ctx.event`, `ctx.llm`, `ctx.execute_tool` | Logs, agent isolation, uniform decision events, metered auxiliary model, committing a held call |

| Directory | Run | Built on | Needs |
|---|---|---|---|
| `none` | R01 | the default hooks | - |
| `kairos` (`kairos-per-agent`) | R03 | KAIROS reference monitor per agent | oracle model |
| `pi_detector` | R05 | AgentDojo's detector (`protectai/deberta-v3-base-prompt-injection-v2`) | torch, transformers |
| `spotlighting` | R06 | AgentDojo's delimiting | - |
| `sandwiching` | R07 | AgentDojo's `repeat_user_prompt` | - |
| `progent` | R08 | the Progent library (`secagent`) of the AutoDojo checkout | policy model |
| `camel` | R09 | the CaMeL code of the AutoDojo checkout | `.venv-camel`, P-LLM/Q-LLM |
| `multi_camel` | R24 | rebuild on `camel` (no released code) | as `camel` |
| `safeflow` | R25 | port after the paper | defense-side model |
| `blindguard` | R26 | detector after the released code, retrained | torch, transformers, a trained checkpoint |

Each directory has a README with the hooks it uses and the adaptation notes (interface-only
or mechanism-changing), and the module docstring states the lifting rules and options.
Lifted single-agent defenses treat tool outputs and received messages as untrusted input.
`tests/test_masbench_defenses.py` runs every adapter offline on scripted cases;
`tests/test_masbench_defense_fit.py` shows with minimal mocks what each hook carries.

## Commands

```bash
python -m masbench.cli generate b2            # regenerate data/b2 from b2/envs
python -m masbench.cli validate               # check every scenario directory
python -m masbench.cli defenses               # list adapters
python -m masbench.cli run -s 'b2.*' --brain replay --out ''          # ground truth, no model
python -m masbench.cli run -s 'b2.*' --model gemma-4-26b-a4b-it \
    --base-url "$UZL_BASE_URL" --api-key-env UZL_API_KEY --seed --repeat 3 --out runs_masbench_b2
python -m masbench.cli run -s b1.banking --defense kairos --defense-options '{"judge_model": "..."}'
python -m masbench.cli run -s 'b2.*' --defense safeflow --model <model> ...
.venv-camel/bin/python -m masbench.cli run -s 'b2.*' --defense camel \
    --defense-options '{"model": "<model>", "base_url": "...", "api_key_env": "UZL_API_KEY"}' ...
python -m masbench.cli summarize runs_masbench_b2          # ASR, U, Ub, NRP per class, macro average, Wilson CI
python -m masbench.cli b2-validate runs_masbench_b2/none/gemma-4-26b-a4b-it   # Implementation Guide §5 table
```

Records are written to `<out>/<defense+options>/<model>/<scenario>/<case>[__rN].json`; existing
records are skipped, so a batch resumes.

## Adding a B2 case

1. Add the tools, state and checks to an environment module in `b2/envs/` (or a new module
   with a `build_cases()` function).
2. Call `build.cases(scenario, "<core_id>", ...)` with the prompt, the attacker, the checks, the
   two scripts and the path; labels come from `b2/core.csv`.
3. `python -m masbench.cli generate b2`, then `pytest tests/test_masbench_b2.py`.
4. Run it undefended and check it with `b2-validate`.
