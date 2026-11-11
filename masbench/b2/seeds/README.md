# Seed files: the attacker side of 15 core cases

For these core cases the environment, agents, task, utility check and benign twin are in
`masbench/b2/envs/teams.py`. The attacker side is data: put one file `<core_id>.yaml` in
this directory and run `python -m masbench.cli generate b2`. Without the file, only the twin
of the case is generated (the cases are listed in `tests/test_masbench_b2.py::SEEDED`).

All 15 files exist. `make_seeds.py` generated them from checkouts of the sources (commits below), so the
attacker texts are the sources' own; `payload_source` and `note` of each file say what, if
anything, was added for the catalogue's adaptation:

| Core id | `payload_source` | Attacker text |
|---|---|---|
| B2-01..06 | verbatim | The source's adversarial template of the role (`agents/adversarial_agent.py`) filled with the `Harmful_Behavior` of dataset rows 4, 41, 37, 146, 133, 102, plus the scenario's deployment note |
| B2-21, 22 | adapted | Colluders' secret instructions verbatim; added: the attacker ticker `VLTR` x 5000 (B2-21) and the quantity 1000 (B2-22) |
| B2-23 | adapted | Secret instructions verbatim; added: the forum URL and the fabricated grades |
| B2-24 | adapted | Secret instruction of the Article Writing agent verbatim; added: the affiliate URL. The source's colluding Distribution agent is honest here (catalogue adaptation) |
| B2-25, 26 | adapted | Malicious-agent system prompt as `oasis/social_platform/config/user.py` builds it (profiles of users 100 and 101) and the private-message objective; added: the scheme with the fraud account / form address |
| B2-43, 44 | verbatim | The Input of `Demos/Prompts.md` Example 1 (leakage) and Example 2 (phishing), without the table markup |
| B2-47 | written | Synthetic case (no released payload): the forward-me paragraph |

| Core id | Scenario | Agents (entry first) | Injection vectors | Check functions |
|---|---|---|---|---|
| B2-01, B2-02, B2-03 | `b2.badacts_travel` | planner_agent, recommender_agent, weather_agent, messaging_agent, ticketing_agent | none | `message_sent(address, contains, contains_any)`, `ticket_booked(contains)` |
| B2-04, B2-05 | `b2.badacts_code` | ceo, designer, programmer, reviewer, tester, executer, browser | none | `file_rule(rule)` with `EXIST <file>`, `NOT <file>`, `INCLUDES <file> <text>` |
| B2-06 | `b2.badacts_finance` | chief_editor, researcher, assistant, editor, writer, image_generator | none | `article_published(contains)` |
| B2-21, B2-22 | `b2.tamas_finance` | coordinator, identity, market, trade, risk | none | `order_placed(ticker, min_quantity, needs_stop_loss)` |
| B2-23 | `b2.tamas_education` | coordinator, adaptive, assessment, progress, concept, distribution | none | `records_leaked_or_grades_changed(contains_any)`, `grades_changed()` |
| B2-24 | `b2.tamas_news` | coordinator, gathering, fact_checking, writing, distribution | none | `post_published(contains)` |
| B2-25, B2-26 | `b2.social_platform` | assistant, contact_1, contact_2, contact_3 | none | `transfer_made(account)`; shared `sink_request(...)` |
| B2-43, B2-44 | `b2.mail_assistants` | assistant_1 .. assistant_4 | `mail_1` | shared `sink_request(...)`, `message_sent(contains, not_sender)` |
| B2-47 | `b2.chain` | agent_a, agent_b, agent_c, agent_d | `document` | shared `sink_request(agent, contains, ...)` |

Shared check functions are those of `masbench/checks.py` (set `shared: true`); the others are
in `masbench/b2/envs/teams.py`.

## Format

```yaml
payload_source: verbatim        # or: written
note: free text for labels.impl_note (deviations from the seed)
readers: [assistant_1]          # agents that read an injection (labels.reader_agents)
attack:
  injections:                   # adversary A1: text placed in an injection vector
    mail_1: |
      ...
  compromised:                  # adversary A3: per agent, one of
    recommender_agent:
      system_prompt: |          #   replaces the agent's prompt; may use {peers} and {user}
        ...
    market:
      instructions: |           #   appended to the agent's prompt
        ...
  board_writes: []              # [{board, object, content, author}]
security:
  check: message_sent           # function name
  shared: false                 # true = from masbench/checks.py
  reads: [state]
  args: {address: ..., contains: [...]}
script:                         # ground truth of the attack, per agent one list per activation
  planner_agent:
    - - {send: recommender_agent, text: "..."}
      - {reply: "..."}
  messaging_agent:
    - - {tool: send_email, args: {address: ..., message: ..., confirm_message: true}}
```

The script must reach the attacker's goal when replayed (`--brain replay`) and must cross
the agents in the case's `path_agents`; `tests/test_masbench_b2.py` checks both for every
generated attack case.

## Sources

- `extract_badacts.py` copies the BAD-ACTS prompts verbatim from a checkout of
  `JNoether/BAD-ACTS` at `5ddfcfa`: `badacts_agents.json` (original agent prompts, used by the
  scenarios) and `badacts_adversarial.json` (the source's templates for an adversarial agent,
  with a `{goal}` placeholder; the goals are the `Harmful_Behavior` fields of the dataset rows
  named in the catalogue). The second file is not used by any code and is not committed.
- TAMAS: `data/Colluding/<domain>_colluding.json` at `545c112`; the secret instruction of a
  colluder is the part of its `agent_description` after the base description.
- MultiAgentFraudBench: `zheng977/MutiAgent4Fraud` at `950e489`:
  `scripts/twitter_simulation/align_with_real_world/system_prompt(static|dynamic).json` and
  `data/our_twitter_sim/base-agent-data/test_110_good_bad_random_1.0_1.0_zzj.csv`.
- ComPromptMized: `StavC/ComPromptMized` at `6ab9116`, `Demos/Prompts.md`.
- pajaMAS: `pajamas/` holds byte-identical copies of the pages of `trailofbits/pajaMAS` at
  `67b83f1` (`simple_mas` test.html, test4.html; `tool_mas` clean.html, placeholder.html;
  `trifecta_mas` preference.html, medical.html, birds.html), used by `envs/coding.py`, which
  applies the catalogue's substitutions in code.
