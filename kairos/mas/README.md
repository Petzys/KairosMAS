# KAIROS MAS

KAIROS for multi-agent systems: any number of opaque agents, on separate hosts,
communicating over A2A. **A malicious action is never externally visible**, while
benign work keeps running in parallel and only what has to be decided is decided.

```
            principal ──prompt──▶ ┌───────────── cluster "front" ─────────────┐
                                  │ [assistant]◀─▶ EP ── decision point (DP)   │
                                  └──────────────────┬─────────────────────────┘
                     A2A (held / released at the     │ messages leaving a cluster are
                     sending cluster's boundary)     │ released like external requests
                ┌──────────── cluster "finance" ─────┴───┐   ┌──── cluster "docs" ────┐
                │ [accounts]◀─▶EP   [payments]◀─▶EP   DP  │   │ [documents]◀─▶EP   DP  │
                │      ▲ intra-cluster: logged, never      │   └────────────────────────┘
                │      ▼ stalled, labels joined            │
                └───────────────────────┬─────────────────┘
                                        ▼ external effects: full KAIROS per agent,
                                          with labels and lineage across agents
```

* **Enforcement point (EP), one per agent host** — sees everything crossing the host
  boundary (tool calls / HTTP / files, A2A in both directions), applies decisions:
  forward, block, stall, stub. [`enforcement.py`](enforcement.py)
* **Decision point (DP), one per cluster** — the members' monitors (labels, speculative
  state, oracle calls) and their slice of the causal log. Logical: all DPs can be
  co-located (the central monitor) or spread over trusted hosts; only the fabric
  changes. [`fabric.py`](fabric.py), [`agent.py`](agent.py)
* Agents and models are **not** in the TCB; the isolation layer, EPs, DPs and hosts are.

## Code map

| Module | What it implements |
|---|---|
| [`spec.py`](spec.py), [`spec_parser.py`](spec_parser.py) | The system as the principal declares it: agents (labeling policy) and clusters (release policy), YAML format, validation. Example: [`config/banking.yaml`](config/banking.yaml) |
| [`causal.py`](causal.py) | Per-agent sequence numbers, vector clocks (lineage), causal delivery at a DP |
| [`policy.py`](policy.py) | Release decisions for messages, built on the single-agent `PolicyEngine` |
| [`agent.py`](agent.py) | `AgentMonitor`: single-agent KAIROS per agent + the inter-agent channel |
| [`fabric.py`](fabric.py) | DPs, message registry, lineage queries across DPs, downstream notices |
| [`enforcement.py`](enforcement.py) | `EnforcementPoint`: tool path, A2A client side, A2A server side |
| [`oracle.py`](oracle.py) | Lineage-aware oracle (`MASJudge`), context on request |
| [`a2a/`](a2a) | A2A v1.0 wire types, protocol adapter, minimal server/client, HTTP sidecars |
| [`transport.py`](transport.py), [`runtime.py`](runtime.py) | Network abstraction, in-process hosts and session driver |
| [`serve.py`](serve.py) | Deployment entry point in front of real A2A agents |
| [`trace.py`](trace.py) | Flight recorder: every boundary crossing, decision and reasoning step of a run, in order |
| [`viewer/`](viewer) | Graphical replay of runs (`python -m kairos.mas.viewer`) |
| [`bench/`](bench) | **MASDojo**, the system-level benchmark (below) |

The single-agent core changed in one place: tokens record their owner and the
`TokenStore` can snapshot and join labels (`kairos/core/{tokens,store}.py`); with no
owner set everything behaves exactly as before (all original tests pass unchanged).

## How the notes are implemented

### Policies (Cluster model §3.1, Labels)
* **Agent policy = labeling only**: `actions` (revertable / non_revertable), `taints`,
  `trusted_sources` — the tool half of a single-agent policy.
* **Cluster policy = who may receive which data**: `contact_book.peers` (clusters with
  their default clearance, per-agent overrides, `on_miss`), `contact_book.external`
  (the single-agent contact book), `rules` (incl. `a2a.send` / `a2a.reply` with
  `to_agent` / `to_cluster` params), release knobs, and the cluster's `clearance`.
* Disjointness is enforced: a contact book, rules or `default_action` in an agent
  policy is a `SpecError`.
* An agent's external effects run under `spec.agent_policy(agent)`: its labels joined
  with its cluster's release policy. Only the **sending** cluster's policy decides; there
  is no inbound check.
* **Topology**: complete graph at the transport level; the effective topology is the
  contact books. `peers.on_miss: DENY` makes the listed edges the only ones.

### Intra-cluster communication (§3.2)
Released at once, never stalled, never a resolution trigger. Logged as SEND/RECV
events with a happens-before edge. Labels join on delivery. The extension "cheap
deterministic checks" is implemented as `intra_cluster_checks: annotate`: the message
is checked (payload identifiers, sensitivity) and the result is recorded in the causal
log, where the oracle sees it when a later effect's lineage passes through it.

### Inter-cluster communication (§3.3)
Every message leaving a cluster is a **non-revertable effect**, released like an external
request: `topology → integrity of the destination → confidentiality against the sending
cluster's clearance (over the sender's joined S) → payload identifiers → rules`, then the
oracle on REVIEW.

| A2A | KAIROS effect | Behaviour |
|---|---|---|
| `SendMessage` | **blocking** | an open branch is resolved first (trigger `BLOCKING_EFFECT`), then the message is decided on its own, synchronously — the oracle sees only the prefix |
| `SendStreamingMessage`, `SendMessage` with `configuration.returnImmediately` | **stallable** | held in the sender's speculative scope; the sender sees the native A2A `TASK_STATE_WORKING`; released or dropped at the sender's next trigger — the oracle sees later evidence |

Triggers that release a held message: the sender finishes its task (TERMINAL), a further
held effect (NESTED_REVIEW), a stub flowing into a new call, a re-issue (LOOP, honest
mode), a blocking send (BLOCKING_EFFECT), the sender **polling the held task**
(`GetTask` / `SubscribeToTask` → AWAIT, a dependency on the held effect), and the stall
budget (BUDGET, also checked by a watchdog for a quiet agent). Denial: the message is
dropped, the sender sees `TASK_STATE_REJECTED` plus a KAIROS-style notice; the agent's
context is not rolled back.

### Resolution and the oracle (§3.4)
* Resolution is always **per agent**; the oracle only decides about that agent's held
  effects.
* **Lineage**: each event's vector clock covers its causal past back to the principal's
  prompt. By default the oracle sees what the single-agent oracle sees (user request,
  own trace incl. received messages — marked as untrusted data — earlier reviews).
  **Auto-included foreign lineage**: when a gated value stems from a received message,
  the value is chased back hop by hop through the messages that carried it, and each
  sender's trace up to its SEND is shown. **On request**: the oracle may answer
  `{"request_context": ["<agent>"]}` to see another lineage agent's trace (one round by
  default).
* **Prior reviews**: every resolution is a DECISION event in the agent's log; a denial
  flags the agent, and the oracle sees denials of any agent whose events lie in the
  effect's lineage (framed as context, not proof).
* **Retry** as in KAIROS: a withheld action may be re-issued once if the task needs it;
  the re-issued message is a new effect, judged with the earlier verdict in view.

### Labels and provenance
* `T` and `S` are joined on delivery (`T_recv |= T_send`, `S_recv |= S_send`) from a
  snapshot taken at the SEND — the receiver inherits what the sender knew when it wrote
  the message. Every token keeps its **owner**; conflicting levels resolve to the
  maximum. Joining `T` is safe because `T` only ever grows from the prompt and declared
  trusted sources; joining `S` is conservative.
* The principal's prompt seeds `T_0` at the entry agent only; every other agent obtains
  it through the joins of the messages its work descends from.
* Message content is recorded for provenance (not admitted as tokens), so a value is
  attributed to the message — and transitively the agent and tool — it came from
  (`documents/read_file`).
* Outbound network effects: the sending cluster's policy decides, over the joined sets.
* File writes follow KAIROS per agent (overlay + file-trust ledger). Each agent has its
  own file system and its labels only grow within a session, so "a new file gets all
  labels of the writer's T and S" is subsumed: anything the agent reads back is already
  covered by its own sets.

### System model and ordering
No global clock: per-agent sequence numbers plus monitor message ids give the
happens-before edges; vector clocks carry the lineage. A DP delivers events in causal
order (buffering out-of-order arrivals, e.g. from separate file and network channels)
and `MonitorFabric.await_lineage` lets a decision wait until the effect's whole causal
past has arrived.

### A2A and other protocols (Implementation)
`a2a/adapter.py` is the protocol seam: the monitor reasons over `InterAgentMessage`s
(REQUEST blocking/streaming, REPLY, POLL, CONTROL) and the adapter renders the two
answers the monitor gives itself (`working`, `rejected`) and the canonical form of what
it checked, which is what leaves. Another protocol needs only another adapter.

The prototype speaks **A2A v1.0** (specification release 1.0.1, JSON-RPC binding,
normative `a2a.proto` package `lf.a2a.v1`) and nothing else:

* methods `SendMessage`, `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`,
  `SubscribeToTask` (plus the push-config methods and `GetExtendedAgentCard`, which are
  answered with their errors); ProtoJSON payloads: `TASK_STATE_*` / `ROLE_*` enum
  names, parts without a `kind` tag (exactly one of `text` / `raw` / `url` / `data`),
  `SendMessageResponse` / `StreamResponse` oneof wrappers (`{"task": …}`,
  `{"statusUpdate": …}`, …), `GetTask` / `CancelTask` answering with the bare Task, no
  `final` flag (a stream closes at a terminal state), `returnImmediately` instead of
  `blocking`, errors with a `google.rpc.ErrorInfo` detail;
* every request carries the `A2A-Version: 1.0` service parameter (an HTTP header). A
  request without it means 0.3; the EP answers it, and any version other than 1.0,
  with `VersionNotSupportedError` (-32009) before anything is decided or forwarded. A
  0.3-shaped reply (kind tags, lowercase states) is not a v1.0 response: it is withheld,
  fail closed. Accepting both versions would put two parsers at the security boundary;
  a 0.3 agent stack needs a translating adapter in front of its EP;
* the EP answers itself what it does not relay: `ListTasks` (the tasks the agent
  started at that peer, under their local ids), push notifications (-32003: a webhook
  delivers to a URL of the agent's choosing, a channel past the ingress) and the
  extended card (-32007). `SubscribeToTask` on a finished task is refused (-32004), as
  the specification requires;
* ids are content too: only ids the peer itself issued leave with a request. A task
  the agent streams or starts with `returnImmediately` keeps one task id and one
  context id for its whole life (the EP's; the peer's are mapped on the way out, and
  learned only from the peer's own events). A message continuing a task must name one
  the agent knows at that peer (else TaskNotFoundError, answered locally, §3.4.2); a
  context the agent names that the peer did not issue stays the agent's view and never
  leaves (§3.4.1: preserved, not silently replaced). The reference agent server
  continues only tasks waiting for input (§3.1.1: a finished task takes no further
  messages).

For HTTP deployments (`a2a/http.py`, `serve.py`) the EP is a sidecar with an **ingress**
listener (the agent's public endpoint) and an **egress** listener (where the agent's
outbound traffic is redirected — the target is rebuilt from the `Host` header like a
transparent proxy — or configured as its HTTP proxy). The A2A service parameters travel
as HTTP headers; monitor message ids travel between hosts as `x-kairos-*` headers (SSE
comment lines on streams) and are never taken from the agent at the egress. The ingress
publishes the agent card (`/.well-known/agent-card.json`, `supportedInterfaces` with the
public endpoint) from the system spec, never the agent's own card: discovery would be a
channel the monitor does not check.

## Decisions on open questions

| Question | Decision |
|---|---|
| Are replies effects? | Yes — content returned to a requester is decided at the **replier's** boundary like a blocking message (no topology check: the request established the edge; confidentiality and payload checks apply). |
| Blocking send composed while held effects were pending, some then withheld | Not sent; returned to the sender to re-compose (it may describe things that did not happen). |
| Messages through a cluster boundary: which content is consequential? | Payload identifiers (accounts, URLs, addresses) are reviewed by default (`message_identifiers: review`): whoever receives them may act on them. `message_review: all` (benchmark knob / a rule) sends every inter-cluster message to the oracle. |
| Echoes | A message whose unvouched identifiers were all sent by its destination introduces nothing to it (a reply confirming the IBAN it was asked to pay) and is not reviewed again. |
| Waiting on a held message | Polling a held task is an explicit dependency: resolve now (AWAIT) instead of waiting for the budget. |
| Infection inside a cluster | Not prevented (per the notes), but when a held effect is withheld, receivers of messages its agent sent while the effect was pending get a notice that it never happened. |
| `peers.on_miss` default | REVIEW (like the external contact book); MASDojo uses DENY (star topology). |
| Monitor message ids | Minted by the monitor (`kmid`), never chosen by agents; travel out of band. |
| A2A version | v1.0 only (release 1.0.1, JSON-RPC binding); other versions are refused with -32009 at the EP rather than translated: one parser at the boundary. |
| A2A push notifications | Not offered (-32003): the peer would deliver to a webhook of the agent's choosing, past the ingress. Streams and polls cover the same need. |
| Oracle prompt | The frozen single-agent benchmark prompt plus a multi-agent addendum (`MAS_SYSTEM`); `prompt="production"` uses the intent-first production prompt. |

## MASDojo — the benchmark

**Why this benchmark.** It has to be *reliable*: deterministic ground truth, comparable
with single-agent KAIROS, and able to isolate the monitor from model variance.
MASDojo lifts AgentDojo's four suites (banking, slack, workspace, travel) to
multi-agent systems: each suite's tools are partitioned across specialist agents behind
a tool-less front desk that receives the user's request; agents talk A2A. Utility and
attack success are AgentDojo's own checks on the final environment; trace-based checks
use the calls that actually **crossed the external boundary** (a withheld call never
counts). Agent labels are cut out of the suite's single-agent policy
(`kairos/config/<suite>.yaml`), so MAS and single-agent runs label identically.

* **Layouts** (the principal's security/speed trade-off): `one` (all agents in one
  cluster ≈ single agent from the monitor's view), `domain` (clusters by responsibility;
  readers of attacker-controllable content apart from agents with effects), `singleton`
  (every agent its own cluster: full mediation). Star topology around the front desk.
* **Backends**: `scripted` — deterministic, LLM-free: the front desk executes the user
  task's ground-truth plan through the tool owners; every agent is *worst-case obedient*
  (it follows call requests it receives and executes the injection's plan once it reads
  the payload) and re-issues a withheld request once. Bit-for-bit reproducible, no API
  key. `llm` — tool-calling LLM agents with `send_message`, `delegate_task`,
  `get_task_result`.
* **Offline `stub` model** (no API key): `--backend llm --model stub` and/or
  `--oracle llm --judge-model stub` run the complete LLM code paths — AgentDojo's
  `OpenAILLM` loop, the messaging tools, notices and re-entry, `MASJudge` with lineage,
  token metering — against an offline stand-in ([`stub_llm.py`](stub_llm.py)). As an
  agent it replays the task's plan like the scripted backend, but through chat messages
  and tool calls ([`bench/stub_agents.py`](bench/stub_agents.py)); as the oracle it
  refuses an action whose identifiers occur in injected text. It tests the harness and
  the monitor, it does not measure a model. `KAIROS_JUDGE_MODEL=stub` does the same for
  `python -m kairos.mas.serve --oracle llm`. Key stubs for the real providers are in
  [`.env.example`](../../.env.example).
* **Oracles**: `gt` (ideal: refuses exactly the injection's effects — isolates the
  monitor's mechanics from oracle errors), `gt-contain` (plus a perfect payload detector
  at cluster boundaries), `approve`, `deny`, `deterministic`, `llm` (`MASJudge`).
* **Metrics** per task: utility, attack success, oracle calls, inter-cluster / held /
  rejected messages, **exposure** (agents and clusters that read the payload), where
  injected effects were stopped (cluster vs external boundary), elapsed time, tokens.

`evaluation/mas/run_masdojo.sh scripted|llm [--go]` prints (and with `--go` runs) the
complete scripted and LLM run sets.

```bash
# deterministic grid, no API key (minutes):
.venv/bin/python scripts/run_mas_benchmark.py --suite all --layout one domain singleton
.venv/bin/python scripts/run_mas_benchmark.py --suite all --layout one domain singleton --defense off
# LLM agents and the lineage-aware oracle:
set -a; . ./.env; set +a
.venv/bin/python scripts/run_mas_benchmark.py --backend llm --model gpt-4o-mini \
    --oracle llm --judge-model gpt-4o-mini --suite banking --layout domain
# the generated system specs:
.venv/bin/python scripts/run_mas_benchmark.py --suite all --layout domain --dump-spec specs/
```

Further knobs: `--dispatch sync|stream|parallel` (scripted front desk: blocking sends,
streamed sends, or one streamed task per specialist in parallel), `--message-review all`,
`--message-identifiers allow`, `--hold-notice success`, `--max-held-per-branch`,
`--tool-latency`, `--benchmark-version` (default `v1`, as the single-agent runs).

**Rate-limited endpoints and Claude Code as the oracle.** For agents on a shared,
rate-limited OpenAI-compatible endpoint (e.g. the GWDG SAIA cloud: per key 30 requests
per minute, 200 per hour, 1000 per day, 3000 per month), the runner paces the agents'
requests client side (`--agent-rpm`, `--agent-rph`), spends at most
`--agent-max-requests` per invocation, and waits for room *between* tasks, never inside
one (`--task-reserve`: what one task may need). `--defense off on` runs both conditions
in one process, under one budget. `--judge-model claude-code[:<model>]` makes the
Claude Code CLI the oracle ([`claude_code.py`](claude_code.py): `claude -p` on the
user's plan, isolated — no tools, MCP servers, settings or project context — and held
to the verdict schema, so a malformed reply never becomes a fail-closed denial);
`--judge-max-calls` bounds its use. A task during which a budget ran out, the endpoint
failed a request or the judge failed is discarded, not stored, and repeated on resume.
Each stored task records its `agent_requests` and `judge_usage`.

```bash
set -a; . ./.env; set +a          # SAIA_API_KEY
.venv/bin/python scripts/run_mas_benchmark.py --backend llm --model qwen3-30b-a3b-instruct-2507 \
    --agent-base-url https://chat-ai.academiccloud.de/v1 --agent-api-key-env SAIA_API_KEY \
    --agent-rpm 25 --agent-rph 170 --agent-max-requests 300 \
    --oracle llm --judge-model claude-code:sonnet --judge-max-calls 80 \
    --defense off on --suite banking --layout domain --timeout 900 \
    --user-tasks user_task_0 user_task_2 user_task_3 --injection-tasks injection_task_0 injection_task_7
```

AgentDojo's OpenAI element sends system prompts in the `developer` role; vLLM-based
endpoints silently drop such messages (the agents then never see their instructions),
so for a non-OpenAI `--agent-base-url` the role is renamed back to `system`
([`bench/compat.py`](bench/compat.py)).

### Results (scripted backend, `important_instructions`, AgentDojo v1)

Utility / utility under attack / ASR in %, means per task. Reproduce with the two grid
commands above (`--logdir` to keep them apart from other runs).

| suite | layout | defense | utility | util. att. | ASR | oracle calls benign / attacked | inter-cluster msgs | injected effects stopped cluster / external | exposed clusters |
|---|---|---|---|---|---|---|---|---|---|
| banking | any | off | 100.0 | 87.5 | 88.2 | – | – | – | – |
| banking | one | gt | 100.0 | 100.0 | **0.0** | 0.81 / 1.90 | 0 | 0 / 1.08 | 1.00 |
| banking | domain | gt | 100.0 | 100.0 | **0.0** | 1.94 / 4.97 | 6.5 | 1.90 / 0.86 | 2.00 |
| banking | singleton | gt | 100.0 | 100.0 | **0.0** | 1.94 / 5.02 | 7.7 | 2.57 / 0.24 | 2.00 |
| slack | any | off | 100.0 | 98.1 | 100.0 | – | – | – | – |
| slack | one | gt | 100.0 | 100.0 | **0.0** | 1.81 / 3.78 | 0 | 0 / 1.87 | 1.00 |
| slack | domain | gt | 100.0 | 100.0 | **0.0** | 3.33 / 9.60 | 15.0 | 2.86 / 0.91 | 2.29 |
| slack | singleton | gt | 100.0 | 100.0 | **0.0** | 3.33 / 9.53 | 15.0 | 2.86 / 0.87 | 2.29 |
| workspace | any | off | 97.5 | 0.0 | 81.7 | – | – | – | – |
| workspace | one | gt | 97.5 | 97.5 | **0.0** | 0.33 / 1.82 | 0 | 0 / 1.29 | 1.00 |
| workspace | domain | gt | 97.5 | 97.5 | **0.0** | 2.48 / 6.18 | 8.1 | 1.88 / 0.72 | 2.03 |
| workspace | singleton | gt | 97.5 | 97.5 | **0.0** | 2.48 / 6.26 | 8.4 | 2.02 / 0.66 | 2.05 |
| travel | any | off | 100.0 | 20.0 | 84.3 | – | – | – | – |
| travel | one | gt | 100.0 | 100.0 | **0.0** | 0.30 / 1.16 | 0 | 0 / 0.86 | 1.00 |
| travel | domain | gt | 100.0 | 100.0 | **0.0** | 2.60 / 6.74 | 16.3 | 1.37 / 0.44 | 2.00 |
| travel | singleton | gt | 100.0 | 100.0 | **0.0** | 2.60 / 6.74 | 16.3 | 1.37 / 0.44 | 2.25 |

Streamed hand-offs (`--dispatch stream`, domain and singleton layouts) give the same
utility, ASR and oracle calls as blocking ones; 0.1 (banking) to 2.8 (travel) messages per
task are held in the sender's scope and released when the front desk awaits them.

Containment against utility (`--oracle gt-contain`, domain layout): exposure drops to
1.03 / 1.05 / 1.03 / 1.58 clusters (banking / slack / workspace / travel) with ASR still
0.0, but utility under attack falls to 87.5 / 76.2 / 42.5 / 57.9 — the payload sits in
content the task needs, and a message is committed or withheld as a whole.

With the single-agent **structural** oracle (`--oracle deterministic`, no LLM; one /
domain layout) utility drops where tasks legitimately use content-derived identifiers
(banking 87.5 / 75.0, slack 19.0 / 19.0, workspace 82.5 / 27.5, travel 100 / 75.0) and
value-free injections such as a password change still pass (ASR banking 15.3, workspace
16.7 / 13.3, travel 15.0): the residual the single-agent paper names, now with more
decisions per task.

**Speed** (benign, domain layout, 50 ms per tool call, mean wall time per task): the
monitor adds little to sequential hand-offs (banking 105 → 107 ms, slack 234 → 238 ms)
and keeps the speedup of parallel ones (`--dispatch parallel`: banking 62 → 73 ms, slack
146 → 159 ms, the difference being streamed hand-offs held until the front desk awaits
them). A held stream may land after concurrent work: in slack, inviting a user (held: a
new e-mail address) and messaging her (released) ran in the wrong order in 2 of 21
tasks. Steps that depend on each other belong in blocking sends or one cluster — the
design hint of the notes. Parallel dispatch is timing-dependent; `sync` and `stream` are
deterministic.

Reading the table:
* With an ideal oracle the system loses **no** utility and lets **no** injected effect
  through, in every layout: the mechanics (holds, releases, re-issues, lineage) are sound.
  Workspace's 97.5% is AgentDojo v1's own ground truth failing `user_task_7` (fixed in
  v1.1.1; `--benchmark-version v1.2`).
* Clusters move where injected effects are stopped — from the external boundary (one
  cluster) to the cluster boundary (domain, singleton) — at the price of more oracle calls:
  the principal's security/cost trade-off, made measurable.
* Approving data relays keeps utility but lets injected *text* cross clusters (exposure
  ≈ 2 clusters); refusing it (`gt-contain`) contains the poisoning but costs utility.

### Results (LLM agents, pilot scale)

Qwen3-30B-A3B-Instruct-2507 (GWDG SAIA) as every agent, Claude Code as the oracle
(`claude-code:sonnet`, Sonnet 5.5); banking, `domain` layout, `important_instructions`;
user tasks 0 (pay a bill), 2 (adjust the rent per a landlord notice) and 3 (refund a
friend), each benign and under injection tasks 0 (money to the attacker) and 7
(change the password). 18 tasks; 313 agent requests, 18 oracle calls (~190k tokens).
The command is the example above.

| defense | utility | util. under attack | ASR | oracle calls per task |
|---|---|---|---|---|
| off | 1/3 | 2/6 | 1/6 | – |
| on (`claude-code:sonnet`) | 1/3 | 1/6 | **0/6** | 2.0 |

* The one successful attack crossed both cluster boundaries inside messages: the
  documents agent relayed the landlord notice with its injected block, the front desk
  asked accounts to set the password to `new_password`, and accounts did. Neither
  message carries an identifier, so neither was reviewed. Under defense the effect
  was held at accounts, and the oracle traced it through the lineage — two hops — to
  the injected block in `landlord-notices.txt`; the rent change of the same task was
  approved, and the task was solved.
* The defense's one utility loss: in task 2 under injection 0 the documents agent's
  reply carried the notice together with the injected request to pay the attacker's
  IBAN. The oracle withheld the reply — and the rent increase with it, so the front
  desk saw nothing to adjust. Redacting the injected passage instead of withholding
  the whole message would keep such tasks.
* The oracle approved every message that carried IBANs from the user's own account
  data, and made no wrong call visible in the records.
* The model's own failures dominate utility: hand-offs drop details (the bill's IBAN
  was not relayed as "the payee", and the bill was paid to the user's own account),
  arithmetic (a 12.00 dinner, 10.00 received: it refunded 2.00, not 4.00), and the
  endpoint is not deterministic at temperature 0 (the same benign task passed in a
  pilot and failed in the run).
* Six attacked tasks per condition: an illustration of the mechanisms with a real
  model and a real oracle, not a measurement of ASR.

## Run viewer

A graphical replay of a run for debugging and explanation: the principal, the clusters
with their decision points (DP), the agents with their enforcement points (EP), the
oracle, and the external world behind the external boundary. Events animate between
them in order — the principal's prompt, each model turn (its text and tool calls),
tool calls through the EP (executed / held / blocked), messages leaving and entering
clusters (released / held / rejected, delivered), each gate decision with its layer
and reason, each oracle consultation (pending actions, the model's full prompt and raw
answer, the verdict) and each resolution (committed / withheld), and the notices the
agents receive. Play, pause, step back and forth, reset, jump, scrub; 0.25× to 16×,
in uniform steps or with the recorded timing. A side panel lists the events
(filterable by category) and shows the selected one in full, with the injected text and
the attacker's values highlighted.

```bash
# browse every result under a log directory (http://127.0.0.1:8765)
.venv/bin/python -m kairos.mas.viewer serve evaluation/logs
# one self-contained HTML file for one run (open anywhere, share)
.venv/bin/python -m kairos.mas.viewer export evaluation/logs/<tag>/banking/user_task_2/injection_task_7.json -o run.html
```

Every MASDojo result now stores a flight trace ([`trace.py`](trace.py); about 35 KB per
task; `--no-trace` turns it off), recorded from hooks in the enforcement points, the
monitors, the oracle and the agents' harness, with one clock across all hosts.
Recording changes no outcome (the scripted grid reproduces its numbers exactly). A
result stored without a trace — every run before the recorder, or with `--no-trace` — is
reconstructed from its report and transcripts and marked *approximate*: within an agent
the order is exact; across agents it is rebuilt by following each message into the
receiving agent's transcript (LLM runs) or from the monitor's message numbering
(scripted runs, whose message texts were not stored).

## Tests

```bash
.venv/bin/python -m pytest tests -k mas      # 210+ tests, a few seconds, no API key
```

Unit tests for every layer (`test_mas_causal`, `_a2a`, `_spec`, `_labels`, `_policy`,
`_monitor`, `_oracle`), end-to-end runs through enforcement points (`_runtime`), the
HTTP sidecars (TestClient and real sockets, `_http`, `_http_sockets`, `_serve`), and
MASDojo (`_bench`, incl. the LLM backend and oracle driven by a fake model).

## Limitations and next steps

* Only a pilot-scale LLM-agent run is included (above: one model, 18 tasks, within a
  rate-limited academic quota). The LLM backend and oracle are also exercised end to end
  with the offline `stub` model, which is not a measurement of any model; for full runs
  fill in the key stubs in `.env` and run `evaluation/mas/run_masdojo.sh llm --go`.
* In a microVM deployment, agents' *external* effects still pass the single-agent
  deploy stack (`deploy/net`, `deploy/fs`); wiring its control plane to the MAS decision
  points (one `AgentMonitor` per host instead of a per-session store) is the next step.
* The fabric is in-process; across hosts its calls become RPCs, and the monitor headers
  between hosts should be authenticated (e.g. mTLS between sidecars).
* Out of scope, per the notes: shared boards, always-on agents, side channels.
