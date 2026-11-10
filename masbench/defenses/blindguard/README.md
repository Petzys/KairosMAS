# blindguard (R26)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Graph anomaly detection on A2A messages; messages of flagged agents are pruned. Sees
messages only, so it works with opaque agents.

| | |
|---|---|
| Level | Message (MAS) |
| Hooks | `on_message`: one graph snapshot per message exchange from `ctx.messages` (nodes = agents, edges = messages, node features = message embeddings); `ctx.isolate(agent, reason)` for a flagged agent, after which the runner rejects its messages |
| Decision | Anomaly score against a threshold calibrated on benign data |
| Inputs from the scenario | Agents and `communication.edges` |
| Own model calls | A text encoder and the trained detector (no LLM) |
| Changes the agent | No |

Training data: records of benign runs (`--kind benign`, defense `none`) on a split disjoint
from the test cases. Adaptation notes: snapshot per message exchange instead of synchronous
rounds, threshold instead of top-k = 3 (both mechanism-changing, Benchmark Design 3.4).
Same-agent attacks pass by design.
