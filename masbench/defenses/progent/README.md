# progent (R08)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Programmable privilege control (Shi et al. 2026): a per-agent policy over tool calls that
allows, forbids or constrains the arguments of each tool.

| | |
|---|---|
| Level | Framework |
| Hooks | `before_tool` (`deny`, or `modify` when a policy has a fallback value), `before_llm` (hide tools the policy forbids outright) |
| Decision | Deterministic policy check per call |
| Inputs from the scenario | Per-agent tool lists and JSON schemas; privileges derived from `effect`, `external`, `impact`; A2A sends are tools of the agent and get a policy as well |
| Own model calls | Optional policy generation / update from the request the agent handles (`ctx.llm()`); manual policies need none |
| Changes the agent | No |

Adaptation notes: interface-only for manual policies; policy generation per agent from the
peer request instead of the user prompt is mechanism-changing and must be reported.
