# safeflow (R25)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Taint tracking over the agent graph with a validator in front of hard sinks (Dai et al. 2026).

| | |
|---|---|
| Level | Framework (MAS) |
| Hooks | `after_tool` and `on_receive` (taint untrusted content and what is derived from it), `on_message` (write the sender's taint into `Message.meta`), `before_tool` (validate before a hard-sink call; `deny` on failure), board tools via `ToolSpec.board` |
| Decision | Global validator before each hard sink |
| Inputs from the scenario | Tool categories from `effect`, `external`, `impact`, `output_trust`; hard sinks = external or high-impact writes |
| Own model calls | The validator (`ctx.llm()`, metered) |
| Changes the agent | No; it stages hard-sink calls |

Adaptation notes: tool outputs and A2A messages are passed as `untrusted_context`
(interface-only); ASB-specific keywords removed; the validator is moved before each hard sink
instead of after the run (mechanism-changing, as decided in Benchmark Design 3.4).
