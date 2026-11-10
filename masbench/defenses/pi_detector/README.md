# pi-detector (R05)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

A prompt-injection classifier on every piece of untrusted input an agent receives. Lifted per
agent: tool outputs and received A2A messages are both scanned.

| | |
|---|---|
| Level | Model |
| Hooks | `after_tool` (tool outputs), `on_receive` (requests and replies) |
| Decision | `Verdict.abort` on a flagged input (AgentDojo behaviour), or `Verdict.deny` to withhold only that input (option) |
| Inputs from the scenario | `ToolSpec.output_trust` to skip trusted outputs (option) |
| Own model calls | One classifier call per input; a local classifier model, or `ctx.llm()` for an LLM detector (metered in `defense_llm`) |
| Changes the agent | No |

Adaptation notes: interface-only (the detector is applied to messages as well as tool
outputs, as Benchmark Design 3.1 prescribes for lifted defenses). Reference: the
`transformers_pi_detector` of AgentDojo, LlamaFirewall PromptGuard.
