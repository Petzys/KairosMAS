# spotlighting (R06)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Marks untrusted content as data (Hines et al. 2024): delimiting or datamarking, plus a
system-prompt instruction not to follow anything inside the marks.

| | |
|---|---|
| Level | Prompt |
| Hooks | `system_prompt` (the instruction), `after_tool` and `on_receive` (mark the text) |
| Decision | Never blocks; rewrites text |
| Inputs from the scenario | `ToolSpec.output_trust` (mark only untrusted outputs, option); peer messages are always marked |
| Own model calls | None |
| Changes the agent | No |

Adaptation notes: interface-only. Reference: AgentDojo `spotlighting_with_delimiting`.
