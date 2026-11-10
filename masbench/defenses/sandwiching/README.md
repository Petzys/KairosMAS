# sandwiching (R07)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Repeats the task after untrusted content, so the last instruction the model reads is the
legitimate one.

| | |
|---|---|
| Level | Prompt |
| Hooks | `before_llm`: after the latest tool result or peer message, append a reminder of the request the agent is handling (the principal's prompt for the entry agent, the peer request otherwise). The view is used for that model call only |
| Decision | Never blocks |
| Inputs from the scenario | None |
| Own model calls | None |
| Changes the agent | No |

Adaptation notes: interface-only; for a worker agent "the task" is the request it received,
because it never sees the principal's prompt. Reference: AgentDojo `repeat_user_prompt`.
