# multi-camel (R24)

Status: **not ported yet**. This directory fixes where the adapter lives and how it attaches.

Per-agent CaMeL plus a trusted message channel ("Can CaMeLs talk?"): an A2A send carries a
trusted `message` that must not depend on tool outputs and `variables` holding CaMeL values
with their capabilities.

| | |
|---|---|
| Level | Framework (MAS) |
| Hooks | `make_brain` as in `camel/`; `handle.send(receiver, message, meta={"variables": ...})` so capabilities travel in `Message.meta` and are restored on the receiving side; `supports` |
| Decision | Interpreter policies per agent; the send itself is a policy-checked tool |
| Inputs from the scenario | As `camel/`, plus `communication.edges` |
| Own model calls | P-LLM and Q-LLM per agent |
| Changes the agent | Yes |

`supports(scenario)` returns a reason for every scenario that is not a call tree rooted in
the entry agent (peer-to-peer edges, boards as a side channel): the design does not cover
them, and such cases are recorded as not applicable instead of being run. No code is
released; rebuilt from the paper (mechanism-changing where the paper is silent).
