# camel (R09)

Status: **implemented** on the vendored CaMeL code; run masbench with `.venv-camel/bin/python`. The module docstring has the lifting rules, the annotation-derived policy and the options.

CaMeL (Debenedetti et al. 2025) on every agent individually ("individual-agent CaMeL" in
"Can CaMeLs talk?"): a privileged LLM writes a plan from the trusted request, an interpreter
runs it with capabilities on every value, a quarantined LLM parses untrusted data.

| | |
|---|---|
| Level | Framework |
| Hooks | `make_brain`: the returned brain runs P-LLM, interpreter and Q-LLM inside one `step`, using `handle.llm` for both models and `handle.call_tool` / `handle.send` for effects, so every call still goes through the runner's records and the scored trace |
| Decision | Security policies on tool calls inside the interpreter |
| Inputs from the scenario | Capabilities from `output_trust` / `output_sensitivity`; policies from `effect`, `external`, `impact`; the agent's tool schemas |
| Own model calls | P-LLM and Q-LLM (the agent's model through `handle.llm`, metered in the agent's stats) |
| Changes the agent | Yes, replaces the agent loop |

Adaptation notes: per agent, a peer request is the "user query" of that agent, and a peer
reply is untrusted data: mechanism-changing, to be reported. Built on the KAIROS-patched CaMeL
(`.venv-camel`).
