"""MASDojo: AgentDojo's suites as multi-agent systems, for system-level evaluation.

  suites       role/tool partitions per suite, cluster layouts, spec generation
  environment  the shared tool environment (ownership, executed-call trace), exposure
  scripted     deterministic LLM-free agents (ground-truth plans, worst-case obedience)
  llm          LLM agents with A2A messaging tools
  stub_agents  the offline stub model's agent behaviour (plan replay)
  oracles      gt / gt-contain / approve / deny / deterministic / llm
  harness      one pair end to end, suites, summaries
  limits       pacing and request budgets for rate-limited endpoints
  compat       fixes for OpenAI-compatible endpoints that are not OpenAI

Entry point: scripts/run_mas_benchmark.py
"""
