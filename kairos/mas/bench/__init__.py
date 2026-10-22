"""MASDojo: AgentDojo's suites as multi-agent systems, for system-level evaluation.

  suites       role/tool partitions per suite, cluster layouts, spec generation
  environment  the shared tool environment (ownership, executed-call trace), exposure
  scripted     deterministic LLM-free agents (ground-truth plans, worst-case obedience)
  llm          LLM agents with A2A messaging tools
  oracles      gt / approve / deny / deterministic / llm
  harness      one pair end to end, suites, summaries

Entry point: scripts/run_mas_benchmark.py
"""
