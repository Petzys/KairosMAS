"""A viewer trace for a MASDojo result stored without one (runs before the flight
recorder existed, or run with --no-trace).

Such a result keeps the monitor's report -- every message with its status and
decision, every gate decision per agent in order, every resolution with the
oracle's verdict -- and, for LLM agents, each agent's transcript. It keeps no
common clock. The order is rebuilt from what is ordered:

  * LLM runs: the entry agent's transcript is replayed, and each message it sends
    is followed into the transcript of the agent that received it (depth first,
    as a blocking send runs); the monitor's records are matched to the calls and
    messages in their own per-agent order.
  * scripted runs (no transcripts): messages in the order the monitor numbered
    them; each agent's gate decisions between its messages.

The result is marked `approximate`: within an agent the order is exact, across
agents it is a plausible interleaving, and times are synthetic (one per event).
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from kairos.mas.trace import TRACE_VERSION, plain, topology

_MESSAGING = {"send_message", "delegate_task", "get_task_result"}


class _Builder:
    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, kind: str, **data: Any) -> None:
        ev = {"kind": kind, **{k: plain(v) for k, v in data.items() if v is not None}}
        ev["i"] = len(self.events)
        ev["t"] = float(len(self.events))
        self.events.append(ev)


def _spec(result: dict[str, Any]) -> Any:
    from kairos.mas.bench.suites import BuildOptions, build_spec
    cfg = result.get("config") or {}
    return build_spec(result["suite"], BuildOptions(layout=cfg.get("layout", "domain"),
                                                    message_identifiers=cfg.get("message_identifiers", "review"),
                                                    message_review=cfg.get("message_review", "policy")))


def _task_texts(result: dict[str, Any]) -> tuple[str, str | None]:
    """The user task's prompt and the injection task's goal (from AgentDojo)."""
    try:
        from agentdojo.task_suite.load_suites import get_suite
        suite = get_suite((result.get("config") or {}).get("benchmark_version", "v1"), result["suite"])
        prompt = suite.user_tasks[result["user_task"]].PROMPT
        it = result.get("injection_task")
        return prompt, suite.injection_tasks[it].GOAL if it else None
    except Exception:                         # noqa: BLE001 - the viewer still works without them
        return "", None


def _status_outcome(m: dict[str, Any]) -> str:
    return "rejected" if m.get("status") == "rejected" else "released"


class _Replay:
    """Shared bookkeeping: the monitor's records, consumed in their own order."""

    def __init__(self, b: _Builder, result: dict[str, Any], spec: Any) -> None:
        self.b = b
        self.spec = spec
        report = result.get("report") or {}
        self.msgs: dict[tuple[str, str, bool], deque] = defaultdict(deque)
        for m in sorted(report.get("messages", []), key=lambda m: int(str(m["kmid"]).lstrip("k") or 0)):
            self.msgs[(m["from"], m["to"], bool(m["reply"]))].append(m)
        self.gates: dict[str, deque] = {a: deque(r.get("trace", [])) for a, r in report.get("agents", {}).items()}
        self.resolutions: dict[str, deque] = {a: deque(r.get("resolutions", []))
                                              for a, r in report.get("agents", {}).items()}
        self.cluster = {a: ag.cluster for a, ag in spec.agents.items()}

    def _is_msg_gate(self, g: dict[str, Any]) -> bool:
        return str(g.get("tool", "")).startswith(("http://", "https://"))

    def gate_for_tool(self, agent: str, tool: str) -> None:
        q = self.gates.get(agent, deque())
        for g in list(q):
            if not self._is_msg_gate(g) and g.get("tool") == tool:
                q.remove(g)
                self.b.emit("gate", agent=agent, cluster=self.cluster.get(agent), target=tool,
                            decision=g.get("decision"), by=g.get("by"), reason=g.get("reason"), channel="TOOL")
                return

    def gate_for_message(self, agent: str, dest: str, kmid: str) -> None:
        q = self.gates.get(agent, deque())
        host = f"{dest}."
        for g in list(q):
            if self._is_msg_gate(g) and host in str(g.get("tool")):
                q.remove(g)
                self.b.emit("gate", agent=agent, cluster=self.cluster.get(agent), kmid=kmid,
                            target=f"message to {dest}", decision=g.get("decision"), by=g.get("by"),
                            reason=g.get("reason"), channel="a2a")
                return

    def message(self, sender: str, dest: str, text: str, *, reply: bool) -> dict[str, Any] | None:
        q = self.msgs.get((sender, dest, reply))
        m = q.popleft() if q else None
        kmid = m["kmid"] if m else None
        ends = {"kmid": kmid, "from": sender, "to": dest}
        self.b.emit("msg.send", **ends, text=text, reply=reply,
                    delivery=(m or {}).get("delivery"), intra=(m or {}).get("intra"))
        if m is None:
            return None
        self.gate_for_message(sender, dest, kmid)
        if m.get("was_held"):
            self.b.emit("msg.outcome", **ends, outcome="held", by=m.get("decision"), reason=m.get("reason"),
                        intra=m.get("intra"))
            self.resolution(sender)
            if m.get("status") == "rejected":
                self.b.emit("msg.drop", **ends, reason=m.get("reason"))
            else:
                self.b.emit("msg.release", **ends)
        else:
            if m.get("decision") == "oracle":
                self.resolution(sender, "a2a.reply" if reply else "a2a.send")
            self.b.emit("msg.outcome", **ends, outcome=_status_outcome(m), by=m.get("decision"),
                        reason=m.get("reason"), intra=m.get("intra"))
        if m.get("status") != "rejected":
            self.b.emit("msg.deliver", **ends, reply=reply)
        return m

    def resolution(self, agent: str, tool: str | None = None, *, effects_only: bool = False) -> bool:
        q = self.resolutions.get(agent)
        if not q:
            return False
        res = q[0]
        tools = (res.get("aborted") or []) + (res.get("committed") or [])
        if tool is not None and tool not in tools:
            return False
        if effects_only and tools and all(str(t).startswith("a2a.") for t in tools):
            return False                       # a message's verdict: placed with the message
        q.popleft()
        cl = self.cluster.get(agent)
        pending = [{"tool": t} for t in (res.get("committed") or []) + (res.get("aborted") or [])]
        if res.get("decided_by") == "judge":
            self.b.emit("oracle.request", agent=agent, cluster=cl, pending=pending, judge="(recorded verdict)")
            if res.get("judge_raw"):
                self.b.emit("oracle.llm", agent=agent, raw=res.get("judge_raw"))
            self.b.emit("oracle.verdict", agent=agent, cluster=cl, consistent=res.get("judge_consistent"),
                        rationale=res.get("rationale"), flagged=res.get("flagged"))
        self.b.emit("resolution", agent=agent, cluster=cl, trigger=res.get("trigger"),
                    committed=[{"tool": t} for t in res.get("committed") or []],
                    aborted=res.get("aborted_actions") or [{"tool": t} for t in res.get("aborted") or []],
                    rationale=res.get("rationale"), decided_by=res.get("decided_by"),
                    errors=res.get("commit_errors"))
        return True

    def leftovers(self) -> None:
        for agent in list(self.resolutions):
            while self.resolutions[agent]:
                self.resolution(agent)
        for (sender, dest, reply), q in list(self.msgs.items()):
            while q:
                self.message(sender, dest, "(content not recorded)", reply=reply)


def _tool_status(msg: dict[str, Any]) -> str:
    content, error = str(msg.get("content") or ""), str(msg.get("error") or "")
    if error.startswith("Blocked") or "REFUSED" in error or "WITHHELD" in error:
        return "blocked"
    if content.startswith("SECURITY NOTICE"):          # a held call's stub
        return "held"
    return "executed"


def _from_transcripts(r: _Replay, b: _Builder, transcripts: list[dict[str, Any]], entry: str, prompt: str) -> None:
    pool: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for t in transcripts:
        pool[t["agent"]].append(t)

    def take(agent: str, text: str) -> dict[str, Any] | None:
        cands = pool.get(agent, [])
        for t in cands:
            first = next((m for m in t["messages"] if m["role"] == "user"), None)
            if first is not None and (first.get("content") or "").strip() == (text or "").strip():
                cands.remove(t)
                return t
        return cands.pop(0) if cands else None

    def run(agent: str, t: dict[str, Any], incoming: str) -> str:
        b.emit("agent.task", agent=agent, task=t.get("task"), text=incoming)
        msgs = t["messages"]
        answer = ""
        i = 0
        seen_first_user = False
        while i < len(msgs):
            m = msgs[i]
            i += 1
            if m["role"] == "user":
                if seen_first_user:
                    b.emit("agent.notice", agent=agent, text=m.get("content"))
                seen_first_user = True
                continue
            if m["role"] != "assistant":
                continue
            calls = m.get("tool_calls") or []
            b.emit("agent.llm", agent=agent, task=t.get("task"), text=m.get("content"), tool_calls=calls)
            answer = m.get("content") or answer
            results = []
            while i < len(msgs) and msgs[i]["role"] == "tool":
                results.append(msgs[i])
                i += 1
            for k, c in enumerate(calls):
                res = results[k] if k < len(results) else {}
                fn, args = c.get("function"), c.get("args") or {}
                if fn in ("send_message", "delegate_task") and args.get("agent") in r.spec.agents:
                    dest, text = args["agent"], str(args.get("message", ""))
                    m_rec = r.message(agent, dest, text, reply=False)
                    if m_rec is not None and m_rec.get("status") != "rejected":
                        sub = take(dest, text)
                        if sub is not None:
                            reply_text = run(dest, sub, text)
                            r.message(dest, agent, reply_text, reply=True)
                    continue
                if fn in _MESSAGING or fn in r.spec.agents:
                    continue
                b.emit("tool.call", agent=agent, tool=fn, args=args)
                r.gate_for_tool(agent, fn)
                status = _tool_status(res)
                b.emit("tool.result", agent=agent, tool=fn, status=status, text=res.get("content"),
                       error=res.get("error"))
                if status in ("held", "blocked"):
                    r.resolution(agent, fn)
        while r.resolution(agent, effects_only=True):   # resolved at the end of the task
            pass
        b.emit("agent.done", agent=agent, task=t.get("task"), text=answer, state="completed")
        return answer

    first = take(entry, prompt) if prompt else (pool[entry].pop(-1) if pool.get(entry) else None)
    if first is not None:
        run(entry, first, prompt)
    for agent, rest in pool.items():               # tasks no message led to
        for t in list(rest):
            rest.remove(t)
            first_user = next((m.get("content") for m in t["messages"] if m["role"] == "user"), "")
            run(agent, t, first_user)


def _from_report(r: _Replay, b: _Builder, result: dict[str, Any], entry: str, prompt: str) -> None:
    """No transcripts: messages in the monitor's order, each agent's gate decisions
    between its messages."""
    report = result.get("report") or {}
    msgs = sorted(report.get("messages", []), key=lambda m: int(str(m["kmid"]).lstrip("k") or 0))
    b.emit("agent.task", agent=entry, task="principal", text=prompt)

    def flush_tools(agent: str) -> None:
        q = r.gates.get(agent, deque())
        while q and not r._is_msg_gate(q[0]):
            g = q[0]
            b.emit("tool.call", agent=agent, tool=g.get("tool"), args=g.get("ids") or {})
            r.gate_for_tool(agent, g.get("tool"))
            status = "executed" if g.get("decision") == "ALLOW" else "held" if g.get("decision") == "REVIEW" else "blocked"
            b.emit("tool.result", agent=agent, tool=g.get("tool"), status=status)
            if status != "executed":
                r.resolution(agent, g.get("tool"))

    flush_tools(entry)
    for m in msgs:
        flush_tools(m["from"])
        q = r.msgs.get((m["from"], m["to"], bool(m["reply"])))
        if not q or q[0] is not m:
            continue
        r.message(m["from"], m["to"], "(content not recorded in this result)", reply=bool(m["reply"]))
        if not m["reply"] and m.get("status") != "rejected":
            b.emit("agent.task", agent=m["to"], text="(content not recorded in this result)")
            flush_tools(m["to"])
        if m["reply"]:
            b.emit("agent.done", agent=m["from"], state="completed")
    for agent in r.gates:
        flush_tools(agent)
    b.emit("agent.done", agent=entry, task="principal", text=result.get("output"), state="completed")


def reconstruct(result: dict[str, Any]) -> dict[str, Any]:
    spec = _spec(result)
    prompt, goal = _task_texts(result)
    b = _Builder()
    r = _Replay(b, result, spec)
    b.emit("run.start", prompt=prompt, agent=spec.entry)
    transcripts = result.get("transcripts") or []
    if transcripts:
        _from_transcripts(r, b, transcripts, spec.entry, prompt)
    else:
        _from_report(r, b, result, spec.entry, prompt)
    r.leftovers()
    b.emit("run.end", agent=spec.entry, output=result.get("output"), utility=result.get("utility"),
           attack_success=result.get("attack_success"), quiescent=(result.get("metrics") or {}).get("quiescent"))
    try:
        from kairos.mas.bench.suites import SYSTEMS
        tools_of = SYSTEMS[result["suite"]].tools_of
    except Exception:                         # noqa: BLE001
        tools_of = None
    cfg = result.get("config") or {}
    return {"version": TRACE_VERSION, "approximate": True,
            "source": "reconstructed from the result's report" + (" and transcripts" if transcripts else ""),
            "config": cfg, "suite": result.get("suite"), "user_task": result.get("user_task"),
            "injection_task": result.get("injection_task"), "prompt": prompt, "injection_goal": goal,
            "injections": {}, "defense": cfg.get("defense", True), "topology": topology(spec, tools_of),
            "events": b.events}


def load_trace(path: str) -> dict[str, Any]:
    """The viewer trace of a stored result: its recorded trace, or a reconstruction."""
    with open(path) as f:
        result = json.load(f)
    if "events" in result and "topology" in result:     # a bare trace file
        trace = result
    elif result.get("trace"):
        trace = result["trace"]
    else:
        trace = reconstruct(result)
    trace.setdefault("result", {k: result.get(k) for k in ("utility", "attack_success", "output")})
    trace["metrics"] = {k: v for k, v in (result.get("metrics") or {}).items()
                        if k in ("oracle_calls", "messages", "inter_cluster", "rejected", "held", "elapsed",
                                 "exposed_agents", "stopped_at_cluster_boundary", "stopped_at_external_boundary",
                                 "tokens", "agent_requests", "judge_usage")}
    return trace


__all__ = ["load_trace", "reconstruct"]
