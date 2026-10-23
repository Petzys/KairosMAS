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

Reading guide: `reconstruct` drives it. `_Replay` hands out the monitor's records
(messages, gate decisions, resolutions) one by one in their own order and turns them
into events; `_from_transcripts` and `_from_report` decide in which order to ask for
them.
"""
from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from kairos.mas.trace import TRACE_VERSION, plain, topology

_MESSAGING = {"send_message", "delegate_task", "get_task_result"}


class _Builder:
    """Collects the rebuilt events; time is synthetic (one unit per event)."""

    def __init__(self) -> None:
        self.events: list[dict[str, Any]] = []

    def emit(self, kind: str, **data: Any) -> None:
        event = {"kind": kind, **{key: plain(value) for key, value in data.items() if value is not None}}
        event["i"] = len(self.events)
        event["t"] = float(len(self.events))
        self.events.append(event)


def _spec(result: dict[str, Any]) -> Any:
    """The system spec the result was run on (rebuilt from its configuration)."""
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
        injection_task = result.get("injection_task")
        return prompt, suite.injection_tasks[injection_task].GOAL if injection_task else None
    except Exception:                         # noqa: BLE001 - the viewer still works without them
        return "", None


def _status_outcome(message: dict[str, Any]) -> str:
    return "rejected" if message.get("status") == "rejected" else "released"


class _Replay:
    """Shared bookkeeping: the monitor's records, consumed in their own order.

    `msgs` holds each (sender, receiver, reply?) channel's messages in the order the
    monitor numbered them; `gates` and `resolutions` each agent's gate decisions and
    resolutions in the order they happened."""

    def __init__(self, builder: _Builder, result: dict[str, Any], spec: Any) -> None:
        self.builder = builder
        self.spec = spec
        report = result.get("report") or {}
        self.msgs: dict[tuple[str, str, bool], deque] = defaultdict(deque)
        for message in sorted(report.get("messages", []), key=lambda record: int(str(record["kmid"]).lstrip("k") or 0)):
            self.msgs[(message["from"], message["to"], bool(message["reply"]))].append(message)
        self.gates: dict[str, deque] = {agent: deque(agent_report.get("trace", []))
                                        for agent, agent_report in report.get("agents", {}).items()}
        self.resolutions: dict[str, deque] = {agent: deque(agent_report.get("resolutions", []))
                                              for agent, agent_report in report.get("agents", {}).items()}
        self.cluster = {name: agent.cluster for name, agent in spec.agents.items()}

    def _is_msg_gate(self, gate: dict[str, Any]) -> bool:
        """A gate decision about a message (its target is the peer's URL)."""
        return str(gate.get("tool", "")).startswith(("http://", "https://"))

    def gate_for_tool(self, agent: str, tool: str) -> None:
        """Emit the agent's next gate decision about `tool`."""
        queue = self.gates.get(agent, deque())
        for gate in list(queue):
            if not self._is_msg_gate(gate) and gate.get("tool") == tool:
                queue.remove(gate)
                self.builder.emit("gate", agent=agent, cluster=self.cluster.get(agent), target=tool,
                                  decision=gate.get("decision"), by=gate.get("by"), reason=gate.get("reason"),
                                  channel="TOOL")
                return

    def gate_for_message(self, agent: str, dest: str, kmid: str) -> None:
        """Emit the agent's next gate decision about a message to `dest`."""
        queue = self.gates.get(agent, deque())
        host = f"{dest}."             # endpoints are http://<agent>.<cluster>.mas.local/...
        for gate in list(queue):
            if self._is_msg_gate(gate) and host in str(gate.get("tool")):
                queue.remove(gate)
                self.builder.emit("gate", agent=agent, cluster=self.cluster.get(agent), kmid=kmid,
                                  target=f"message to {dest}", decision=gate.get("decision"), by=gate.get("by"),
                                  reason=gate.get("reason"), channel="a2a")
                return

    def message(self, sender: str, dest: str, text: str, *, reply: bool) -> dict[str, Any] | None:
        """Emit the next message on the (sender, dest, reply) channel with its whole
        story: sent, gated, held/released/rejected, delivered. Returns the monitor's
        record of it (None if the report has no further message there)."""
        queue = self.msgs.get((sender, dest, reply))
        record = queue.popleft() if queue else None
        kmid = record["kmid"] if record else None
        ends = {"kmid": kmid, "from": sender, "to": dest}
        self.builder.emit("msg.send", **ends, text=text, reply=reply,
                          delivery=(record or {}).get("delivery"), intra=(record or {}).get("intra"))
        if record is None:
            return None
        self.gate_for_message(sender, dest, kmid)
        if record.get("was_held"):
            self.builder.emit("msg.outcome", **ends, outcome="held", by=record.get("decision"),
                              reason=record.get("reason"), intra=record.get("intra"))
            # A held message is decided by the sender's next resolution.
            self.resolution(sender)
            if record.get("status") == "rejected":
                self.builder.emit("msg.drop", **ends, reason=record.get("reason"))
            else:
                self.builder.emit("msg.release", **ends)
        else:
            if record.get("decision") == "oracle":
                self.resolution(sender, "a2a.reply" if reply else "a2a.send")
            self.builder.emit("msg.outcome", **ends, outcome=_status_outcome(record), by=record.get("decision"),
                              reason=record.get("reason"), intra=record.get("intra"))
        if record.get("status") != "rejected":
            self.builder.emit("msg.deliver", **ends, reply=reply)
        return record

    def resolution(self, agent: str, tool: str | None = None, *, effects_only: bool = False) -> bool:
        """Emit the agent's next resolution (with the oracle's request and verdict) --
        only if it concerns `tool` when one is given, and not if `effects_only` and it
        was only about messages. Returns whether one was emitted."""
        queue = self.resolutions.get(agent)
        if not queue:
            return False
        recorded = queue[0]
        tools = (recorded.get("aborted") or []) + (recorded.get("committed") or [])
        if tool is not None and tool not in tools:
            return False
        if effects_only and tools and all(str(name).startswith("a2a.") for name in tools):
            return False                       # a message's verdict: placed with the message
        queue.popleft()
        cluster = self.cluster.get(agent)
        pending = [{"tool": name} for name in (recorded.get("committed") or []) + (recorded.get("aborted") or [])]
        if recorded.get("decided_by") == "judge":
            self.builder.emit("oracle.request", agent=agent, cluster=cluster, pending=pending,
                              judge="(recorded verdict)")
            if recorded.get("judge_raw"):
                self.builder.emit("oracle.llm", agent=agent, raw=recorded.get("judge_raw"))
            self.builder.emit("oracle.verdict", agent=agent, cluster=cluster,
                              consistent=recorded.get("judge_consistent"),
                              rationale=recorded.get("rationale"), flagged=recorded.get("flagged"))
        self.builder.emit("resolution", agent=agent, cluster=cluster, trigger=recorded.get("trigger"),
                          committed=[{"tool": name} for name in recorded.get("committed") or []],
                          aborted=recorded.get("aborted_actions")
                          or [{"tool": name} for name in recorded.get("aborted") or []],
                          rationale=recorded.get("rationale"), decided_by=recorded.get("decided_by"),
                          errors=recorded.get("commit_errors"))
        return True

    def leftovers(self) -> None:
        """Emit whatever was not matched to a call or message (at the end)."""
        for agent in list(self.resolutions):
            while self.resolutions[agent]:
                self.resolution(agent)
        for (sender, dest, reply), queue in list(self.msgs.items()):
            while queue:
                self.message(sender, dest, "(content not recorded)", reply=reply)


def _tool_status(msg: dict[str, Any]) -> str:
    """What became of a tool call, judged from its result message in the transcript."""
    content, error = str(msg.get("content") or ""), str(msg.get("error") or "")
    if error.startswith("Blocked") or "REFUSED" in error or "WITHHELD" in error:
        return "blocked"
    if content.startswith("SECURITY NOTICE"):          # a held call's stub
        return "held"
    return "executed"


def _from_transcripts(replay: _Replay, builder: _Builder, transcripts: list[dict[str, Any]], entry: str,
                      prompt: str) -> None:
    """LLM runs: replay the entry agent's conversation and follow each message it sends
    into the conversation of the agent that received it."""
    pool: dict[str, list[dict[str, Any]]] = defaultdict(list)    # agent -> its unreplayed transcripts
    for transcript in transcripts:
        pool[transcript["agent"]].append(transcript)

    def take(agent: str, text: str) -> dict[str, Any] | None:
        """The agent's transcript that began with `text` (else its oldest unreplayed one)."""
        candidates = pool.get(agent, [])
        for transcript in candidates:
            first = next((message for message in transcript["messages"] if message["role"] == "user"), None)
            if first is not None and (first.get("content") or "").strip() == (text or "").strip():
                candidates.remove(transcript)
                return transcript
        return candidates.pop(0) if candidates else None

    def run(agent: str, transcript: dict[str, Any], incoming: str) -> str:
        """Replay one conversation; returns the agent's final answer."""
        builder.emit("agent.task", agent=agent, task=transcript.get("task"), text=incoming)
        messages = transcript["messages"]
        answer = ""
        i = 0
        seen_first_user = False
        while i < len(messages):
            message = messages[i]
            i += 1
            if message["role"] == "user":
                # the first user message is the task; later ones are KAIROS notices
                if seen_first_user:
                    builder.emit("agent.notice", agent=agent, text=message.get("content"))
                seen_first_user = True
                continue
            if message["role"] != "assistant":
                continue
            calls = message.get("tool_calls") or []
            builder.emit("agent.llm", agent=agent, task=transcript.get("task"), text=message.get("content"),
                         tool_calls=calls)
            answer = message.get("content") or answer
            results = []
            while i < len(messages) and messages[i]["role"] == "tool":
                results.append(messages[i])
                i += 1
            for index, call in enumerate(calls):
                result = results[index] if index < len(results) else {}
                function, args = call.get("function"), call.get("args") or {}
                if function in ("send_message", "delegate_task") and args.get("agent") in replay.spec.agents:
                    # Follow the message into the receiver's conversation (depth first),
                    # then the receiver's reply comes back.
                    dest, text = args["agent"], str(args.get("message", ""))
                    record = replay.message(agent, dest, text, reply=False)
                    if record is not None and record.get("status") != "rejected":
                        received = take(dest, text)
                        if received is not None:
                            reply_text = run(dest, received, text)
                            replay.message(dest, agent, reply_text, reply=True)
                    continue
                if function in _MESSAGING or function in replay.spec.agents:
                    continue
                builder.emit("tool.call", agent=agent, tool=function, args=args)
                replay.gate_for_tool(agent, function)
                status = _tool_status(result)
                builder.emit("tool.result", agent=agent, tool=function, status=status, text=result.get("content"),
                             error=result.get("error"))
                if status in ("held", "blocked"):
                    replay.resolution(agent, function)
        while replay.resolution(agent, effects_only=True):   # resolved at the end of the task
            pass
        builder.emit("agent.done", agent=agent, task=transcript.get("task"), text=answer, state="completed")
        return answer

    first = take(entry, prompt) if prompt else (pool[entry].pop(-1) if pool.get(entry) else None)
    if first is not None:
        run(entry, first, prompt)
    for agent, rest in pool.items():               # tasks no message led to
        for transcript in list(rest):
            rest.remove(transcript)
            first_user = next((message.get("content") for message in transcript["messages"]
                               if message["role"] == "user"), "")
            run(agent, transcript, first_user)


def _from_report(replay: _Replay, builder: _Builder, result: dict[str, Any], entry: str, prompt: str) -> None:
    """No transcripts: messages in the monitor's order, each agent's gate decisions
    between its messages."""
    report = result.get("report") or {}
    messages = sorted(report.get("messages", []), key=lambda record: int(str(record["kmid"]).lstrip("k") or 0))
    builder.emit("agent.task", agent=entry, task="principal", text=prompt)

    def flush_tools(agent: str) -> None:
        """Emit the agent's tool gate decisions up to its next message."""
        queue = replay.gates.get(agent, deque())
        while queue and not replay._is_msg_gate(queue[0]):
            gate = queue[0]
            builder.emit("tool.call", agent=agent, tool=gate.get("tool"), args=gate.get("ids") or {})
            replay.gate_for_tool(agent, gate.get("tool"))
            if gate.get("decision") == "ALLOW":
                status = "executed"
            elif gate.get("decision") == "REVIEW":
                status = "held"
            else:
                status = "blocked"
            builder.emit("tool.result", agent=agent, tool=gate.get("tool"), status=status)
            if status != "executed":
                replay.resolution(agent, gate.get("tool"))

    flush_tools(entry)
    for message in messages:
        flush_tools(message["from"])
        queue = replay.msgs.get((message["from"], message["to"], bool(message["reply"])))
        if not queue or queue[0] is not message:
            continue
        replay.message(message["from"], message["to"], "(content not recorded in this result)",
                       reply=bool(message["reply"]))
        if not message["reply"] and message.get("status") != "rejected":
            builder.emit("agent.task", agent=message["to"], text="(content not recorded in this result)")
            flush_tools(message["to"])
        if message["reply"]:
            builder.emit("agent.done", agent=message["from"], state="completed")
    for agent in replay.gates:
        flush_tools(agent)
    builder.emit("agent.done", agent=entry, task="principal", text=result.get("output"), state="completed")


def reconstruct(result: dict[str, Any]) -> dict[str, Any]:
    """An approximate viewer trace for a result stored without one."""
    spec = _spec(result)
    prompt, goal = _task_texts(result)
    builder = _Builder()
    replay = _Replay(builder, result, spec)
    builder.emit("run.start", prompt=prompt, agent=spec.entry)
    transcripts = result.get("transcripts") or []
    if transcripts:
        _from_transcripts(replay, builder, transcripts, spec.entry, prompt)
    else:
        _from_report(replay, builder, result, spec.entry, prompt)
    replay.leftovers()
    builder.emit("run.end", agent=spec.entry, output=result.get("output"), utility=result.get("utility"),
                 attack_success=result.get("attack_success"),
                 quiescent=(result.get("metrics") or {}).get("quiescent"))
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
            "events": builder.events}


def load_trace(path: str) -> dict[str, Any]:
    """The viewer trace of a stored result: its recorded trace, or a reconstruction."""
    with open(path) as file:
        result = json.load(file)
    if "events" in result and "topology" in result:     # a bare trace file
        trace = result
    elif result.get("trace"):
        trace = result["trace"]
    else:
        trace = reconstruct(result)
    trace.setdefault("result", {key: result.get(key) for key in ("utility", "attack_success", "output")})
    if "policy" not in trace.get("topology", {}) and result.get("suite"):   # traces recorded before it was kept
        try:
            trace["topology"]["policy"] = topology(_spec(result))["policy"]
        except Exception:                     # noqa: BLE001
            pass
    trace["metrics"] = {key: value for key, value in (result.get("metrics") or {}).items()
                        if key in ("oracle_calls", "messages", "inter_cluster", "rejected", "held", "elapsed",
                                   "exposed_agents", "stopped_at_cluster_boundary", "stopped_at_external_boundary",
                                   "tokens", "agent_requests", "judge_usage")}
    return trace


__all__ = ["load_trace", "reconstruct"]
