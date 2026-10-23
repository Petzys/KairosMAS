"""A flight recorder for KAIROS MAS runs: what happened, in order, for the viewer.

The monitor's causal log answers the monitor's questions (lineage, vector clocks)
and exists only when the defense is on. Debugging and explaining a run needs more:
the agents' reasoning, every boundary crossing, every decision with its reason,
and one clock across all hosts. The recorder collects semantic events from a few
hooks (enforcement points, monitors, the oracle, the agents' harness), each with
a time offset and a global sequence number:

  run.start / run.end                     the principal's prompt; the outcome
  agent.task / agent.done                 a task starts / finishes at an agent
  agent.llm                               one model turn: its text and tool calls
  agent.notice                            a KAIROS notice handed to the agent
  tool.call / tool.result                 an effect at the external boundary, and
                                          what came of it (executed/held/blocked/...)
  gate                                    the monitor's policy decision on an effect
  msg.send / msg.outcome / msg.deliver    an A2A message: emitted, decided
                                          (released/held/rejected), delivered
  msg.release / msg.drop                  a held message's fate at resolution
  oracle.request / oracle.llm /           the oracle consulted: the pending actions,
  oracle.verdict                          the model's prompt and raw answer, the verdict
  resolution                              a branch resolved: committed / aborted
  inbound.external                        content from a party outside the system

`python -m kairos.mas.viewer` renders a recorded run (or reconstructs one from an
older result without a trace).
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any

TRACE_VERSION = 1
_ORACLE = threading.local()   # set while an oracle evaluates: its model calls are oracle calls
_TEXT = 6000          # characters kept of a text field (oracle prompts: _PROMPT)
_PROMPT = 24000


def clip(value: Any, n: int = _TEXT) -> Any:
    """A string cut to `n` characters (saying how much was cut); anything else as is."""
    if isinstance(value, str):
        return value if len(value) <= n else value[:n] + f"… [{len(value) - n} more characters]"
    return value


def plain(value: Any, depth: int = 0) -> Any:
    """JSON-safe, size-bounded copy of an argument or result."""
    if depth > 6:
        return clip(repr(value), 500)
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        return clip(value)
    if isinstance(value, dict):
        return {str(key): plain(item, depth + 1) for key, item in list(value.items())[:200]}
    if isinstance(value, (list, tuple, set)):
        return [plain(item, depth + 1) for item in list(value)[:200]]
    return clip(str(value))


class TraceRecorder:
    """Thread-safe event sink. `emit` never raises: tracing must not break a run."""

    def __init__(self) -> None:
        self.t0 = time.monotonic()
        self.events: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def emit(self, kind: str, **data: Any) -> None:
        """Record one event: its kind, its fields (None fields left out), the time since
        the recorder started (`t`) and its position in the run (`i`)."""
        try:
            # Oracle prompts are kept longer than other texts.
            event = {"kind": kind, **{key: plain(value) if key not in ("prompt", "system") else clip(value, _PROMPT)
                                      for key, value in data.items() if value is not None}}
            with self._lock:
                event["t"] = round(time.monotonic() - self.t0, 4)
                event["i"] = len(self.events)
                self.events.append(event)
        except Exception:                     # noqa: BLE001 - never fail the run
            pass

    def export(self, header: dict[str, Any]) -> dict[str, Any]:
        """The trace as stored with a result: `header` (what was run) plus the events."""
        with self._lock:
            events = list(self.events)
        return {"version": TRACE_VERSION, "approximate": False, **header, "events": events}


def topology(spec: Any, tools_of: Any = None) -> dict[str, Any]:
    """The system as the viewer draws it: clusters, their agents, the entry agent."""
    clusters = []
    for cluster_id, cluster in spec.clusters.items():
        clearance = getattr(cluster, "clearance", None)
        clusters.append({"id": cluster_id, "clearance": getattr(clearance, "name", str(clearance)).lower()
                         if clearance is not None else None,
                         "agents": [name for name, agent in spec.agents.items() if agent.cluster == cluster_id]})
    agents = {name: {"cluster": agent.cluster, "description": agent.description, "endpoint": agent.endpoint,
                     "tools": list(tools_of(name)) if tools_of else []}
              for name, agent in spec.agents.items()}
    drawing = {"entry": spec.entry, "clusters": clusters, "agents": agents}
    try:                                       # the declared policies, as the spec file states them
        from kairos.mas.spec_parser import spec_to_dict
        declared = spec_to_dict(spec)
        drawing["policy"] = {"system": declared.get("system", {}), "clusters": declared.get("clusters", {}),
                             "agents": declared.get("agents", {})}
    except Exception:                         # noqa: BLE001 - the viewer works without it
        pass
    return drawing


def emit(fabric: Any, kind: str, **data: Any) -> None:
    """Emit on the fabric's recorder, if it has one."""
    recorder = getattr(fabric, "recorder", None)
    if recorder is not None:
        recorder.emit(kind, **data)


class TracedJudge:
    """The oracle with a recorder: what it was asked, what the model saw and
    answered (for LLM judges), and the verdict. Delegates everything else."""

    def __init__(self, inner: Any, recorder: TraceRecorder, agent: str, cluster: str) -> None:
        self._inner, self._rec, self._agent, self._cluster = inner, recorder, agent, cluster
        # An LLM judge's chat client is wrapped once to record the model's prompt and
        # answer. The client outlives runs (one client serves a whole benchmark), so
        # the wrapper looks up the recorder on the client: the current run's.
        client = getattr(inner, "client", None)
        if client is not None:
            try:                              # a client outlives runs: the current run's recorder
                client._kairos_recorder = recorder
            except AttributeError:
                return
            if not getattr(client, "_kairos_traced", False):
                self._wrap(client)

    @staticmethod
    def _wrap(client: Any) -> None:
        try:
            original_create = client.chat.completions.create
        except AttributeError:
            return

        def create(*args: Any, **kwargs: Any) -> Any:
            response = original_create(*args, **kwargs)
            # Only calls made while an oracle evaluates are recorded (the thread-local
            # marker); the same client may serve the agents too.
            if not getattr(_ORACLE, "agent", None):     # the same client may serve the agents
                return response
            messages = kwargs.get("messages") or []
            system = "\n\n".join(str(message.get("content")) for message in messages
                                  if message.get("role") in ("system", "developer"))
            prompt = "\n\n".join(str(message.get("content")) for message in messages
                                  if message.get("role") not in ("system", "developer"))
            try:
                raw = response.choices[0].message.content
            except Exception:                 # noqa: BLE001
                raw = None
            recorder = getattr(client, "_kairos_recorder", None)
            if recorder is not None:
                recorder.emit("oracle.llm", agent=_ORACLE.agent, model=kwargs.get("model"),
                              system=system, prompt=prompt, raw=raw)
            return response

        try:
            client.chat.completions.create = create
            client._kairos_traced = True
        except AttributeError:
            pass

    def evaluate(self, user_prompt: str, branch: Any) -> Any:
        """Record the request, evaluate with the real judge, record the verdict."""
        pending = [{"tool": getattr(held, "tool", "?"), "args": getattr(held, "args", {}),
                    "reason": getattr(held, "reason", "")} for held in getattr(branch, "held_calls", [])]
        self._rec.emit("oracle.request", agent=self._agent, cluster=self._cluster, pending=pending,
                       judge=type(self._inner).__name__)
        _ORACLE.agent = self._agent
        try:
            verdict = self._inner.evaluate(user_prompt, branch)
        finally:
            _ORACLE.agent = None
        self._rec.emit("oracle.verdict", agent=self._agent, cluster=self._cluster,
                       consistent=getattr(verdict, "consistent", None),
                       per_action=getattr(verdict, "per_action", None),
                       rationale=getattr(verdict, "rationale", None), flagged=getattr(verdict, "flagged", None))
        return verdict

    def __getattr__(self, name: str) -> Any:
        # Everything else (llm_calls, client, ...) is the real judge's.
        return getattr(self._inner, name)


def dumps(trace: dict[str, Any]) -> str:
    return json.dumps(trace, ensure_ascii=False)


__all__ = ["TRACE_VERSION", "TraceRecorder", "TracedJudge", "clip", "dumps", "emit", "plain", "topology"]
