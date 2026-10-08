"""Token metering + per-task monitor-decision logging for AgentDojo runs.

Two things AgentDojo doesn't capture: which KAIROS layer decided each action,
and token usage. We attach both to a per-task JSON keyed by (user_task,
injection_task) — the ids are read from the harness's logger context, so the
join to utility/security is by construction, not execution order.
"""
from __future__ import annotations

import sys, io
import time, random
from typing import Any, Sequence

from agentdojo.agent_pipeline.base_pipeline_element import BasePipelineElement
from agentdojo.functions_runtime import EmptyEnv, Env, FunctionsRuntime
from agentdojo.types import ChatMessage
from agentdojo.logging import Logger

try:
    import openai
    _RATE_LIMIT = openai.RateLimitError
except Exception:
    _RATE_LIMIT = None

_CAPTURE: "TeeCapture | None" = None

def get_capture() -> "TeeCapture | None":
    return _CAPTURE

def install_capture() -> "TeeCapture":
    global _CAPTURE
    _CAPTURE = TeeCapture()
    _CAPTURE.install()
    return _CAPTURE

class TeeCapture:
    """Mirror everything written to stdout into an in-memory buffer, while still
    printing to the real terminal. reset() clears the buffer per task; text()
    returns what was captured."""
    def __init__(self) -> None:
        self._buf = io.StringIO()
        self._real = sys.stdout

    def write(self, s: str) -> int:
        self._real.write(s)
        self._buf.write(s)
        return len(s)

    def flush(self) -> None:
        self._real.flush()

    def reset(self) -> None:
        self._buf = io.StringIO()

    def text(self) -> str:
        return self._buf.getvalue()

    def install(self) -> None:
        sys.stdout = self

    def uninstall(self) -> None:
        sys.stdout = self._real

class TokenMeter:
    """Accumulates exact usage for ONE task. Reset between tasks."""
    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self.llm_calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    def record(self, response: Any) -> None:
        usage = getattr(response, "usage", None)
        if usage is None:
            return
        self.llm_calls += 1
        self.prompt_tokens += getattr(usage, "prompt_tokens", 0) or 0
        self.completion_tokens += getattr(usage, "completion_tokens", 0) or 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def snapshot(self) -> dict[str, int]:
        return {
            "llm_calls": self.llm_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens
        }

def instrument_client(client: Any, meter: TokenMeter) -> Any:
    """Patch client.chat.completions.create to (1) record usage on success and
    (2) retry rate-limit errors with backoff. Records ONLY on the successful
    response, so retries never double-count."""
    if getattr(client, "_kairos_instrumented", False):
        return client
    orig = client.chat.completions.create

    def wrapped(*args, **kwargs):
        delay = 1.0
        for _ in range(6):
            try:
                resp = orig(*args, **kwargs)
                meter.record(resp)
                return resp
            except Exception as e:
                if _RATE_LIMIT is not None and isinstance(e, _RATE_LIMIT):
                    wait = getattr(e, "retry_after", None)
                    if not wait:
                        wait = delay + random.uniform(0, 0.3)
                        delay = min(delay * 2, 30.0)
                    time.sleep(float(wait))
                    continue
                raise
        # final attempt — let it raise if still failing
        resp = orig(*args, **kwargs)
        meter.record(resp)
        return resp

    client.chat.completions.create = wrapped
    client._kairos_instrumented = True
    return client

def _current_ids() -> tuple[str | None, str | None]:
    try:
        ctx = getattr(Logger.get(), "context", {}) or {}
    except Exception:
        return None, None
    return ctx.get("user_task_id"), ctx.get("injection_task_id")

def flush_to_trace(monitor: Any | None, meter: TokenMeter, capture: TeeCapture | None) -> None:
    """Write the kairos block into the CURRENT task's trace JSON. Safe to call
    repeatedly (last-write-wins) and with monitor=None (undefended: tokens only)."""
    cap = get_capture()            # ALWAYS the singleton; ignore the (possibly None) arg
    try:
        logger = Logger.get()
    except Exception:
        return
    set_fn = getattr(logger, "set_contextarg", None)
    if set_fn is None:
        return
    block: dict = {"tokens": meter.snapshot()}
    if cap is not None:
        block["terminal_log"] = cap.text()
    if monitor is not None:
        try:
            block["session"] = monitor.session.summary()
        except Exception as e:
            block["session_error"] = repr(e)
    try:
        set_fn("kairos", block)
    except Exception:
        pass

class MeterReset(BasePipelineElement):
    """Reset the meter at the start of every pipeline.query (once per task).
    Used standalone in the undefended pipeline; defense-on uses SessionReset
    which already resets the meter."""
    name = "meter_reset"

    def __init__(self, meter: TokenMeter) -> None:
        self.meter = meter

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        self.meter.reset()
        return query, runtime, env, messages, extra_args

class TelemetryFlush(BasePipelineElement):
    """Flush the kairos block into the trace. monitor may be None (undefended)."""
    name = "telemetry_flush"

    def __init__(self, monitor: Any | None, meter: TokenMeter, capture: TeeCapture | None = None) -> None:
        self.monitor = monitor
        self.meter = meter
        self.capture = capture

    def query(self, query: str, runtime: FunctionsRuntime, env: Env = EmptyEnv(),
              messages: Sequence[ChatMessage] = [], extra_args: dict = {}):
        flush_to_trace(self.monitor, self.meter, self.capture)
        return query, runtime, env, messages, extra_args
