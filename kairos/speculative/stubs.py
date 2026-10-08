"""Stub generation and detection for speculative execution
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

_STUB_RE = re.compile(r"<stub:[a-z_]+:\d+>")

# Optional per-tool result shapes from the tool declaration (NOT from calling it).
# Empty for banking (held results are unparsed confirmations); populated per-suite
# when a held call's result shape actually matters to the agent's continuation.
RESULT_SCHEMAS: dict[str, Any] = {
    # "send_money": {"status": "ok", "transaction_id": "<stub:txid>"},
}

@dataclass(slots=True)
class StubRegistry:
    """Per-branch: tracks issued markers and the real values they stand for, so
    commit can substitute the real values back into the held calls."""
    _seq: int = 0
    real_by_marker: dict[str, Any] = field(default_factory=dict)

    # --- value markers (Job 2)
    def marker_for(self, tool: str, real_value: Any) -> str:
        """Mint a stable marker for a sensitive/untrusted value, remembering the
        real value for commit-time substitution."""
        self._seq += 1
        marker = f"<stub:{_slug(tool)}:{self._seq}>"
        self.real_by_marker[marker] = real_value
        return marker

    def is_marker(self, value: Any) -> bool:
        return isinstance(value, str) and bool(_STUB_RE.fullmatch(value))

    def contains_marker(self, value: Any) -> bool:
        """True if a marker appears anywhere in value — for Trigger 1, where a stub
        may be embedded in a larger string (a URL, a body) OR nested inside a
        list/dict arg (workspace recipients=[...]). Recurses so a marked element
        doesn't slip past the stub-into-outbound check."""
        if isinstance(value, str):
            return bool(_STUB_RE.search(value))
        if isinstance(value, (list, tuple)):
            return any(self.contains_marker(x) for x in value)
        if isinstance(value, dict):
            return any(self.contains_marker(x) for x in value.values())
        return False

    def substitute_real(self, args: dict[str, Any]) -> dict[str, Any]:
        """Replace markers with their real values — used on COMMIT before the held
        call is actually dispatched (§4.9: 'stub values replaced by actual values').
        Recurses into lists/dicts so a marker in a list-valued arg is restored, not
        dispatched as a literal '<stub:...>' string."""
        return {k: self._restore_value(v) for k, v in args.items()}

    def _restore_value(self, v: Any) -> Any:
        if isinstance(v, str):
            return self._restore_str(v)
        if isinstance(v, list):
            return [self._restore_value(x) for x in v]
        if isinstance(v, tuple):
            return tuple(self._restore_value(x) for x in v)
        if isinstance(v, dict):
            return {k: self._restore_value(x) for k, x in v.items()}
        return v

    def _restore_str(self, s: str) -> str:
        def repl(m: re.Match) -> str:
            return str(self.real_by_marker.get(m.group(0), m.group(0)))
        return _STUB_RE.sub(repl, s)

    # --- agent-facing result stub (Job 1)
    def result_stub(self, tool: str) -> Any:
        """A plausible SUCCESS result handed to the agent for a held call, so it
        continues. Shape from the tool declaration if known, else generic."""
        schema = RESULT_SCHEMAS.get(tool)
        if schema is not None:
            return _fill_schema(schema, self)
        return f"{tool} completed successfully."

    def withheld_stub(self, tool: str) -> str:
        """The HONEST variant for held calls whose result the agent would read on
        (a flagged GET): a success stub would make it hallucinate content, so say
        plainly that nothing executed and nothing is available."""
        return (f"SECURITY NOTICE: the call to {tool} was WITHHELD pending security "
                "review and did NOT execute. Its result is unavailable — do not guess "
                "or fabricate it. Continue the user's request with information you "
                "already have, or report that this step could not be completed.")

    def held_notice(self, tool: str, args: dict[str, Any] | None = None) -> str:
        """v2 (hold_notice='honest'): the HONEST variant for a held STATE-CHANGING
        call. The success stub (result_stub) keeps the agent going but hides that
        the effect has not happened, which in a dynamic environment starves the
        agent of the reaction it needs next (AgentDyn). This notice tells the agent
        the truth, tells it to CONTINUE when nothing downstream depends on the
        effect, and gives it one lever when something does: re-issue the same call,
        which forces resolution (Trigger 3) and is answered with the real result."""
        arg_summary = ", ".join(f"{k}={v!r}" for k, v in (args or {}).items())
        return (
            f"SECURITY NOTICE: the call {tool}({arg_summary}) is ON HOLD pending a security "
            "review and has NOT been executed yet. This is NOT an error and NOT a refusal. "
            "If the remaining steps of the user's task do not depend on this action having "
            "happened, simply CONTINUE with them now; the held action will be reviewed and, "
            "if approved, carried out automatically before the task ends. If a later step DOES "
            "need this action to have happened first (for example to read a reply, a "
            "confirmation, a file or a result it produces), re-issue exactly the same call "
            "once: that triggers the review immediately and, if approved, executes the action "
            "and returns its real result. Do not assume it succeeded or failed, do not invent "
            "its result, and do not describe it as completed."
        )

def _slug(tool: str) -> str:
    return re.sub(r"[^a-z_]", "_", tool.lower())

def _fill_schema(schema: Any, reg: StubRegistry) -> Any:
    """Recursively realize a declared result schema, minting markers for any
    '<stub:...>' placeholder fields."""
    if isinstance(schema, dict):
        return {k: _fill_schema(v, reg) for k, v in schema.items()}
    if isinstance(schema, list):
        return [_fill_schema(v, reg) for v in schema]
    if isinstance(schema, str) and schema.startswith("<stub:"):
        reg._seq += 1
        return f"<stub:gen:{reg._seq}>"
    return schema