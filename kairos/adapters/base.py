"""The channel abstraction — the one seam between core and the world (§4.2).

Both the AgentDojo adapter (synthetic events) and the production channels
(FUSE / mitmproxy / vsock) implement these. The core depends ONLY on these
protocols and never imports a concrete adapter.
"""
from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Protocol, runtime_checkable

from kairos.core.events import Event
from kairos.speculative.branch import Branch

@runtime_checkable
class EventSource(Protocol):
    def events(self) -> Iterator[Event]:
        """Yield uniform events as the agent acts."""
        ...

@runtime_checkable
class Effector(Protocol):
    # per-event outcomes
    def forward(self, event: Event) -> Any: ...   # ALLOW: dispatch, return real result
    def block(self, event: Event) -> Any: ...     # DENY: synthesized error to the agent
    def stub(self, event: Event, stub_value: Any) -> Any: ...  # REVIEW: hand back a stub
    def stall(self, event: Event) -> None: ...    # hold non-revertable outbound at boundary
    # branch resolution (4.9)
    def commit(self, branch: Branch) -> None: ...  # dispatch stalled w/ real values; merge CoW
    def abort(self, branch: Branch) -> None: ...   # drop stalled; discard CoW; error stubs