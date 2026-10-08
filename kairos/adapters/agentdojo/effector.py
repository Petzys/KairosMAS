"""In-memory Effector for the AgentDojo simulation (Phase 1, §4.2).

No real filesystem or network: 'overlay' is a buffer of writes, 'stall queue' is
a buffer of pending tool calls. Implements the same Effector protocol as prod.
"""
from __future__ import annotations

from typing import Any

from kairos.adapters.base import Effector
from kairos.core.events import Event
from kairos.speculative.branch import Branch


class SimEffector(Effector):
    def __init__(self) -> None:
        self._fs_buffer: dict[str, Any] = {}     # simulated overlay upper layer

    def forward(self, event: Event) -> Any:
        raise NotImplementedError

    def block(self, event: Event) -> Any:
        raise NotImplementedError

    def stub(self, event: Event, stub_value: Any) -> Any:
        raise NotImplementedError

    def stall(self, event: Event) -> None:
        raise NotImplementedError

    def commit(self, branch: Branch) -> None:
        raise NotImplementedError

    def abort(self, branch: Branch) -> None:
        raise NotImplementedError