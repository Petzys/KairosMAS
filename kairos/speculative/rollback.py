"""Commit/abort coordinator and the atomicity property
"""
from __future__ import annotations

from kairos.adapters.base import Effector
from kairos.core.store import TokenStore
from kairos.speculative.branch import Branch

class RollbackCoordinator:
    def __init__(self, store: TokenStore, effector: Effector) -> None:
        self.store = store
        self.effector = effector

    def commit(self, branch: Branch) -> None:
        """Merge overlay, merge tokens (store.commit_branch), dispatch stalled with
        real values (effector.commit). The speculative state becomes real."""
        raise NotImplementedError

    def abort(self, branch: Branch) -> None:
        """Discard overlay, drop branch tokens (store.abort_branch), drop the queue,
        return synthesized errors for stubbed results (effector.abort)."""
        raise NotImplementedError