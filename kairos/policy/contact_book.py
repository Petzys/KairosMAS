"""Destination trust + confidentiality clearance
"""
from __future__ import annotations

from kairos.core.matching import Strategy, matches, normalize
from kairos.core.tokens import Level
from kairos.policy.schema import CbEntry
from kairos.policy.schema import ContactBook as ContactBookSchema

class ContactBook:
    def __init__(self, schema: ContactBookSchema) -> None:
        self._schema = schema
        self._entries = schema.entries
        self._seeded: set[str] = {
            normalize(v) for vals in schema.seed.values() for v in vals
        }

    @property
    def lookup_fields(self) -> list[str]:
        return self._schema.lookup_fields

    @property
    def on_miss(self):
        return self._schema.on_miss

    def lookup(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> CbEntry | None:
        """First entry whose `match` covers `value`. (entry.fields scoping is a
        documented MVP simplification — match applies across all lookup_fields.)"""
        for e in self._entries:
            if matches(value, e.match, strategy):
                return e
        return None

    def clearance(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> Level | None:
        """max_level the destination may receive, or None if it has no entry."""
        e = self.lookup(value, strategy)
        return e.max_level if e is not None else None

    def is_known(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> bool:
        """Known = matches an entry OR appears in seed. Feeds the integrity axis."""
        return self.lookup(value, strategy) is not None or normalize(value) in self._seeded