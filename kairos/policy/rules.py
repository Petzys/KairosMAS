"""Simple- and sequence-rule matching
"""
from __future__ import annotations

from kairos.core.events import Event
from kairos.core.matching import Strategy
from kairos.core.store import TokenStore
from kairos.engine.decision import Decision
from kairos.policy.contact_book import ContactBook
from kairos.policy.schema import (
    MatchBlock, OriginCondition, ParamConstraint, SequenceRule, SimpleRule, TaintCondition,
)

class SimpleRuleMatcher:
    def __init__(self, rules: list[SimpleRule]) -> None:
        self._rules = list(rules)

    def matching(
        self, event: Event, store: TokenStore,
        contact_book: ContactBook | None, branch: str | None = None,
    ) -> list[SimpleRule]:
        """All rules whose match block applies to `event`, in policy order."""
        return [r for r in self._rules if self._matches(r.match, event, store, contact_book, branch)]

    def evaluate(
        self, event: Event, store: TokenStore,
        contact_book: ContactBook | None = None, branch: str | None = None,
    ) -> Decision | None:
        """First matching rule's decision (back-compat; pipeline uses matching())."""
        for r in self.matching(event, store, contact_book, branch):
            for r in self.matching(event, store, contact_book, branch):
                return r.decision
        return None

    # match internals
    def _matches(
        self, m: MatchBlock, event: Event, store: TokenStore,
        contact_book: ContactBook | None, branch: str | None,
    ) -> bool:
        if not self._action_matches(m.action, event):
            return False
        if m.params and not self._params_match(m.params, event, contact_book):
            return False
        if m.origin is not None and not self._origin_matches(m.origin, event, store):
            return False
        if m.taint is not None and not self._taint_matches(m.taint, event, store, branch):
            return False
        return True

    @staticmethod
    def _action_matches(action: str | list[str], event: Event) -> bool:
        # NET-routed tools (get_webpage) carry the URL in event.object and the
        # tool name in metadata.function — a rule names the TOOL, so check both.
        names = {event.object, (event.metadata or {}).get("function")}
        return action in names if isinstance(action, str) else bool(names & set(action))

    @staticmethod
    def _arg(event: Event, key: str) -> object | None:
        return event.content.get(key) if isinstance(event.content, dict) else None

    def _params_match(
            self, params: dict[str, ParamConstraint], event: Event, contact_book: ContactBook | None,
        ) -> bool:
        return all(self._constraint_holds(c, self._arg(event, name), contact_book) for name, c in params.items())

    @staticmethod
    def _constraint_holds(c: ParamConstraint, val: object | None, cb: ContactBook | None) -> bool:
        if c.op in ("in", "not_in"):
            known = cb is not None and val is not None and cb.is_known(str(val))
            return known if c.op == "in" else not known
        if val is None:
            return False
        sval = str(val)
        if c.op == "equals":
            return sval == str(c.value)
        if c.op == "contains":
            return str(c.value) in sval
        if c.op in ("gt", "lt"):
            try:
                num = float(sval.replace(",", "").replace("_", ""))
            except ValueError:
                return False
            return num > float(c.value) if c.op == "gt" else num < float(c.value)

    @staticmethod
    def _origin_matches(origin: OriginCondition, event: Event, store: TokenStore) -> bool:
        """required=True: condition holds when the param IS in the user prompt.
        required=False: NEGATED — holds when the param is NOT in the user prompt
        (e.g. review-untrusted-get: gate fetches of URLs the user never named).
        A missing param never matches either way."""
        val = SimpleRuleMatcher._arg(event, origin.param_in_user_prompt_key)
        if val is None:
            return False
        in_prompt = store.in_user_prompt(str(val))
        return in_prompt if origin.required else not in_prompt

    @staticmethod
    def _taint_matches(
        taint: TaintCondition, event: Event, store: TokenStore, branch: str | None,
    ) -> bool:
        if taint.has or taint.has_not:
            raise NotImplementedError(
                "taint has/has_not by name needs a taint-name->source map (deferred); "
                "use level_gte in the MVP"
            )
        if taint.level_gte is not None:
            texts: list[str] = []
            c = event.content
            if isinstance(c, dict):
                texts = [str(v) for v in c.values()]
            elif isinstance(c, str):
                texts = [c]
            for t in texts:
                lvl = store.sensitivity_of(t, branch=branch, strategy=Strategy.TOKEN_SPLIT)
                if lvl is not None and lvl >= taint.level_gte:
                    return True
            return False
        return True

class SequenceRuleMatcher:
    """Deferred — the pipeline calls observe() only when a matcher is provided."""
    def __init__(self, rules: list[SequenceRule]) -> None:
        self._rules = rules
        self._history: list[Event] = []

    def observe(self, event: Event) -> Decision | None:
        """Append to history and return a decision if `event` completes a pattern."""
        raise NotImplementedError