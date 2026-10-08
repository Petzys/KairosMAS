"""Stage-1 deterministic enforcement
"""
from __future__ import annotations

from typing import Literal

from kairos.core.events import Event
from kairos.core.matching import Strategy
from kairos.core.store import TokenStore
from kairos.engine.action_class import ActionClass, classify, consequential_values
from kairos.engine.confidentiality import (
    check_confidentiality, is_navigational_reference, outbound_sensitivity,
)
from kairos.engine.decision import Decision, StageResult, resolve
from kairos.engine.integrity import check_embedded_identifiers, check_integrity
from kairos.policy.contact_book import ContactBook
from kairos.policy.rules import SequenceRuleMatcher, SimpleRuleMatcher
from kairos.policy.ratelimit import RateLimiter
from kairos.policy.schema import Policy, SimpleRule

Mode = Literal["full", "baseline"]

class PolicyEngine:
    def __init__(
        self,
        policy: Policy,
        store: TokenStore,
        *,
        contact_book: ContactBook | None = None,
        simple_rules: SimpleRuleMatcher | None = None,
        sequence_rules: SequenceRuleMatcher | None = None,
        rate_limiter: RateLimiter | None = None,
        mode: Mode = "full",
        default_strategy: Strategy = Strategy.NORMALIZED,
    ) -> None:
        self.policy = policy
        self.store = store
        self.contact_book = contact_book
        self._simple = simple_rules
        self._sequence = sequence_rules
        self._rate = rate_limiter
        self.mode: Mode = mode
        self.default_strategy = default_strategy

    @classmethod
    def build(
        cls, policy: Policy, store: TokenStore, *, 
        mode: Mode = "full", default_strategy: Strategy = Strategy.NORMALIZED,
    ) -> "PolicyEngine":
        """Construct from a parsed policy. Sequence/rate matchers are deferred (None)."""
        cb = ContactBook(policy.resources.contact_book) if policy.resources.contact_book else None
        simple = SimpleRuleMatcher([r for r in policy.rules if isinstance(r, SimpleRule)])
        return cls(policy, store, contact_book=cb, simple_rules=simple,
                   mode=mode, default_strategy=default_strategy)

    # entry point
    def evaluate(self, event: Event, branch: str | None = None) -> StageResult:
        ac = classify(event, self.policy)
        rules_on = self.mode == "full"
        matched = (self._simple.matching(event, self.store, self.contact_book, branch)
                   if rules_on and self._simple is not None else [])

        # 1. Guard
        if rules_on:
            guard = self._guard(event, matched)
            if guard is not None:
                dec, by, reason = guard
                return StageResult(dec, stage=1, produced_by=by, reason=reason)

        # non-outobund classes
        if ac is ActionClass.PASSIVE:
            return StageResult(Decision.ALLOW, stage=1, produced_by="passive")
        if ac is ActionClass.FS_WRITE:
            return StageResult(Decision.ALLOW, stage=1, produced_by="fs_write_deferred",
                               reason="untrusted-write REVIEW deferred to file-trust ledger")

        # 2. Axes (NET_STATE_CHANGE, NET_GET) - scan sensitivity once
        # cvals = consequential_values(event, ac)
        id_fields = set(self.contact_book.lookup_fields) if self.contact_book else None
        cvals = consequential_values(event, ac, id_fields)
        data_level = outbound_sensitivity(event, ac, self.store, branch=branch)
        # Navigational-reference rule (§4.6): a GET whose sensitivity-carrying URL
        # appears VERBATIM in the prompt/admitted content is navigation, not
        # exfiltration — the URL's author already knew it. Suppress the exfil flag
        # (policy knob context.navigational_get; "review" keeps today's REVIEW).
        nav_ref = False
        if (data_level is not None
                and self.policy.context.navigational_get == "allow"
                and is_navigational_reference(event, ac, self.store, branch=branch)):
            nav_ref, data_level = True, None
        integ, ireason = check_integrity(
            event, ac, self.store, self.policy,
            contact_book=self.contact_book, branch=branch,
            default_strategy=self.default_strategy,
        )
        conf, creason = check_confidentiality(
            event, ac, self.store, self.contact_book, data_level=data_level, branch=branch,
        )
        # Optional third integrity check over payload-embedded identifiers
        # (context.embedded_identifiers; off by default, so normally a no-op).
        emb, ereason = check_embedded_identifiers(
            event, ac, self.store, self.policy,
            contact_book=self.contact_book, branch=branch,
            default_strategy=self.default_strategy,
        )
        axis = resolve([integ, conf, emb])

        id_values = {name: val for name, val in cvals if name != "__destination__"}
        dest = next((val for name, val in cvals if name == "__destination__"), None)
        if dest is not None:
            id_values["__destination__"] = dest

        if axis is None:
            if nav_ref: # attribution: the navigational rule (not the axes) vouched
                return StageResult(Decision.ALLOW, stage=1, produced_by="navigational_reference",
                                   identifiers=id_values,
                                   reason="URL appears verbatim in admitted content (navigational reference)")
            if cvals: # axes vouched for a real value
                return StageResult(Decision.ALLOW, stage=1, produced_by="axes", identifiers=id_values)
            return StageResult(self.policy.context.default_action, stage=1, produced_by="default", identifiers=id_values,
                               reason="consequential action with no derivable value to vouch for")

        # 3. Exemption - operator allow overrides axis review
        if rules_on:
            for r in matched:
                if r.decision is Decision.ALLOW:
                    return StageResult(Decision.ALLOW, stage=1, produced_by=f"rule:{r.id}", identifiers=id_values,
                                       reason="operator ALLOW exemption overrides axis review")
        
        if integ is not None:
            by, reason = "integrity", ireason
        elif conf is not None:
            by, reason = "confidentiality", creason
        else:
            by, reason = "embedded_identifiers", ereason
        return StageResult(axis, stage=1, produced_by=by, identifiers=id_values, reason=reason)

    # --- ordered checks (each returns Decision | None; None == pass) ---------
    def _guard(self, event: Event, matched: list[SimpleRule]) -> tuple[Decision, str, str] | None:
        """Categorical safety-invariant rules (DENY/REVIEW) before prompt trust.
        Open Decision #3 — reconcile with §4.4's written rule order."""
        candidates: list[tuple[Decision, str, str]] = []
        if self._rate is not None:
            d = self._rate.evaluate(event)
            if d is not None:
                candidates.append((d, "rate_limit", "rate limit exceeded"))
        if self._sequence is not None:
            d = self._sequence.observe(event)
            if d in (Decision.DENY, Decision.REVIEW):
                candidates.append((d, "sequence_rule", "sequence pattern matched"))
        for r in matched:
            if r.decision in (Decision.DENY, Decision.REVIEW):
                candidates.append((r.decision, f"rule:{r.id}", "operator safety rule"))
        if not candidates:
            return None
        best = resolve([d for d, _, _ in candidates]) # DENY>REVIEW>ALLOW
        return next(c for c in candidates if c[0] is best)

    def _contact_book(self, event: Event) -> Decision | None:
        raise NotImplementedError

    def _integrity(self, event: Event, branch: str | None) -> Decision | None:
        raise NotImplementedError

    def _confidentiality(self, event: Event, branch: str | None) -> Decision | None:
        raise NotImplementedError