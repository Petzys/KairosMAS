"""TokenStore: committed and branch token sets
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
import re
import time
from typing import Any

from kairos.core.extract import ExtractConfig, as_text, extract, prompt_extract_config
from kairos.core.matching import Strategy, matches, tokenize, normalize
from kairos.core.tokens import Level, SensitivityToken, TrustToken

def _strip_scheme(value: str) -> str:
    """URL-normalize for verbatim matching: lowercase, drop scheme://, trailing /."""
    return re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value.strip().lower()).rstrip("/")

@dataclass(frozen=True, slots=True)
class LabelSnapshot:
    """The committed labels of one agent's store at one point in time.

    Multi-agent systems join a receiver's sets with the sender's when a message is
    delivered (T_recv |= T_send, S_recv |= S_send). The snapshot is taken at the
    send event, so the receiver inherits exactly what the sender knew when it wrote
    the message, not what it learned afterwards. Every token keeps its owner.
    """
    owner: str | None
    trust: frozenset[TrustToken]
    sens: frozenset[SensitivityToken]
    admitted_texts: tuple[tuple[str, str, str | None, str | None], ...]
    user_prompt: str
    provenance_texts: tuple[tuple[str, str, str | None], ...] = ()


class TokenStore:
    def __init__(self, owner: str | None = None) -> None:
        # The agent this store belongs to (multi-agent systems); None for a
        # single-agent deployment, where every token is the agent's own.
        self.owner = owner
        self._trust: set[TrustToken] = set()
        self._sens: set[SensitivityToken] = set()
        self._user_prompt: str = "" # raw prompt
        # raw admitted content, for verbatim-reference queries (§4.6 navigational
        # rule). Tokens can't answer "did this exact URL appear in something the
        # agent read" — token extraction shreds URLs into words.
        # (source, lowered text, branch_origin, owner)
        self._admitted_texts: list[tuple[str, str, str | None, str | None]] = []
        # content recorded for ATTRIBUTION only (messages from other agents): sources_of
        # scans it, seen_verbatim does not -- a URL a peer merely wrote is not one the
        # agent read, so it must not make a GET to it "navigation". (source, text, owner)
        self._provenance_texts: list[tuple[str, str, str | None]] = []

    # growth
    def seed(self, user_prompt: str, cfg: ExtractConfig | None = None) -> None:
        """T_0 = extract(user_prompt). The root of trust (§4.5)."""
        self._user_prompt = user_prompt
        cfg = cfg or prompt_extract_config()
        ts = time.time()
        for value in extract(user_prompt, cfg):
            self._trust.add(TrustToken(value=value, source="user_prompt", branch_origin=None,
                                       timestamp=ts, owner=self.owner))

    def user_prompt(self) -> str:
        """Expose the raw user prompt for in_user_prompt checks."""
        return self._user_prompt

    def clear(self) -> None:
        """Wipe all tokens and the recorded prompt (per-task reset)."""
        self._trust.clear()
        self._sens.clear()
        self._user_prompt = ""
        self._admitted_texts.clear()
        self._provenance_texts.clear()

    def admit(
        self,
        content: Any,
        source: str,
        *,
        trusted: bool,
        level: Level | None,
        branch_origin: str | None,
        extract_cfg: ExtractConfig,
    ) -> None:
        """Transitively admit tokens extracted from a trusted/sensitive result (4.3, 4.5).

        Caller (engine) decides `trusted`/`level` from policy and ensures the
        producing call was ALLOWed. A source can be both (banking tool), so both
        token kinds may be added from one call.
        """
        ts = time.time()
        for value in extract(content, extract_cfg):
            if trusted:
                self._trust.add(TrustToken(value, source, branch_origin, ts, self.owner))
            if level is not None:
                self._sens.add(SensitivityToken(value, level, source, branch_origin, ts, self.owner))
        self._admitted_texts.append((source, as_text(content).lower(), branch_origin, self.owner))

    def record_text(self, content: Any, source: str) -> None:
        """Remember raw content for provenance queries WITHOUT admitting tokens.

        Untrusted, non-sensitive content (a message from another agent) enters
        neither set, but `sources_of` must still be able to say "this value came from
        that message" -- the attribution the oracle checks a delegation against. It
        does not feed seen_verbatim (the navigational-reference rule)."""
        self._provenance_texts.append((source, as_text(content).lower(), self.owner))

    # active-set helpers (committed-onyl when branch is None)
    def _active_trust(self, branch: str | None) -> set[TrustToken]:
        if branch is None:
            return {t for t in self._trust if t.branch_origin is None}
        return {t for t in self._trust if t.branch_origin in (None, branch)}

    def _active_sens(self, branch: str | None) -> set[SensitivityToken]:
        if branch is None:
            return {t for t in self._sens if t.branch_origin is None}
        return {t for t in self._sens if t.branch_origin in (None, branch)}

    # queries
    def derivable(self, value: str, strategy: Strategy, branch: str | None = None) -> bool:
        """v ⊆_match T_i (or T_i^B when `branch` is set) (4.5).

        token_split is evaluated closure-wide: every token of `value` must appear
        among the union of all closure tokens.
        """
        closure = self._active_trust(branch)
        if not closure:
            return False
        if strategy is Strategy.TOKEN_SPLIT:
            union: set[str] = set()
            for t in closure:
                union |= tokenize(t.value)
            v_tokens = tokenize(value)
            return bool(v_tokens) and v_tokens <= union
        return any(matches(value, t.value, strategy) for t in closure)

    def sensitivity_of(
        self, value: str, branch: str | None = None, strategy: Strategy = Strategy.NORMALIZED
    ) -> Level | None:
        """Highest sensitivity level a sensitive token implies for `value`, else None.

        token_split here is the LEAK direction: a sensitive token's tokens all
        appear in `value`. The per-source scan strategy is threaded in by the
        confidentiality engine step; NORMALIZED is the safe primitive default.
        """
        sens = self._active_sens(branch)
        if not sens:
            return None
        if strategy is Strategy.TOKEN_SPLIT:
            v_tokens = tokenize(value)
            hits = [t.level for t in sens if (st := tokenize(t.value)) and st <= v_tokens]
        else:
            hits = [t.level for t in sens if matches(value, t.value, strategy)]
        return max(hits) if hits else None

    def trust_closure(self, branch: str | None = None) -> set[TrustToken]:
        return self._active_trust(branch)

    def sensitivity_set(self, branch: str | None = None) -> set[SensitivityToken]:
        return self._active_sens(branch)

    def seen_verbatim(self, value: str, branch: str | None = None) -> bool:
        """Did `value` appear verbatim (URL-normalized: lowercased, scheme and
        trailing slash stripped) in the user prompt or in admitted content?

        The navigational-reference query (§4.6): a URL the agent merely read —
        as opposed to composed — matches here. Substring matching tolerates
        surrounding punctuation ("visit www.x.com."); scheme-stripping tolerates
        the agent adding http:// to a bare domain from content."""
        needle = _strip_scheme(value)
        if not needle:
            return False
        if needle in self._user_prompt.lower():
            return True
        return any(needle in text for (_src, text, bo, _own) in self._admitted_texts
                   if bo is None or bo == branch)

    def sources_of(self, value: str, branch: str | None = None,
                   strategy: Strategy = Strategy.NORMALIZED) -> list[str]:
        """Which admitted sources could have supplied `value` (§4.5, provenance).

        `derivable` answers "is this value in the closure"; this answers "and who
        put it there". The judge is otherwise told only a CATEGORY ("from a
        file/tool"), which it cannot check a delegation against: "pay the bill in
        bill-december-2023.txt" is satisfied by read_file:bill-december-2023.txt
        and by NOTHING else, and only the specific source distinguishes the two.

        Trusted sources carry their label on the token. Untrusted content produces
        no trust token at all -- and that is the case that matters, since an
        injected value is untrusted by construction -- so the raw admitted text is
        scanned as well. Order is trusted-first, then admission order.

        Substring containment can name more than one source when a short value
        appears in several results; every candidate is returned rather than one
        guessed winner, so a caller comparing against an expected source sees the
        ambiguity instead of a false match.
        """
        hits: list[str] = []
        for t in self._active_trust(branch):
            label = self._qualified(t.source, t.owner)
            if label not in hits and matches(value, t.value, strategy):
                hits.append(label)
        needle = _strip_scheme(value)
        if needle:
            for src, text, bo, own in self._admitted_texts:
                if bo is not None and bo != branch:
                    continue
                label = self._qualified(src, own)
                if label not in hits and needle in text:
                    hits.append(label)
            for src, text, own in self._provenance_texts:
                label = self._qualified(src, own)
                if label not in hits and needle in text:
                    hits.append(label)
        return hits

    def _qualified(self, source: str, owner: str | None) -> str:
        """A source as seen from this store: its own sources bare, another agent's
        prefixed with that agent ("documents/read_file"), so a joined value names
        the agent whose boundary it crossed."""
        if owner is None or owner == self.owner:
            return source
        return f"{owner}/{source}"

    def in_user_prompt(self, value: str, strategy: Strategy = Strategy.NORMALIZED) -> bool:
        """Does `value` appear in the user's prompt? (origin: param_in_user_prompt, §4.4)

        Checks the RAW prompt, not the token closure — its job is to rescue a value
        the tokenizer mangled but the user literally typed. For values the closure
        already covers, integrity passes and this is never consulted.
        """
        if not self._user_prompt:
            return False
        if strategy is Strategy.EXACT:
            return value in self._user_prompt
        if strategy is Strategy.TOKEN_SPLIT:
            v, p = tokenize(value), tokenize(self._user_prompt)
            return bool(v) and v <= p
        return normalize(value) in normalize(self._user_prompt)

    # reconcilication (4.9)
    def commit_branch(self, branch_id: str) -> None:
        """T_{i+1} = T_i^B, S_{i+1} = S_i^B: clear branch_origin on the branch's tokens."""
        prompte_t = {t for t in self._trust if t.branch_origin == branch_id}
        self._trust -= prompte_t
        self._trust |= {dataclasses.replace(t, branch_origin=None) for t in prompte_t}
        prompte_s = {t for t in self._sens if t.branch_origin == branch_id}
        self._sens -= prompte_s
        self._sens |= {dataclasses.replace(t, branch_origin=None) for t in prompte_s}
        self._admitted_texts = [
            (src, text, None if bo == branch_id else bo, own)
            for (src, text, bo, own) in self._admitted_texts
        ]

    def abort_branch(self, branch_id: str) -> None:
        """Drop every token with branch_origin == branch_id; committed sets unchanged."""
        self._trust = {t for t in self._trust if t.branch_origin != branch_id}
        self._sens = {t for t in self._sens if t.branch_origin != branch_id}
        self._admitted_texts = [t for t in self._admitted_texts if t[2] != branch_id]

    # multi-agent label flow
    def snapshot(self) -> LabelSnapshot:
        """The committed T, S and admitted texts, for a join into another store."""
        return LabelSnapshot(
            owner=self.owner,
            trust=frozenset(t for t in self._trust if t.branch_origin is None),
            sens=frozenset(t for t in self._sens if t.branch_origin is None),
            admitted_texts=tuple(a for a in self._admitted_texts if a[2] is None),
            user_prompt=self._user_prompt,
            provenance_texts=tuple(self._provenance_texts),
        )

    def join(self, snap: LabelSnapshot) -> None:
        """T |= T_snap, S |= S_snap (labels of a message's sender).

        Safe for T: the monitor computes it from the user prompt and declared
        trusted sources only, so a compromised sender cannot place a value in it.
        Conservative for S: a value the sender held at any level is held here at
        that level too; conflicting levels resolve to the maximum, because
        sensitivity_of already takes the max over matching tokens. Owners are kept.

        The raw prompt is the principal's: every agent's work descends from it, so
        a store that has none yet takes the sender's."""
        self._trust |= snap.trust
        self._sens |= snap.sens
        have = {(src, text, own) for (src, text, _bo, own) in self._admitted_texts}
        for src, text, bo, own in snap.admitted_texts:
            key = (src, text, own)
            if key not in have:
                have.add(key)
                self._admitted_texts.append((src, text, bo, own))
        known = set(self._provenance_texts)
        for item in snap.provenance_texts:
            if item not in known:
                known.add(item)
                self._provenance_texts.append(item)
        if not self._user_prompt and snap.user_prompt:
            self._user_prompt = snap.user_prompt
