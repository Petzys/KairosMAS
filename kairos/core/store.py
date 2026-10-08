"""TokenStore: committed and branch token sets
"""
from __future__ import annotations

import dataclasses
import re
import time
from typing import Any

from kairos.core.extract import ExtractConfig, as_text, extract, prompt_extract_config
from kairos.core.matching import Strategy, matches, tokenize, normalize
from kairos.core.tokens import Level, SensitivityToken, TrustToken

def _strip_scheme(value: str) -> str:
    """URL-normalize for verbatim matching: lowercase, drop scheme://, trailing /."""
    return re.sub(r"^[a-z][a-z0-9+.\-]*://", "", value.strip().lower()).rstrip("/")

class TokenStore:
    def __init__(self) -> None:
        self._trust: set[TrustToken] = set()
        self._sens: set[SensitivityToken] = set()
        self._user_prompt: str = "" # raw prompt
        # raw admitted content, for verbatim-reference queries (§4.6 navigational
        # rule). Tokens can't answer "did this exact URL appear in something the
        # agent read" — token extraction shreds URLs into words.
        self._admitted_texts: list[tuple[str, str, str | None]] = []  # (source, lowered text, branch_origin)

    # growth
    def seed(self, user_prompt: str, cfg: ExtractConfig | None = None) -> None:
        """T_0 = extract(user_prompt). The root of trust (§4.5)."""
        self._user_prompt = user_prompt
        cfg = cfg or prompt_extract_config()
        ts = time.time()
        for value in extract(user_prompt, cfg):
            self._trust.add(TrustToken(value=value, source="user_prompt", branch_origin=None, timestamp=ts))

    def user_prompt(self) -> str:
        """Expose the raw user prompt for in_user_prompt checks."""
        return self._user_prompt

    def clear(self) -> None:
        """Wipe all tokens and the recorded prompt (per-task reset)."""
        self._trust.clear()
        self._sens.clear()
        self._user_prompt = ""
        self._admitted_texts.clear()

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
                self._trust.add(TrustToken(value, source, branch_origin, ts))
            if level is not None:
                self._sens.add(SensitivityToken(value, level, source, branch_origin, ts))
        self._admitted_texts.append((source, as_text(content).lower(), branch_origin))

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
        return any(needle in text for (_src, text, bo) in self._admitted_texts
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
            if t.source not in hits and matches(value, t.value, strategy):
                hits.append(t.source)
        needle = _strip_scheme(value)
        if needle:
            for src, text, bo in self._admitted_texts:
                if bo is not None and bo != branch:
                    continue
                if src not in hits and needle in text:
                    hits.append(src)
        return hits

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
            (src, text, None if bo == branch_id else bo)
            for (src, text, bo) in self._admitted_texts
        ]

    def abort_branch(self, branch_id: str) -> None:
        """Drop every token with branch_origin == branch_id; committed sets unchanged."""
        self._trust = {t for t in self._trust if t.branch_origin != branch_id}
        self._sens = {t for t in self._sens if t.branch_origin != branch_id}
        self._admitted_texts = [t for t in self._admitted_texts if t[2] != branch_id]
