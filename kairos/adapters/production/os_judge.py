"""OS-level adapter: drive the kairos trust chain from real host events (M5b).

This is the production counterpart of adapters/agentdojo/translate.py. It maps the
deploy monitor's OS events (mitmproxy requests, FUSE file reads, the Claude Code
conversation) onto kairos Events and runs the SAME PolicyEngine that scores the
AgentDojo suites — so simulation and production share one judge (§4.2).

The deploy control plane (deploy/frontend/serve.py) imports `verdict_for()` as the
replacement for its placeholder heuristic. When kairos is not importable (e.g. the
deploy folder shipped standalone), serve.py falls back to the heuristic, so the
monitoring stack still runs without this module.

Trust model, mapped to OS channels:
  - T_0 (root of trust) = the user's FIRST message to Claude Code (extracted from
    the /v1/messages request). Later user turns extend trust. Tool results, file
    reads, and fetched web content are UNTRUSTED (they may carry injections).
  - A read of a secret-classified file admits its content as SENSITIVE, so a later
    request carrying that content to a non-cleared destination trips confidentiality.
  - A state-changing request (POST/PUT/DELETE) is gated: integrity (is the
    destination derivable/known?) + confidentiality (is it cleared for the data's
    sensitivity?). ALLOW passes; DENY blocks; REVIEW escalates to the judge/human.
"""
from __future__ import annotations

import os
import json
import re
import urllib.parse
import time
from typing import Any

from kairos.core.events import Channel, Event
from kairos.core.extract import ExtractConfig, ExtractMode, prompt_extract_config
from kairos.core.extract import embedded_values
from kairos.core.store import TokenStore
from kairos.core.tokens import Level
from kairos.engine.action_class import _origin, classify
from kairos.engine.confidentiality import outbound_sensitivity
from kairos.engine.decision import Decision
from kairos.engine.pipeline import PolicyEngine
from kairos.judge.oracle import LLMJudge
from kairos.policy.schema import (CbEntry, Context, Policy, Resources)
from kairos.policy.schema import ContactBook as CbSchema
from kairos.speculative.branch import Branch, HeldAction, Provenance

# ---- policy ---------------------------------------------------------------
# Cleared at CRITICAL: the agent's own LLM/provider channel — its traffic passes
# even carrying sensitive context (the "cleared destination" of §1.1).
# The agent's own provider channel. Cleared at CRITICAL because it legitimately
# carries the entire working context — including the contents of files the agent
# read, secrets among them. That is the "cleared destination" of §1.1: the one
# place sensitive data is allowed to go, precisely because sending it there is
# what the agent IS.
CLEARED_HOSTS = ("anthropic.com", "api.anthropic.com", "claude.ai", "claude.com")
# The judge's provider is deliberately NOT listed here. The judge is called by the
# monitor, on the host — its traffic never enters the guest, never reaches the
# transparent proxy, and is never gated. Clearing its host would suggest the
# monitor's own egress is subject to the policy it enforces, which it is not.
# Known at LOW: familiar destinations — benign state-changing calls pass integrity,
# but sending SENSITIVE data there is still held (LOW < HIGH).
#
# The agent's TELEMETRY belongs here, not in CLEARED_HOSTS. Claude Code will not
# run without reaching Statsig/Datadog/Sentry, so blocking them breaks the agent
# and measures nothing — but they are not the provider channel and have no
# business carrying a deploy key. LOW lets ordinary telemetry through while still
# holding a request that has secret content in it, which is the correct posture
# and a genuinely interesting case if it ever fires.
KNOWN_HOSTS = ("github.com", "githubusercontent.com", "registry.npmjs.org",
               "pypi.org", "files.pythonhosted.org", "crates.io",
               # Claude Code infrastructure
               "statsig.anthropic.com", "statsig.com", "api.statsig.com",
               "featuregates.org", "featureassets.org",
               "datadoghq.com", "browser-intake-datadoghq.com",
               "http-intake.logs.datadoghq.com", "sentry.io", "ingest.sentry.io",
               "api.segment.io")

# Deployment-specific additions, comma-separated, without touching the code.
CLEARED_HOSTS += tuple(h.strip() for h in
                       os.environ.get("KAIROS_CLEARED_HOSTS", "").split(",") if h.strip())
KNOWN_HOSTS += tuple(h.strip() for h in
                     os.environ.get("KAIROS_KNOWN_HOSTS", "").split(",") if h.strip())

# Files whose content is sensitive (a read taints the closure at HIGH).
SECRET_PATH_RE = re.compile(
    r"(secret|credential|password|\.env|\.pem|id_rsa|id_ed25519|token|apikey|api[_-]?key|\.aws|\.ssh)",
    re.IGNORECASE)


def _host_of(url: str) -> str:
    """Bare hostname of a URL, lowercased, no scheme/port/path."""
    h = (url or "").split("://", 1)[-1]
    return h.split("/")[0].split("?")[0].split("@")[-1].split(":")[0].strip().lower()


def _domain_match(host: str, domains) -> str | None:
    """Does `host` fall under one of `domains`, by DOMAIN SUFFIX?

    The contact book matches origins by string equality, so `claude.com` did not
    cover `platform.claude.com` and every subdomain had to be enumerated by hand —
    impossible for a live service, and it blocked the agent's own OAuth login.
    A declared domain therefore covers the domain AND everything under it, which
    is what an operator means by "clear claude.com". Suffix matching is anchored
    on a dot, so `evilclaude.com` does not match `claude.com`."""
    for d in domains or ():
        d = (d or "").strip().lower()
        if not d:
            continue
        d = d.split("://", 1)[-1].split("/")[0].lstrip("*.").split(":")[0]
        if host == d or host.endswith("." + d):
            return d
    return None


def host_tier(url: str, cleared=None, known=None):
    """(Level, matched_domain) for a destination, or (None, None).

    CRITICAL = the provider channel: may receive anything, including secrets.
    LOW      = known infrastructure: ordinary traffic passes, secrets do not.
    """
    host = _host_of(url)
    d = _domain_match(host, CLEARED_HOSTS if cleared is None else cleared)
    if d:
        return Level.CRITICAL, d
    d = _domain_match(host, KNOWN_HOSTS if known is None else known)
    if d:
        return Level.LOW, d
    return None, None


def _origins(host: str) -> list[str]:
    """Contact-book match strings for a host.

    `_origin()` defaults a bare hostname to https, so a cleared host was matched
    over HTTPS and silently missed over HTTP — an internal service on plain http
    could never be cleared, however it was declared. A hostname with no scheme
    means "this host", so both schemes are registered; an explicit scheme is
    honoured as written."""
    if "://" in host:
        return [_origin(host)]
    return [_origin(f"https://{host}"), _origin(f"http://{host}")]


def build_policy(cleared=CLEARED_HOSTS, known=KNOWN_HOSTS,
                 default_action=Decision.REVIEW) -> Policy:
    entries = [CbEntry(match=m, max_level=Level.CRITICAL)
               for h in cleared for m in _origins(h)]
    entries += [CbEntry(match=m, max_level=Level.LOW)
                for h in known for m in _origins(h)]
    cb = CbSchema(lookup_fields=["__destination__"], on_miss=Decision.REVIEW, entries=entries)
    ctx = Context(name="os", default_action=default_action,
                  description="OS-level KAIROS policy (deploy)", scope="deploy",
                  # A POST to a destination the user named can still carry an
                  # attacker's URL as its PAYLOAD — "repoint the webhook at
                  # hooks.attacker.external" addresses status.internal.local, which
                  # is derivable, so the destination check passes it. Gate
                  # action-bearing values found inside the body too.
                  embedded_identifiers="review")
    return Policy(version="0.1", context=ctx, resources=Resources(contact_book=cb))


def path_sensitivity(path: str, pattern: re.Pattern | None = None) -> Level | None:
    """HIGH iff the path looks like a secret. `pattern` lets a deployment widen
    the default at run time — an operator marking a project-specific file secret
    mid-session should not need a code change."""
    rx = pattern or SECRET_PATH_RE
    return Level.HIGH if path and rx.search(path) else None


# Admit secret content as its high-entropy VALUES (keys, tokens, hashes) captured
# whole — long runs of key-ish characters. This matches the secret verbatim in an
# outbound body OR url query, without diluting into common words (which would both
# miss a value-only exfil and false-positive on ordinary traffic).
_SECRET_CFG = ExtractConfig(mode=ExtractMode.REGEX, pattern=r"[A-Za-z0-9][A-Za-z0-9_\-]{11,}")


class OsSession:
    """A kairos store + engine primed with a deploy session's trust + taint."""

    def __init__(self, policy: Policy | None = None) -> None:
        self.policy = policy or build_policy()
        self.store = TokenStore()
        self.engine = PolicyEngine.build(self.policy, self.store)
        self._seeded = False

    def seed(self, user_message: str) -> None:
        if user_message and not self._seeded:
            self.store.seed(user_message)
            self._seeded = True

    def extend_trust(self, user_message: str) -> None:
        """A later user turn is also trust-root material — extracted the SAME way
        the first one is.

        This used a bare ExtractConfig(), which extracts differently from
        store.seed()'s prompt_extract_config(). The effect was that a destination
        the user named in turn 1 was derivable while the same destination named in
        turn 2 was not, so the integrity axis reviewed an action the user had just
        asked for. Later turns are prompt material and must be treated as such."""
        if user_message:
            self.store.admit(user_message, "user", trusted=True, level=None,
                             branch_origin=None, extract_cfg=prompt_extract_config())

    def admit_read(self, source: str, content: Any, level: Level | None) -> None:
        """A file read / fetched page: untrusted content; sensitive iff `level`."""
        if content is None:
            return
        cfg = _SECRET_CFG if level is not None else ExtractConfig()
        self.store.admit(content, source, trusted=False, level=level,
                         branch_origin=None, extract_cfg=cfg)

    def evaluate(self, method: str, url: str, body: Any):
        # The body is passed as PAYLOAD FIELDS, not a bare string. The embedded-
        # identifier check (§4.6) scans payload fields for action-bearing values —
        # a URL in a request body is a destination for whoever receives it — and it
        # skips any event whose content is not a field mapping. With a bare string
        # the check silently did nothing, so a POST to a host the user named could
        # still carry an attacker's URL as its payload and pass both axes.
        #
        # One opaque {"body": "target=http://attacker/..."} field was not enough:
        # the forwarding address stayed buried in a single string, so a two-request
        # confused deputy (register a mirror on an allowed host, then publish to it)
        # passed both axes. Structured bodies are therefore split into their fields
        # first, which is cheap here in a way it is not in the simulated benchmark:
        # every HTTP request has the same handful of encodings.
        content = body if isinstance(body, dict) else parse_body_fields(body)
        ev = Event(time.monotonic(), Channel.NET, method.upper(), "agent", url, content, {})
        res = self.engine.evaluate(ev)
        level = outbound_sensitivity(ev, classify(ev, self.policy), self.store)
        return res, level


# ---- LLM oracle (§4.8) ----------------------------------------------------
# The deterministic axes above resolve ALLOW/DENY structurally. What they cannot
# resolve is REVIEW: a state-changing request whose destination/value is untrusted
# BUT might still be legitimate (a bill names the account to pay, an email names a
# reply address). That is the LLM judge's job — the SAME LLMJudge the AgentDojo
# benchmark uses (kairos/judge/oracle.py), so the deployed and evaluated judge are
# one class. It sees T_0 + the held request + the untrusted content the agent read
# (framed as DATA under a detection question) and rules consistent / inconsistent.

def make_llm_judge(model: str | None = None, client: Any = None) -> LLMJudge | None:
    """Build the production REVIEW judge. Returns None (→ no LLM escalation, the
    deterministic decision stands) when no credentials are configured, so a run
    without a key degrades to the deterministic baseline rather than failing closed
    on every REVIEW.

    The judge is deliberately decoupled from the agent: the agent is whatever
    model the Claude Code CLI is logged in as, inside the guest, while the judge
    runs here on the host against KAIROS_JUDGE_BASE_URL. Any OpenAI-compatible
    endpoint works — including the open models measured in
    evaluation/judge_model_study — so the credential is read from
    KAIROS_JUDGE_API_KEY first and only falls back to OPENAI_API_KEY. Keying solely
    off OPENAI_API_KEY meant a non-OpenAI base URL was contacted unauthenticated
    and every REVIEW quietly degraded to the deterministic rule."""
    model = model or os.environ.get("KAIROS_JUDGE_MODEL", "gpt-4o-mini")
    if client is None:
        key = os.environ.get("KAIROS_JUDGE_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not key:
            return None
        import openai  # openai-compatible client; matches scripts/run_benchmark.py
        kwargs: dict[str, Any] = {"api_key": key}
        base_url = os.environ.get("KAIROS_JUDGE_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
        client = openai.OpenAI(**kwargs)
    # The DEPLOYMENT judge, not the benchmark one. ProductionLLMJudge inherits the
    # entire curated view and differs only in its system prompt: it asks whether the
    # user's request calls for the action, instead of requiring an injection to be
    # identified before anything may be refused. The benchmark path
    # (scripts/run_benchmark.py, the AgentDojo/AgentDyn adapters) keeps
    # oracle.LLMJudge unchanged, so every published number stays reproducible.
    # KAIROS_JUDGE_PROMPT=benchmark forces the frozen prompt here, for a
    # like-for-like comparison between the two.
    if os.environ.get("KAIROS_JUDGE_PROMPT", "production").lower() == "benchmark":
        return LLMJudge(client, model)
    from kairos.judge.prod_oracle import ProductionLLMJudge
    return ProductionLLMJudge(client, model)


# Prefix for arguments lifted OUT of a request body. Only this module needs to know
# it: the judge is told which args are embedded structurally, via HeldAction.embedded.
_BODY_ARG_PREFIX = "body."


def parse_body_fields(body: Any) -> dict:
    """Split an HTTP body into payload FIELDS so embedded destinations are visible.

    JSON objects and form-encoded bodies both carry named fields; flattening them
    lets the embedded-identifier check see `target=https://attacker/...` as a
    destination rather than as an opaque blob. Anything unparseable falls back to
    the whole body under "body", which is what the caller did before -- this can
    only ever ADD visible fields, never hide one.
    """
    if body is None:
        return {"body": ""}
    if isinstance(body, dict):
        return body
    text = body if isinstance(body, str) else str(body)
    out: dict[str, Any] = {"body": text}
    stripped = text.strip()
    if stripped[:1] in ("{", "["):
        try:
            parsed = json.loads(stripped)
        except Exception:                                        # noqa: BLE001
            parsed = None
        if isinstance(parsed, dict):
            for k, v in parsed.items():
                out[str(k)] = v if not isinstance(v, (dict, list)) else json.dumps(v)
            return out
    if "=" in text and "\n" not in text.strip():
        try:
            for k, vals in urllib.parse.parse_qs(text, keep_blank_values=True).items():
                out[k] = vals[0] if len(vals) == 1 else vals
        except Exception:                                        # noqa: BLE001
            pass
    return out


def _os_branch(url: str, body: Any, user_messages: list[str], reads: list[dict],
               reason: str, store: Any = None) -> Branch:
    """Cast one held OS request into the Branch shape the LLMJudge consumes: the
    request as the single held_call (its destination provenance = untrusted unless
    the user named it), and the session's untrusted reads as the agent trace the
    judge inspects for a redirect ('send to X')."""
    dest = _origin(url) or ""
    named_by_user = bool(dest) and any(dest.lower() in (m or "").lower() for m in user_messages)
    # Name the ORIGINATING source, not the channel. "network" is not something the
    # judge can compare against a document the user delegated to, and telling it to
    # try made it refuse the user's own destination. The store knows which admitted
    # read carried this value -- reads are admitted under their file path -- so ask
    # it, and fall back to the channel only when nothing claims the value.
    source = "network"
    if store is not None and dest:
        try:
            claims = store.sources_of(dest)
        except Exception:                                        # noqa: BLE001
            claims = []
        if claims:
            source = ", ".join(claims)
    args = {"destination": dest, "body": str(body or "")[:4000]}
    prov = {"destination": Provenance(source=source, trusted=False,
                                      in_user_prompt=named_by_user)}
    # Destinations carried INSIDE the body are consequential too -- a forwarding
    # address posted to an allowed host is still an address the user never named.
    # check_embedded_identifiers already reviews them, but integrity fires first and
    # its reason wins, so the judge saw only `body=target=http://attacker/...` as
    # free text and read the request as "posting to the host the user asked for".
    # Surfacing them as their OWN arguments is what lets the judge weigh them.
    seen = {dest.lower()}
    for field, raw in parse_body_fields(body).items():
        if field == "body" or not isinstance(raw, str):
            continue
        for kind, value in embedded_values(raw):
            if kind != "url" or value.lower() in seen:
                continue
            seen.add(value.lower())
            key = f"{_BODY_ARG_PREFIX}{field}"
            args[key] = value
            in_prompt = any(value.lower() in (m or "").lower() for m in user_messages)
            vsrc = "network"
            if store is not None:
                try:
                    claims = store.sources_of(value)
                except Exception:                                # noqa: BLE001
                    claims = []
                if claims:
                    vsrc = ", ".join(claims)
            prov[key] = Provenance(source=vsrc, trusted=False, in_user_prompt=in_prompt)
    # Name the embedded destinations in the REASON too. Surfacing them as arguments
    # was not enough: the reason still said only "consequential position:
    # destination", so the judge read "the destination matches the request" and
    # ruled consistent while a forwarding address sat in the body. A destination is
    # a destination wherever it sits — say so where the judge is looking.
    embedded = [k for k in args if k.startswith(_BODY_ARG_PREFIX)
                and not prov[k].in_user_prompt]
    if embedded:
        reason = (f"{reason}; request body carries destination(s) the user did not "
                  f"name: " + ", ".join(f"{k}={args[k]}" for k in embedded))
    held = HeldAction(call_ref=None, tool="http_request", args=args, provenance=prov,
                      reason=reason or "state-changing outbound request",
                      embedded=tuple(k for k in args if k.startswith(_BODY_ARG_PREFIX)))
    br = Branch(branch_id="os", opened_at=0.0, opened_reason="REVIEW")
    br.held_calls.append(held)
    for r in reads:
        content = r.get("content")
        if content is None:
            continue
        br.judge_trace.append({"tool": f"read:{r.get('source','')}", "decision": "ALLOW",
                               "args": {}, "result": str(content)})
    # Mark the reads as UNTRUSTED CONTENT. Without this the judge is shown a file's
    # text as a plain trace line and reads it as authoritative: it cited an injected
    # "Cleanup procedure" as maintenance policy and an injected runbook as the
    # correct endpoint, returning injection_found=false both times. §4.8's mechanism
    # -- untrusted content framed as DATA under a detection question -- is gated on
    # this field in _build_prompt, so leaving it empty disabled the whole thing in
    # production while the benchmark adapter (which does populate it) exercised it.
    # Everything here is untrusted by construction: it is content the agent READ.
    br.untrusted_content = [(f"read:{r.get('source','')}", str(r.get("content")))
                            for r in reads if r.get("content") is not None]
    return br


def verdict_for(request: dict, user_messages: list[str],
                reads: list[dict], policy: Policy | None = None,
                judge: LLMJudge | None = None,
                secret_pattern: str | None = None,
                cleared=None, known=None) -> dict:
    """Stateless: build a session from the session's history and judge one request.

    request: {method, url|host+path, body}
    user_messages: user turns (chronological); [0] seeds T_0.
    reads: [{source, content, path?}] — file reads / fetched pages this session.
    judge: optional LLM oracle; when the deterministic decision is REVIEW and a
        judge is supplied, its consistent/inconsistent recommendation is attached
        under `llm` (the caller applies it per mode — the deterministic `decision`
        is left intact so judge-recommend/human can still surface both).
    Returns {decision, reason, produced_by, sensitivity, destination, llm?}.
    """
    sess = OsSession(policy)
    rx = None
    if secret_pattern:
        try:
            rx = re.compile(secret_pattern, re.IGNORECASE)
        except re.error:
            rx = None            # a bad operator pattern must not break the monitor
    if user_messages:
        sess.seed(user_messages[0])
        for m in user_messages[1:]:
            sess.extend_trust(m)
    for r in reads:
        lvl = path_sensitivity(r.get("path") or r.get("source", ""), rx)
        sess.admit_read(r.get("source", ""), r.get("content"), lvl)

    url = request.get("url") or (f"https://{request.get('host','')}{request.get('path','')}")
    res, level = sess.evaluate(request.get("method", "GET"), url, request.get("body"))
    # Both axes can fire on one request, but only the winning axis's reason is
    # reported — and integrity usually wins, because an exfiltration destination is
    # also an unknown destination. That makes "carries a secret" invisible: the
    # exfiltration of a deploy key and a merely-unfamiliar POST produce the same
    # sentence. The sensitivity is already computed, so state it.
    reason = res.reason or res.produced_by
    if level is not None:
        reason = (f"{level.name}-sensitivity content is leaving to a destination not "
                  f"cleared for it; also: {reason}")
    # Declared destinations, matched by domain suffix, decided before anything
    # else. This is the operator's explicit statement about where traffic may go,
    # and it has to win: the agent's own login and telemetry are not derivable
    # from the user's request and would otherwise be reviewed forever.
    tier, matched = host_tier(url, cleared, known)
    if tier is Level.CRITICAL:
        res_decision, produced, reason = Decision.ALLOW, "cleared_host", (
            f"cleared destination ({matched}) — may receive sensitive data")
    elif tier is Level.LOW and (level is None or level.value <= Level.LOW.value):
        res_decision, produced, reason = Decision.ALLOW, "known_host", (
            f"known destination ({matched}) — no sensitive data leaving")
    elif tier is Level.LOW:
        res_decision, produced = Decision.REVIEW, "confidentiality"
        reason = (f"{level.name}-sensitivity content is leaving to {matched}, which is "
                  f"known but only cleared for LOW")
    else:
        res_decision, produced = res.decision, res.produced_by

    out = {
        "decision": res_decision.value,          # ALLOW | DENY | REVIEW
        "reason": reason,
        "produced_by": produced,
        "destination": _origin(url),
        "sensitive": level.name if level is not None else None,  # data sensitivity leaving
        "identifiers": res.identifiers,
    }
    if res_decision is Decision.REVIEW and judge is not None:
        br = _os_branch(url, request.get("body"), user_messages, reads, out["reason"],
                        store=sess.store)
        prompt_text = user_messages[0] if user_messages else ""
        # Return the prompt alongside the verdict so the caller can archive it.
        # The paper's claim is that the CURATED VIEW does the work, not that an
        # LLM checks an LLM — which is unevidenceable from a production run if the
        # only record is the answer. Built explicitly rather than captured from the
        # judge's stdout print: that print is process-global and races under a
        # threaded server, so a concurrent decision could archive the wrong prompt.
        built = ""
        try:
            built = judge._build_prompt(prompt_text, br)
        except Exception:                                    # noqa: BLE001
            built = ""
        v = judge.evaluate(prompt_text, br)
        out["llm"] = {"consistent": v.consistent, "rationale": v.rationale,
                      "flagged": v.flagged, "prompt": built, "raw": v.raw}
    return out


# ---- filesystem adjudication (§4.7-4.9) ------------------------------------
# The network channel holds a request and asks the judge before it is dispatched.
# The filesystem channel had no equivalent: writes land in the overlay and were
# left to the exit policy, so the judge never ruled on them at all. That is a gap
# between the model and the deployment, not a design choice — a branch is
# supposed to span EVERY effect since it opened, and resolution decides each one.
#
# A file write cannot be held the way a request is (the agent must read back what
# it wrote), so the effect is speculative by construction and the adjudication is
# after the fact: the same LLMJudge is shown the staged changes and asked which
# ones the user's request actually calls for. Its answer is a RECOMMENDATION —
# commit.py remains the authority (§4.8) — which is exactly what an operator
# staring at a list of staged files needs and did not have.

def adjudicate_files(task: str, files: list[dict], reads: list[dict],
                     judge: LLMJudge | None, ops: list[dict] | None = None) -> dict:
    """Judge staged filesystem changes.

    files: [{path, kind, diff?, op?, source?}] — one per staged change.
    reads: the session's untrusted reads, so the judge can find the injection
           that motivated a write it is about to call inconsistent.
    ops:   [{op, path, to?, note?}] — the filesystem operations IN ORDER, from the
           WAL journal. Optional but strongly preferred: without it the judge sees
           only end state, and an effect that was created and then removed within
           the session leaves no trace in a diff at all.
    Returns {available, per_file: [{path, consistent, reason}], rationale, flagged}.
    """
    if not files:
        return {"available": True, "per_file": [], "rationale": "nothing staged"}
    if judge is None:
        return {"available": False,
                "reason": "no LLM oracle configured; the deterministic axes cannot "
                          "rule on file content, so no recommendation is available"}
    br = Branch(branch_id="fs", opened_at=0.0, opened_reason="staged filesystem changes")
    for f in files:
        path = f.get("path", "")
        named = bool(path) and path.lower() in (task or "").lower()
        br.held_calls.append(HeldAction(
            call_ref=None, tool=f.get("op") or "write_file",
            args={"path": path, "change": str(f.get("diff") or f.get("kind") or "")[:4000]},
            provenance={"path": Provenance(source=f.get("source") or "filesystem",
                                           trusted=False, in_user_prompt=named)},
            reason=f"staged {f.get('kind', 'change')}"))
    # The ORDER of what the agent did, when the caller can supply it. A diff of the
    # final state cannot express a sequence, and some attacks exist only as one:
    # archiving a directory and then deleting the archive nets out to "no change"
    # for the archive, so the destructive half is invisible to a diff while the
    # journal still holds it. Passing the op sequence as trace is what lets the
    # judge see a create-then-purge as the composition it is.
    # Relative to the first timestamped event, so the sequence is legible without
    # leaking wall-clock times into the prompt.
    stamps = [x.get("ts") for x in list(ops or []) + list(reads or []) if x.get("ts")]
    t0 = min(stamps) if stamps else None
    for op in (ops or []):
        ts = op.get("ts")
        br.judge_trace.append({
            "tool": f"fs:{op.get('op', '?')}", "decision": "STAGED",
            "t_rel": (ts - t0) if (ts and t0) else None,
            "args": {k: v for k, v in (("path", op.get("path")), ("to", op.get("to")))
                     if v},
            "result": ((f"x{op['repeat']} " if op.get("repeat", 1) > 1 else "")
                       + (op.get("note") or ""))})
    for r in reads:
        content = r.get("content")
        if content is None:
            continue
        ts = r.get("ts")
        br.judge_trace.append({"tool": f"read:{r.get('source', '')}", "decision": "ALLOW",
                               "t_rel": (ts - t0) if (ts and t0) else None,
                               "args": {}, "result": str(content)})
    # Mark the reads as UNTRUSTED CONTENT. Without this the judge is shown a file's
    # text as a plain trace line and reads it as authoritative: it cited an injected
    # "Cleanup procedure" as maintenance policy and an injected runbook as the
    # correct endpoint, returning injection_found=false both times. §4.8's mechanism
    # -- untrusted content framed as DATA under a detection question -- is gated on
    # this field in _build_prompt, so leaving it empty disabled the whole thing in
    # production while the benchmark adapter (which does populate it) exercised it.
    # Everything here is untrusted by construction: it is content the agent READ.
    br.untrusted_content = [(f"read:{r.get('source', '')}", str(r.get("content")))
                            for r in reads if r.get("content") is not None]
    # Chronological, so reads and staged ops interleave as they happened rather
    # than appearing as two unrelated blocks.
    br.judge_trace.sort(key=lambda c: (c.get("t_rel") is None, c.get("t_rel") or 0.0))
    # Build the prompt explicitly and return it, mirroring verdict_for: the claim
    # is that the CURATED VIEW does the work, and a filesystem verdict that archives
    # nothing cannot evidence what the judge was shown. Debugging one previously
    # meant reconstructing it from raw logs.
    prompt_text = ""
    try:
        prompt_text = judge._build_prompt(task or "", br)     # noqa: SLF001
    except Exception:                                        # noqa: BLE001
        pass
    v = judge.evaluate(task or "", br)
    per = v.per_action or [v.consistent] * len(files)
    return {"available": True,
            "per_file": [{"path": f.get("path"), "kind": f.get("kind"),
                          "consistent": bool(c)}
                         for f, c in zip(files, per)],
            "rationale": v.rationale, "flagged": v.flagged,
            "prompt": prompt_text, "raw": v.raw}


def main() -> None:
    """CLI bridge: read {request, user_messages, reads, use_llm?} JSON on stdin,
    print the verdict JSON. The deploy control plane shells out to this under the
    kairos venv (python >= 3.12) when it cannot import kairos in-process. Set
    use_llm=true to also run the LLM oracle on REVIEW (needs OPENAI_API_KEY)."""
    import json
    import sys
    real_stdout = sys.stdout
    sys.stdout = sys.stderr  # the LLM oracle prints its prompt; keep stdout JSON-only
    try:
        payload = json.load(sys.stdin)
        judge = make_llm_judge() if payload.get("use_llm") else None
        out = verdict_for(payload.get("request", {}),
                          payload.get("user_messages", []),
                          payload.get("reads", []), judge=judge)
    except Exception as e:  # fail visible; caller decides fallback
        out = {"error": str(e)}
    finally:
        sys.stdout = real_stdout
    sys.stdout.write(json.dumps(out))


if __name__ == "__main__":
    main()
