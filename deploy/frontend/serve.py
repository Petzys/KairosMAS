#!/usr/bin/env python3
"""
Kairos frontend + control plane  (M4 dashboard, M5 enforcement, audit review)
============================================================================
A dependency-free stdlib HTTP server that is (1) the dashboard's data source,
(2) the reference monitor's control plane, and (3) an audit-log viewer.

Sessions: each run writes an audit directory under KAIROS_SESSIONS_ROOT
(/var/lib/kairos/sessions/<ts>/) with net_events.jsonl, fs_events.jsonl, bodies/
(full request/response bodies, content-addressed), decisions.jsonl, session.json
and, at exit, fs_report.json snapshot. The server serves the `latest` session by
default, or any past session via ?session=<id>.

Dashboard (observe):
  GET /                     short notice (this release has no web UI)
  GET /api/net[?session=]   network exchanges (grouped; headers + body previews)
  GET /api/fs[?session=]    changed files (unified diffs) + per-turn timeline
  GET /api/net/body?sha=[&session=]   FULL request/response body (untruncated)
  GET /api/sessions         list audit sessions

Control plane (enforce, M5):
  GET  /api/mode                       current decision mode
  POST /api/mode {mode}                observe | human | judge-auto | judge-recommend
  POST /api/net/hold {req}             addon registers a state-changing request
  GET  /api/net/decision?id=           addon polls until commit/abort
  GET  /api/net/pending                held requests awaiting a human
  POST /api/net/resolve {id,action}    human commits/aborts a held request
  POST /api/fs/resolve {paths[],action}commit(merge)/abort(discard) files
  POST /api/fs/finalize {action?}      resolve ALL staged changes now, session continues
                                       (no action = apply the judge's per-file verdict)

The judge behind judge-auto / judge-recommend is the real kairos/ trust chain
(M5b): the deterministic confidentiality/integrity axes resolve ALLOW/DENY, and an
LLM oracle (M5c, the SAME LLMJudge the AgentDojo benchmark uses) resolves REVIEW.
If kairos isn't importable (deploy/ shipped standalone) a heuristic stands in.
"""

import os
import re
import sys
import json
import time
import threading
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "fs"))
try:
    import report as fsreport
except Exception:
    fsreport = None
try:
    import resolve as fsresolve
except Exception:
    fsresolve = None

# The Nuxt dashboard (deploy/frontend/new), pre-built to static files. Served
# from the same origin as /api/* so there is no CORS or dev proxy in play. When
# the directory is absent — a deploy that never ran `npm run generate` — the MVP
# index.html is served instead, so the stack is never without a UI. Set
# KAIROS_NEW_UI=/nonexistent to force the MVP page back.
NEW_UI = os.environ.get("KAIROS_NEW_UI", os.path.join(HERE, "new", ".output", "public"))
CTYPES = {"html": "text/html; charset=utf-8", "js": "text/javascript",
          "mjs": "text/javascript", "css": "text/css", "json": "application/json",
          "svg": "image/svg+xml", "ico": "image/x-icon", "png": "image/png",
          "jpg": "image/jpeg", "webp": "image/webp", "woff2": "font/woff2",
          "woff": "font/woff", "ttf": "font/ttf", "map": "application/json",
          "txt": "text/plain; charset=utf-8"}

SESSIONS_ROOT = os.environ.get("KAIROS_SESSIONS_ROOT", "/var/lib/kairos/sessions")
FS_ROOT = os.environ.get("KAIROS_FS_ROOT", "/var/lib/kairos/fs")
DECISIONS = os.environ.get("KAIROS_DECISIONS", "")   # current session's decisions.jsonl
PORT = int(os.environ.get("KAIROS_UI_PORT", "8090"))
MODES = ("observe", "human", "judge-auto", "judge-recommend")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}

# fallbacks for running standalone against loose files (no session dir)
FALLBACK_NET = os.environ.get("KAIROS_NET_EVENTS", "/tmp/kairos_net_events.jsonl")
FALLBACK_FS = os.environ.get("KAIROS_FS_EVENTS", "/tmp/kairos_fs_events.jsonl")


# ---- the judge --------------------------------------------------------------
# The real judge is the kairos/ trust chain (M5b/M5c). Preferred path: import it
# IN-PROCESS (this server runs under the kairos venv's python>=3.12 when launched
# by run.sh), which also lets us build the LLM oracle ONCE and reuse it. Fallbacks,
# in order: (1) a subprocess under KAIROS_KAIROS_PY, (2) a simple heuristic — so the
# monitoring stack still runs when deploy/ is shipped standalone without kairos.
import subprocess

KAIROS_PY = os.environ.get("KAIROS_KAIROS_PY", "")     # python that can import kairos
KAIROS_CWD = os.environ.get("KAIROS_KAIROS_CWD", "")   # dir to run it from (repo root)
USE_LLM_JUDGE = os.environ.get("KAIROS_LLM_JUDGE", "1") not in ("0", "", "false", "no")

# Try to import kairos in-process (only succeeds under python>=3.12 with kairos on
# the path). KAIROS_CWD is the repo root; add it so `import kairos` resolves.
_bf_verdict_for = None
_bf_llm_judge = None
if KAIROS_CWD and KAIROS_CWD not in sys.path:
    sys.path.insert(0, KAIROS_CWD)
try:
    from kairos.adapters.production.os_judge import verdict_for as _bf_verdict_for
    from kairos.adapters.production.os_judge import make_llm_judge as _bf_make_llm_judge
    if USE_LLM_JUDGE:
        _bf_llm_judge = _bf_make_llm_judge()   # None if no OPENAI_API_KEY → deterministic only
    print(f"[serve] judge: kairos in-process (llm={'on' if _bf_llm_judge else 'off'})",
          file=sys.stderr)
except Exception as _e:
    if KAIROS_PY:
        print(f"[serve] judge: kairos subprocess ({_e})", file=sys.stderr)
    else:
        print(f"[serve] judge: heuristic ({_e})", file=sys.stderr)
DEFAULT_SECRET_RE = (r"(secret|credential|password|\.env|\.pem|id_rsa|id_ed25519"
                     r"|token|apikey|api[_-]?key|\.aws|\.ssh)")
SECRET_PATH_RE = re.compile(DEFAULT_SECRET_RE, re.IGNORECASE)

# Cap on reads handed to the judge. The trace is evidence, not an archive: an
# unbounded one crowds out the injection it exists to reveal and costs tokens.
JUDGE_TRACE_MAX_READS = int(os.environ.get("KAIROS_JUDGE_TRACE_READS", "40"))
# Entries per path. A file rewritten repeatedly (an archive being built) is one
# fact, not twenty, and the duplicates push real evidence past the cap.
JUDGE_TRACE_MAX_PER_PATH = int(os.environ.get("KAIROS_JUDGE_TRACE_PER_PATH", "2"))


def _looks_binary(preview) -> bool:
    """Heuristic: a preview that is a long unbroken hex run is binary content.

    fs_monitor already sets `binary` for most cases; this catches previews that
    arrive as hex text (zip/gzip headers) and would otherwise fill the trace with
    bytes no judge can reason about."""
    if not isinstance(preview, str) or len(preview) < 32:
        return False
    head = preview[:64]
    return all(c in "0123456789abcdefABCDEF" for c in head)


class LivePolicy:
    """The deployment policy, editable while the session runs.

    A real deployment's policy is per-project: which files are secret and which
    destinations are cleared cannot be known when the code is written. Editing it
    live is also what makes the interactive walkthrough honest — an operator who
    notices the agent reading something sensitive can classify it on the spot,
    and the very next decision uses the new classification. `extra_secret_paths`
    are OR-ed onto the built-in pattern rather than replacing it, so widening the
    policy can never accidentally narrow it."""

    def __init__(self):
        import kairos.adapters.production.os_judge as _oj  # may be absent standalone
        self.cleared = list(getattr(_oj, "CLEARED_HOSTS", CLEARED_HOSTS))
        self.known = list(getattr(_oj, "KNOWN_HOSTS", ()))
        self.extra_secret_paths = []
        # Values the operator vouches for. These EXTEND THE TRUST ROOT, which is a
        # different lever from `cleared`: clearing a host raises how much
        # sensitivity may leave TO it (confidentiality), while trusting a value
        # makes it derivable (integrity). An operator who wants a destination
        # allowed needs the latter — the integrity axis fires first and a cleared
        # but non-derivable destination is still REVIEW.
        self.trusted_values = []

    def secret_pattern(self):
        pats = [DEFAULT_SECRET_RE] + [re.escape(p) for p in self.extra_secret_paths]
        return "(" + "|".join(pats) + ")"

    def matches_secret(self, path):
        try:
            return bool(re.search(self.secret_pattern(), path or "", re.IGNORECASE))
        except re.error:
            return bool(SECRET_PATH_RE.search(path or ""))

    def as_dict(self):
        return {"cleared_hosts": self.cleared, "known_hosts": self.known,
                "extra_secret_paths": self.extra_secret_paths,
                "trusted_values": self.trusted_values,
                "default_secret_pattern": DEFAULT_SECRET_RE}

    def update(self, d):
        if isinstance(d.get("cleared_hosts"), list):
            self.cleared = [str(h).strip() for h in d["cleared_hosts"] if str(h).strip()]
        if isinstance(d.get("known_hosts"), list):
            self.known = [str(h).strip() for h in d["known_hosts"] if str(h).strip()]
        if isinstance(d.get("extra_secret_paths"), list):
            self.extra_secret_paths = [str(x).strip() for x in d["extra_secret_paths"] if str(x).strip()]
        if isinstance(d.get("trusted_values"), list):
            self.trusted_values = [str(x).strip() for x in d["trusted_values"] if str(x).strip()]
        log_decision({"by": "operator", "channel": "policy", "policy": self.as_dict()})
        return self.as_dict()


CLEARED_HOSTS = ("anthropic.com", "claude.ai", "claude.com", "statsig",
                 "registry.npmjs.org", "npmjs.org", "datadoghq.com",
                 "githubusercontent.com", "github.com", "sentry.io")
SECRET_HINTS = ("secret", "api_key", "apikey", "api-key", "token", "password",
                "passwd", "sk-ant", "sk-", "private", "credential", "ssh-rsa",
                "-----begin", "aws_", "authorization")

# Instantiated here, not next to the class: LivePolicy falls back to the module
# constants above, which are defined further down the file than the class is.
try:
    POLICY = LivePolicy()
except Exception as _pe:                # kairos not importable -> heuristic path
    print(f"[serve] live policy unavailable ({_pe}); using built-in constants",
          file=sys.stderr)
    POLICY = None


def _heuristic_verdict(req):
    host = (req.get("host") or "").lower()
    body = (req.get("body_preview") or "").lower()
    cleared = any(c in host for c in CLEARED_HOSTS)
    if cleared:
        return {"verdict": "allow", "reason": f"cleared destination ({host})", "source": "heuristic"}
    if any(h in body for h in SECRET_HINTS):
        return {"verdict": "abort", "sensitive": True,
                "reason": f"state-changing request to {host} carrying secret-like data", "source": "heuristic"}
    return {"verdict": "hold", "reason": f"state-changing request to non-cleared host {host}", "source": "heuristic"}


def _kairos_context():
    """Assemble T_0 (the user's turns) + sensitive reads from the live session.

    T_0 normally comes from the agent's own /v1/messages traffic. When the
    scenario is driven BY HAND there is no such traffic, so the trust root would
    be empty and *nothing* would be derivable — every destination unknown, every
    action REVIEW, including the one the operator explicitly asked for. The
    operator-declared task (KAIROS_TASK / POST /api/task) is prepended so the
    manual path has the same trust root the agent path derives automatically."""
    p = session_paths(None)
    # user turns: from the latest /v1/messages request body (has the full history)
    user_messages = []
    root = CTL.task
    if POLICY is not None and POLICY.trusted_values:
        # Folded into the SEED string, not appended as later turns. os_judge seeds
        # T_0 from user_messages[0] via store.seed() and passes the rest through
        # extend_trust(), and only the former makes a value *derivable* — a value
        # added as a later turn stays non-derivable and the integrity axis still
        # reviews it. Verified: same value seeded -> ALLOW, extended -> REVIEW.
        root = (root + "\n" if root else "") + "\n".join(
            f"Operator vouches for: {v}" for v in POLICY.trusted_values)
    if root:
        user_messages.append(root)
    try:
        reqs = [e for e in _load_jsonl(p["net"])
                if e.get("kind") == "request" and "/v1/messages" in (e.get("path") or "")
                and "count_tokens" not in (e.get("path") or "")]
        if reqs:
            last = reqs[-1]
            body = None
            sha = last.get("body_sha")
            if sha:
                bp = os.path.join(p["bodies"] or "", sha)
                if os.path.isfile(bp):
                    body = open(bp, encoding="utf-8", errors="replace").read()
            body = body or last.get("body_preview") or ""
            rq = json.loads(body)
            for m in rq.get("messages", []):
                if m.get("role") == "user":
                    c = m.get("content")
                    user_messages.append(c if isinstance(c, str)
                                         else " ".join(b.get("text", "") for b in c if isinstance(b, dict)))
    except Exception:
        pass
    # Content the agent READ, for the judge's trace. This deliberately includes
    # non-secret files. Restricting it to secret-looking paths conflated two
    # different jobs: the confidentiality axis needs SENSITIVE values (still keyed
    # on the path, via path_sensitivity in verdict_for), while the judge needs the
    # UNTRUSTED CONTENT that motivated the action. With only secret paths collected,
    # the injection itself was never shown — a poisoned NOTICE.md was invisible —
    # and the judge, told to prefer consistent when it can point to no injected
    # instruction, allowed the action it was never given grounds to refuse.
    # Non-secret reads are admitted with level=None, so this widens the judge's
    # evidence without making anything sensitive that was not already.
    reads = []
    try:
        seen, per_path = set(), {}
        since = getattr(CTL, "task_ts", 0.0) or 0.0
        for e in _load_jsonl(p["fs"]):
            path = e.get("path")
            if e.get("op") not in ("read", "open", "write", "create") or not path:
                continue
            if since and (e.get("ts") or 0.0) < since:
                continue          # belongs to an earlier task, not this one's context
            preview = e.get("preview")
            # Binary content is not evidence a judge can read, and archive writes
            # emit a lot of it: eight `write` ops of zip fragments crowded out the
            # one document that carried the injection. Skip it and keep the count.
            if e.get("binary") or _looks_binary(preview):
                continue
            # One entry per path: repeated writes to the same file are the same
            # fact restated, and the tail of the trace is what survives the cap.
            if path in per_path and per_path[path] >= JUDGE_TRACE_MAX_PER_PATH:
                continue
            key = (path, (preview or "")[:200])
            if key in seen:            # the same cat produces many identical ops
                continue
            seen.add(key)
            per_path[path] = per_path.get(path, 0) + 1
            reads.append({"source": path, "content": preview, "path": path,
                          "ts": e.get("ts")})
        if len(reads) > JUDGE_TRACE_MAX_READS:      # newest wins: closest to the action
            reads = reads[-JUDGE_TRACE_MAX_READS:]
    except Exception:
        pass
    return user_messages, reads


def _shape(out):
    """Map an os_judge verdict dict onto serve's verdict shape (allow/abort/hold),
    carrying the raw decision + the LLM oracle's recommendation for per-mode use."""
    if out is None or "error" in (out or {}):
        return None
    dec = out.get("decision")
    verdict = {"ALLOW": "allow", "DENY": "abort", "REVIEW": "hold"}.get(dec, "hold")
    return {"verdict": verdict, "reason": out.get("reason", ""),
            "sensitive": bool(out.get("sensitive")), "destination": out.get("destination"),
            "produced_by": out.get("produced_by"), "decision": dec,
            "llm": out.get("llm"), "source": "kairos"}


def _kairos_verdict(req):
    """Run the kairos trust chain. Prefers the in-process import (with the shared
    LLM oracle); falls back to a subprocess under KAIROS_KAIROS_PY. Returns a shaped
    verdict dict, or None if kairos is unavailable (caller falls back to heuristic)."""
    user_messages, reads = _kairos_context()
    request = {"method": req.get("method"), "host": req.get("host"),
               "path": req.get("path"), "url": req.get("url"),
               "body": req.get("body_preview")}
    # in-process (preferred): reuses the persistent LLM judge, no per-request python
    if _bf_verdict_for is not None:
        try:
            pol = secret = None
            if POLICY is not None:
                import kairos.adapters.production.os_judge as _oj
                pol = _oj.build_policy(cleared=tuple(POLICY.cleared),
                                       known=tuple(POLICY.known))
                secret = POLICY.secret_pattern()
            shaped = _shape(_bf_verdict_for(
                request, user_messages, reads, policy=pol, judge=_bf_llm_judge,
                secret_pattern=secret,
                # live host lists, so adding a domain in the Monitor tab takes
                # effect on the very next decision
                cleared=(POLICY.cleared if POLICY else None),
                known=(POLICY.known if POLICY else None)))
            # move the prompt out of the verdict and into its own archive
            llm = (shaped or {}).get("llm") or {}
            if llm.get("prompt"):
                log_judge_prompt({"host": request.get("host"), "path": request.get("path"),
                                  "method": request.get("method"),
                                  "prompt": llm.pop("prompt"), "raw": llm.pop("raw", ""),
                                  "consistent": llm.get("consistent"),
                                  "rationale": llm.get("rationale")})
            return shaped
        except Exception:
            pass
    # subprocess fallback
    if KAIROS_PY:
        payload = {"request": request, "user_messages": user_messages, "reads": reads,
                   "use_llm": USE_LLM_JUDGE}
        try:
            proc = subprocess.run([KAIROS_PY, "-m", "kairos.adapters.production.os_judge"],
                                  input=json.dumps(payload), capture_output=True, text=True,
                                  cwd=KAIROS_CWD or None, timeout=30)
            return _shape(json.loads(proc.stdout))
        except Exception:
            return None
    return None


def judge(req):
    """Unified verdict: real kairos trust chain when available, else heuristic."""
    return _kairos_verdict(req) or _heuristic_verdict(req)


def _auto_action(v):
    """judge-auto (no human present): turn a verdict into allow/abort.
      ALLOW → allow, DENY → abort. REVIEW is the interesting case: if the LLM oracle
      ruled, follow it (consistent→allow, inconsistent→abort); otherwise (no key /
      heuristic) fall back to the deterministic rule — block only if sensitive data
      was leaving, so benign held traffic isn't needlessly killed unattended."""
    if v["verdict"] == "allow":
        return "allow"
    if v["verdict"] == "abort":
        return "abort"
    # v["verdict"] == "hold"  (deterministic REVIEW, or heuristic uncertainty)
    llm = v.get("llm")
    if llm is not None:
        return "allow" if llm.get("consistent") else "abort"
    return "abort" if v.get("sensitive") else "allow"


def current_lower():
    """The overlay lower dir for the live session (published by run.sh), so the
    dashboard diffs against the right base even though this server persists across
    runs with different projects."""
    try:
        with open("/run/kairos/fs_lower") as f:
            p = f.read().strip()
            if p:
                return p
    except OSError:
        pass
    return os.environ.get("KAIROS_FS_LOWER") or os.path.join(FS_ROOT, "base")


def log_judge_prompt(record):
    """Archive the judge's curated view into the session directory.

    Kept OUT of decisions.jsonl on purpose: prompts are kilobytes each, that file
    feeds the dashboard's polling API, and the audit record is more useful when
    the decision log stays scannable and the prompts sit beside it."""
    d = session_paths(None).get("dir")
    if not d:
        return
    try:
        record["ts"] = record.get("ts", time.time())
        with open(os.path.join(d, "judge_prompts.jsonl"), "a") as f:
            f.write(json.dumps(record, ensure_ascii=False) + "\n")
    except OSError:
        pass


def log_decision(record):
    if not DECISIONS:
        return
    try:
        record["ts"] = record.get("ts", time.time())
        with open(DECISIONS, "a") as f:
            f.write(json.dumps(record) + "\n")
    except OSError:
        pass


class Control:
    def __init__(self, mode):
        self.mode = mode if mode in MODES else "observe"
        self.holds = {}
        self._seq = 0
        self.turn = 0
        self.task = os.environ.get("KAIROS_TASK", "").strip()
        # When the task was declared. Declaring a task declares a new TRUST ROOT,
        # so it also starts a new evidence window: reads from before it belong to a
        # different request and must not be shown as this one's context. Without
        # this, walking several scenarios through one guest let an earlier
        # scenario's document justify a later scenario's action — a file that
        # legitimises mirroring, read under a previous task, made a later
        # unrelated mirror look delegated.
        self.task_ts = 0.0
        self.lock = threading.Lock()

    def set_task(self, task):
        """Declare the trust root. Everything derivable from this string passes
        integrity; everything else is untrusted-origin and gets reviewed."""
        with self.lock:
            self.task = (task or "").strip()
            self.task_ts = time.time()
        log_decision({"by": "operator", "channel": "task", "task": self.task})
        return self.task

    def note_turn(self, req):
        """Advance the branch id when the agent starts a new turn.

        A POST to the provider's /v1/messages IS a new turn, and the proxy
        already routes every state-changing request through register_hold — so
        the turn boundary is observable here with no extra plumbing. The id goes
        to a file the FUSE layer reads (the same handoff run.sh uses for
        fs_lower), which is what attributes each filesystem write to the turn
        that produced it. Without that, the journal records what changed but not
        which action changed it, and per-branch resolution is impossible."""
        path = req.get("path") or ""
        host = (req.get("host") or "").lower()
        if "/v1/messages" not in path or "count_tokens" in path:
            return
        if not any(h in host for h in ("anthropic", "claude")):
            return
        with self.lock:
            self.turn += 1
            turn = self.turn
        try:
            import wal as wal_mod
            wal_mod.set_branch(f"t{turn}")
        except Exception:                                    # noqa: BLE001
            pass

    def set_mode(self, mode):
        if mode in MODES:
            with self.lock:
                self.mode = mode
        return self.mode

    def _set_fs_branch(self, value):
        """Point the FUSE layer's attribution at `value` (a hold id, or the turn).

        The WAL already records WHICH branch each file op belongs to; until now the
        branch was only ever the turn counter, so a filesystem change could never be
        tied to the network hold it happened under -- and aborting that hold left the
        file change in place. Binding attribution to the open hold is what makes a
        branch's file effects resolvable WITH it."""
        try:
            import wal as wal_mod
            wal_mod.set_branch(value)
        except Exception:                                    # noqa: BLE001
            pass

    def _resolve_fs_for_branch(self, branch, action):
        """Apply a branch's verdict to the file changes made under it.

        This is the missing half of speculation on the filesystem channel: a held
        network request that is aborted must also discard the file effects staged
        while it was open, or the agent keeps a world the monitor refused."""
        if fsresolve is None or not branch:
            return None
        root = FS_ROOT
        try:
            if not os.path.ismount(os.path.join(root, "merged")):
                return None                     # not live; the exit path resolves it
            results, conflicts = fsresolve.resolve_records(
                root, "commit" if action == "commit" else "abort",
                branch=branch, target=os.path.join(root, "merged"))
            if results or conflicts:
                log_decision({"by": "monitor", "channel": "fs-branch", "branch": branch,
                              "action": action, "results": results, "conflicts": conflicts})
            return {"results": results, "conflicts": conflicts}
        except Exception as e:                               # noqa: BLE001
            log_decision({"by": "monitor", "channel": "fs-branch", "branch": branch,
                          "action": action, "error": str(e)})
            return None

    def register_hold(self, req):
        mode = self.mode
        self.note_turn(req)          # every mode: attribution is not enforcement
        # observe: never hold; a cheap heuristic verdict is enough for the log
        if mode == "observe":
            return {"action": "allow", "verdict": _heuristic_verdict(req)}
        # enforced modes: consult the real trust chain (may shell out / call the LLM
        # oracle; do NOT hold the lock while it runs)
        v = judge(req)
        with self.lock:
            if mode == "judge-auto":
                action = _auto_action(v)
                log_decision({"by": "judge-auto", "req": req, "verdict": v, "action": action})
                # A REVIEW that was aborted also discards whatever the agent staged
                # under the current branch. ALLOW needs no action: the changes are
                # already staged and the overlay merges them at exit.
                if action == "abort":
                    self._resolve_fs_for_branch(f"t{self.turn}", "abort")
                return {"action": action, "verdict": v}
            # human / judge-recommend: the trust chain auto-passes ALLOW; anything it
            # flags (DENY/REVIEW) is held for the human, with the judge's verdict — and
            # the LLM oracle's recommendation, when present — shown alongside.
            if v["verdict"] == "allow":
                log_decision({"by": mode, "req": req, "verdict": v, "action": "allow-auto"})
                return {"action": "allow", "verdict": v}
            self._seq += 1
            hid = f"h{self._seq}"
            self.holds[hid] = {"id": hid, "status": "pending", "req": req,
                               "verdict": v, "mode": mode, "ts": time.time()}
            # From here until the operator rules, file changes belong to THIS hold.
            self._set_fs_branch(hid)
            return {"id": hid, "status": "pending", "verdict": v}

    def decision(self, hid):
        with self.lock:
            h = self.holds.get(hid)
            return {"status": h["status"]} if h else {"status": "commit"}

    def pending(self):
        with self.lock:
            return [h for h in self.holds.values() if h["status"] == "pending"]

    def resolve(self, hid, action):
        action = "commit" if action in ("commit", "allow") else "abort"
        with self.lock:
            h = self.holds.get(hid)
            if not h:
                return False
            h["status"] = action
        log_decision({"by": "human", "req": h["req"], "verdict": h["verdict"], "action": action})
        # The hold's file effects share its verdict, then attribution returns to
        # the turn -- ops outside any hold stay unattributed to a hold branch.
        self._resolve_fs_for_branch(hid, action)
        self._set_fs_branch(f"t{self.turn}")
        return True


def adjudicate_staged(session=None):
    """Ask the judge which staged file changes the user's request actually calls
    for. Advisory only — the operator (or the exit policy) still decides."""
    if _bf_verdict_for is None:
        return {"available": False, "reason": "kairos not importable"}
    try:
        import kairos.adapters.production.os_judge as _oj
    except Exception as e:                                   # noqa: BLE001
        return {"available": False, "reason": str(e)}
    changes = []
    if fsreport is not None:
        try:
            # `op` so the judge sees what actually happened. Without it every
            # change was announced as `write_file`, so a directory removal read as
            # a write.
            _OP_FOR_KIND = {"deleted": "delete", "added": "create", "modified": "write"}
            for c in fsreport.collect_changes(FS_ROOT, base=current_lower()):
                d = ""
                if c["kind"] in ("added", "modified"):
                    d = fsreport.unified(c.get("before"), c.get("after"), c["path"])
                changes.append({"path": c["path"], "kind": c["kind"], "diff": d,
                                "op": _OP_FOR_KIND.get(c["kind"], "write_file")})
        except Exception:
            changes = []

    # The overlay diff is END STATE. A path created and then removed inside the
    # session nets out to nothing there — deleting an upper-only file needs no
    # whiteout, so it simply vanishes — which is how "archive the project, then
    # delete the archive" was adjudicated as a plain, requested cleanup. The WAL
    # journal keeps every op in order, so take the sequence from it and add back
    # any path the diff cannot represent.
    ops, seen_paths = [], {c["path"] for c in changes}
    try:
        import wal as wal_mod
        w = wal_mod.Wal(os.path.join(FS_ROOT, "wal"),
                        target_root=os.path.join(FS_ROOT, "merged"))
        for r in w.select(status=None):
            if r.get("kind") != "op":
                continue
            entry = {"op": r.get("op"), "path": r.get("path"), "to": r.get("to"),
                     "ts": r.get("ts"),
                     "note": f"branch={r.get('branch') or '-'} status={r.get('status')}"}
            # Collapse a consecutive run of the same op on the same path into one
            # entry with a count. Writing a file in chunks is one action reported
            # many times; eight identical lines crowd out the evidence and say
            # nothing the count does not. General, not tuned to any one tool.
            if (ops and ops[-1]["op"] == entry["op"]
                    and ops[-1]["path"] == entry["path"] and not entry["to"]):
                ops[-1]["repeat"] = ops[-1].get("repeat", 1) + 1
                continue
            ops.append(entry)
        # transient effects: journalled, but absent from the diff
        # A path both CREATED and REMOVED inside this session, and never renamed to
        # something that survives, is an implementation detail rather than a change
        # to adjudicate -- `zip` writes to a temp name before renaming it into
        # place. Listing them made a 1-attack/4-innocuous deletion set look routine.
        # A rename TARGET is created here just as surely as an O_CREAT is: `zip`
        # builds the archive under a temp name and renames it into place, so the
        # file that finally exists was never the subject of a `create`. Counting
        # only create/mkdir would label such a file "pre-existing" and mis-describe
        # it to the judge.
        created = {r.get("path") for r in ops if r.get("op") in ("create", "mkdir")}
        created |= {r.get("to") for r in ops if r.get("op") == "rename" and r.get("to")}
        renamed_from = {r.get("path") for r in ops if r.get("op") == "rename"}
        transient = created & renamed_from
        for r in ops:
            pth = r.get("path") or ""
            if not pth or pth in seen_paths or pth in transient:
                continue
            if r["op"] in ("unlink", "rmdir", "rename"):
                # Say only what the journal supports. A path missing from the
                # overlay diff is NOT necessarily transient: deleting a directory
                # produces one whiteout for the directory, so its pre-existing
                # children disappear from the diff while never having been created
                # here. Labelling those "created and removed within this session"
                # told the judge something FALSE about the user's own files -- and
                # gave the one genuine attack the most innocuous description in the
                # prompt, which reads exactly like a temp file. The timestamps in the
                # trace carry the argument; this only has to be accurate.
                was_created_here = pth in created
                changes.append({
                    "path": pth,
                    "kind": "removed-in-session" if was_created_here else "deleted",
                    "op": r["op"],
                    "diff": ("removed; created earlier in this session"
                             if was_created_here else
                             "removed; pre-existing file, absent from the overlay diff "
                             "because a parent directory was removed")})
                seen_paths.add(pth)
    except Exception as e:                                   # noqa: BLE001
        log_decision({"by": "monitor", "channel": "fs-adjudication",
                      "warning": f"WAL sequence unavailable: {e}"})

    _um, reads = _kairos_context()
    try:
        out = _oj.adjudicate_files(CTL.task, changes, reads, _bf_llm_judge, ops=ops)
    except Exception as e:                                   # noqa: BLE001
        return {"available": False, "reason": f"judge failed: {e}"}
    # Archive the curated view, same as the network path (log_judge_prompt), then
    # strip it from the response: the dashboard shows verdicts, the audit file
    # holds the evidence.
    if out.get("prompt"):
        log_judge_prompt({"channel": "fs-adjudication", "task": CTL.task,
                          "prompt": out.get("prompt"), "raw": out.get("raw"),
                          "per_file": out.get("per_file"),
                          "rationale": out.get("rationale"), "ts": time.time()})
    out = {k: v for k, v in out.items() if k not in ("prompt", "raw")}
    log_decision({"by": "judge", "channel": "fs-adjudication", "action": "recommend",
                  "recommendation": out})
    return out


def monitor_payload(session=None, limit=200):
    """The reference monitor's own state — what the other tabs cannot show.

    Network shows traffic and Filesystem shows changes, but neither shows the
    monitor DECIDING: which axis produced a verdict, what the judge was asked,
    what it answered, and what is still staged. That is the thing this system is,
    so it gets its own view."""
    p = session_paths(session)
    dec = _load_jsonl(p.get("decisions") or "")
    events = []
    for d in dec[-limit:]:
        v = d.get("verdict") or {}
        req = d.get("req") or {}
        llm = v.get("llm") or None
        events.append({
            "ts": d.get("ts"), "by": d.get("by"), "action": d.get("action"),
            "channel": d.get("channel") or ("net" if req else "?"),
            "method": req.get("method"), "host": req.get("host"), "path": req.get("path"),
            "body_preview": (req.get("body_preview") or "")[:400],
            "decision": v.get("decision"), "verdict": v.get("verdict"),
            "produced_by": v.get("produced_by"), "reason": v.get("reason"),
            "sensitive": v.get("sensitive"), "source": v.get("source"),
            "llm_consistent": (llm or {}).get("consistent"),
            "llm_rationale": (llm or {}).get("rationale"),
            "llm_flagged": (llm or {}).get("flagged"),
            "paths": d.get("paths"), "branch": d.get("branch"), "via": d.get("via"),
            "task": d.get("task"),
            # the fs adjudication result — logged all along, but dropped here, so
            # the row rendered as an empty "recommend / judge / trust chain / —"
            "recommendation": d.get("recommendation"),
            "policy": d.get("policy"),
        })

    # filesystem disposition: what is staged and how it can be resolved
    mounted = os.path.ismount(os.path.join(FS_ROOT, "merged"))
    staged, wal_pending = [], []
    if fsresolve is not None:
        try:
            staged = fsresolve.list_changes(FS_ROOT)
        except Exception:
            staged = []
        try:
            wal_pending = fsresolve.wal_changes(FS_ROOT, os.path.join(FS_ROOT, "merged"))
        except Exception:
            wal_pending = []

    counts = {}
    for e in events:
        counts[e["action"] or "?"] = counts.get(e["action"] or "?", 0) + 1
    return {
        "mode": CTL.mode,
        "task": CTL.task,
        "turn": CTL.turn,
        "judge": {
            "model": os.environ.get("KAIROS_JUDGE_MODEL", ""),
            "base_url": os.environ.get("KAIROS_JUDGE_BASE_URL", ""),
            "llm_active": bool(_bf_llm_judge),
            "chain": "kairos" if _bf_verdict_for is not None else
                     ("kairos-subprocess" if KAIROS_PY else "heuristic"),
        },
        "policy": POLICY.as_dict() if POLICY else None,
        "events": events,
        "counts": counts,
        "pending": CTL.pending(),
        "fs": {
            "root": FS_ROOT,
            "lower": current_lower(),
            "mounted": mounted,          # session still live -> WAL resolution
            "staged": staged,            # overlay upper/ entries (final disposition)
            "wal": wal_pending,          # per-action, with the turn that made it
            "branches": sorted({r["branch"] for r in wal_pending if r["branch"]}),
        },
    }


CTL = Control(os.environ.get("KAIROS_MODE", "observe"))


# ---- session resolution -------------------------------------------------
def session_paths(session):
    """Resolve a session id (or None -> latest) to its file paths."""
    if session:
        d = os.path.join(SESSIONS_ROOT, os.path.basename(session))
    else:
        d = os.path.join(SESSIONS_ROOT, "latest")
    if os.path.isdir(d):
        return {"dir": os.path.realpath(d),
                "net": os.path.join(d, "net_events.jsonl"),
                "fs": os.path.join(d, "fs_events.jsonl"),
                "tmp": os.path.join(d, "tmp_fs_events.jsonl"),
                "bodies": os.path.join(d, "bodies"),
                "decisions": os.path.join(d, "decisions.jsonl"),
                "fs_report": os.path.join(d, "fs_report.json")}
    return {"dir": None, "net": FALLBACK_NET, "fs": FALLBACK_FS,
            "tmp": os.environ.get("KAIROS_TMP_EVENTS", "/tmp/kairos_tmp_events.jsonl"),
            "bodies": os.environ.get("KAIROS_BODIES_DIR", ""),
            "decisions": DECISIONS, "fs_report": ""}


def tmp_summary(path):
    """Files the agent wrote to /tmp (from the observe-only tmp channel)."""
    files = {}
    for e in _load_jsonl(path):
        op = e.get("op"); p = e.get("path")
        if op in ("create", "write", "unlink", "rename", "truncate") and p:
            files.setdefault(p, {"path": p, "ops": set(), "preview": None})
            files[p]["ops"].add(op)
            if e.get("preview") and not files[p]["preview"]:
                files[p]["preview"] = e["preview"]
    return [{"path": f["path"], "ops": sorted(f["ops"]), "preview": f["preview"]}
            for f in sorted(files.values(), key=lambda x: x["path"])]


def list_sessions():
    out = []
    if os.path.isdir(SESSIONS_ROOT):
        for name in sorted(os.listdir(SESSIONS_ROOT), reverse=True):
            p = os.path.join(SESSIONS_ROOT, name)
            if name == "latest" or not os.path.isdir(p) or os.path.islink(p):
                continue
            meta = {}
            try:
                meta = json.load(open(os.path.join(p, "session.json")))
            except Exception:
                pass
            out.append({"id": name, "ended": meta.get("ended"),
                        "started": meta.get("started"), "mode": meta.get("mode"),
                        "live": not meta.get("ended")})
    latest = os.path.join(SESSIONS_ROOT, "latest")
    cur = os.path.basename(os.path.realpath(latest)) if os.path.islink(latest) else None
    return {"sessions": out, "current": cur}


def _load_jsonl(path):
    out = []
    if path and os.path.exists(path):
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        out.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    return out


def net_payload(path, limit=None, before=None):
    """Network exchanges, oldest→newest. Optional windowing for large sessions:
    every exchange gets a stable `seq`; `before=<seq>` keeps only exchanges with
    seq < before, `limit=<n>` keeps the last n of those. `count` is always the
    session TOTAL. Without params the full payload is returned (old behavior)."""
    events = _load_jsonl(path)
    flows, order, tunnels = {}, [], []
    for e in events:
        k = e.get("kind")
        if k == "request":
            fid = e.get("flow")
            flows[fid] = {
                "flow": fid, "ts": e.get("ts"), "method": e.get("method"),
                "scheme": e.get("scheme"), "host": e.get("host"), "port": e.get("port"),
                "path": e.get("path"), "url": e.get("url"),
                "req_headers": e.get("headers", {}), "req_body_len": e.get("body_len", 0),
                "req_body_preview": e.get("body_preview"), "req_body_binary": e.get("body_binary", False),
                "req_body_sha": e.get("body_sha"), "req_body_truncated": e.get("body_truncated", False),
                "status": None, "resp_headers": {}, "resp_body_len": 0,
                "resp_body_preview": None, "resp_body_binary": False, "resp_body_sha": None,
                "resp_body_truncated": False,
                "state_changing": e.get("method") in STATE_CHANGING, "decision": None,
            }
            order.append(fid)
        elif k == "response":
            fx = flows.get(e.get("flow"))
            if fx:
                fx.update(status=e.get("status"), resp_headers=e.get("headers", {}),
                          resp_body_len=e.get("body_len", 0), resp_body_preview=e.get("body_preview"),
                          resp_body_binary=e.get("body_binary", False), resp_body_sha=e.get("body_sha"),
                          resp_body_truncated=e.get("body_truncated", False))
        elif k == "decision":
            fx = flows.get(e.get("flow"))
            if fx:
                fx["decision"] = e.get("action")
        elif k == "tunnel_close":
            tunnels.append({"host": e.get("host"), "bytes_out": e.get("bytes_out"),
                            "bytes_in": e.get("bytes_in"), "ts": e.get("ts")})
    exchanges = [flows[f] for f in order]
    for i, x in enumerate(exchanges):
        x["seq"] = i
    total = len(exchanges)
    if before is not None:
        exchanges = [x for x in exchanges if x["seq"] < before]
    if limit is not None and limit >= 0:
        exchanges = exchanges[-limit:]
        tunnels = tunnels[-limit:]
    return {"exchanges": exchanges, "tunnels": tunnels, "count": total}


def _window_turns(data, turns_limit=None, turns_before=None):
    """Optional windowing of the (potentially huge) per-turn timeline: adds
    `turns_total`, then keeps turns with n < turns_before (if given) and the
    last `turns_limit` of those. No params -> full list (old behavior)."""
    turns = data.get("turns") or []
    data["turns_total"] = len(turns)
    if turns_before is not None:
        turns = [t for t in turns if t.get("n", 0) < turns_before]
    if turns_limit is not None and turns_limit >= 0:
        turns = turns[-turns_limit:]
    data["turns"] = turns
    return data


def fs_payload(paths, turns_limit=None, turns_before=None):
    # a past session serves its frozen snapshot; the live/current session is computed
    snap = paths.get("fs_report")
    if snap and os.path.exists(snap):
        try:
            data = json.load(open(snap))
            data["resolvable"] = False
            data["snapshot"] = True
            data["tmp"] = tmp_summary(paths.get("tmp"))
            return _window_turns(data, turns_limit, turns_before)
        except Exception:
            pass
    if fsreport is None:
        return {"error": "fs report module unavailable", "changes": [], "turns": []}
    changes = fsreport.collect_changes(FS_ROOT, base=current_lower())
    for c in changes:
        if c["kind"] in ("added", "modified"):
            c["diff"] = fsreport.unified(c.get("before"), c.get("after"), c["path"])
    events = fsreport.load_events(paths["fs"])
    turns_out = [{"n": i + 1, "ops": len(t),
                  "files": sorted({e["path"] for e in t if "path" in e}),
                  "start": t[0].get("ts"), "end": t[-1].get("ts"),
                  "detail": [{"op": e.get("op"), "path": e.get("path")} for e in t if "path" in e][:200]}
                 for i, t in enumerate(fsreport.segment_turns(events, 8.0))]
    mounted = os.path.ismount(os.path.join(FS_ROOT, "merged"))
    # A live session is resolvable too, via the journal — that is the whole point
    # of the WAL. Tag each change with the branch that produced it so the UI can
    # offer per-branch commit/abort while the agent is still working; without a
    # journal (KAIROS_FS_WAL=0) the old rule stands and resolution waits for exit.
    wal_pending = []
    if fsresolve is not None:
        try:
            wal_pending = fsresolve.wal_changes(FS_ROOT, os.path.join(FS_ROOT, "merged"))
        except Exception:                                    # noqa: BLE001
            wal_pending = []
    by_path = {}
    for r in wal_pending:
        by_path.setdefault(r["path"].lstrip("/"), r)
    for c in changes:
        hit = by_path.get((c.get("path") or "").lstrip("/"))
        if hit:
            c["branch"] = hit["branch"]
    return _window_turns(
        {"root": FS_ROOT, "changes": changes, "turns": turns_out,
         "event_count": len(events),
         "resolvable": (not mounted) or bool(wal_pending), "snapshot": False,
         "live": mounted, "wal": bool(wal_pending),
         "branches": sorted({r["branch"] for r in wal_pending if r["branch"]}),
         "tmp": tmp_summary(paths.get("tmp"))},
        turns_limit, turns_before)


def _qint(q, key):
    """Parse an optional integer query param (None if absent/invalid)."""
    try:
        v = q.get(key, [None])[0]
        return int(v) if v not in (None, "") else None
    except (TypeError, ValueError):
        return None


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, code, body, ctype="application/json"):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self):
        n = int(self.headers.get("Content-Length", 0) or 0)
        if not n:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    def _serve_ui(self, path):
        # The guest fetches the walkthrough helper from here. Served from source
        # rather than copied into the built bundle, because `npm run generate`
        # wipes .output/public and the copy would silently go stale.
        if path == "/steps.sh":
            sp = os.path.join(HERE, "..", "casestudy", "steps.sh")
            try:
                with open(sp, "rb") as f:
                    self._send(200, f.read(), "text/plain; charset=utf-8")
            except OSError:
                self._send(404, {"error": "steps.sh not found"})
            return

        """Static file from the built Nuxt bundle, else the MVP page.

        Deep links (/network, /filesystem/…) have no file of their own in an SPA,
        so anything that does not resolve falls through to 200.html — Nuxt's
        client-side router then takes over. The realpath check keeps a crafted
        ../ out of the rest of the filesystem."""
        if os.path.isdir(NEW_UI):
            root = os.path.realpath(NEW_UI)
            fp = os.path.realpath(os.path.join(root, path.lstrip("/") or "index.html"))
            if not (fp == root or fp.startswith(root + os.sep)):
                self._send(404, {"error": "not found"})
                return
            if os.path.isdir(fp):
                fp = os.path.join(fp, "index.html")
            if not os.path.isfile(fp):
                # Route-like paths (no file extension) are SPA deep links and fall
                # through to the client-side router. A missing *asset* must 404:
                # answering with HTML where JS was requested turns a broken build
                # into a mystery routing bug.
                if "." in os.path.basename(fp):
                    self._send(404, {"error": "not found"})
                    return
                fp = os.path.join(root, "200.html")          # SPA fallback route
            try:
                with open(fp, "rb") as f:
                    body = f.read()
            except OSError:
                self._send(404, {"error": "not found"})
                return
            self._send(200, body, CTYPES.get(fp.rsplit(".", 1)[-1].lower(),
                                             "application/octet-stream"))
            return
        try:
            with open(os.path.join(HERE, "index.html"), "rb") as f:
                self._send(200, f.read(), "text/html; charset=utf-8")
        except OSError:
            self._send(200, b"Kairos control plane: the API is under /api/ (this release has no web UI).\n", "text/plain")

    def do_GET(self):
        u = urlparse(self.path)
        q = parse_qs(u.query)
        sess = q.get("session", [None])[0]
        if not u.path.startswith("/api/"):
            self._serve_ui(u.path)
        elif u.path == "/api/net":
            self._send(200, net_payload(session_paths(sess)["net"],
                                        limit=_qint(q, "limit"),
                                        before=_qint(q, "before")))
        elif u.path == "/api/fs":
            self._send(200, fs_payload(session_paths(sess),
                                       turns_limit=_qint(q, "turns_limit"),
                                       turns_before=_qint(q, "turns_before")))
        elif u.path == "/api/net/body":
            sha = os.path.basename(q.get("sha", [""])[0])
            bp = os.path.join(session_paths(sess)["bodies"] or "", sha)
            if not sha or not os.path.isfile(bp):
                self._send(404, {"error": "body not found"})
                return
            with open(bp, "rb") as f:
                data = f.read()
            try:
                data.decode("utf-8")
                self._send(200, data, "text/plain; charset=utf-8")
            except UnicodeDecodeError:
                self._send(200, data, "application/octet-stream")
        elif u.path == "/api/sessions":
            self._send(200, list_sessions())
        elif u.path == "/api/monitor":
            self._send(200, monitor_payload(sess, limit=_qint(q, "limit") or 200))
        elif u.path == "/api/task":
            self._send(200, {"task": CTL.task})
        elif u.path == "/api/policy":
            self._send(200, POLICY.as_dict() if POLICY else {"error": "live policy unavailable"})
        elif u.path == "/api/fs/adjudicate":
            self._send(200, adjudicate_staged(sess))
        elif u.path == "/api/mode":
            self._send(200, {"mode": CTL.mode, "modes": list(MODES)})
        elif u.path == "/api/net/pending":
            self._send(200, {"mode": CTL.mode, "pending": CTL.pending()})
        elif u.path == "/api/net/decision":
            self._send(200, CTL.decision(q.get("id", [""])[0]))
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        u = urlparse(self.path)
        b = self._json_body()
        if u.path == "/api/mode":
            self._send(200, {"mode": CTL.set_mode(b.get("mode", ""))})
        elif u.path == "/api/task":
            # Declaring the task IS declaring the trust root. Everything derivable
            # from it passes integrity; everything else is untrusted-origin.
            self._send(200, {"task": CTL.set_task(b.get("task", ""))})
        elif u.path == "/api/policy":
            if POLICY is None:
                self._send(500, {"error": "live policy unavailable"})
            else:
                self._send(200, POLICY.update(b))
        elif u.path == "/api/net/hold":
            self._send(200, CTL.register_hold(b))
        elif u.path == "/api/net/resolve":
            ok = CTL.resolve(b.get("id", ""), b.get("action", ""))
            self._send(200 if ok else 404, {"ok": ok})
        elif u.path == "/api/fs/finalize":
            # A FORCED resolution that leaves the session running. Until now the
            # only ways to resolve staged filesystem changes were per-file in the
            # dashboard or at exit, so a scenario could not be resolved and then
            # followed by the next one in the same guest -- which is exactly what
            # walking through several cases needs. This asks the judge for a
            # per-file recommendation and applies it: consistent -> commit,
            # inconsistent -> abort. Advisory stays advisory; `action` can force
            # one outcome for everything instead.
            if fsresolve is None:
                self._send(500, {"error": "resolve module unavailable"})
                return
            root = b.get("root", FS_ROOT)
            forced = b.get("action")           # "commit" | "abort" | None (= per-file)
            rec = adjudicate_staged(sess) if forced is None else {"available": True}
            if forced is None and not rec.get("available"):
                self._send(503, {"error": "no judge recommendation available",
                                 "detail": rec.get("reason")})
                return
            live = os.path.ismount(os.path.join(root, "merged"))
            applied, errors = [], []
            groups = {}
            if forced is not None:
                groups[forced] = None          # all pending records
            else:
                for f in rec.get("per_file", []):
                    act = "commit" if f.get("consistent") else "abort"
                    groups.setdefault(act, []).append(f.get("path"))
            for act, paths in groups.items():
                try:
                    if live:
                        results, conflicts = fsresolve.resolve_records(
                            root, act, paths=paths,
                            target=os.path.join(root, "merged"),
                            force=bool(b.get("force")))
                        if conflicts:
                            errors.append({"action": act, "conflicts": conflicts})
                        applied.append({"action": act, "paths": paths, "results": results})
                    else:
                        r = (fsresolve.resolve_all(root, act, base_root=current_lower())
                             if not paths else
                             [fsresolve.resolve_file(root, x, act, base_root=current_lower())
                              for x in paths])
                        applied.append({"action": act, "paths": paths, "results": r})
                except Exception as e:                       # noqa: BLE001
                    errors.append({"action": act, "error": str(e)})
            log_decision({"by": "operator" if forced else "judge",
                          "channel": "fs-finalize", "action": forced or "per-file",
                          "applied": applied, "errors": errors})
            self._send(200 if not errors else 207,
                       {"applied": applied, "errors": errors,
                        "recommendation": rec if forced is None else None,
                        "session_continues": True})
        elif u.path == "/api/fs/resolve":
            if fsresolve is None:
                self._send(500, {"error": "resolve module unavailable"})
                return
            root = b.get("root", FS_ROOT)
            action = b.get("action", "")
            live = os.path.ismount(os.path.join(root, "merged"))
            paths = b.get("paths") or None
            branch = b.get("branch")

            # LIVE session -> the journal. Undo is ordinary file I/O through the
            # same merged view, so nothing has to be unmounted and the agent can
            # keep working. The overlay's merge/abort stays the end-of-run step.
            if live:
                try:
                    results, conflicts = fsresolve.resolve_records(
                        root, action, branch=branch, paths=paths,
                        target=os.path.join(root, "merged"), force=bool(b.get("force")))
                except Exception as e:                       # noqa: BLE001
                    self._send(500, {"error": f"wal resolve failed: {e}"})
                    return
                if conflicts:
                    # Whole-file undo would roll back a later surviving change.
                    # Say so rather than silently discarding someone else's work.
                    self._send(409, {"error": "later pending changes to the same "
                                              "path would be lost",
                                     "conflicts": conflicts})
                    return
                log_decision({"by": "human", "channel": "fs", "action": action,
                              "paths": paths, "branch": branch, "via": "wal"})
                self._send(200, {"results": results, "via": "wal"})
                return

            # session over -> the overlay is the disposition
            base_root = current_lower()
            results = []
            for p in (paths or fsresolve.list_changes(root)):
                try:
                    results.append(fsresolve.resolve_file(root, p, action, base_root))
                except Exception as e:                       # noqa: BLE001
                    results.append(f"error {p}: {e}")
            log_decision({"by": "human", "channel": "fs", "action": action,
                          "paths": paths, "via": "overlay"})
            self._send(200, {"results": results, "via": "overlay"})
        else:
            self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--host", default="0.0.0.0")
    args = ap.parse_args()
    srv = ThreadingHTTPServer((args.host, args.port), Handler)
    sys.stderr.write(f"[ui] Kairos dashboard + control plane on http://localhost:{args.port} "
                     f"(mode={CTL.mode}, sessions={SESSIONS_ROOT})\n")
    sys.stderr.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
