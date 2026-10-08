"""
Network channel monitor — mitmproxy addon  (M3, observe-only)
=============================================================

Loaded into a transparent-mode mitmproxy that intercepts the guest's egress
(iptables REDIRECTs guest TCP -> host:8080). Records every request/response —
method, URL, headers, body (with sha256 + capped preview) — as a structured
JSONL event stream, the network counterpart to the filesystem event log.

This milestone is OBSERVE-ONLY: nothing is held or blocked. The hold/stall +
per-request commit/abort is KAIROS enforcement (M5).

By default EVERYTHING is decrypted and logged (the guest trusts the mitmproxy CA,
installed in its trust store at build time) — you see all traffic, including the
LLM channel. If a host is opted into TLS-passthrough (mitmdump --ignore-hosts),
it is never decrypted and appears here as `tunnel` events (host + byte counts).

Events -> $KAIROS_NET_EVENTS (default /tmp/kairos_net_events.jsonl).

Strict boundary (KAIROS_NET_STRICT=1, see sinkhole_policy.py)
------------------------------------------------------------
With the DNS sinkhole every guest connection arrives with the bridge address as its
original destination, so the proxy picks the real upstream itself: from the SNI in
`tls_clienthello`, or from the Host header in `request`, and only if
sinkhole_policy permits it (pinned name -> the host-side sink; otherwise a name that
resolves to globally routable addresses). A flow with no name to check — raw TCP,
TLS passthrough — is pointed at a dead address in `tcp_start` and never relayed.
Refusals are events of kind `sinkhole_refused`; accepted upstreams are `upstream`.
Off by default: with KAIROS_NET_STRICT unset none of this runs and the addon behaves
exactly as before.
"""

import os
import sys
import json
import time
import asyncio
import hashlib
import urllib.request

from mitmproxy import http

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from sinkhole_policy import (  # noqa: E402
    DEAD, STRICT, CachedResolver, Refusal, Upstream, check_address, decide_upstream,
    is_sinkhole, parse_authority,
)

EVENTS_PATH = os.environ.get("KAIROS_NET_EVENTS", "/tmp/kairos_net_events.jsonl")
MAX_BODY = int(os.environ.get("KAIROS_NET_MAX_BODY", "8192"))          # inline preview cap
BODIES_DIR = os.environ.get("KAIROS_BODIES_DIR", "")                    # full body blobs (audit)
# Bodies larger than this are NOT stored — only metadata (method/url/len) is kept,
# so the audit log stays bounded. Uniform with the filesystem cap.
BODY_CAP = int(os.environ.get("KAIROS_MAX_LOG_BYTES", str(100 * 1024 * 1024)))  # 100MB
# Control plane (serve.py). Enforcement is a no-op (observe) unless it decides otherwise.
CTL_URL = os.environ.get("KAIROS_CTL_URL", "http://127.0.0.1:8090")
STATE_CHANGING = {"POST", "PUT", "PATCH", "DELETE"}
POLL_S = 0.4
POLL_MAX = 1500  # 1500 * 0.4s = 10 min max hold, then fail-open


class NetMonitor:
    def __init__(self):
        self._f = open(EVENTS_PATH, "a", buffering=1)
        self._resolve = CachedResolver()
        self._tls_refusals = {}   # client peername -> reason decided at the TLS stage

    def _emit(self, **event):
        event["ts"] = round(time.time(), 6)
        self._f.write(json.dumps(event, separators=(",", ":"), ensure_ascii=False) + "\n")

    @staticmethod
    def _body(content):
        """Full-fidelity body metadata. The COMPLETE body is written to a
        content-addressed blob (bodies/<sha256>) so nothing is truncated in the
        audit record; a capped preview is kept inline for the list view."""
        if not content:
            return {"len": 0, "sha": None, "preview": None, "binary": False,
                    "truncated": False, "stored": False}
        full = len(content)
        sha = hashlib.sha256(content).hexdigest()
        stored, truncated = False, False
        if BODIES_DIR:
            if full > BODY_CAP:
                truncated = True          # too large — metadata only, no blob
            else:
                try:
                    os.makedirs(BODIES_DIR, exist_ok=True)
                    bp = os.path.join(BODIES_DIR, sha)
                    if not os.path.exists(bp):
                        with open(bp, "wb") as f:
                            f.write(content)
                    stored = True
                except OSError:
                    pass
        chunk = content[:MAX_BODY]
        try:
            preview, binary = chunk.decode("utf-8"), False
        except UnicodeDecodeError:
            preview, binary = chunk[:64].hex(), True
        return {"len": full, "sha": sha, "preview": preview, "binary": binary,
                "truncated": truncated, "stored": stored}

    @staticmethod
    def _client(flow):
        try:
            return flow.client_conn.peername[0]
        except Exception:
            return None

    # ---- control-plane calls (to serve.py) ----

    @staticmethod
    def _ctl_post(path, obj):
        req = urllib.request.Request(CTL_URL + path, data=json.dumps(obj).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=5) as r:
            return json.loads(r.read().decode())

    @staticmethod
    def _ctl_get(path):
        with urllib.request.urlopen(CTL_URL + path, timeout=5) as r:
            return json.loads(r.read().decode())

    async def _enforce(self, flow):
        """Register a state-changing request with the control plane and hold it
        (awaiting the decision) if the mode requires. Returns 'allow' | 'abort'.
        Fails OPEN if the control plane is unreachable so egress still works."""
        r = flow.request
        b = self._body(r.content)   # .content is decoded/decompressed (raw_content is gzip'd)
        summary = {"method": r.method, "host": r.pretty_host, "path": r.path,
                   "url": r.pretty_url, "body_preview": b["preview"],
                   "body_len": b["len"]}
        try:
            resp = await asyncio.to_thread(self._ctl_post, "/api/net/hold", summary)
        except Exception:
            return "allow"
        if resp.get("action") in ("allow", "abort"):
            return resp["action"]
        hid = resp.get("id")
        if not hid:
            return "allow"
        for _ in range(POLL_MAX):
            await asyncio.sleep(POLL_S)
            try:
                d = await asyncio.to_thread(self._ctl_get, f"/api/net/decision?id={hid}")
            except Exception:
                return "allow"
            st = d.get("status")
            if st == "abort":
                return "abort"
            if st == "commit":
                return "allow"
        return "allow"

    # ---- strict boundary: the proxy picks the upstream, the guest only sees the sinkhole ----

    async def _decide(self, name, port):
        # the resolver blocks on the host's DNS; keep it off the proxy's event loop
        return await asyncio.to_thread(decide_upstream, name, port, resolver=self._resolve)

    async def _strict_request(self, flow):
        """Fix the upstream of an HTTP request under the strict boundary. Returns True to
        let the request proceed, False after answering 403 (no upstream connection is
        opened either way: mitmproxy connects lazily, after this hook)."""
        r = flow.request
        cur = (r.host, r.port)          # transparent mode: original destination, or what tls_clienthello set
        stage = "addr"
        if cur == DEAD:
            reason = self._tls_refusals.pop(self._client(flow), "refused at the TLS stage")
            dec = Refusal(reason)
            stage = "tls"
        elif is_sinkhole(cur):
            auth = parse_authority(r.host_header or "", r.port)
            dec = await self._decide(auth[0], auth[1]) if auth else Refusal("no Host header")
            stage = "host"
        else:
            dec = check_address(cur[0], cur[1])
        if isinstance(dec, Upstream):
            if (dec.ip, dec.port) != cur:
                # mitmproxy's host/port setters also rewrite the Host header (and
                # :authority); keep the name the guest sent, the upstream needs it for
                # virtual hosting and the judge sees it as the destination.
                host_header = r.host_header
                r.host, r.port = dec.ip, dec.port
                if host_header:
                    r.host_header = host_header
                self._emit(kind="upstream", stage=stage, flow=flow.id, host=r.pretty_host,
                           ip=dec.ip, port=dec.port, how=dec.how)
            return True
        self._emit(kind="sinkhole_refused", stage=stage, flow=flow.id, client=self._client(flow),
                   host=r.pretty_host, port=cur[1], reason=dec.reason)
        flow.response = http.Response.make(
            403, f"Refused by the Kairos strict boundary: {dec.reason}\n".encode(),
            {"Content-Type": "text/plain"})
        return False

    # ---- decrypted HTTP(S) flows ----

    async def request(self, flow):
        r = flow.request
        b = self._body(r.content)   # decoded/decompressed body
        self._emit(kind="request", flow=flow.id, client=self._client(flow),
                   method=r.method, scheme=r.scheme, host=r.pretty_host, port=r.port,
                   path=r.path, url=r.pretty_url,
                   headers=dict(r.headers), body_len=b["len"], body_sha=b["sha"],
                   body_preview=b["preview"], body_binary=b["binary"],
                   body_truncated=b["truncated"])

        if STRICT and not await self._strict_request(flow):
            return

        # M5 enforcement: hold irreversible (state-changing) requests for a decision.
        if r.method in STATE_CHANGING:
            action = await self._enforce(flow)
            self._emit(kind="decision", flow=flow.id, host=r.pretty_host,
                       path=r.path, action=action)
            if action == "abort":
                flow.response = http.Response.make(
                    403, b"Blocked by the Kairos reference monitor.\n",
                    {"Content-Type": "text/plain"})

    def response(self, flow):
        resp = flow.response
        b = self._body(resp.content)   # decoded/decompressed body (was gzip'd on the wire)
        self._emit(kind="response", flow=flow.id, host=flow.request.pretty_host,
                   url=flow.request.pretty_url, status=resp.status_code,
                   headers=dict(resp.headers), body_len=b["len"], body_sha=b["sha"],
                   body_preview=b["preview"], body_binary=b["binary"],
                   body_truncated=b["truncated"])

    # ---- TLS-passthrough (cleared hosts) appear as raw TCP tunnels ----

    async def tls_clienthello(self, data):
        # capture SNI even for passthrough connections
        sni = None
        try:
            sni = data.client_hello.sni
            if sni:
                self._emit(kind="tls_sni", sni=sni,
                           client=self._client(data.context.client) if hasattr(data, "context") else None)
        except Exception:
            pass
        if not STRICT:
            return
        # Strict boundary: decide the upstream from the SNI BEFORE any server connection
        # exists (connection_strategy=lazy; TlsConfig only connects first under eager).
        srv = data.context.server
        addr = srv.address
        try:
            if is_sinkhole(addr):
                if not sni:
                    return              # no name yet; the request hook will use the Host header
                dec = await self._decide(sni, addr[1])
            else:
                dec = check_address(addr[0], addr[1])
            if isinstance(dec, Upstream):
                if (dec.ip, dec.port) != tuple(addr):
                    srv.address = (dec.ip, dec.port)
                    self._emit(kind="upstream", stage="tls", sni=sni, ip=dec.ip, port=dec.port, how=dec.how)
                return
            reason = dec.reason
        except Exception as e:      # never let a policy error fall through to a relay
            reason = f"policy error: {e.__class__.__name__}"
        srv.address = DEAD
        try:
            self._tls_refusals[data.context.client.peername[0]] = reason
        except Exception:
            pass
        self._emit(kind="sinkhole_refused", stage="tls", sni=sni, port=addr[1] if addr else None,
                   reason=reason)

    def tcp_start(self, flow):
        try:
            addr = flow.server_conn.address
            self._emit(kind="tunnel_open", flow=flow.id, client=self._client(flow),
                       host=addr[0] if addr else None, port=addr[1] if addr else None)
        except Exception:
            pass
        if STRICT:
            # A flow with no request to judge (raw TCP, or TLS passthrough) cannot be
            # mediated, so it does not leave: point it at the dead address before the
            # layer opens its upstream connection.
            try:
                addr = flow.server_conn.address
                flow.server_conn.address = DEAD
                self._emit(kind="sinkhole_refused", stage="tcp", flow=flow.id,
                           client=self._client(flow), host=addr[0] if addr else None,
                           port=addr[1] if addr else None,
                           reason="non-HTTP flow cannot be mediated")
            except Exception:
                pass

    def tcp_end(self, flow):
        try:
            sent = sum(len(m.content) for m in flow.messages if m.from_client)
            recv = sum(len(m.content) for m in flow.messages if not m.from_client)
            addr = flow.server_conn.address
            self._emit(kind="tunnel_close", flow=flow.id,
                       host=addr[0] if addr else None,
                       bytes_out=sent, bytes_in=recv)
        except Exception:
            pass

    def done(self):
        try:
            self._f.close()
        except Exception:
            pass


addons = [NetMonitor()]
