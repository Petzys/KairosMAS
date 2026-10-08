#!/bin/bash
#
# Bring up the network channel  (M3, observe-only)
# ================================================
# Transparent mitmproxy on the guest's egress + the redirect rules. Logs every
# request/response to JSONL via net_monitor_addon.py. This mirrors the proven
# prototype invocation (deploy/old/start_mitm_transparent.sh + orchestrator).
#
# By default EVERYTHING is decrypted and logged ("see everything"). Set
# KAIROS_MITM_PASSTHROUGH to a host regex to TLS-passthrough cleared hosts
# (e.g. the LLM provider) if MITM ever breaks them.
#
# Env:
#   KAIROS_NET_EVENTS       event log (default /tmp/kairos_net_events.jsonl)
#   KAIROS_MITM_PASSTHROUGH regex of hosts to NOT decrypt (default: none)
#   KAIROS_MITM_MODE        transparent (guest) | regular (host testing w/ curl -x)
#   KAIROS_NET_STRICT       1 = strict boundary: DNS sinkhole + proxy-only egress; the
#                          addon picks the upstream from SNI / Host (sinkhole_policy.py).
#                          Incompatible with KAIROS_MITM_PASSTHROUGH (a passthrough flow
#                          has no name the proxy could redirect by).
#
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
EVENTS="${KAIROS_NET_EVENTS:-/tmp/kairos_net_events.jsonl}"
PASS="${KAIROS_MITM_PASSTHROUGH:-}"       # default: decrypt everything (see all)
MODE="${KAIROS_MITM_MODE:-transparent}"   # transparent (guest) | regular (host testing)
STRICT="${KAIROS_NET_STRICT:-0}"
RUN="/run/kairos"; mkdir -p "$RUN"

if [ "$STRICT" = 1 ] && [ -n "$PASS" ]; then
    echo "KAIROS_NET_STRICT=1 cannot be combined with KAIROS_MITM_PASSTHROUGH: a passthrough" >&2
    echo "connection carries no name the proxy could redirect, so it would never leave anyway." >&2
    exit 1
fi
if [ "$STRICT" = 1 ] && [ "$MODE" != "transparent" ]; then
    echo "KAIROS_NET_STRICT=1 requires KAIROS_MITM_MODE=transparent" >&2
    exit 1
fi

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi

MITM="$(command -v mitmdump || echo /usr/local/bin/mitmdump)"
[ -x "$MITM" ] || { echo "mitmdump not found"; exit 1; }

# 1) redirect rules (only in transparent mode)
MITM_ARGS=(--mode transparent --listen-host 0.0.0.0 --showhost)
if [ "$MODE" = "transparent" ]; then
    bash "$HERE/setup_proxy_rules.sh" up
else
    MITM_ARGS=(--mode regular)   # host-side testing with `curl -x`
fi
MITM_ARGS+=(--listen-port 8080 --set confdir=/root/.mitmproxy --set flow_detail=0)
[ -n "$PASS" ] && MITM_ARGS+=(--ignore-hosts "$PASS")
if [ "$STRICT" = 1 ]; then
    # The addon changes the upstream address in tls_clienthello / request; that only
    # works if no server connection exists yet. Lazy is mitmproxy 9's default, pinned
    # here so an option change upstream cannot silently break the boundary.
    MITM_ARGS+=(--set connection_strategy=lazy)
    export KAIROS_NET_STRICT="$STRICT"
    export KAIROS_DNS_HOSTS="${KAIROS_DNS_HOSTS:-}" KAIROS_DNS_TARGET="${KAIROS_DNS_TARGET:-192.168.100.1}"
    export KAIROS_NET_PINNED_PORTS="${KAIROS_NET_PINNED_PORTS:-80,443}"
fi
MITM_ARGS+=(-s "$HERE/net_monitor_addon.py")

# 2) mitmproxy with our addon (enforcement talks to the control plane / serve.py)
: > "$EVENTS" 2>/dev/null || true
export KAIROS_NET_EVENTS="$EVENTS"
export KAIROS_CTL_URL="${KAIROS_CTL_URL:-http://127.0.0.1:${KAIROS_UI_PORT:-8090}}"
setsid "$MITM" "${MITM_ARGS[@]}" >/var/log/kairos-mitmproxy.log 2>&1 < /dev/null &
echo $! > "$RUN/mitmproxy.pid"

for i in $(seq 1 50); do ss -ltn 2>/dev/null | grep -q ':8080' && break; sleep 0.1; done
if ! ss -ltn 2>/dev/null | grep -q ':8080'; then
    echo "mitmproxy failed to listen on :8080; see /var/log/kairos-mitmproxy.log"
    tail -5 /var/log/kairos-mitmproxy.log 2>/dev/null || true
    exit 1
fi
echo "[net] mitmproxy $MODE on :8080 (events -> $EVENTS)"
[ -n "$PASS" ] && echo "[net] passthrough (not decrypted): $PASS" || echo "[net] decrypting ALL hosts (see everything)"
[ "$STRICT" = 1 ] && echo "[net] STRICT boundary: DNS sinkholed, upstream chosen by the proxy (pinned: ${KAIROS_DNS_HOSTS:-none} -> ${KAIROS_DNS_TARGET:-192.168.100.1} on ${KAIROS_NET_PINNED_PORTS:-80,443}); non-HTTP flows refused"
echo "[net] network channel up."
