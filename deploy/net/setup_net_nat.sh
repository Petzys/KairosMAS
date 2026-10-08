#!/bin/bash
#
# Guest network setup — NAT only  (M1)
# ====================================
# Minimal, SURGICAL network for the microVM so Claude Code inside the guest can
# reach the internet (Anthropic API + OAuth login). This is deliberately *not*
# the transparent-proxy setup — that arrives in M4 (mitmproxy on the network
# channel). For now the guest gets plain masqueraded egress.
#
# Surgical on purpose: we only ADD rules for the guest subnet and never flush
# existing chains or change default policies, so we don't break this host's own
# networking (it may itself rely on NAT/forwarding).
#
#   bridge br0  = 192.168.100.1/24   (guest default gateway + DNS)
#   tap0        = VM tap, enslaved to br0
#   guest       = 192.168.100.2/24   (static, baked into the rootfs)
#
# KAIROS_NET_STRICT=1 (strict boundary, see setup_proxy_rules.sh): dnsmasq becomes a
# SINKHOLE — no upstream resolver at all, every name answers with the bridge address —
# so no DNS query ever leaves the host, and the guest subnet gets no MASQUERADE (the
# proxy's own upstream connections originate on the host and need none).
#
set -e
STRICT="${KAIROS_NET_STRICT:-0}"

BR=br0
TAP=tap0
SUBNET=192.168.100.0/24
GW_CIDR=192.168.100.1/24

if [ "$EUID" -ne 0 ]; then echo "run as root"; exit 1; fi

# ---- bridge ----
if ! ip link show "$BR" >/dev/null 2>&1; then
    ip link add name "$BR" type bridge
    ip addr add "$GW_CIDR" dev "$BR"
    ip link set "$BR" up
    echo "[net] created bridge $BR ($GW_CIDR)"
else
    ip addr add "$GW_CIDR" dev "$BR" 2>/dev/null || true
    ip link set "$BR" up
    echo "[net] bridge $BR present"
fi

# ---- tap enslaved to bridge ----
if ! ip link show "$TAP" >/dev/null 2>&1; then
    ip tuntap add "$TAP" mode tap
    echo "[net] created tap $TAP"
fi
ip link set "$TAP" master "$BR"
ip link set "$TAP" up
echo "[net] tap $TAP up, master $BR"

# ---- forwarding ----
sysctl -w net.ipv4.ip_forward=1 >/dev/null

# ---- NAT + forward accepts for our subnet only (idempotent) ----
EXT=$(ip route | awk '/^default/{print $5; exit}')
if [ "$STRICT" = 1 ]; then
    echo "[net] STRICT: no MASQUERADE for $SUBNET (guest egress exists only through the proxy)"
elif [ -n "$EXT" ]; then
    iptables -t nat -C POSTROUTING -s "$SUBNET" -o "$EXT" -j MASQUERADE 2>/dev/null \
        || iptables -t nat -A POSTROUTING -s "$SUBNET" -o "$EXT" -j MASQUERADE
    echo "[net] MASQUERADE $SUBNET -> $EXT"
else
    echo "[net] WARN: no default route; guest will not reach internet"
fi
# Purge stale M4 transparent-proxy rules left by the old prototype: a blanket
# REDIRECT of guest TCP -> host:8080 (nothing listens there in M1, so egress is
# refused), and a FORWARD DROP/LOG for the guest that would silently drop all
# egress. We are NOT running the proxy yet (that is M4); this is plain NAT.
iptables -t nat -D PREROUTING -s 192.168.100.2/32 -i "$BR" -p tcp -j REDIRECT --to-ports 8080 2>/dev/null || true
iptables -t nat -D PREROUTING -s 192.168.100.2/32 -d 192.168.100.1/32 -i "$BR" -p tcp -m tcp --dport 8080 -j RETURN 2>/dev/null || true
iptables -t nat -D PREROUTING -s 192.168.100.2/32 -i "$BR" -p tcp -m tcp --dport 53 -j RETURN 2>/dev/null || true
iptables -D FORWARD -s 192.168.100.2/32 -j DROP 2>/dev/null || true
iptables -D FORWARD -s 192.168.100.2/32 -j LOG --log-prefix "VM-BLOCKED: " --log-level 4 2>/dev/null || true

# Our ACCEPTs go at the TOP so they win over any residual DROP still in the chain.
iptables -D FORWARD -s "$SUBNET" -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -d "$SUBNET" -j ACCEPT 2>/dev/null || true
iptables -I FORWARD 1 -d "$SUBNET" -j ACCEPT
iptables -I FORWARD 1 -s "$SUBNET" -j ACCEPT

# ---- DNS forwarder for the guest (resolv.conf points at 192.168.100.1) ----
# --filter-AAAA: the guest is deliberately single-stack IPv4 (see note). Strip
# IPv6 answers so guest apps (curl, Claude Code) never try a v6 route that
# doesn't exist. This also keeps ALL guest egress on the IPv4 path that the
# transparent proxy mediates in M4 — an IPv6 path would bypass the monitor.
#
# KAIROS_DNS_HOSTS (comma-separated) pins extra names to the host side of the
# bridge. Hostnames that must resolve but have no real DNS record — e.g. the
# latency benchmark's status.internal.local (deploy/bench) — are declared here
# rather than by appending to
# /etc/dnsmasq.conf: passing them as flags keeps the run self-contained, leaves
# no host state behind, and puts the mapping in this session's log where an
# auditor can see it.
if command -v dnsmasq >/dev/null 2>&1; then
    DNS_EXTRA=()
    if [ -n "${KAIROS_DNS_HOSTS:-}" ]; then
        for h in ${KAIROS_DNS_HOSTS//,/ }; do
            [ -n "$h" ] || continue
            DNS_EXTRA+=(--address=/"$h"/"${KAIROS_DNS_TARGET:-192.168.100.1}")
        done
    fi
    # Strict boundary: a sinkhole, not a forwarder. --no-resolv removes every upstream
    # server, --address=/#/<bridge> answers ANY name with the bridge address (a pinned
    # KAIROS_DNS_HOSTS entry is more specific and still wins), --log-queries keeps the
    # names the guest asked for in this session's log. The proxy resolves the real
    # host itself, on the host side, only for connections it admits.
    DNS_MODE=()
    if [ "$STRICT" = 1 ]; then
        DNS_MODE=(--no-resolv --no-hosts --address=/#/192.168.100.1 --log-queries)
    fi
    # always (re)start ours so the AAAA filter is guaranteed to be active
    pkill -f "dnsmasq.*192.168.100.1" 2>/dev/null || true
    sleep 0.3
    dnsmasq --listen-address=192.168.100.1 \
            --bind-interfaces \
            --except-interface=lo \
            --filter-AAAA \
            "${DNS_MODE[@]}" \
            "${DNS_EXTRA[@]}" \
            --no-daemon >/var/log/kairos-dnsmasq.log 2>&1 &
    disown || true
    sleep 0.3
    if [ "$STRICT" = 1 ]; then
        echo "[net] dnsmasq SINKHOLE on 192.168.100.1:53 (no upstream; every name -> 192.168.100.1; queries logged)"
    else
        echo "[net] dnsmasq forwarding on 192.168.100.1:53 (IPv4-only, --filter-AAAA)"
    fi
    [ ${#DNS_EXTRA[@]} -gt 0 ] && \
        echo "[net] pinned to ${KAIROS_DNS_TARGET:-192.168.100.1}: ${KAIROS_DNS_HOSTS}"
else
    echo "[net] WARN: dnsmasq not installed; guest DNS may fail"
fi

echo "[net] done."
