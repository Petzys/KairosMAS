#!/bin/bash
#
# Network channel — transparent-proxy iptables rules  (M3)
# ========================================================
# Redirects the guest's outbound TCP into the local mitmproxy (:8080) so every
# connection is intercepted. This re-adds the REDIRECT that the M1 NAT setup
# purges — the difference is that now there IS a listener on :8080.
#
#   up   (default) install the redirect + input-accept rules
#   down          remove them (revert to plain NAT egress)
#
# DNS (:53 -> dnsmasq) and traffic already headed at the proxy are excluded so
# there is no redirect loop.
#
# Strict boundary (KAIROS_NET_STRICT=1): the guest's only paths off the VM are the
# proxy (:8080) and the DNS sinkhole (:53); everything else is dropped, and nothing
# is forwarded. Concretely, in addition to the redirect above:
#   * every DNS query, whatever server the guest names, is redirected to the local
#     dnsmasq (which answers all names with the bridge address, see setup_net_nat.sh);
#   * INPUT from the guest accepts only :8080 and :53 — the control plane (:8090),
#     the host's other services and ICMP are unreachable;
#   * FORWARD from the guest is dropped (no UDP, no QUIC, no direct IP egress);
#   * IPv6 from the bridge is dropped, in INPUT and FORWARD.
# The rules that must sit ABOVE the M1 accepts are (re)inserted at the top on every
# `up`, so a stale rule left by a crashed session cannot reorder them.
#
# KAIROS_IPT_DRY_RUN=1 prints the iptables commands instead of running them.
#
set -uo pipefail
BR=br0
GUEST=192.168.100.2
GW=192.168.100.1
PORT=8080
ACT="${1:-up}"
STRICT="${KAIROS_NET_STRICT:-0}"
DRY="${KAIROS_IPT_DRY_RUN:-0}"

ipt()  { if [ "$DRY" = 1 ]; then echo "iptables $*"; else iptables "$@"; fi; }
ipt6() { if [ "$DRY" = 1 ]; then echo "ip6tables $*"; else ip6tables "$@"; fi; }
add() {  # idempotent append: add <table> <spec...>
    local tbl="$1"; shift
    if [ "$DRY" = 1 ]; then ipt -t "$tbl" -A "$@"; return; fi
    iptables -t "$tbl" -C "$@" 2>/dev/null || iptables -t "$tbl" -A "$@"
}
addi() { # idempotent insert-at-top for INPUT
    if [ "$DRY" = 1 ]; then ipt -I "$@"; return; fi
    iptables -C "$@" 2>/dev/null || iptables -I "$@"
}
addtop() { # delete if present, then insert at position 1 (order-sensitive strict rules)
    local chain="$1"; shift
    if [ "$DRY" = 1 ]; then ipt -D "$chain" "$@"; ipt -I "$chain" 1 "$@"; return; fi
    while iptables -C "$chain" "$@" 2>/dev/null; do iptables -D "$chain" "$@"; done
    iptables -I "$chain" 1 "$@"
}
addtop6() {
    local chain="$1"; shift
    command -v ip6tables >/dev/null 2>&1 || return 0
    if [ "$DRY" = 1 ]; then ipt6 -D "$chain" "$@"; ipt6 -I "$chain" 1 "$@"; return; fi
    while ip6tables -C "$chain" "$@" 2>/dev/null; do ip6tables -D "$chain" "$@"; done
    ip6tables -I "$chain" 1 "$@" 2>/dev/null || true
}
addtop_nat() { # delete if present, then insert at position 1 of a nat chain
    local chain="$1"; shift
    if [ "$DRY" = 1 ]; then ipt -t nat -D "$chain" "$@"; ipt -t nat -I "$chain" 1 "$@"; return; fi
    while iptables -t nat -C "$chain" "$@" 2>/dev/null; do iptables -t nat -D "$chain" "$@"; done
    iptables -t nat -I "$chain" 1 "$@"
}
del() {
    local tbl="$1"; shift
    if [ "$DRY" = 1 ]; then ipt -t "$tbl" -D "$@"; return; fi
    iptables -t "$tbl" -D "$@" 2>/dev/null || true
}
del6() {
    command -v ip6tables >/dev/null 2>&1 || return 0
    if [ "$DRY" = 1 ]; then ipt6 -D "$@"; return; fi
    ip6tables -D "$@" 2>/dev/null || true
}

strict_down() {   # remove the strict rules (idempotent; also run on a plain `down`)
    del nat PREROUTING -i "$BR" -s "$GUEST" -p udp --dport 53 -j REDIRECT --to-ports 53
    del nat PREROUTING -i "$BR" -s "$GUEST" -p tcp --dport 53 -j REDIRECT --to-ports 53
    del filter INPUT -i "$BR" -s "$GUEST" -p tcp --dport "$PORT" -j ACCEPT
    del filter INPUT -i "$BR" -s "$GUEST" -p udp --dport 53 -j ACCEPT
    del filter INPUT -i "$BR" -s "$GUEST" -p tcp --dport 53 -j ACCEPT
    del filter INPUT -i "$BR" -s "$GUEST" -j DROP
    del filter FORWARD -i "$BR" -s "$GUEST" -j DROP
    del6 INPUT -i "$BR" -j DROP
    del6 FORWARD -i "$BR" -j DROP
}

if [ "$ACT" = "down" ]; then
    del nat PREROUTING -i "$BR" -s "$GUEST" -p tcp --dport 53 -j RETURN
    del nat PREROUTING -i "$BR" -s "$GUEST" -d "$GW" -p tcp --dport "$PORT" -j RETURN
    del nat PREROUTING -i "$BR" -s "$GUEST" -p tcp -j REDIRECT --to-ports "$PORT"
    if [ "$DRY" = 1 ]; then ipt -D INPUT -i "$BR" -s "$GUEST" -p tcp --dport "$PORT" -j ACCEPT
    else iptables -D INPUT -i "$BR" -s "$GUEST" -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || true; fi
    strict_down
    echo "[proxy-rules] removed (plain NAT egress restored)"
    exit 0
fi

# transparent proxy needs these to avoid redirect loops / mis-DNAT on bridges
if [ "$DRY" != 1 ]; then
    sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null 2>&1 || true
    [ -f /proc/sys/net/bridge/bridge-nf-call-iptables ] && \
        sysctl -w net.bridge.bridge-nf-call-iptables=0 >/dev/null 2>&1 || true
fi

if [ "$STRICT" = 1 ]; then
    # every DNS query goes to the local sinkhole resolver, whatever server the guest
    # names. Inserted at the TOP of the chain: they must precede the generic TCP
    # redirect, which may already be in place from an earlier session.
    del nat PREROUTING -i "$BR" -s "$GUEST" -p tcp --dport 53 -j RETURN
    addtop_nat PREROUTING -i "$BR" -s "$GUEST" -p udp --dport 53 -j REDIRECT --to-ports 53
    addtop_nat PREROUTING -i "$BR" -s "$GUEST" -p tcp --dport 53 -j REDIRECT --to-ports 53
else
    # exclude DNS (it goes to dnsmasq on the bridge address directly)
    add nat PREROUTING -i "$BR" -s "$GUEST" -p tcp --dport 53 -j RETURN
fi
# exclude the proxy port itself, then redirect everything else
add nat PREROUTING -i "$BR" -s "$GUEST" -d "$GW" -p tcp --dport "$PORT" -j RETURN
add nat PREROUTING -i "$BR" -s "$GUEST" -p tcp -j REDIRECT --to-ports "$PORT"

if [ "$STRICT" = 1 ]; then
    # host side, top of INPUT (last inserted ends up first): proxy, DNS, then DROP the rest
    addtop INPUT -i "$BR" -s "$GUEST" -j DROP
    addtop INPUT -i "$BR" -s "$GUEST" -p tcp --dport 53 -j ACCEPT
    addtop INPUT -i "$BR" -s "$GUEST" -p udp --dport 53 -j ACCEPT
    addtop INPUT -i "$BR" -s "$GUEST" -p tcp --dport "$PORT" -j ACCEPT
    # nothing is forwarded for the guest: no UDP, no QUIC, no direct IP egress
    addtop FORWARD -i "$BR" -s "$GUEST" -j DROP
    # and no IPv6 at all from the bridge
    addtop6 INPUT -i "$BR" -j DROP
    addtop6 FORWARD -i "$BR" -j DROP
    echo "[proxy-rules] STRICT: guest TCP -> mitmproxy :$PORT, all DNS -> sinkhole :53, everything else dropped (no forwarding, no IPv6)"
else
    addi INPUT -i "$BR" -s "$GUEST" -p tcp --dport "$PORT" -j ACCEPT
    echo "[proxy-rules] guest TCP -> mitmproxy :$PORT (DNS + proxy port excluded)"
fi
