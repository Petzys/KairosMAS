"""
Strict network boundary — upstream policy behind the DNS sinkhole  (KAIROS_NET_STRICT=1)
=======================================================================================
Pure policy, no mitmproxy import, so it is unit-testable (tests/test_sinkhole_policy.py).

In strict mode the guest never resolves a name: dnsmasq answers EVERY query with the
bridge address (the "sinkhole"), so no query leaves the host and every TCP connection the
guest opens lands on the transparent proxy with original destination <GW>:<port>. The
proxy must then pick the real upstream itself, from the TLS SNI or the HTTP Host header,
and this module decides whether that upstream is permitted:

  * a name pinned by KAIROS_DNS_HOSTS goes to KAIROS_DNS_TARGET (e.g. a local endpoint
    such as deploy/bench/sink.py), on KAIROS_NET_PINNED_PORTS only (default 80,443);
  * any other name is resolved with the HOST's resolver, and every address it yields must
    be globally routable: never loopback, link-local, the bridge subnet or a LAN address,
    so a rebinding name cannot point the proxy at the host's own services;
  * an IP literal (Host header or original destination) must be globally routable too.

Everything else is refused. A flow that carries neither SNI nor Host header (raw TCP) has
no name to check and is refused as well; strict mode admits HTTP(S) only.
"""
from __future__ import annotations

import ipaddress
import os
import socket
import time
from dataclasses import dataclass
from typing import Callable, Iterable, Optional, Union

GW = os.environ.get("KAIROS_NET_GW", "192.168.100.1")
STRICT = os.environ.get("KAIROS_NET_STRICT", "0").strip().lower() in ("1", "true", "yes", "on")
# Upstream given to a refused non-HTTP flow: nothing listens there, so the proxy's connect
# fails at once and the guest sees a reset instead of a relay.
DEAD = ("127.0.0.1", 1)


def _csv(v: str) -> list[str]:
    return [x.strip().lower() for x in v.split(",") if x.strip()]


PINNED = frozenset(_csv(os.environ.get("KAIROS_DNS_HOSTS", "")))
TARGET = os.environ.get("KAIROS_DNS_TARGET", GW)
PINNED_PORTS = frozenset(int(p) for p in _csv(os.environ.get("KAIROS_NET_PINNED_PORTS", "80,443")))


@dataclass(frozen=True)
class Upstream:
    ip: str
    port: int
    how: str            # pinned | literal | resolved


@dataclass(frozen=True)
class Refusal:
    reason: str


Decision = Union[Upstream, Refusal]
Resolver = Callable[[str, int], Iterable[str]]


def is_sinkhole(addr, gw: str = GW) -> bool:
    """Is this (host, port) the sinkhole address every guest lookup was answered with?"""
    return bool(addr) and addr[0] == gw


def is_global_ip(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.is_global and not a.is_multicast


def parse_authority(authority: str, default_port: int) -> Optional[tuple[str, int]]:
    """'example.com' | 'example.com:8443' | '[::1]:80' | '1.2.3.4:80' -> (host, port)."""
    a = (authority or "").strip()
    if not a:
        return None
    if a.startswith("["):                       # bracketed IPv6 literal
        end = a.find("]")
        if end < 0:
            return None
        host, rest = a[1:end], a[end + 1:]
        if rest and not rest.startswith(":"):
            return None
        port_s = rest[1:] if rest else ""
    elif a.count(":") == 1:
        host, port_s = a.split(":", 1)
    else:
        host, port_s = a, ""
    host = host.strip().rstrip(".").lower()
    if not host:
        return None
    if port_s:
        if not port_s.isdigit():
            return None
        port = int(port_s)
        if not 0 < port < 65536:
            return None
    else:
        port = default_port
    return host, port


def system_resolver(name: str, port: int) -> list[str]:
    """The HOST's resolver (never the guest's sinkhole). IPv4 only: the guest is single-stack
    and the proxy connects upstream over IPv4."""
    infos = socket.getaddrinfo(name, port, socket.AF_INET, socket.SOCK_STREAM)
    out: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in out:
            out.append(ip)
    return out


class CachedResolver:
    """Small TTL cache in front of a resolver, so a busy agent does not re-resolve the
    same name for every connection."""

    def __init__(self, resolver: Resolver = system_resolver, ttl_s: float = 60.0,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self._resolver = resolver
        self._ttl = ttl_s
        self._clock = clock
        self._cache: dict[tuple[str, int], tuple[float, list[str]]] = {}

    def __call__(self, name: str, port: int) -> list[str]:
        key = (name, port)
        now = self._clock()
        hit = self._cache.get(key)
        if hit and hit[0] > now:
            return hit[1]
        addrs = list(self._resolver(name, port))
        self._cache[key] = (now + self._ttl, addrs)
        return addrs


def decide_upstream(name: Optional[str], port: int, *,
                    pinned: Iterable[str] = PINNED, target: str = TARGET,
                    pinned_ports: Iterable[int] = PINNED_PORTS,
                    resolver: Resolver = system_resolver) -> Decision:
    """The upstream for a connection the guest addressed by NAME (SNI or Host header)."""
    name = (name or "").strip().rstrip(".").lower()
    if not name:
        return Refusal("no destination name (no SNI and no Host header)")
    if name in set(pinned):
        if port not in set(pinned_ports):
            return Refusal(f"pinned host {name} is not permitted on port {port}")
        return Upstream(target, port, "pinned")
    try:
        ipaddress.ip_address(name)
        literal = True
    except ValueError:
        literal = False
    if literal:
        if is_global_ip(name):
            return Upstream(name, port, "literal")
        return Refusal(f"non-global address {name}")
    try:
        addrs = list(resolver(name, port))
    except Exception as e:  # NXDOMAIN, timeout, ...
        return Refusal(f"cannot resolve {name}: {e.__class__.__name__}")
    if not addrs:
        return Refusal(f"cannot resolve {name}: no address")
    for ip in addrs:
        if not is_global_ip(ip):
            return Refusal(f"{name} resolves to non-global address {ip}")
    return Upstream(addrs[0], port, "resolved")


def check_address(ip: str, port: int, *, target: str = TARGET,
                  pinned_ports: Iterable[int] = PINNED_PORTS) -> Decision:
    """The upstream for a connection whose destination is already an address: an IP literal
    the guest connected to directly, or what an earlier stage resolved."""
    if ip == target and port in set(pinned_ports):
        return Upstream(ip, port, "pinned")
    if is_global_ip(ip):
        return Upstream(ip, port, "literal")
    return Refusal(f"non-global address {ip}")
