"""The network between agent hosts, as the enforcement points see it.

Every agent runs on a *host*. The host's enforcement point (EP) sits at its boundary:
the agent's outgoing A2A requests leave through it, and incoming requests reach the
agent's own A2A server only through it. This module is the plumbing between hosts:

* `Network` is how an EP sends: a request/response call (`request`), or a call whose
  answer arrives as a stream of events (`stream`).
* `ServerSide` is what a host offers the network: the server side of its EP.
* `InProcessNetwork` connects hosts that live in one Python process (the tests and
  the benchmark). A deployment uses the HTTP network in `kairos.mas.a2a.http`.
* `EventStream` carries one streamed answer (A2A's SendStreamingMessage, for one): a
  queue of events that ends when the sending side closes it.

What travels is raw protocol bytes (A2A JSON-RPC) plus a small dictionary of *monitor
headers*. Only enforcement points read and write those headers, and agents never see
them. The most important one carries the monitor's message id (`KMID_HEADER`). Over
HTTP they become `x-kairos-*` headers between the two hosts' sidecars.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Iterator
from typing import Protocol

from kairos.mas.spec import endpoint_origin

# The monitor's message id ("kmid") of the content a request or response carries. The
# sending enforcement point sets it; the receiving one checks it against the message
# registry and consumes it. It is a single-use capability for exactly the bytes that
# were released.
KMID_HEADER = "x-kairos-message"

Headers = dict[str, str]


class EventStream:
    """One streamed response: a sequence of (event bytes, headers) until closed.

    Producers call `put` and finally `close`; consumers iterate (or call `get`) until
    the stream ends. Several threads may produce or consume at the same time.
    """

    # Marker put into the queue on close; never handed out to a reader.
    _CLOSED = object()

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._closed = threading.Event()
        # Every event ever put, in order. The HTTP transport looks at it to tell a
        # stream that failed before its first event from one that simply ended.
        self.history: list[tuple[bytes, Headers]] = []
        self._lock = threading.Lock()

    def put(self, body: bytes, headers: Headers | None = None) -> None:
        """Add one event. Events put after `close` are dropped."""
        with self._lock:
            if self._closed.is_set():
                return
            item = (body, dict(headers or {}))
            self.history.append(item)
            self._q.put(item)

    def close(self) -> None:
        """End the stream (idempotent). Readers get every event put before this."""
        with self._lock:
            if not self._closed.is_set():
                self._closed.set()
                self._q.put(self._CLOSED)

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def get(self, timeout: float | None = None) -> tuple[bytes, Headers] | None:
        """The next event, or None when the stream is closed (or `timeout` passed)."""
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        if item is self._CLOSED:
            # Put the marker back so that every later reader sees the end too.
            self._q.put(self._CLOSED)
            return None
        return item

    def __iter__(self) -> Iterator[tuple[bytes, Headers]]:
        while True:
            item = self.get()
            if item is None:
                return
            yield item


class ServerSide(Protocol):
    """The server side of an agent host: its enforcement point in front of its
    A2A server."""
    def serve(self, body: bytes, headers: Headers) -> tuple[bytes, Headers]: ...
    def serve_stream(self, body: bytes, headers: Headers) -> EventStream: ...


class Network(Protocol):
    """How an enforcement point reaches other hosts (by URL)."""
    def request(self, url: str, body: bytes, headers: Headers) -> tuple[bytes, Headers]: ...
    def stream(self, url: str, body: bytes, headers: Headers) -> EventStream: ...


class UnreachableError(ConnectionError):
    """No host listens at the URL."""


class InProcessNetwork:
    """Hosts in one process, found by the origin (scheme://host:port) of a URL.

    Routing by origin rather than by the full URL means any path at an agent's
    endpoint reaches that agent, as it would over HTTP.
    """

    def __init__(self) -> None:
        self._hosts: dict[str, ServerSide] = {}

    def register(self, url: str, host: ServerSide) -> None:
        self._hosts[endpoint_origin(url)] = host

    def _host(self, url: str) -> ServerSide:
        host = self._hosts.get(endpoint_origin(url))
        if host is None:
            raise UnreachableError(f"no agent listens at {url}")
        return host

    def request(self, url: str, body: bytes, headers: Headers) -> tuple[bytes, Headers]:
        return self._host(url).serve(body, headers)

    def stream(self, url: str, body: bytes, headers: Headers) -> EventStream:
        return self._host(url).serve_stream(body, headers)
