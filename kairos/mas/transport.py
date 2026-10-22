"""The network between agent hosts, as the enforcement points see it.

Requests and responses are raw protocol bytes (A2A JSON-RPC); next to them travel
the monitor's own headers, which only enforcement points read and write. The
in-process network routes a URL to the server side of the destination host; an
HTTP deployment routes it over the wire (kairos.mas.a2a.http), with the headers as
HTTP headers between the two hosts' proxies.
"""
from __future__ import annotations

import queue
import threading
from collections.abc import Iterator
from typing import Protocol

from kairos.mas.spec import endpoint_origin

# The monitor's message id of the content a request/response carries. Set by the
# sending enforcement point, consumed (and stripped) by the receiving one.
KMID_HEADER = "x-kairos-message"

Headers = dict[str, str]


class EventStream:
    """One streamed response: a sequence of (event bytes, headers) until closed."""

    _CLOSED = object()

    def __init__(self) -> None:
        self._q: queue.Queue = queue.Queue()
        self._closed = threading.Event()
        self.history: list[tuple[bytes, Headers]] = []
        self._lock = threading.Lock()

    def put(self, body: bytes, headers: Headers | None = None) -> None:
        with self._lock:
            if self._closed.is_set():
                return
            item = (body, dict(headers or {}))
            self.history.append(item)
            self._q.put(item)

    def close(self) -> None:
        with self._lock:
            if not self._closed.is_set():
                self._closed.set()
                self._q.put(self._CLOSED)

    @property
    def closed(self) -> bool:
        return self._closed.is_set()

    def get(self, timeout: float | None = None) -> tuple[bytes, Headers] | None:
        """Next event; None when the stream is closed (or on timeout)."""
        try:
            item = self._q.get(timeout=timeout)
        except queue.Empty:
            return None
        if item is self._CLOSED:
            self._q.put(self._CLOSED)        # stay closed for later readers
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
    def request(self, url: str, body: bytes, headers: Headers) -> tuple[bytes, Headers]: ...
    def stream(self, url: str, body: bytes, headers: Headers) -> EventStream: ...


class UnreachableError(ConnectionError):
    pass


class InProcessNetwork:
    """Routes by endpoint origin to registered host server sides."""

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
