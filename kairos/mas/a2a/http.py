"""A2A over HTTP, and the enforcement point as a sidecar proxy.

An agent host in a deployment has three HTTP listeners:

  agent    the agent's own A2A server (private; only the host's ingress reaches it)
  ingress  the agent's PUBLIC endpoint: the enforcement point's server side. Other
           hosts' requests arrive here; the reply goes back through it.
  egress   where the agent's outbound traffic goes -- redirected by the host
           firewall (transparent: the target is rebuilt from the Host header, as a
           transparent HTTP proxy does) or configured as the agent's HTTP proxy
           (absolute-form request target). The enforcement point's client side.

The agent is unmodified: it serves A2A and sends A2A. The monitor's message ids
travel between ingress and egress listeners as HTTP headers (x-kairos-*); on a
stream they ride as SSE comment lines, which SSE clients ignore. Hosts trust each
other's listeners (they are the TCB); authenticating them (e.g. mTLS between
hosts) is a deployment concern outside this module.

All endpoints are synchronous (Starlette runs them in its thread pool): an
enforcement decision may block on the oracle, and a stalled message must not stall
the event loop.
"""
from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from typing import Any

import anyio.from_thread
import httpx
from starlette.applications import Starlette
from starlette.requests import Request as HttpRequest
from starlette.responses import JSONResponse, Response, StreamingResponse
from starlette.routing import Route

from kairos.mas.a2a.protocol import Method, ProtocolError, parse_request
from kairos.mas.a2a.server import A2AServer
from kairos.mas.transport import EventStream, Headers

MONITOR_PREFIX = "x-kairos-"
SSE = "text/event-stream"


def _is_streaming(body: bytes) -> bool:
    try:
        return parse_request(body).method in (Method.STREAM, Method.RESUBSCRIBE)
    except ProtocolError:
        return False


def _monitor_headers(headers: Any) -> Headers:
    return {k.lower(): v for k, v in headers.items() if k.lower().startswith(MONITOR_PREFIX)}


def sse_encode(body: bytes, headers: Headers | None = None) -> bytes:
    """One SSE event; monitor headers as comment lines (ignored by SSE clients)."""
    comments = b"".join(f": {k}={v}\n".encode() for k, v in (headers or {}).items())
    return comments + b"data: " + body + b"\n\n"


def sse_events(lines: Iterator[str]) -> Iterator[tuple[bytes, Headers]]:
    data: list[str] = []
    hdrs: Headers = {}
    for line in lines:
        if line == "":
            if data:
                yield "\n".join(data).encode(), hdrs
            data, hdrs = [], {}
        elif line.startswith(":"):
            k, _, v = line[1:].strip().partition("=")
            if k.startswith(MONITOR_PREFIX):
                hdrs[k] = v
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        yield "\n".join(data).encode(), hdrs


def _stream_response(stream: EventStream, *, monitor: bool) -> StreamingResponse:
    def gen() -> Iterator[bytes]:
        for body, hdrs in stream:
            yield sse_encode(body, hdrs if monitor else None)
    return StreamingResponse(gen(), media_type=SSE)


# --- the agent's own server -------------------------------------------------------
def agent_app(server: A2AServer, path: str = "/a2a") -> Starlette:
    """An unmodified agent's A2A endpoint (JSON-RPC; SSE for streaming methods)."""

    def rpc(request: HttpRequest) -> Response:
        body = read_body(request)
        if _is_streaming(body):
            return _stream_response(server.handle_stream(body), monitor=False)
        return Response(server.handle(body), media_type="application/json")

    def card(_request: HttpRequest) -> Response:
        return JSONResponse(server.card.to_dict())

    return Starlette(routes=[Route(path, rpc, methods=["POST"]),
                             Route("/.well-known/agent-card.json", card, methods=["GET"])])


def read_body(request: HttpRequest) -> bytes:
    """The request body, from a synchronous endpoint (Starlette's worker thread)."""
    return anyio.from_thread.run(request.body)


# --- HTTP clients ---------------------------------------------------------------
ClientFactory = Callable[[str], Any]     # base URL -> an httpx.Client-like object


class HttpNetwork:
    """The network as an enforcement point uses it: POST to a peer host's ingress.
    `resolve` maps a spec endpoint to where it is reachable (DNS in a deployment)."""

    def __init__(self, *, resolve: Callable[[str], str] | None = None,
                 client: ClientFactory | None = None, timeout: float = 300.0) -> None:
        self.resolve = resolve or (lambda u: u)
        self._client = client or (lambda _base: httpx.Client(timeout=timeout))
        self.timeout = timeout

    def request(self, url: str, body: bytes, headers: Headers) -> tuple[bytes, Headers]:
        target = self.resolve(url)
        r = self._client(target).post(target, content=body,
                                      headers={**headers, "content-type": "application/json"})
        return r.content, _monitor_headers(r.headers)

    def stream(self, url: str, body: bytes, headers: Headers) -> EventStream:
        target = self.resolve(url)
        out = EventStream()
        client = self._client(target)
        ready = threading.Event()
        failure: list[BaseException] = []

        def pump() -> None:
            try:
                with client.stream("POST", target, content=body,
                                   headers={**headers, "content-type": "application/json",
                                            "accept": SSE}) as r:
                    ready.set()
                    for ev, hdrs in sse_events(r.iter_lines()):
                        out.put(ev, hdrs)
            except BaseException as e:            # noqa: BLE001 — surfaced to the caller
                failure.append(e)
                ready.set()
            finally:
                out.close()

        threading.Thread(target=pump, daemon=True).start()
        ready.wait(self.timeout)
        if failure and not out.history:
            raise ConnectionError(str(failure[0]))
        return out


class HttpAgentServer:
    """The ingress's view of the agent behind it: its private A2A endpoint."""

    def __init__(self, url: str, *, client: ClientFactory | None = None, timeout: float = 300.0) -> None:
        self.url = url
        self._net = HttpNetwork(client=client, timeout=timeout)

    def handle(self, body: bytes) -> bytes:
        return self._net.request(self.url, body, {})[0]

    def handle_stream(self, body: bytes) -> EventStream:
        return self._net.stream(self.url, body, {})


class HttpClientTransport:
    """An agent's A2A client transport when its traffic is redirected to the host's
    egress listener: connect there, keep the target in the Host header."""

    def __init__(self, egress: str, *, client: Any = None, timeout: float = 300.0) -> None:
        self.egress = egress.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout)

    def _req(self, url: str) -> tuple[str, dict[str, str]]:
        u = httpx.URL(url)
        return self.egress + u.raw_path.decode(), {"host": u.netloc.decode()}

    def send(self, url: str, body: bytes) -> bytes:
        target, hdrs = self._req(url)
        return self._client.post(target, content=body, headers={**hdrs, "content-type": "application/json"}).content

    def send_stream(self, url: str, body: bytes) -> EventStream:
        target, hdrs = self._req(url)
        out = EventStream()

        def pump() -> None:
            try:
                with self._client.stream("POST", target, content=body,
                                         headers={**hdrs, "content-type": "application/json"}) as r:
                    for ev, _ in sse_events(r.iter_lines()):
                        out.put(ev)
            finally:
                out.close()

        threading.Thread(target=pump, daemon=True).start()
        return out


# --- the enforcement point as a sidecar -----------------------------------------
def ingress_app(ep: Any, path: str = "/a2a") -> Starlette:
    """The agent's public endpoint: the enforcement point's server side."""

    def rpc(request: HttpRequest) -> Response:
        body = read_body(request)
        hdrs = _monitor_headers(request.headers)
        if _is_streaming(body):
            return _stream_response(ep.serve_stream(body, hdrs), monitor=True)
        resp, out = ep.serve(body, hdrs)
        return Response(resp, media_type="application/json", headers=out)

    def card(_request: HttpRequest) -> Response:
        return JSONResponse(ep.server.card.to_dict()) if hasattr(ep.server, "card") else JSONResponse({})

    return Starlette(routes=[Route(path, rpc, methods=["POST"]),
                             Route("/.well-known/agent-card.json", card, methods=["GET"])])


def egress_app(ep: Any) -> Any:
    """Where the agent's outbound requests land: the enforcement point's client
    side. The target is the absolute request URI (explicit proxy) or Host + path
    (transparent redirect).

    An ASGI server hands an absolute-form target ("POST http://peer/a2a") through
    as the path, which no route matches; the wrapper routes it while the target
    stays in raw_path."""

    def forward(request: HttpRequest) -> Response:
        body = read_body(request)
        raw = request.scope.get("raw_path", b"").decode() or request.url.path
        if raw.startswith(("http://", "https://")):
            target = raw
        else:
            target = f"http://{request.headers.get('host', '')}{raw}"
        if _is_streaming(body):
            return _stream_response(ep.send_stream(target, body), monitor=False)
        return Response(ep.send(target, body), media_type="application/json")

    inner = Starlette(routes=[Route("/{path:path}", forward, methods=["POST"])])

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and not scope.get("path", "/").startswith("/"):
            raw = scope.get("raw_path") or scope["path"].encode()
            scope = {**scope, "path": "/", "raw_path": raw}
        await inner(scope, receive, send)

    return app
