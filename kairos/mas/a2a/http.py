"""A2A v1.0 over HTTP (JSON-RPC binding), and the enforcement point as a sidecar proxy.

An agent host in a deployment has three HTTP listeners:

  agent    the agent's own A2A server (private; only the host's ingress reaches it)
  ingress  the agent's PUBLIC endpoint: the enforcement point's server side. Other
           hosts' requests arrive here; the reply goes back through it.
  egress   where the agent's outbound traffic goes -- redirected by the host
           firewall (transparent: the target is rebuilt from the Host header, as a
           transparent HTTP proxy does) or configured as the agent's HTTP proxy
           (absolute-form request target). The enforcement point's client side.

The agent is unmodified: it serves A2A and sends A2A. The A2A service parameters
(A2A-Version, A2A-Extensions) travel as HTTP headers, as the binding specifies; the
monitor's message ids travel between ingress and egress listeners as HTTP headers
too (x-kairos-*), and on a stream as SSE comment lines, which SSE clients ignore.
Only an ingress reads x-kairos-* headers, and only from the network: the egress
never takes them from the agent. Hosts trust each other's listeners (they are the
TCB); authenticating them (e.g. mTLS between hosts) is a deployment concern outside
this module.

The ingress publishes the agent's card from the system spec. The agent's own card
is content the monitor has not checked; discovery must not become a channel past it.

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

from kairos.mas.a2a.protocol import AgentCard, ProtocolError, parse_request, version_headers
from kairos.mas.a2a.server import A2AServer
from kairos.mas.transport import EventStream, Headers

MONITOR_PREFIX = "x-kairos-"
SERVICE_PREFIX = "a2a-"          # A2A service parameters: A2A-Version, A2A-Extensions
JSON = "application/json"
SSE = "text/event-stream"


def _is_streaming(body: bytes) -> bool:
    """Is this a request answered with an SSE stream? (Malformed bodies are not: they
    get an ordinary JSON-RPC error response.)"""
    try:
        return parse_request(body).method.streams
    except ProtocolError:
        return False


def _monitor_headers(headers: Any) -> Headers:
    """The monitor's own headers (x-kairos-*), lower-cased."""
    return {key.lower(): value for key, value in headers.items() if key.lower().startswith(MONITOR_PREFIX)}


def _service_headers(headers: Any) -> Headers:
    """The A2A service parameters (a2a-*), lower-cased."""
    return {key.lower(): value for key, value in headers.items() if key.lower().startswith(SERVICE_PREFIX)}


def sse_encode(body: bytes, headers: Headers | None = None) -> bytes:
    """One SSE event; monitor headers as comment lines (ignored by SSE clients)."""
    comments = b"".join(f": {k}={v}\n".encode() for k, v in (headers or {}).items())
    return comments + b"data: " + body + b"\n\n"


def sse_events(lines: Iterator[str]) -> Iterator[tuple[bytes, Headers]]:
    """Split an SSE stream into (event body, monitor headers). A blank line ends an
    event; comment lines of the form `: x-kairos-...=value` carry the monitor's
    headers for that event."""
    data: list[str] = []
    headers: Headers = {}
    for line in lines:
        if line == "":
            if data:
                yield "\n".join(data).encode(), headers
            data, headers = [], {}
        elif line.startswith(":"):
            key, _, value = line[1:].strip().partition("=")
            if key.startswith(MONITOR_PREFIX):
                headers[key] = value
        elif line.startswith("data:"):
            data.append(line[5:].lstrip())
    if data:
        yield "\n".join(data).encode(), headers


def _stream_response(stream: EventStream, *, monitor: bool) -> StreamingResponse:
    """An EventStream as an SSE response. `monitor`: include the monitor headers as
    comment lines (between hosts only; never toward an agent)."""
    def generate() -> Iterator[bytes]:
        for body, headers in stream:
            yield sse_encode(body, headers if monitor else None)
    return StreamingResponse(generate(), media_type=SSE)


# --- the agent's own server -------------------------------------------------------
def agent_app(server: A2AServer, path: str = "/a2a") -> Starlette:
    """An unmodified agent's A2A endpoint (JSON-RPC; SSE for streaming methods)."""

    def rpc(request: HttpRequest) -> Response:
        body = read_body(request)
        headers = _service_headers(request.headers)
        if _is_streaming(body):
            return _stream_response(server.handle_stream(body, headers), monitor=False)
        return Response(server.handle(body, headers), media_type=JSON)

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
        response = self._client(target).post(target, content=body, headers={**headers, "content-type": JSON})
        return response.content, _monitor_headers(response.headers)

    def stream(self, url: str, body: bytes, headers: Headers) -> EventStream:
        """POST and read the SSE answer in a background thread. Returns once the
        connection is up, so that a host that cannot be reached raises
        ConnectionError here, like `request` does."""
        target = self.resolve(url)
        events = EventStream()
        client = self._client(target)
        ready = threading.Event()
        failure: list[BaseException] = []

        def pump() -> None:
            try:
                with client.stream("POST", target, content=body,
                                   headers={**headers, "content-type": JSON, "accept": SSE}) as response:
                    ready.set()
                    for event_body, event_headers in sse_events(response.iter_lines()):
                        events.put(event_body, event_headers)
            except BaseException as e:            # noqa: BLE001 — surfaced to the caller
                failure.append(e)
                ready.set()
            finally:
                events.close()

        threading.Thread(target=pump, daemon=True).start()
        ready.wait(self.timeout)
        # A failure before the first event is the caller's error; a stream that broke
        # later simply ends.
        if failure and not events.history:
            raise ConnectionError(str(failure[0]))
        return events


class HttpAgentServer:
    """The ingress's view of the agent behind it: its private A2A endpoint."""

    def __init__(self, url: str, *, client: ClientFactory | None = None, timeout: float = 300.0) -> None:
        self.url = url
        self._net = HttpNetwork(client=client, timeout=timeout)

    # Same interface as A2AServer: `headers` None means "an in-process caller", which
    # over HTTP has to say its version explicitly.
    def handle(self, body: bytes, headers: Headers | None = None) -> bytes:
        return self._net.request(self.url, body, dict(headers) if headers is not None else version_headers())[0]

    def handle_stream(self, body: bytes, headers: Headers | None = None) -> EventStream:
        return self._net.stream(self.url, body, dict(headers) if headers is not None else version_headers())


class HttpClientTransport:
    """An agent's A2A client transport when its traffic is redirected to the host's
    egress listener: connect there, keep the target in the Host header."""

    def __init__(self, egress: str, *, client: Any = None, timeout: float = 300.0) -> None:
        self.egress = egress.rstrip("/")
        self._client = client or httpx.Client(timeout=timeout)

    def _req(self, url: str) -> tuple[str, dict[str, str]]:
        """Where to connect (the egress, with the target's path) and the Host header
        that names the real target."""
        parsed = httpx.URL(url)
        return self.egress + parsed.raw_path.decode(), {"host": parsed.netloc.decode()}

    def send(self, url: str, body: bytes, headers: Headers | None = None) -> bytes:
        target, host = self._req(url)
        service = dict(headers) if headers is not None else version_headers()
        return self._client.post(target, content=body, headers={**service, **host, "content-type": JSON}).content

    def send_stream(self, url: str, body: bytes, headers: Headers | None = None) -> EventStream:
        target, host = self._req(url)
        service = dict(headers) if headers is not None else version_headers()
        events = EventStream()

        def pump() -> None:
            try:
                with self._client.stream("POST", target, content=body,
                                         headers={**service, **host, "content-type": JSON,
                                                  "accept": SSE}) as response:
                    for event_body, _ in sse_events(response.iter_lines()):
                        events.put(event_body)
            finally:
                events.close()

        threading.Thread(target=pump, daemon=True).start()
        return events


# --- the enforcement point as a sidecar -----------------------------------------
def ingress_app(ep: Any, path: str = "/a2a") -> Starlette:
    """The agent's public endpoint: the enforcement point's server side."""

    def rpc(request: HttpRequest) -> Response:
        body = read_body(request)
        # From another host's egress: the service parameters and the monitor's headers
        # (the capability of the message, a poll's task reference, the principal token).
        headers = {**_service_headers(request.headers), **_monitor_headers(request.headers)}
        if _is_streaming(body):
            return _stream_response(ep.serve_stream(body, headers), monitor=True)
        response_body, response_headers = ep.serve(body, headers)
        return Response(response_body, media_type=JSON, headers=response_headers)

    def card(_request: HttpRequest) -> Response:
        # Built from the spec, never fetched from the agent (see the module docstring).
        agent = ep.spec.agents[ep.agent_id]
        return JSONResponse(AgentCard(name=agent.id, url=agent.endpoint,
                                      description=agent.description).to_dict())

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
        headers = _service_headers(request.headers)          # never the agent's x-kairos-* headers
        if _is_streaming(body):
            return _stream_response(ep.send_stream(target, body, headers), monitor=False)
        return Response(ep.send(target, body, headers), media_type=JSON)

    inner = Starlette(routes=[Route("/{path:path}", forward, methods=["POST"])])

    async def app(scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope["type"] == "http" and not scope.get("path", "/").startswith("/"):
            raw = scope.get("raw_path") or scope["path"].encode()
            scope = {**scope, "path": "/", "raw_path": raw}
        await inner(scope, receive, send)

    return app
