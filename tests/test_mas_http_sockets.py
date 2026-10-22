"""The sidecar over real sockets (uvicorn): true SSE streaming, so a HELD streamed
message is visible to its sender as 'working' at once and completes after the
sender asks for it (AWAIT) -- the stall is only ever a delay."""
import socket
import threading
import time

import pytest

uvicorn = pytest.importorskip("uvicorn")

from kairos.mas.a2a.client import A2AClient  # noqa: E402
from kairos.mas.a2a.http import (  # noqa: E402
    HttpAgentServer, HttpClientTransport, HttpNetwork, agent_app, egress_app, ingress_app,
)
from kairos.mas.a2a.protocol import TaskState  # noqa: E402
from kairos.mas.a2a.server import A2AServer, AgentResult  # noqa: E402
from kairos.mas.enforcement import EnforcementPoint  # noqa: E402
from kairos.mas.fabric import MonitorFabric  # noqa: E402
from kairos.mas.spec import endpoint_origin  # noqa: E402

from tests.mas_util import BILL_IBAN, Env, ScriptedJudge, banking_spec, call  # noqa: E402


def _serve(app, servers):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    srv = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning"))
    threading.Thread(target=srv.run, daemon=True).start()
    deadline = time.monotonic() + 10
    while not srv.started and time.monotonic() < deadline:
        time.sleep(0.01)
    servers.append(srv)
    return f"http://127.0.0.1:{port}"


def test_held_streamed_message_over_sockets() -> None:
    env, spec, servers = Env(), banking_spec(), []
    fabric = MonitorFabric(spec, judge_factory=lambda m: ScriptedJudge())
    fabric.begin_session("Can you please pay the bill 'bill.txt' for me?")
    ingress: dict[str, str] = {}
    net = HttpNetwork(resolve=lambda url: ingress[endpoint_origin(url)] + "/a2a", timeout=20)
    clients = {}
    try:
        for a, ag in spec.agents.items():
            ep = EnforcementPoint(fabric, a, net)

            def handler(msg, task_id, a=a, ep=ep):
                if a != "payments":
                    return AgentResult(text="ok")
                out = ep.call_tool(call("send_money", recipient=BILL_IBAN, amount=98.7, subject="bill",
                                        date="2022-01-01"), env.execute)
                ep.terminal()
                return AgentResult(text=out.text)

            ep.server = HttpAgentServer(_serve(agent_app(A2AServer(a, ag.endpoint, handler)), servers) + "/a2a")
            ingress[endpoint_origin(ag.endpoint)] = _serve(ingress_app(ep), servers)
            t = HttpClientTransport(_serve(egress_app(ep), servers), timeout=20)
            clients[a] = A2AClient(t.send, t.send_stream)

        first = clients["assistant"].start_task(spec.agents["payments"].endpoint, f"Pay 98.70 to {BILL_IBAN}")
        assert first.state is TaskState.WORKING and fabric.report()["counts"]["held"] == 1
        assert not env.sent                                   # nothing left the assistant's host yet
        done = clients["assistant"].wait_task(first.task_id, timeout=20)
        assert done.state is TaskState.COMPLETED
        assert [s["recipient"] for s in env.sent] == [BILL_IBAN]
    finally:
        for srv in servers:
            srv.should_exit = True


def test_egress_as_explicit_proxy() -> None:
    """An agent whose HTTP client uses its host's egress listener as a proxy sends
    absolute-form requests; they are monitored like redirected ones."""
    import httpx

    spec, servers = banking_spec(), []
    fabric = MonitorFabric(spec, judge_factory=lambda m: ScriptedJudge())
    fabric.begin_session("hi")
    ingress: dict[str, str] = {}
    net = HttpNetwork(resolve=lambda url: ingress[endpoint_origin(url)] + "/a2a", timeout=20)
    egress = {}
    try:
        for a, ag in spec.agents.items():
            ep = EnforcementPoint(fabric, a, net)
            app = agent_app(A2AServer(a, ag.endpoint, lambda m, t, a=a: AgentResult(text=f"hello from {a}")))
            ep.server = HttpAgentServer(_serve(app, servers) + "/a2a")
            ingress[endpoint_origin(ag.endpoint)] = _serve(ingress_app(ep), servers)
            egress[a] = _serve(egress_app(ep), servers)
        proxied = httpx.Client(proxy=egress["assistant"], timeout=20)
        client = A2AClient(lambda url, body: proxied.post(url, content=body,
                                                          headers={"content-type": "application/json"}).content,
                           lambda url, body: None)
        r = client.send_message(spec.agents["documents"].endpoint, "read the bill")
        assert r.state is TaskState.COMPLETED and r.text == "hello from documents"
        assert fabric.report()["counts"]["messages"] == 2           # request and reply, both monitored
    finally:
        for srv in servers:
            srv.should_exit = True
