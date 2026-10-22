"""Run KAIROS MAS in front of real, unmodified A2A agents.

    python -m kairos.mas.serve --spec kairos/mas/config/banking.yaml --hosts hosts.yaml

hosts.yaml maps every agent of the spec to its host:

    assistant: {agent: "http://10.0.0.2:8000/a2a", ingress: "0.0.0.0:9101", egress: "0.0.0.0:9201"}
    payments:  {agent: "http://10.0.0.3:8000/a2a", ingress: "0.0.0.0:9102", egress: "0.0.0.0:9202",
                address: "http://10.0.0.1:9102/a2a"}

  agent    the agent's own (private) A2A endpoint
  ingress  where this agent's PUBLIC endpoint (the spec's `endpoint`) is served
  egress   where the agent's outbound A2A traffic must arrive: point the agent's HTTP
           proxy at it (absolute-form requests), or redirect its traffic there with the
           host firewall (the target is rebuilt from the Host header)
  address  how other hosts reach this ingress (default: http://<ingress>/a2a)

This process holds every decision point (the central monitor) and every host's
listeners. The principal starts a session on the control endpoint:

    POST /session {"prompt": "..."}   -> seeds T_0, sends the prompt to the entry agent,
                                         returns its answer and the session report
    GET  /report                      -> the current session report

Oracle: deterministic by default; --oracle llm uses the lineage-aware LLM oracle
(KAIROS_JUDGE_MODEL, KAIROS_JUDGE_BASE_URL, KAIROS_JUDGE_API_KEY or OPENAI_API_KEY).
"""
from __future__ import annotations

import argparse
import json
import os
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import openai
import uvicorn
import yaml
from starlette.applications import Starlette
from starlette.requests import Request as HttpRequest
from starlette.responses import JSONResponse
from starlette.routing import Route

from kairos.judge.oracle import DeterministicJudge
from kairos.mas.a2a.client import A2AClient
from kairos.mas.a2a.http import HttpAgentServer, HttpNetwork, egress_app, ingress_app, read_body
from kairos.mas.enforcement import EnforcementPoint
from kairos.mas.fabric import MonitorFabric
from kairos.mas.oracle import MASJudge
from kairos.mas.spec import MASSpec, endpoint_origin
from kairos.mas.spec_parser import load_spec


@dataclass(slots=True)
class HostConfig:
    agent: str           # the agent's private A2A URL
    ingress: str         # host:port to listen on for its public endpoint
    egress: str          # host:port to listen on for its outbound traffic
    address: str = ""    # how peers reach the ingress (URL)

    def ingress_url(self) -> str:
        return self.address or f"http://{self.ingress}/a2a"


def load_hosts(path: str | Path) -> dict[str, HostConfig]:
    raw = yaml.safe_load(Path(path).read_text()) or {}
    return {a: HostConfig(**{k: str(v) for k, v in d.items()}) for a, d in raw.items()}


def judge_factory(kind: str):
    if kind == "deterministic":
        return lambda _m: DeterministicJudge()
    key = os.environ.get("KAIROS_JUDGE_API_KEY") or os.environ.get("OPENAI_API_KEY")
    kwargs: dict[str, Any] = {"api_key": key}
    if os.environ.get("KAIROS_JUDGE_BASE_URL"):
        kwargs["base_url"] = os.environ["KAIROS_JUDGE_BASE_URL"]
    client = openai.OpenAI(**kwargs)
    model = os.environ.get("KAIROS_JUDGE_MODEL", "gpt-4o-mini")
    return lambda m: MASJudge(client, model, m, prompt="production")


class Deployment:
    def __init__(self, spec: MASSpec, hosts: dict[str, HostConfig], fabric: MonitorFabric) -> None:
        missing = sorted(set(spec.agents) - set(hosts))
        if missing:
            raise ValueError(f"hosts file lacks agent(s): {', '.join(missing)}")
        self.spec, self.hosts, self.fabric = spec, hosts, fabric
        by_origin = {endpoint_origin(spec.agents[a].endpoint): h.ingress_url() for a, h in hosts.items()}
        self.network = HttpNetwork(resolve=lambda url: by_origin.get(endpoint_origin(url), url))
        self.eps = {}
        for a, h in hosts.items():
            ep = EnforcementPoint(fabric, a, self.network)
            ep.server = HttpAgentServer(h.agent)
            self.eps[a] = ep
        self._lock = threading.Lock()

    def apps(self) -> list[tuple[str, Starlette]]:
        out = []
        for a, h in self.hosts.items():
            out.append((h.ingress, ingress_app(self.eps[a])))
            out.append((h.egress, egress_app(self.eps[a])))
        return out

    def run_session(self, prompt: str) -> dict[str, Any]:
        """The principal's prompt: seed T_0, then deliver it to the entry agent through
        its ingress (a request with no monitor id: the principal, not an agent)."""
        with self._lock:
            self.fabric.begin_session(prompt)
            for ep in self.eps.values():
                ep.reset()
            entry = self.spec.entry
            client = A2AClient(lambda url, body: self.network.request(url, body, {})[0],
                               lambda url, body: self.network.stream(url, body, {}))
            r = client.send_message(self.spec.agents[entry].endpoint, prompt)
            deadline = time.monotonic() + 60
            for ep in self.eps.values():
                ep.join(timeout=max(0.0, deadline - time.monotonic()))
            return {"state": r.state.value, "answer": r.text or r.notice, "report": self.fabric.report()}

    def control_app(self) -> Starlette:
        def session(request: HttpRequest) -> JSONResponse:
            body = json.loads(read_body(request) or b"{}")
            return JSONResponse(self.run_session(str(body.get("prompt", ""))))

        def report(_request: HttpRequest) -> JSONResponse:
            return JSONResponse(self.fabric.report())

        return Starlette(routes=[Route("/session", session, methods=["POST"]),
                                 Route("/report", report, methods=["GET"])])


def _server(bind: str, app: Starlette) -> uvicorn.Server:
    host, _, port = bind.rpartition(":")
    return uvicorn.Server(uvicorn.Config(app, host=host or "127.0.0.1", port=int(port), log_level="warning"))


def start(deployment: Deployment, control: str) -> list[uvicorn.Server]:
    servers = [_server(bind, app) for bind, app in deployment.apps()]
    servers.append(_server(control, deployment.control_app()))
    for s in servers:
        threading.Thread(target=s.run, daemon=True).start()
    deadline = time.monotonic() + 15
    while not all(s.started for s in servers):
        if time.monotonic() > deadline:
            raise RuntimeError("listeners did not start")
        time.sleep(0.02)
    return servers


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--spec", required=True)
    p.add_argument("--hosts", required=True)
    p.add_argument("--control", default="127.0.0.1:9000")
    p.add_argument("--oracle", default="deterministic", choices=["deterministic", "llm"])
    p.add_argument("--hold-notice", default="honest", choices=["honest", "success"])
    args = p.parse_args(argv)
    spec = load_spec(args.spec)
    fabric = MonitorFabric(spec, judge_factory=judge_factory(args.oracle), hold_notice=args.hold_notice)
    dep = Deployment(spec, load_hosts(args.hosts), fabric)
    servers = start(dep, args.control)
    print(f"KAIROS MAS: {len(spec.agents)} agents, {len(spec.clusters)} clusters; "
          f"control on http://{args.control}")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        for s in servers:
            s.should_exit = True
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
