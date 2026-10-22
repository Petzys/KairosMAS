"""Agent hosts on a network, and a session driver.

An AgentHost is one (micro)VM of the system model: the agent -- its A2A server,
its A2A client and whatever logic answers tasks -- behind the host's enforcement
point. The agent never talks to the network directly: its client's transport is
the enforcement point's client side, and the network reaches its server only
through the enforcement point's server side.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from kairos.mas.a2a.client import A2AClient
from kairos.mas.a2a.protocol import Message
from kairos.mas.a2a.server import A2AServer, AgentResult
from kairos.mas.enforcement import EnforcementPoint
from kairos.mas.fabric import MonitorFabric
from kairos.mas.spec import MASSpec
from kairos.mas.transport import InProcessNetwork

TaskHandler = Callable[["AgentHost", Message, str], AgentResult]


class AgentHost:
    def __init__(self, fabric: MonitorFabric, agent_id: str, network: InProcessNetwork,
                 handler: TaskHandler | None = None, *, defense: bool = True,
                 formatter: Callable[[Any], str] = str) -> None:
        spec = fabric.spec
        self.agent_id = agent_id
        self.spec = spec
        self.fabric = fabric
        self.handler = handler
        self.ep = EnforcementPoint(fabric, agent_id, network, defense=defense, formatter=formatter)
        self.server = A2AServer(agent_id, spec.agents[agent_id].endpoint, self._on_task,
                                description=spec.agents[agent_id].description)
        self.ep.server = self.server
        self.client = A2AClient(self.ep.send, self.ep.send_stream)
        network.register(spec.agents[agent_id].endpoint, self.ep)
        self.active = 0
        self._cv = threading.Condition()
        self.tasks_run = 0

    def url_of(self, agent: str) -> str:
        return self.spec.agents[agent].endpoint

    def _on_task(self, msg: Message, task_id: str) -> AgentResult:
        if self.handler is None:
            return AgentResult(text="no handler")
        with self._cv:
            self.active += 1
            self.tasks_run += 1
        try:
            return self.handler(self, msg, task_id)
        finally:
            with self._cv:
                self.active -= 1
                self._cv.notify_all()

    def run_prompt(self, prompt: str) -> AgentResult:
        """The principal's prompt, handed to this (entry) agent directly."""
        return self._on_task(Message.user_text(prompt), "principal")

    def idle(self) -> bool:
        with self._cv:
            return self.active == 0


@dataclass(slots=True)
class SessionResult:
    output: str
    elapsed: float
    report: dict[str, Any] = field(default_factory=dict)
    quiescent: bool = True


class MASRuntime:
    def __init__(self, spec: MASSpec, fabric: MonitorFabric, handlers: dict[str, TaskHandler], *,
                 defense: bool = True, formatter: Callable[[Any], str] = str) -> None:
        self.spec = spec
        self.fabric = fabric
        self.network = InProcessNetwork()
        self.hosts = {a: AgentHost(fabric, a, self.network, handlers.get(a), defense=defense,
                                   formatter=formatter)
                      for a in spec.agents}
        self.defense = defense

    def run(self, prompt: str, *, timeout: float = 300.0, tick: float = 0.5) -> SessionResult:
        """One session: the prompt to the entry agent, then wait until every agent is
        idle and every background delivery has finished. A watchdog resolves
        branches whose stall budget runs out while their agent is quiet."""
        self.fabric.begin_session(prompt)
        for h in self.hosts.values():
            h.ep.reset()
        stop = threading.Event()

        def watchdog() -> None:
            while not stop.wait(tick):
                if self.defense:
                    self.fabric.tick()

        wd = threading.Thread(target=watchdog, daemon=True)
        wd.start()
        t0 = time.monotonic()
        try:
            result = self.hosts[self.spec.entry].run_prompt(prompt)
            quiescent = self.wait_quiescent(timeout=max(1.0, timeout - (time.monotonic() - t0)))
        finally:
            stop.set()
            wd.join(2.0)
        report = self.fabric.report()
        return SessionResult(output=result.text, elapsed=time.monotonic() - t0, report=report,
                             quiescent=quiescent)

    def wait_quiescent(self, timeout: float = 60.0) -> bool:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            for h in self.hosts.values():
                h.ep.join(timeout=max(0.0, deadline - time.monotonic()))
            if all(h.idle() for h in self.hosts.values()) and not self._threads_alive():
                return True
            time.sleep(0.02)
        return False

    def _threads_alive(self) -> bool:
        return any(t.is_alive() for h in self.hosts.values() for t in h.ep._threads)
