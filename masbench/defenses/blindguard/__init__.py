"""BlindGuard (Miao et al., ACL 2026), retrained. Run R26.

A graph anomaly detector on A2A messages that needs no labelled attacks; the messages of
flagged agents are pruned. It sees messages only, so it also works with opaque agents.

Detector and training follow the released code (see `model.py`). Adaptations of this port
(Benchmark Design 3.4):
* One graph snapshot per message exchange instead of synchronous rounds: nodes are the
  agents that have spoken, an agent's feature is the embedding of its latest message,
  edges are sender -> receiver.
* Trained on benign masbench traces (`train.py`, training split of the benign B1 runs)
  instead of the paper's QA dialogues.
* A threshold calibrated on benign data replaces the fixed top-k = 3, which would flag
  three agents in every graph.
* Remediation as released: a flagged agent is isolated, i.e. its messages are dropped for
  the rest of the run. Attacks that never cross a message pass by design.

Options: `checkpoint` (default: `checkpoint.pt` next to this file, written by `train.py`),
`threshold` (override the calibrated one), `protect_entry` (never isolate the entry agent,
default false).
Needs `torch` and `transformers`.
"""
from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from masbench.runner.defense import Defense, Message, RunContext, Verdict

CHECKPOINT = Path(__file__).parent / "checkpoint.pt"
_MODELS: dict[str, Any] = {}


def load(path: Path) -> tuple[Any, float]:
    if str(path) not in _MODELS:
        import torch

        from masbench.defenses.blindguard.model import Encoder

        if not path.exists():
            raise RuntimeError(f"no BlindGuard checkpoint at {path}; train one with "
                               "`python -m masbench.defenses.blindguard.train <benign records>`")
        ckpt = torch.load(path, weights_only=False)
        model = Encoder(in_channels=ckpt["in_channels"])
        model.load_state_dict(ckpt["state"])
        _MODELS[str(path)] = (model.eval(), ckpt["threshold"])
    return _MODELS[str(path)]


class BlindGuard(Defense):
    name = "blindguard"
    run_id = "R26"

    def __init__(self, checkpoint: str | None = None, threshold: float | None = None,
                 protect_entry: bool = False, **options: Any) -> None:
        super().__init__(checkpoint=checkpoint, threshold=threshold, protect_entry=protect_entry, **options)
        self.path, self.threshold, self.protect_entry = Path(checkpoint) if checkpoint else CHECKPOINT, threshold, protect_entry

    async def setup(self, ctx: RunContext) -> None:
        await super().setup(ctx)
        self.model, calibrated = load(self.path)
        self.limit = calibrated if self.threshold is None else self.threshold

    def score(self, messages: list[tuple[str, str, str]]) -> dict[str, float]:
        """Anomaly score of every agent that has spoken (low = anomalous)."""
        import torch

        from masbench.defenses.blindguard.model import snapshot

        graph = snapshot(messages)
        if graph is None:
            return {}
        agents, x, adj = graph
        with torch.no_grad():
            return dict(zip(agents, self.model.scores(self.model.encode(x, adj)).tolist()))

    async def on_message(self, msg: Message) -> Verdict:
        history = [(m.sender, m.receiver, m.text) for m in self.ctx.messages if m.status == "delivered"]
        scores = await asyncio.to_thread(self.score, history)  # ctx.messages already holds this message
        self.ctx.log.append({"message": msg.id, "scores": {a: round(s, 4) for a, s in scores.items()}})
        for agent, s in scores.items():
            if s < self.limit and not (self.protect_entry and agent == self.ctx.scenario.entry_agent.id):
                self.ctx.isolate(agent, f"BlindGuard anomaly score {s:.3f} below {self.limit:.3f}")
        return Verdict.allow()  # the runner drops the message if its sender or receiver is now isolated


DEFENSE = BlindGuard
