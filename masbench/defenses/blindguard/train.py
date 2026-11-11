"""Train BlindGuard's detector on benign run records and calibrate its threshold.

    python -m masbench.defenses.blindguard.train runs_masbench_b1/none/<model> [--out <checkpoint>]

Unsupervised, as the method: the records are benign runs (defense `none`); anomalies are
simulated by corrupting agent embeddings. Only cases of the training split are used
(`is_train`), so the cases a checkpoint was fitted on can be left out of an evaluation.
The threshold is the `fpr` quantile of the agent scores on the benign snapshots of the
training split (it replaces the release's fixed top-k = 3, Benchmark Design 3.4).
"""
from __future__ import annotations

import argparse
import hashlib
import random
from pathlib import Path

import torch

from masbench.defenses.blindguard.model import Encoder, corrupt, snapshot
from masbench.schema import RunRecord

CHECKPOINT = Path(__file__).parent / "checkpoint.pt"


def is_train(case_id: str) -> bool:
    """Deterministic half of the cases, by a hash of the case's own id."""
    return int(hashlib.sha256(case_id.encode()).hexdigest(), 16) % 2 == 0


def snapshots(record: RunRecord) -> list[tuple[list[str], torch.Tensor, torch.Tensor]]:
    """One graph per message exchange of a run."""
    delivered = [(m.sender, m.receiver, m.text) for m in record.messages if m.status == "delivered"]
    out = [snapshot(delivered[:k]) for k in range(2, len(delivered) + 1)]
    return [s for s in out if s is not None]


def fit(graphs: list[tuple[list[str], torch.Tensor, torch.Tensor]], epochs: int = 20, lr: float = 1e-3,
        seed: int = 42) -> Encoder:
    torch.manual_seed(seed)
    random.seed(seed)
    model = Encoder(in_channels=graphs[0][1].size(1))
    opt = torch.optim.Adam(model.parameters(), lr=lr, weight_decay=2e-4)
    sched = torch.optim.lr_scheduler.CosineAnnealingLR(opt, T_max=10, eta_min=1e-5)
    for epoch in range(epochs):
        random.shuffle(graphs)
        total = 0.0
        for _, x, adj in graphs:
            n = x.size(0)
            anomalous = torch.zeros(n)
            anomalous[torch.randperm(n)[: max(1, round(n * 3 / 8))]] = 1  # the release corrupts 3 of 8 agents
            if anomalous.sum() == n:
                anomalous[0] = 0
            loss = model.contrastive_loss(model.encode(corrupt(x, anomalous), adj), anomalous)
            opt.zero_grad()
            loss.backward()
            opt.step()
            total += loss.item()
        sched.step()
        print(f"epoch {epoch + 1}/{epochs}: loss {total / len(graphs):.4f}")
    return model.eval()


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("records", help="directory with benign run records (defense none)")
    p.add_argument("--out", default=str(CHECKPOINT))
    p.add_argument("--epochs", type=int, default=20)
    p.add_argument("--fpr", type=float, default=0.05, help="share of benign agent scores below the threshold")
    a = p.parse_args()
    records = [RunRecord.model_validate_json(f.read_text()) for f in sorted(Path(a.records).rglob("*.json"))]
    records = [r for r in records if r.variant == "twin" and r.defense == "none" and not r.error and is_train(r.case)]
    graphs = [g for r in records for g in snapshots(r)]
    if not graphs:
        raise SystemExit("no benign snapshots found (need benign records of the training split with messages)")
    print(f"{len(records)} benign runs of the training split, {len(graphs)} snapshots")
    model = fit(list(graphs), epochs=a.epochs)
    with torch.no_grad():
        scores = torch.cat([model.scores(model.encode(x, adj)) for _, x, adj in graphs])
    threshold = torch.quantile(scores, a.fpr).item()
    torch.save({"state": model.state_dict(), "threshold": threshold, "fpr": a.fpr, "in_channels": graphs[0][1].size(1),
                "train_cases": sorted({r.case for r in records}), "snapshots": len(graphs)}, a.out)
    print(f"threshold {threshold:.4f} (benign scores: min {scores.min():.4f}, median {scores.median():.4f}); saved {a.out}")


if __name__ == "__main__":
    main()
