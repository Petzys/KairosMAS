"""BlindGuard's detector (Miao et al., ACL 2026), after the released code (MR9812/BlindGuard,
`PI/TAM.py:GATSCL` with `rep_type 0` and `PI/train_un1.py`, defend type "SCL").

Kept from the release: the hierarchical agent encoder (an agent's own embedding, the
normalized mean of its neighbours and the graph mean, through one linear layer), the
corruption-guided training (noise of 0.8 times the embedding norm on pseudo-anomalous
nodes, supervised contrastive loss with temperature 0.3 on a projection of the encoding),
and the score (sum of cosine similarities to all agents; low = anomalous). Written with
dense adjacency matrices, so torch-geometric is not needed.
"""
from __future__ import annotations

import threading

import torch
import torch.nn.functional as F
from torch import nn

EMBEDDER = "sentence-transformers/all-MiniLM-L6-v2"  # as in the release


class Encoder(nn.Module):
    def __init__(self, in_channels: int = 384, out_channels: int = 512) -> None:
        super().__init__()
        self.fc = nn.Linear(in_channels * 3, out_channels)
        self.fc1 = nn.Linear(out_channels, out_channels)

    def encode(self, x: torch.Tensor, adj: torch.Tensor) -> torch.Tensor:
        """x: (n, d) agent embeddings; adj: (n, n), adj[i, j] = 1 if i sent a message to j."""
        deg = adj.sum(dim=1)
        inv = deg.pow(-0.5)
        inv[torch.isinf(inv)] = 0
        neighbours = (inv.view(-1, 1) * adj * inv.view(1, -1)) @ x
        graph = x.mean(0, keepdim=True).expand_as(x)
        return self.fc(torch.cat((x, neighbours, graph), 1))

    def contrastive_loss(self, z: torch.Tensor, anomalous: torch.Tensor, tem: float = 0.3) -> torch.Tensor:
        emb = F.normalize(self.fc1(F.relu(z)), p=2, dim=-1)
        exp_sim = torch.exp(emb @ emb.t() / tem)
        mask = torch.eq(anomalous.unsqueeze(1), anomalous.unsqueeze(0)).int()
        neg = (exp_sim * (1 - mask)).sum(dim=1, keepdim=True)
        pos = -((torch.log(exp_sim / (1e-8 + exp_sim + neg)) * mask).sum(1)) / mask.sum(0)
        return pos.mean()

    @staticmethod
    def scores(z: torch.Tensor) -> torch.Tensor:
        """Mean cosine similarity of each agent to the other agents (the release sums over all
        agents and takes the lowest k; the mean makes graphs of different size comparable)."""
        z = F.normalize(z, p=2, dim=-1)
        n = z.size(0)
        return ((z @ z.t()).sum(1) - 1) / max(n - 1, 1)


def corrupt(x: torch.Tensor, anomalous: torch.Tensor) -> torch.Tensor:
    noise = F.normalize(torch.randn_like(x), dim=1)
    return x + noise * 0.8 * torch.norm(x, dim=1, keepdim=True) * anomalous.unsqueeze(1)


_EMBEDDER: dict[str, tuple] = {}
_LOCK = threading.RLock()


def embed(texts: list[str]) -> torch.Tensor:
    """Sentence embeddings of all-MiniLM-L6-v2 (mean pooling, normalized), via transformers."""
    with _LOCK:  # loaded once; the model is used by one thread at a time
        if EMBEDDER not in _EMBEDDER:
            from transformers import AutoModel, AutoTokenizer

            _EMBEDDER[EMBEDDER] = (AutoTokenizer.from_pretrained(EMBEDDER), AutoModel.from_pretrained(EMBEDDER).eval())
        tok, model = _EMBEDDER[EMBEDDER]
    with _LOCK, torch.no_grad():
        batch = tok(texts, padding=True, truncation=True, max_length=256, return_tensors="pt")
        hidden = model(**batch).last_hidden_state
        mask = batch["attention_mask"].unsqueeze(-1).float()
        return F.normalize((hidden * mask).sum(1) / mask.sum(1).clamp(min=1e-9), p=2, dim=1)


def snapshot(messages: list[tuple[str, str, str]], embedding=embed) -> tuple[list[str], torch.Tensor, torch.Tensor] | None:  # noqa: ANN001
    """The graph after a message exchange. `messages`: (sender, receiver, text), oldest first.
    Nodes are the agents that have sent a message; an agent's feature is the embedding of its
    latest message; edges are sender -> receiver. None if fewer than two agents have spoken."""
    latest: dict[str, str] = {}
    for sender, _, text in messages:
        latest[sender] = text
    agents = sorted(latest)
    if len(agents) < 2:
        return None
    index = {a: i for i, a in enumerate(agents)}
    adj = torch.eye(len(agents))
    for sender, receiver, _ in messages:
        if receiver in index:
            adj[index[sender], index[receiver]] = 1.0
    return agents, embedding([latest[a] for a in agents]), adj
