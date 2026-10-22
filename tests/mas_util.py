"""Shared helpers for the multi-agent tests: the example banking system, scripted
judges, and a tiny tool environment."""
from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import Any

import yaml

from kairos.judge.oracle import Verdict
from kairos.mas.spec_parser import load_spec, parse_spec

BANKING_SPEC = Path(__file__).parent.parent / "kairos" / "mas" / "config" / "banking.yaml"
BILL_IBAN = "UK12345678901234567890"
ATTACKER_IBAN = "US133000000121212121212"


def banking_spec(mutate=None):
    if mutate is None:
        return load_spec(BANKING_SPEC)
    raw = yaml.safe_load(BANKING_SPEC.read_text())
    mutate(raw)
    return parse_spec(raw)


class ScriptedJudge:
    """Per-call verdicts in order (True/False or a mask); records what it saw."""

    def __init__(self, verdicts=None, default: bool = True) -> None:
        self.verdicts = list(verdicts or [])
        self.default = default
        self.seen: list[Any] = []

    def evaluate(self, user_prompt, branch):
        self.seen.append(branch)
        v = self.verdicts.pop(0) if self.verdicts else self.default
        mask = list(v) if isinstance(v, (list, tuple)) else [v] * len(branch.held_calls)
        return Verdict(consistent=all(mask), rationale="scripted", per_action=mask or None)


class ValueJudge:
    """Inconsistent iff a held action mentions one of `bad` values (an oracle that
    recognises the attacker's identifiers)."""

    def __init__(self, bad) -> None:
        self.bad = [b.lower() for b in bad]
        self.calls = 0

    def evaluate(self, user_prompt, branch):
        self.calls += 1
        mask = [not any(b in str(h.args).lower() for b in self.bad) for h in branch.held_calls]
        return Verdict(consistent=all(mask), rationale="value judge", per_action=mask or None)


class Env:
    """A minimal bank + file system for tool calls."""

    def __init__(self, files=None) -> None:
        self.files = dict(files or {"bill.txt": f"Car rental 98.70, pay to {BILL_IBAN}"})
        self.sent: list[dict] = []
        self.balance = 1810.0

    def execute(self, fn: str, args: dict):
        if fn == "read_file":
            return self.files.get(args.get("file_path", ""), ""), None
        if fn == "send_money":
            self.sent.append(dict(args))
            return f"Transaction to {args['recipient']} for {args['amount']} sent.", None
        if fn == "get_balance":
            return str(self.balance), None
        if fn == "get_most_recent_transactions":
            return "- amount: 50.0, recipient: Spotify, subject: Spotify Premium", None
        return "", f"unknown tool {fn}"


_n = [0]


def call(fn: str, **args):
    _n[0] += 1
    return SimpleNamespace(function=fn, args=args, id=f"call-{_n[0]}")
