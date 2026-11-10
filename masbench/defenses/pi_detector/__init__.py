"""Prompt-injection detector on every untrusted input, lifted to every agent. Run R05.

Same detector and behaviour as AgentDojo's `transformers_pi_detector`: the classifier
`protectai/deberta-v3-base-prompt-injection-v2`, threshold 0.5 on the SAFE score, applied per
message; a flagged text is replaced by "<Data omitted because a prompt injection was
detected>". Lifted to a MAS, the detector scans every tool output and every message received
from another agent.

Options: `model_name`, `safe_label`, `threshold`, `messages` (scan peer messages, default
true), `on_detect` ("omit" as in AgentDojo, or "abort" to end the run).
Needs `torch` and `transformers`; the model is downloaded from the Hugging Face Hub once.
"""
from __future__ import annotations

import asyncio
import threading
from typing import Any

from masbench.runner.defense import Defense, Message, ToolCall, Verdict

OMITTED = "<Data omitted because a prompt injection was detected>"
_PIPELINES: dict[str, Any] = {}
_LOCK = threading.Lock()


def classifier(model_name: str) -> Any:
    with _LOCK:
        if model_name not in _PIPELINES:
            import torch
            from transformers import pipeline

            _PIPELINES[model_name] = pipeline(
                "text-classification", model=model_name, tokenizer=model_name, truncation=True, max_length=512,
                device=torch.device("cuda" if torch.cuda.is_available() else "cpu"))
        return _PIPELINES[model_name]


class PiDetector(Defense):
    name = "pi-detector"
    run_id = "R05"

    def __init__(self, model_name: str = "protectai/deberta-v3-base-prompt-injection-v2", safe_label: str = "SAFE",
                 threshold: float = 0.5, messages: bool = True, on_detect: str = "omit", **options: Any) -> None:
        super().__init__(model_name=model_name, threshold=threshold, messages=messages, on_detect=on_detect, **options)
        self.model_name, self.safe_label, self.threshold = model_name, safe_label, threshold
        self.messages, self.on_detect = messages, on_detect

    def score(self, text: str) -> float:
        """The SAFE score of a text (override in tests to avoid loading the model)."""
        with _LOCK:
            pipe = _PIPELINES.get(self.model_name)
        pipe = pipe or classifier(self.model_name)
        with _LOCK:  # one text at a time: the pipeline is not thread-safe
            result = pipe(text)[0]
        return result["score"] if result["label"] == self.safe_label else 1 - result["score"]

    async def _scan(self, hook: str, agent: str, target: str, text: str) -> str | Verdict:
        if not text or not text.strip():
            return text
        score = await asyncio.to_thread(self.score, text)
        if score >= self.threshold:
            return text
        reason = f"prompt injection detected (safe score {score:.3f})"
        if self.on_detect == "abort":
            return Verdict.abort(reason)
        self.ctx.event(hook, agent, "omit", reason, target)
        return OMITTED

    async def after_tool(self, call: ToolCall, result: str) -> str | Verdict:
        return await self._scan("after_tool", call.agent, call.function, result)

    async def on_receive(self, msg: Message, text: str) -> str | Verdict:
        if not self.messages or msg.sender == "user":
            return text
        return await self._scan("on_receive", msg.receiver, msg.sender, text)


DEFENSE = PiDetector
