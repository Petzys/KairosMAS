"""The flight recorder and the run viewer: what a run records, that recording
changes nothing, the reconstruction of results stored without a trace, and the
viewer's export and server."""
import json
from dataclasses import asdict, replace
from pathlib import Path

import pytest
from agentdojo.task_suite.load_suites import get_suite

from kairos.mas.bench.harness import RunConfig, make_attack, run_pair, save
from kairos.mas.viewer.__main__ import RunIndex, make_handler, render_html
from kairos.mas.viewer.legacy import load_trace, reconstruct

from tests.test_mas_bench import FakeModel


def _pair(ut, it, **kw):
    cfg = RunConfig(suite="banking", layout="domain", **kw)
    suite = get_suite("v1", "banking")
    inj = suite.injection_tasks[it] if it else None
    injections = make_attack(cfg, suite).attack(suite.user_tasks[ut], inj) if inj else {}
    return cfg, run_pair(cfg, suite, suite.user_tasks[ut], inj, injections)


def _timeless(metrics):
    return {k: v for k, v in metrics.items() if k != "elapsed"}


def _of(trace, kind, *keys):
    return sorted(tuple(e[k] for k in keys) for e in trace["events"] if e["kind"] == kind)


def _kinds(trace):
    return [e["kind"] for e in trace["events"]]


def test_a_defended_run_records_every_crossing_and_decision() -> None:
    _, r = _pair("user_task_0", "injection_task_0")
    t = r.trace
    assert t["topology"]["entry"] == "assistant" and {c["id"] for c in t["topology"]["clusters"]} == {"front", "finance", "docs"}
    assert t["events"][0]["kind"] == "run.start" and t["events"][-1]["kind"] == "run.end"
    assert [e["i"] for e in t["events"]] == list(range(len(t["events"])))
    assert all(a["t"] <= b["t"] for a, b in zip(t["events"], t["events"][1:]))
    kinds = set(_kinds(t))
    assert {"agent.task", "agent.done", "tool.call", "tool.result", "gate", "msg.send", "msg.outcome",
            "msg.deliver", "oracle.request", "oracle.verdict", "resolution"} <= kinds
    pos = {}
    for e in t["events"]:                          # each message: sent, gated, decided, in that order
        if "kmid" in e:
            pos.setdefault(e["kmid"], []).append(e["kind"])
    for kmid, ks in pos.items():
        assert ks[0] == "msg.send" and ks.index("gate") < ks.index("msg.outcome"), (kmid, ks)
        if "msg.deliver" in ks:
            assert ks.index("msg.outcome") < ks.index("msg.deliver")
    rejected = [e for e in t["events"] if e["kind"] == "msg.outcome" and e["outcome"] == "rejected"]
    assert rejected and all(e["reason"] for e in rejected)
    assert t["result"] if "result" in t else True
    assert t["injections"] and t["injection_goal"]


def test_an_undefended_run_records_messages_without_a_monitor() -> None:
    _, r = _pair("user_task_0", "injection_task_0", defense=False)
    kinds = _kinds(r.trace)
    assert "msg.send" in kinds and "tool.call" in kinds
    assert not {"gate", "oracle.request", "resolution"} & set(kinds)
    assert {e["by"] for e in r.trace["events"] if e["kind"] == "msg.outcome"} == {"nodefense"}


def test_recording_changes_no_outcome() -> None:
    for ut, it in (("user_task_0", "injection_task_0"), ("user_task_3", "injection_task_4")):
        _, on = _pair(ut, it)
        _, off = _pair(ut, it, trace=False)
        assert off.trace is None
        assert (on.utility, on.attack_success, _timeless(on.metrics)) == \
            (off.utility, off.attack_success, _timeless(off.metrics))


def test_llm_runs_record_reasoning_and_the_oracle_prompt() -> None:
    model = FakeModel({
        "assistant": [{"calls": [("send_message", {"agent": "accounts",
                                                   "message": "List my 100 most recent transactions."})]},
                      {"content": "Your total spending in March 2022 was £1,050."}],
        "accounts": [{"calls": [("get_most_recent_transactions", {"n": 100})]},
                     {"content": "Transactions: see above, March total 1050."}],
    })
    cfg = RunConfig(suite="banking", backend="llm", oracle="llm", model="fake-model")
    suite = get_suite("v1", "banking")
    r = run_pair(cfg, suite, suite.user_tasks["user_task_1"], None, {}, client=model, judge_client=model)
    llm = [e for e in r.trace["events"] if e["kind"] == "agent.llm"]
    assert [e["agent"] for e in llm] == ["assistant", "accounts", "accounts", "assistant"]
    assert llm[0]["tool_calls"][0]["function"] == "send_message" and "1,050" in llm[-1]["text"]
    prompts = [e for e in r.trace["events"] if e["kind"] == "oracle.llm"]
    assert len(prompts) == len(model.oracle_prompts) and all(p["prompt"] and p["system"] for p in prompts)


def test_a_result_without_trace_is_reconstructed(tmp_path) -> None:
    cfg, r = _pair("user_task_0", "injection_task_0")
    recorded = r.trace
    legacy = json.loads(json.dumps({"config": asdict(cfg), **{k: getattr(r, k) for k in (
        "suite", "user_task", "injection_task", "utility", "attack_success", "output", "metrics", "report",
        "transcripts")}}, default=str))
    t = reconstruct(legacy)
    assert t["approximate"] and t["topology"] == recorded["topology"]
    assert _of(t, "msg.outcome", "kmid", "outcome") == _of(recorded, "msg.outcome", "kmid", "outcome")
    assert _of(t, "oracle.verdict", "agent", "consistent") == _of(recorded, "oracle.verdict", "agent", "consistent")
    for e in t["events"]:                          # a message's verdict sits between its gate and its outcome
        if e["kind"] == "msg.outcome" and e["by"] == "oracle":
            before = [x["kind"] for x in t["events"][:e["i"]]]
            assert before[-1] == "resolution" and "oracle.verdict" in before[-3:]
    path = tmp_path / "r.json"
    save(path, replace(cfg, trace=False), replace(r, trace=None))
    assert load_trace(str(path))["approximate"]
    save(path, cfg, r)
    assert not load_trace(str(path))["approximate"]


def test_export_embeds_the_trace_safely() -> None:
    trace = {"events": [{"kind": "msg.send", "text": "</script><script>alert(1)</script>"}], "topology": {}}
    html = render_html(trace)
    data = html.split('<script id="trace-data" type="application/json">', 1)[1].split("</script>", 1)[0]
    assert json.loads(data.replace("<\\/", "</")) == trace
    assert render_html(None).count('type="application/json">null</script>') == 1


def test_the_server_lists_runs_and_stays_in_its_directory(tmp_path) -> None:
    cfg, r = _pair("user_task_0", None)
    save(tmp_path / "tag" / "banking" / "user_task_0" / "none.json", cfg, r)
    (tmp_path / "tag" / "banking" / "summary.json").write_text("{}")
    idx = RunIndex(tmp_path)
    (run,) = idx.runs()
    assert run["user_task"] == "user_task_0" and run["traced"] and run["group"] == str(Path("tag") / "banking")
    assert idx.resolve(run["path"]).exists()
    for bad in ("../etc/passwd", "/etc/passwd", "tag/banking/user_task_0/../../../../x.json"):
        with pytest.raises(PermissionError):
            idx.resolve(bad)
    assert make_handler(idx) is not None
