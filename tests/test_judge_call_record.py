# tests/test_judge_call_record.py — oracle-call diagnostics in the session record
#
# The raw reply, finish reason and token counts of every oracle call are logged with its
# resolution, so an unparseable verdict can be diagnosed. Logging only: the verdict, the
# commit decision and the prompt of later oracle calls must be unchanged.
from types import SimpleNamespace

from kairos.judge.oracle import LLMJudge, Verdict, judge_call_record


def _resp(content, finish="stop", reasoning=None, completion=12, reasoning_tokens=None):
    msg = SimpleNamespace(content=content, model_extra={"reasoning": reasoning} if reasoning else {})
    usage = SimpleNamespace(completion_tokens=completion,
                            completion_tokens_details=SimpleNamespace(reasoning_tokens=reasoning_tokens))
    return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason=finish)], usage=usage)


class _Client:
    def __init__(self, resp):
        self._resp = resp
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kw):
        if isinstance(self._resp, Exception):
            raise self._resp
        return self._resp


def _judge(resp):
    j = LLMJudge(_Client(resp), "qwen/qwen3.5-9b")
    j._build_prompt = lambda user_prompt, branch: "PROMPT"      # isolate from branch rendering
    return j


GOOD = '{"actions": [{"index": 0, "consistent": true, "reason": "ok"}], "injection_found": false, "quote": ""}'


def test_parsed_verdict_carries_call_diagnostics():
    v = _judge(_resp(GOOD, completion=40, reasoning="thinking...", reasoning_tokens=30)).evaluate("u", None)
    assert v.consistent is True and v.per_action == [True]           # decision unchanged
    rec = judge_call_record(v)
    assert rec["judge_raw"] == GOOD and rec["judge_raw_len"] == len(GOOD)
    assert rec["judge_finish_reason"] == "stop"
    assert rec["judge_completion_tokens"] == 40 and rec["judge_reasoning_tokens"] == 30
    assert rec["judge_reasoning_len"] == len("thinking...")
    assert "judge_reasoning_tail" not in rec                          # only kept when unparseable


def test_empty_content_with_answer_in_reasoning_is_visible():
    v = _judge(_resp(None, finish="stop", reasoning="...so the verdict is " + GOOD)).evaluate("u", None)
    assert v.consistent is False and v.rationale.startswith("unparseable")   # still fails closed
    rec = judge_call_record(v)
    assert rec["judge_raw"] == "" and rec["judge_raw_len"] == 0
    assert rec["judge_reasoning_tail"].endswith(GOOD)


def test_truncated_reply_shows_length_finish():
    v = _judge(_resp('{"actions": [{"index": 0, "consis', finish="length")).evaluate("u", None)
    rec = judge_call_record(v)
    assert v.rationale.startswith("unparseable") and rec["judge_finish_reason"] == "length"


def test_api_error_still_fails_closed_and_records_nothing_extra():
    v = _judge(RuntimeError("Error code: 402")).evaluate("u", None)
    assert v.consistent is False and v.rationale.startswith("judge unavailable")
    rec = judge_call_record(v)
    assert rec["judge_raw"] == "" and rec["judge_finish_reason"] is None


def test_record_works_for_plain_verdicts_and_caps_size():
    rec = judge_call_record(Verdict(False, "unparseable judge output; failing closed", raw="x" * 10000))
    assert rec["judge_raw_len"] == 10000 and len(rec["judge_raw"]) == 4000
    assert judge_call_record(SimpleNamespace(consistent=True, rationale="det"))["judge_raw"] == ""


def test_new_keys_never_reach_the_oracle_prompt():
    # an earlier ABORTED resolution of the same action is rendered into the next prompt;
    # the diagnostic keys must not be
    from kairos.speculative.branch import Branch, HeldAction
    b = Branch(branch_id="b2", opened_at=0.0, opened_reason="t")
    b.held_calls.append(HeldAction(call_ref=None, tool="send_money", args={"recipient": "X1"},
                                   provenance={}, reason="r"))
    prior = {"aborted": ["send_money"], "aborted_actions": [{"tool": "send_money", "ids": {"recipient": "X1"}}],
             "rationale": "redirect", **judge_call_record(Verdict(False, "unparseable judge output", raw="SECRETRAW"))}
    b.prior_resolutions = [prior]
    prompt = LLMJudge(None, "m")._build_prompt("pay the bill", b)
    assert "PREVIOUSLY WITHHELD" in prompt and "SECRETRAW" not in prompt and "judge_raw" not in prompt
