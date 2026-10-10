"""Triage engine behavior, tested offline with a scripted fake backend."""

import json

import pytest

from exhibita.backends.base import LLMError, extract_json
from exhibita.core import engine as engine_mod
from exhibita.core.engine import Cache, build_prompt, triage, triage_one
from exhibita.models import AIFinding, Finding, Severity


class FakeBackend:
    name = "fake"
    model = "fake-1"
    max_concurrency = 1

    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def complete(self, prompt, *, system=None, schema=None, image=None, audio=None):
        self.calls += 1
        r = self.responses.pop(0)
        if isinstance(r, Exception):
            raise r
        return r


def finding(**kw):
    base = dict(tool="semgrep", rule_id="r", file="app.py", line=1, severity=Severity.CRITICAL, message="msg")
    base.update(kw)
    return Finding(**base)


def ok_json(**kw):
    d = {"explanation": "real bug", "likely_false_positive": False, "confidence": 0.9}
    d.update(kw)
    return json.dumps(d)


@pytest.fixture
def cache(tmp_path):
    return Cache(root=tmp_path / "c")


@pytest.mark.parametrize("raw, expected", [
    ('{"a": 1}', {"a": 1}),
    ('```json\n{"a": 1}\n```', {"a": 1}),
    ('Here you go: {"a": 1} done', {"a": 1}),
    ("not json at all", None),
    ("", None),
])
def test_extract_json(raw, expected):
    assert extract_json(raw) == expected


def test_valid_response_parses_and_attaches_finding(tmp_path, cache):
    be = FakeBackend([ok_json(suggested_fix="use params", exploit_class="sql_injection")])
    ai = triage_one(finding(), be, tmp_path, cache)
    assert ai.explanation == "real bug"
    assert ai.exploit_class == "sql_injection"
    assert ai.finding.rule_id == "r"
    assert be.calls == 1


def test_exploit_class_none_becomes_null(tmp_path, cache):
    be = FakeBackend([ok_json(exploit_class="none")])
    assert triage_one(finding(), be, tmp_path, cache).exploit_class is None


def test_malformed_then_valid_is_retried(tmp_path, cache):
    be = FakeBackend(["garbage {", ok_json()])
    ai = triage_one(finding(), be, tmp_path, cache)
    assert ai.explanation == "real bug"
    assert be.calls == 2


def test_fallback_keeps_scanner_message_when_model_never_valid(tmp_path, cache):
    be = FakeBackend(["nope", "still nope"])
    ai = triage_one(finding(message="scanner said this"), be, tmp_path, cache)
    assert ai.explanation == "scanner said this"
    assert ai.likely_false_positive is False
    assert ai.confidence == 0.8  # critical fallback confidence


def test_llm_error_falls_back_without_crashing(tmp_path, cache):
    be = FakeBackend([LLMError("down"), LLMError("still down")])
    ai = triage_one(finding(), be, tmp_path, cache)
    assert ai.finding is not None and ai.explanation


def test_cache_prevents_a_second_model_call(tmp_path, cache):
    be1 = FakeBackend([ok_json(explanation="first")])
    triage_one(finding(), be1, tmp_path, cache)
    be2 = FakeBackend([ok_json(explanation="second")])  # would differ if called
    ai = triage_one(finding(), be2, tmp_path, cache)
    assert ai.explanation == "first"
    assert be2.calls == 0


def test_language_option_targets_only_the_explanation(tmp_path):
    system, _ = build_prompt(finding(), tmp_path, lang="te")
    assert "Telugu" in system
    assert "code, in English" in system


def test_code_context_marks_the_flagged_line(tmp_path):
    (tmp_path / "app.py").write_text("a\nb\nTARGET\nd\ne\n", encoding="utf-8")
    ctx = engine_mod.code_context(tmp_path, finding(line=3), radius=1)
    assert ">>   3 | TARGET" in ctx
    assert "   2 | b" in ctx


def test_triage_preserves_order_and_filters_none(tmp_path, cache):
    be = FakeBackend([ok_json(explanation="one"), ok_json(explanation="two")])
    out = triage([finding(file="a.py"), finding(file="b.py")], be, tmp_path, cache=cache)
    assert [a.explanation for a in out] == ["one", "two"]


def test_threat_model_parses_image_analysis():
    from exhibita.core.engine import threat_model
    payload = json.dumps({
        "summary": "A web app with a public API and a database.",
        "threats": [{"title": "SQLi at /users", "description": "Unparameterized query.",
                     "severity": "critical", "suggested_check": "run exhibita verify on the users route"}],
    })
    tm = threat_model(b"\x89PNG-fake-bytes", FakeBackend([payload]))
    assert tm.threats[0].title == "SQLi at /users"
    assert tm.threats[0].severity.value == "critical"


def test_threat_model_falls_back_on_garbage():
    from exhibita.core.engine import threat_model
    tm = threat_model(b"img", FakeBackend(["not json", "still not json"]))
    assert tm.threats == []
    assert "parse" in tm.summary or "schema" in tm.summary


def _real(rule_id, cls):
    f = finding(rule_id=rule_id)
    return AIFinding(explanation="x", likely_false_positive=False, confidence=0.9,
                     exploit_class=cls, finding=f)


def test_attack_chains_need_two_findings():
    from exhibita.core.engine import attack_chains
    be = FakeBackend([])  # must not be called
    assert attack_chains([_real("r1", "sqli")], be) == []
    assert be.calls == 0


def test_attack_chains_parsed_and_mermaid_validated():
    from exhibita.core.engine import attack_chains
    payload = json.dumps({"chains": [
        {"title": "SQLi to file read", "narrative": "chain them",
         "mermaid": "flowchart TD\n  A[SQLi] --> B[read files]"},
        {"title": "bad graph", "narrative": "n", "mermaid": "this is not mermaid"},
    ]})
    chains = attack_chains([_real("exhibita-sql-injection", "sqli"),
                            _real("exhibita-path-traversal", "path_traversal")], FakeBackend([payload]))
    assert [c.title for c in chains] == ["SQLi to file read"]  # invalid mermaid dropped
    assert chains[0].mermaid.startswith("flowchart TD")


def test_attack_chains_strip_code_fences():
    from exhibita.core.engine import _clean_mermaid
    assert _clean_mermaid("```mermaid\nflowchart TD\n A-->B\n```").startswith("flowchart TD")
    assert _clean_mermaid("not a graph") is None
