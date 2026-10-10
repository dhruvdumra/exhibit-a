"""SARIF, Markdown, and inline-comment output — including honest evidence labels."""

from exhibita.core import report as report_mod
from exhibita.models import AIFinding, Finding, Report, Severity, Verification


def ai(rule_id, sev, *, fp=False, fix=None, s=None, e=None, line=10):
    return AIFinding(
        explanation=f"explain {rule_id}", likely_false_positive=fp, confidence=0.9,
        suggested_fix=fix, fix_start_line=s, fix_end_line=e,
        finding=Finding(tool="semgrep", rule_id=rule_id, file="app.py", line=line, severity=sev),
    )


def proven(fix_ok=False):
    return Verification(attempted=True, red_passed=True, patch_applied=fix_ok,
                        green_passed=fix_ok, still_works_passed=fix_ok)


def test_sarif_excludes_false_positives_and_maps_levels():
    f1, f2 = ai("sqli", Severity.CRITICAL), ai("noise", Severity.MEDIUM, fp=True)
    sarif = report_mod.to_sarif(Report(ai_findings=[f1, f2]))
    results = sarif["runs"][0]["results"]
    assert len(results) == 1
    assert results[0]["ruleId"] == "sqli"
    assert results[0]["level"] == "error"


def test_sarif_records_proof_evidence():
    f = ai("sqli", Severity.CRITICAL)
    rep = Report(ai_findings=[f], verifications={f.finding.key: proven(fix_ok=True)})
    props = report_mod.to_sarif(rep)["runs"][0]["results"][0]["properties"]
    assert props["evidence"] == "proven + fix verified"


def test_inline_comment_includes_suggestion_only_with_line_range():
    with_fix = ai("sqli", Severity.CRITICAL, fix="safe = 1", s=10, e=10)
    without = ai("xss", Severity.HIGH)
    comments = report_mod.inline_comments(Report(ai_findings=[with_fix, without]))
    by_path = {c["body"].split("·")[1].split("**")[0].strip(): c for c in comments}
    assert "```suggestion" in by_path["sqli"]["body"]
    assert "```suggestion" not in by_path["xss"]["body"]
    assert all(c["line"] >= 1 for c in comments)


def test_markdown_states_gate_and_counts():
    f = ai("sqli", Severity.CRITICAL)
    rep = Report(ai_findings=[f, ai("noise", Severity.LOW, fp=True)],
                 verifications={f.finding.key: proven()}, backend="ollama:gemma4:e4b")
    md = report_mod.to_markdown(rep)
    assert "Build gate: FAILED" in md
    assert "proven exploitable" in md
    assert "ollama:gemma4:e4b" in md


def test_markdown_passes_gate_without_proof():
    md = report_mod.to_markdown(Report(ai_findings=[ai("sqli", Severity.CRITICAL)]))
    assert "Build gate: passed" in md


def test_write_outputs(tmp_path):
    rep = Report(ai_findings=[ai("sqli", Severity.CRITICAL)])
    sp, mp = tmp_path / "out.sarif", tmp_path / "out.md"
    report_mod.write_outputs(rep, str(sp), str(mp))
    assert sp.exists() and mp.exists()
    assert "2.1.0" in sp.read_text(encoding="utf-8")
