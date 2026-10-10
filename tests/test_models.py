"""The merge gate: no proof, no block — and proof beats the model's opinion."""

from exhibita.models import AIFinding, Finding, Report, Severity, Verification


def ai(severity: Severity, false_positive: bool = False) -> AIFinding:
    finding = Finding(tool="semgrep", rule_id=f"r-{severity.value}", file="app.py", line=1, severity=severity)
    return AIFinding(explanation="x", likely_false_positive=false_positive, confidence=0.9, finding=finding)


def exploited(**kw) -> Verification:
    return Verification(attempted=True, red_passed=True, **kw)


def test_unverified_critical_does_not_block():
    assert not Report(ai_findings=[ai(Severity.CRITICAL)]).gate_failed


def test_confirmed_critical_blocks_even_if_the_fix_failed():
    f = ai(Severity.CRITICAL)
    report = Report(ai_findings=[f], verifications={f.finding.key: exploited()})
    assert report.gate_failed
    assert not report.verifications[f.finding.key].fix_verified


def test_proof_beats_a_false_positive_label():
    f = ai(Severity.CRITICAL, false_positive=True)
    assert Report(ai_findings=[f], verifications={f.finding.key: exploited()}).gate_failed


def test_failed_exploit_does_not_block():
    f = ai(Severity.CRITICAL)
    attempt = Verification(attempted=True, red_passed=False)
    assert not Report(ai_findings=[f], verifications={f.finding.key: attempt}).gate_failed


def test_confirmed_high_does_not_block():
    f = ai(Severity.HIGH)
    assert not Report(ai_findings=[f], verifications={f.finding.key: exploited()}).gate_failed


def test_fix_verified_needs_every_step():
    full = exploited(patch_applied=True, green_passed=True, still_works_passed=True)
    assert full.fix_verified
    assert full.badge == "Exploited OK -> Patched OK -> Blocked OK -> Still works OK"
    broke_app = exploited(patch_applied=True, green_passed=True, still_works_passed=False)
    assert not broke_app.fix_verified
