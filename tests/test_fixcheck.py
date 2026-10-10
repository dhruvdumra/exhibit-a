"""Fix-check: apply a fix to a copy and confirm the scanner stops reporting it.

The scanner is monkeypatched so these stay fast and Docker-free.
"""

from exhibita.core import fixcheck
from exhibita.core import scanners as scanners_mod
from exhibita.models import AIFinding, Finding, Severity


def ai_with_fix(fix="API_TOKEN = os.environ['API_TOKEN']", s=2, e=2, rule="generic-api-key",
                tool="gitleaks", file="config.py"):
    return AIFinding(
        explanation="x", confidence=0.9, suggested_fix=fix, fix_start_line=s, fix_end_line=e,
        finding=Finding(tool=tool, rule_id=rule, file=file, line=2, severity=Severity.HIGH),
    )


def _stub_scanner(monkeypatch, tool, returns):
    monkeypatch.setitem(scanners_mod._SCANNERS, tool, lambda target: returns)


def test_checked_when_scanner_goes_clean(tmp_path, monkeypatch):
    (tmp_path / "config.py").write_text("import os\nAPI_TOKEN = 'secret-value-123'\n", encoding="utf-8")
    _stub_scanner(monkeypatch, "gitleaks", [])  # nothing left after the fix
    ok, detail = fixcheck.check(ai_with_fix(), tmp_path)
    assert ok
    assert "no longer reports" in detail


def test_not_checked_when_finding_persists(tmp_path, monkeypatch):
    (tmp_path / "config.py").write_text("import os\nAPI_TOKEN = 'secret-value-123'\n", encoding="utf-8")
    still = Finding(tool="gitleaks", rule_id="generic-api-key", file="config.py", line=2, severity=Severity.HIGH)
    _stub_scanner(monkeypatch, "gitleaks", [still])
    ok, detail = fixcheck.check(ai_with_fix(), tmp_path)
    assert not ok
    assert "still reports" in detail


def test_no_fix_means_no_check(tmp_path):
    bare = AIFinding(explanation="x", confidence=0.9,
                     finding=Finding(tool="gitleaks", rule_id="r", file="config.py", line=2, severity=Severity.HIGH))
    ok, detail = fixcheck.check(bare, tmp_path)
    assert not ok and "no usable fix" in detail


def test_non_compiling_python_fix_rejected(tmp_path, monkeypatch):
    (tmp_path / "app.py").write_text("x = 1\ny = bad(\n", encoding="utf-8")
    _stub_scanner(monkeypatch, "semgrep", [])
    ai = ai_with_fix(fix="y = still broken(", s=2, e=2, rule="exhibita-weak-hash", tool="semgrep", file="app.py")
    ok, detail = fixcheck.check(ai, tmp_path)
    assert not ok and "compile" in detail
