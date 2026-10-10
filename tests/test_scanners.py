"""Scanner parsers, tested against real output captured from the demo app.

Refresh the fixtures with `python scripts/capture_fixtures.py`.
"""

import json
from pathlib import Path

import pytest

from exhibita.core import scanners
from exhibita.models import Finding, Severity

FIXTURES = Path(__file__).parent / "fixtures"


def load(name: str):
    return json.loads((FIXTURES / name).read_text(encoding="utf-8"))


def test_semgrep_flags_the_provable_bugs_as_critical():
    found = scanners.parse_semgrep(load("semgrep.json"))
    by_rule = {f.rule_id for f in found}
    # every exploit class ExhibitA can prove is detected
    assert {
        "exhibita-sql-injection", "exhibita-command-injection", "exhibita-path-traversal",
        "exhibita-template-injection", "exhibita-reflected-xss", "exhibita-xxe",
    } <= by_rule
    crit = {f.rule_id: f for f in found if f.severity == Severity.CRITICAL}
    assert crit["exhibita-sql-injection"].line == 52
    assert crit["exhibita-command-injection"].line == 60
    assert crit["exhibita-path-traversal"].file == "app.py"


def test_semgrep_login_placeholder_is_not_a_snippet():
    data = {"results": [{
        "check_id": "rules.r", "path": "/src/a.py", "start": {"line": 3},
        "extra": {"lines": "requires login", "severity": "ERROR", "metadata": {}},
    }]}
    (f,) = scanners.parse_semgrep(data)
    assert f.snippet == ""
    assert f.severity == Severity.HIGH  # falls back to Semgrep's own severity


def test_gitleaks_keeps_matches_redacted():
    found = scanners.parse_gitleaks(load("gitleaks.json"))
    assert [(f.file, f.line) for f in found] == [("Dockerfile", 4), ("config.py", 6)]
    assert all("REDACTED" in f.snippet for f in found)
    assert all(f.severity == Severity.HIGH for f in found)


def test_hadolint_codes_and_lines():
    found = scanners.parse_hadolint(load("hadolint.json"), "Dockerfile")
    assert {(f.rule_id, f.line) for f in found} == {
        ("DL3007", 2), ("DL3064", 4), ("DL3013", 9), ("DL3042", 9), ("DL3025", 13),
    }
    assert {f.file for f in found} == {"Dockerfile"}


def test_checkov_covers_all_three_frameworks():
    found = scanners.parse_checkov(load("checkov.json"))
    assert len(found) == 26
    assert {f.file for f in found} == {
        "k8s/deployment.yaml", "Dockerfile", ".github/workflows/deploy.yml",
    }


def test_checkov_accepts_a_single_report_object():
    single = {"results": {"failed_checks": [{"check_id": "CKV_X", "file_path": "/src/main.tf",
                                             "file_line_range": [7, 9], "check_name": "x"}]}}
    (f,) = scanners.parse_checkov(single)
    assert (f.rule_id, f.file, f.line) == ("CKV_X", "src/main.tf", 7)


@pytest.mark.parametrize("container_path, expected", [
    ("/src/app.py", "app.py"),
    ("/src/src_utils/db.py", "src_utils/db.py"),
    ("/src/src/main.py", "src/main.py"),
    ("relative.py", "relative.py"),
])
def test_rel_strips_only_the_mount_point(container_path, expected):
    assert scanners._rel(container_path) == expected


def test_fill_snippets_reads_source_but_never_secrets(tmp_path):
    (tmp_path / "app.py").write_text("import os\npassword = 'hunter2'\n", encoding="utf-8")
    code = Finding(tool="semgrep", rule_id="r", file="app.py", line=2)
    secret = Finding(tool="gitleaks", rule_id="s", file="app.py", line=2)
    scanners.fill_snippets([code, secret], tmp_path)
    assert code.snippet == "password = 'hunter2'"
    assert secret.snippet == ""


def test_dedupe_keeps_first_of_identical_findings():
    a = Finding(tool="semgrep", rule_id="r", file="a.py", line=1, message="first")
    b = Finding(tool="semgrep", rule_id="r", file="a.py", line=1, message="second")
    assert [f.message for f in scanners._dedupe([a, b])] == ["first"]
