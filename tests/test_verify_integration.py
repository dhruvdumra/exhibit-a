"""End-to-end verification against the demo's real runtime. Needs Docker.

Slow (builds/runs containers); skipped automatically where Docker or the runtime
image isn't available, so the fast unit suite stays Docker-free.
"""

from pathlib import Path

import pytest

from exhibita.core import verify as verify_mod
from exhibita.models import AIFinding, Finding, Severity

DEMO = Path(__file__).resolve().parent.parent / "demo" / "vulnerable_app"

pytestmark = pytest.mark.skipif(
    not verify_mod.runtime_ready(DEMO)[0] or not verify_mod.sandbox_available()
    and not (DEMO / "Dockerfile").exists(),
    reason="Docker runtime not available",
)


def _ai(rule_id, line, fix, start, end, cls, sev=Severity.CRITICAL):
    return AIFinding(explanation="x", confidence=1.0, exploit_class=cls, suggested_fix=fix,
                     fix_start_line=start, fix_end_line=end,
                     finding=Finding(tool="semgrep", rule_id=rule_id, file="app.py",
                                     line=line, severity=sev, message="x"))


def test_sql_injection_proves_and_fix_verifies():
    ai = _ai("exhibita-sql-injection", 52,
             'query = "SELECT owner, body FROM notes WHERE owner = ?"\n'
             'rows = conn.execute(query, (owner,)).fetchall()',
             51, 52, "sql_injection")
    v = verify_mod.verify_finding(ai, DEMO)
    assert v.exploit_confirmed, v.detail
    assert v.fix_verified, v.badge


def test_ineffective_fix_is_rejected_but_exploit_still_confirmed():
    ai = _ai("exhibita-sql-injection", 52,
             'query = "SELECT owner, body FROM notes WHERE owner = \'%s\'" % owner  # unchanged\n'
             'rows = conn.execute(query).fetchall()',
             51, 52, "sql_injection")
    v = verify_mod.verify_finding(ai, DEMO)
    assert v.exploit_confirmed
    assert not v.fix_verified


def test_gate_blocks_on_a_confirmed_exploit():
    from exhibita.models import Report
    ai = _ai("exhibita-command-injection", 60, None, None, None, "command_injection")
    v = verify_mod.verify_finding(ai, DEMO)
    assert v.exploit_confirmed
    assert Report(ai_findings=[ai], verifications={ai.finding.key: v}).gate_failed
