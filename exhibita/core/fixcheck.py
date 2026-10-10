"""Fix-check: lighter evidence for findings that can't get a full sandbox proof.

For a finding ExhibitA can't exploit-prove (a secret, a Dockerfile or Kubernetes
misconfig, a code smell), apply the AI's fix to a copy and re-run the scanner that
raised it. If the scanner no longer reports that rule for that file — and the file
still parses — the fix is "checked": not proof the bug was exploitable, but evidence
the fix actually resolves what was flagged. Never touches the working tree.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path

from ..models import AIFinding
from . import scanners as scanners_mod
from .patch import apply_fix, compiles


def check(ai: AIFinding, app_dir: str | Path) -> tuple[bool, str]:
    """Return (checked, detail): whether the fix makes the scanner stop reporting it."""
    f = ai.finding
    if f is None:
        return False, "no finding"
    if not (ai.suggested_fix and ai.fix_start_line and ai.fix_end_line):
        return False, "no usable fix to check"
    scanner_fn = scanners_mod._SCANNERS.get(f.tool)
    if scanner_fn is None:
        return False, f"no scanner to re-run for {f.tool}"

    with tempfile.TemporaryDirectory(prefix="exhibita-fixcheck-") as tmp:
        dest = Path(tmp) / "app"
        shutil.copytree(app_dir, dest, ignore=scanners_mod.SNAPSHOT_IGNORE)
        target = dest / f.file
        if not target.exists():
            return False, "flagged file not found in copy"
        original = target.read_text(encoding="utf-8", errors="replace")
        try:
            patched = apply_fix(original, ai.fix_start_line, ai.fix_end_line, ai.suggested_fix)
        except ValueError as e:
            return False, f"fix could not be applied ({e})"
        if f.file.endswith(".py") and not compiles(patched, f.file):
            return False, "fix did not compile"
        target.write_text(patched, encoding="utf-8")
        try:
            remaining = scanner_fn(dest)
        except Exception as e:  # noqa: BLE001 - a scanner failure is a non-result
            return False, f"re-scan failed: {str(e)[:120]}"

    still_there = any(x.rule_id == f.rule_id and x.file == f.file for x in remaining)
    if still_there:
        return False, f"{f.tool} still reports {f.rule_id} after the fix"
    return True, f"{f.tool} no longer reports {f.rule_id} after the fix"
