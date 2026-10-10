"""Scope a run to the files a pull request changed.

On a PR there is no reason to re-triage and re-prove unchanged code every time.
`changed_files()` asks git which paths changed since a base ref and maps them to
the scan root's layout; `filter_to_changed()` keeps only findings in those files.
Full-repo coverage is still available by not passing a base ref (e.g. on a nightly
or merge-to-main run).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from ..models import Finding


def _git(repo_dir: Path, *args: str, timeout: int = 60) -> str | None:
    try:
        r = subprocess.run(["git", "-C", str(repo_dir), *args],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:  # noqa: BLE001 - git missing / not a repo is a non-result
        return None
    return r.stdout if r.returncode == 0 else None


def changed_files(scan_path: str | Path, base_ref: str) -> set[str] | None:
    """Paths changed since base_ref, relative to the scan root. None if git can't tell."""
    scan_path = Path(scan_path).resolve()
    base = scan_path if scan_path.is_dir() else scan_path.parent

    root_out = _git(base, "rev-parse", "--show-toplevel", timeout=30)
    if root_out is None:
        return None
    repo_root = Path(root_out.strip())
    diff = _git(base, "diff", "--name-only", f"{base_ref}...HEAD")
    if diff is None:
        return None

    out: set[str] = set()
    for line in diff.splitlines():
        p = line.strip()
        if not p:
            continue
        try:
            rel = (repo_root / p).resolve().relative_to(base).as_posix()
        except ValueError:
            continue  # changed file lives outside the scanned folder
        out.add(rel)
    return out


def filter_to_changed(findings: list[Finding], changed: set[str]) -> list[Finding]:
    return [f for f in findings if f.file in changed]
