"""Refresh tests/fixtures/*.json with real scanner output from the demo app.

    python scripts/capture_fixtures.py

Needs Docker and the four scanner images. Output is trimmed to the fields the
parsers read, so fixtures stay small and reviewable.
"""

from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path

from exhibita.core import scanners as s

ROOT = Path(__file__).resolve().parent.parent
DEMO = ROOT / "demo" / "vulnerable_app"
FIXTURES = ROOT / "tests" / "fixtures"


def _dump(name: str, data) -> None:
    (FIXTURES / name).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    print(f"wrote tests/fixtures/{name}")


def _pick(d: dict, *keys: str) -> dict:
    return {k: d.get(k) for k in keys}


def main() -> None:
    FIXTURES.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="exhibita-fx-") as tmp:
        src = Path(tmp) / "src"
        shutil.copytree(DEMO, src, ignore=s.SNAPSHOT_IGNORE)
        rules = Path(tmp) / "rules"
        shutil.copytree(s.RULES_DIR, rules)

        r = s._run(
            s._base(s.IMAGES["semgrep"], s._mount(src, "/src") + s._mount(rules, "/rules"))
            + ["semgrep", "scan", "--config", "/rules", "--json", "--quiet",
               "--disable-version-check", "--metrics=off", "/src"],
            timeout=300,
        )
        semgrep = s._extract_json(r.stdout)
        _dump("semgrep.json", {
            "results": [
                _pick(res, "check_id", "path", "start", "end")
                | {"extra": _pick(res["extra"], "message", "severity", "metadata", "lines")}
                for res in semgrep["results"]
            ],
            "errors": [],
        })

        out = Path(tmp) / "out"
        out.mkdir()
        s._run(
            s._base(s.IMAGES["gitleaks"], s._mount(src, "/src") + s._mount(out, "/out", read_only=False))
            + ["dir", "/src", "--report-format", "json", "--report-path", "/out/gl.json",
               "--exit-code", "0", "--no-banner", "--redact"],
            timeout=180,
        )
        gitleaks = json.loads((out / "gl.json").read_text(encoding="utf-8"))
        _dump("gitleaks.json", [_pick(i, "RuleID", "Description", "File", "StartLine", "Match") for i in gitleaks])

        r = s._run(
            ["docker", "run", "--rm", "-i", "--network=none", s.IMAGES["hadolint"],
             "hadolint", "--format", "json", "--no-fail", "-"],
            stdin=(DEMO / "Dockerfile").read_text(encoding="utf-8"),
        )
        _dump("hadolint.json", s._extract_json(r.stdout))

        r = s._run(
            s._base(s.IMAGES["checkov"], s._mount(src, "/src"))
            + ["-d", "/src", "-o", "json", "--compact", "--quiet", "--soft-fail"],
            timeout=300,
        )
        checkov = s._extract_json(r.stdout)
        blocks = checkov if isinstance(checkov, list) else [checkov]
        _dump("checkov.json", [
            {
                "check_type": b.get("check_type"),
                "results": {"failed_checks": [
                    _pick(c, "check_id", "check_name", "file_path", "file_line_range", "resource", "severity")
                    for c in b.get("results", {}).get("failed_checks", [])
                ]},
            }
            for b in blocks
        ])


if __name__ == "__main__":
    main()
