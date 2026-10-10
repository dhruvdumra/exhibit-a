"""Optional `.exhibita.yml` policy file.

Lets a project choose scanners, ignore paths, the gate threshold, the explanation
language, and — importantly — declare HTTP routes for findings so verification
works on frameworks the AST locator doesn't read (FastAPI, Django, Express, ...).
Absent or malformed config falls back to safe defaults; a project without one
behaves exactly as before.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml

from .models import Finding, Severity

CONFIG_NAME = ".exhibita.yml"


@dataclass
class RouteHint:
    """Maps a finding (by rule_id or vulnerability class) to its HTTP entry point."""
    match: str
    path: str
    param: str | None = None


@dataclass
class ExhibitaConfig:
    scanners: list[str] | None = None
    ignore: list[str] = field(default_factory=list)
    gate_severity: Severity = Severity.CRITICAL
    lang: str = "en"
    fix_check: bool = True
    routes: list[RouteHint] = field(default_factory=list)
    source: Path | None = None

    @classmethod
    def load(cls, start: str | Path) -> ExhibitaConfig:
        """Find and parse .exhibita.yml at the target dir (or its parent); defaults if absent."""
        start = Path(start)
        search = [start] if start.is_dir() else [start.parent]
        for base in search:
            candidate = base / CONFIG_NAME
            if candidate.exists():
                return cls._parse(candidate)
        return cls()

    @classmethod
    def _parse(cls, path: Path) -> ExhibitaConfig:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError):
            return cls()
        if not isinstance(data, dict):
            return cls()
        verify = data.get("verify") or {}
        sev = str(data.get("gate_severity", "critical")).lower()
        routes = [
            RouteHint(match=str(r["match"]), path=str(r["path"]), param=r.get("param"))
            for r in (verify.get("routes") or [])
            if isinstance(r, dict) and r.get("match") and r.get("path")
        ]
        return cls(
            scanners=data.get("scanners"),
            ignore=list(data.get("ignore") or []),
            gate_severity=Severity(sev) if sev in Severity._value2member_map_ else Severity.CRITICAL,
            lang=str(data.get("lang", "en")),
            fix_check=bool(data.get("fix_check", True)),
            routes=routes,
            source=path,
        )

    def route_for(self, finding: Finding, exploit_class: str | None) -> RouteHint | None:
        """A declared route matching this finding's rule_id or class, if any."""
        for r in self.routes:
            if r.match in (finding.rule_id, exploit_class):
                return r
        return None
