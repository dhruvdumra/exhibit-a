"""Run security scanners as Docker images and normalize their output to Finding[].

Every scanner runs in its official container with no network, reads the target
read-only, and has its output parsed by a pure `parse_*` function (unit-tested
against saved real output in tests/fixtures). If one scanner is missing or errors,
we record a warning and keep going — a broken tool never kills the run.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Finding, Severity

RULES_DIR = Path(__file__).resolve().parent.parent / "rules"

IMAGES = {
    "semgrep": "semgrep/semgrep:latest",
    "gitleaks": "ghcr.io/gitleaks/gitleaks:latest",
    "hadolint": "hadolint/hadolint:latest",
    "checkov": "bridgecrew/checkov:latest",
}
DEFAULT_SCANNERS = ["semgrep", "gitleaks", "hadolint", "checkov"]

SNAPSHOT_IGNORE = shutil.ignore_patterns(
    ".git", ".venv", "venv", "node_modules", "__pycache__", ".pytest_cache", ".exhibita_cache"
)


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    tool_status: dict[str, str] = field(default_factory=dict)


# --- docker plumbing ---------------------------------------------------------

def docker_available() -> bool:
    try:
        r = subprocess.run(
            ["docker", "info", "--format", "{{.ServerVersion}}"],
            capture_output=True, text=True, timeout=30,
        )
        return r.returncode == 0
    except Exception:
        return False


def _run(cmd: list[str], timeout: int = 180, stdin: str | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        input=stdin, encoding="utf-8", errors="replace",
    )


def _mount(src: Path, target: str, read_only: bool = True) -> list[str]:
    spec = f"type=bind,source={src.resolve().as_posix()},target={target}"
    if read_only:
        spec += ",readonly"
    return ["--mount", spec]


def _base(image: str, mounts: list[str]) -> list[str]:
    return ["docker", "run", "--rm", "--network=none", *mounts, image]


def _extract_json(text: str):
    """Tolerantly pull the first JSON object/array out of mixed stdout."""
    text = text.strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    m = re.search(r"(\{.*\}|\[.*\])", text, re.DOTALL)
    if m:
        try:
            return json.loads(m.group(1))
        except json.JSONDecodeError:
            return None
    return None


def _rel(path: str) -> str:
    """Turn a container path like /src/app.py back into a repo-relative path."""
    return path[len("/src/"):] if path.startswith("/src/") else path.lstrip("/")


# --- parsers (pure, unit-tested) ---------------------------------------------

_SEMGREP_SEV = {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}
_HADOLINT_SEV = {"error": Severity.HIGH, "warning": Severity.MEDIUM, "info": Severity.LOW, "style": Severity.INFO}
_CHECKOV_SEV = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
}


def parse_semgrep(data: dict) -> list[Finding]:
    out = []
    for res in data.get("results", []):
        extra = res.get("extra", {})
        declared = extra.get("metadata", {}).get("exhibita_severity")
        if declared in Severity._value2member_map_:
            severity = Severity(declared)
        else:
            severity = _SEMGREP_SEV.get(extra.get("severity", "WARNING"), Severity.MEDIUM)
        lines = (extra.get("lines") or "").strip()
        if lines == "requires login":  # Semgrep CE withholds code lines without a login
            lines = ""
        out.append(Finding(
            tool="semgrep",
            rule_id=res.get("check_id", "semgrep").split(".")[-1],
            file=_rel(res.get("path", "")),
            line=res.get("start", {}).get("line", 0),
            severity=severity,
            message=extra.get("message", "").strip(),
            snippet=lines[:400],
        ))
    return out


def parse_gitleaks(data: list) -> list[Finding]:
    return [
        Finding(
            tool="gitleaks",
            rule_id=item.get("RuleID", "secret"),
            file=_rel(item.get("File", "")),
            line=item.get("StartLine", 0),
            severity=Severity.HIGH,
            message=f"Hardcoded secret: {item.get('Description', 'detected credential').rstrip('.')}.",
            snippet=(item.get("Match", "") or "").strip()[:200],
        )
        for item in data or []
    ]


def parse_hadolint(data: list, rel_path: str) -> list[Finding]:
    return [
        Finding(
            tool="hadolint",
            rule_id=item.get("code", "DL"),
            file=rel_path,
            line=item.get("line", 0),
            severity=_HADOLINT_SEV.get(item.get("level", "warning"), Severity.MEDIUM),
            message=item.get("message", "").strip(),
        )
        for item in data or []
    ]


def parse_checkov(data: dict | list) -> list[Finding]:
    blocks = data if isinstance(data, list) else [data]
    out = []
    for block in blocks:
        for chk in (block or {}).get("results", {}).get("failed_checks", []):
            line_range = chk.get("file_line_range") or [0]
            out.append(Finding(
                tool="checkov",
                rule_id=chk.get("check_id", "CKV"),
                # Checkov reports paths relative to its -d root ("/k8s/app.yaml"),
                # so only the leading slash goes — a repo folder named "src" stays.
                file=(chk.get("file_path") or "").lstrip("/"),
                line=line_range[0],
                severity=_CHECKOV_SEV.get((chk.get("severity") or "").upper(), Severity.MEDIUM),
                message=chk.get("check_name", "").strip(),
                snippet=(chk.get("resource", "") or "").strip()[:200],
            ))
    return out


# --- scanners (docker + parse) -----------------------------------------------

def scan_semgrep(target: Path) -> list[Finding]:
    # Mount a fresh copy of the rules each run; Docker Desktop can serve a stale,
    # empty view of a directory whose files changed after it was first mounted.
    with tempfile.TemporaryDirectory(prefix="exhibita-rules-") as rules_tmp:
        for rule_file in RULES_DIR.glob("*.y*ml"):
            shutil.copy2(rule_file, rules_tmp)
        mounts = _mount(target, "/src") + _mount(Path(rules_tmp), "/rules")
        cmd = _base(IMAGES["semgrep"], mounts) + [
            "semgrep", "scan", "--config", "/rules", "--json", "--quiet",
            "--disable-version-check", "--metrics=off", "/src",
        ]
        r = _run(cmd, timeout=300)
    data = _extract_json(r.stdout)
    if not data:
        raise RuntimeError((r.stderr or "no JSON output").strip()[:300])
    return parse_semgrep(data)


def scan_gitleaks(target: Path) -> list[Finding]:
    # gitleaks cannot reliably write its report to /dev/stdout (it seeks on the
    # file), so give it a writable output dir and read the JSON back from the host.
    with tempfile.TemporaryDirectory(prefix="exhibita-gl-") as outdir:
        mounts = _mount(target, "/src") + _mount(Path(outdir), "/out", read_only=False)
        cmd = _base(IMAGES["gitleaks"], mounts) + [
            "dir", "/src", "--report-format", "json", "--report-path", "/out/gl.json",
            "--exit-code", "0", "--no-banner", "--redact",
        ]
        r = _run(cmd, timeout=180)
        report = Path(outdir) / "gl.json"
        if not report.exists():
            raise RuntimeError((r.stderr or "gitleaks produced no report").strip()[:300])
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    return parse_gitleaks(data)


def scan_hadolint(target: Path) -> list[Finding]:
    dockerfiles = [
        p for p in target.rglob("*")
        if p.is_file() and p.name.lower().startswith("dockerfile")
        and not any(part in {".git", "node_modules", ".venv"} for part in p.parts)
    ]
    out = []
    for df in dockerfiles:
        cmd = ["docker", "run", "--rm", "-i", "--network=none", IMAGES["hadolint"],
               "hadolint", "--format", "json", "--no-fail", "-"]
        r = _run(cmd, timeout=120, stdin=df.read_text(encoding="utf-8", errors="replace"))
        data = _extract_json(r.stdout)
        if data:
            out.extend(parse_hadolint(data, df.relative_to(target).as_posix()))
    return out


def scan_checkov(target: Path) -> list[Finding]:
    cmd = _base(IMAGES["checkov"], _mount(target, "/src")) + [
        "-d", "/src", "-o", "json", "--compact", "--quiet", "--soft-fail",
    ]
    r = _run(cmd, timeout=300)
    data = _extract_json(r.stdout)
    if data is None:
        raise RuntimeError((r.stderr or "no JSON output").strip()[:300])
    return parse_checkov(data)


_SCANNERS = {
    "semgrep": scan_semgrep,
    "gitleaks": scan_gitleaks,
    "hadolint": scan_hadolint,
    "checkov": scan_checkov,
}


# --- orchestration -----------------------------------------------------------

def _visible_in_docker(path: Path) -> bool:
    """True if a container mounting `path` actually sees its files."""
    cmd = [
        "docker", "run", "--rm", "--network=none", *_mount(path, "/src"),
        "--entrypoint", "ls", IMAGES["semgrep"], "-A", "/src",
    ]
    try:
        r = _run(cmd, timeout=60)
    except subprocess.TimeoutExpired:
        return False
    return r.returncode == 0 and bool(r.stdout.strip())


def _stage_target(target: Path, result: ScanResult) -> tuple[Path, tempfile.TemporaryDirectory | None]:
    """Return a directory the scanners can really see, snapshotting if needed.

    A scanner that silently sees an empty mount would report "no findings" for code
    it never read. We refuse to let that look like a clean result.
    """
    if target.is_file():
        tmp = tempfile.TemporaryDirectory(prefix="exhibita-src-")
        shutil.copy2(target, tmp.name)
        return Path(tmp.name), tmp
    if not any(target.iterdir()) or _visible_in_docker(target):
        return target, None
    tmp = tempfile.TemporaryDirectory(prefix="exhibita-src-")
    snapshot = Path(tmp.name) / "src"
    shutil.copytree(target, snapshot, ignore=SNAPSHOT_IGNORE)
    if not _visible_in_docker(snapshot):
        tmp.cleanup()
        raise RuntimeError(
            "Docker cannot see the files to scan, even from a temporary copy. "
            "Check Docker Desktop > Settings > Resources > File sharing."
        )
    result.warnings.append(
        "Docker could not read the target folder directly (Docker Desktop file sharing), "
        "so ExhibitA scanned a temporary snapshot of it."
    )
    return snapshot, tmp


def run_all(path: str | Path, scanners: list[str] | None = None) -> ScanResult:
    target = Path(path).resolve()
    result = ScanResult()
    if not target.exists():
        result.warnings.append(f"Target not found: {target}")
        return result
    if not docker_available():
        result.warnings.append("Docker is not running. Start Docker Desktop and retry.")
        return result

    try:
        scan_root, snapshot = _stage_target(target, result)
    except RuntimeError as e:
        result.warnings.append(str(e))
        return result

    try:
        for name in (scanners or DEFAULT_SCANNERS):
            fn = _SCANNERS.get(name)
            if not fn:
                result.warnings.append(f"Unknown scanner: {name}")
                continue
            try:
                found = fn(scan_root)
                result.findings.extend(found)
                result.tool_status[name] = f"{len(found)} finding(s)"
            except subprocess.TimeoutExpired:
                result.tool_status[name] = "timed out"
                result.warnings.append(f"{name}: timed out")
            except Exception as e:  # noqa: BLE001 - one tool failing must not stop the rest
                result.tool_status[name] = "error"
                result.warnings.append(f"{name}: {e}")
    finally:
        if snapshot is not None:
            snapshot.cleanup()

    result.findings = _dedupe(result.findings)
    fill_snippets(result.findings, target if target.is_dir() else target.parent)
    result.findings.sort(key=lambda f: (-f.severity.rank, f.file, f.line))
    return result


def fill_snippets(findings: list[Finding], base: Path) -> None:
    """Fill missing snippets with the flagged source line.

    Secret findings are skipped on purpose: their snippet stays the scanner's
    redacted match, so a live credential never reaches a prompt or a PR comment.
    """
    cache: dict[str, list[str]] = {}
    for f in findings:
        if f.snippet or f.tool == "gitleaks" or f.line <= 0:
            continue
        if f.file not in cache:
            try:
                cache[f.file] = (base / f.file).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                cache[f.file] = []
        lines = cache[f.file]
        if f.line <= len(lines):
            f.snippet = lines[f.line - 1].strip()[:400]


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen: dict[str, Finding] = {}
    for f in findings:
        seen.setdefault(f.key, f)
    return list(seen.values())
