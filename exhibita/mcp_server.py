"""MCP server — exposes ExhibitA to coding agents as tools.

An agent (Claude Code, Gemini CLI, etc.) can call `scan`, `verify`, and
`threat_model` over the Model Context Protocol, so it can review its own changes
before proposing them. Each tool wraps the same core pipeline the CLI uses and
returns plain JSON-serializable data.

Run with:  python -m exhibita.mcp_server   (stdio transport)
"""

from __future__ import annotations

import os
from pathlib import Path

from mcp.server.mcpserver import MCPServer

from . import __version__
from .backends import get_backend
from .backends.base import LLMError
from .core import engine as engine_mod
from .core import scanners as scanners_mod
from .core import verify as verify_mod
from .models import Report

server = MCPServer(
    name="exhibita",
    version=__version__,
    instructions=(
        "ExhibitA proves and fixes security vulnerabilities. Use `scan` for a fast "
        "triaged review, `verify` to prove critical findings in a sandbox before "
        "trusting a fix, and `threat_model` to read an architecture image. Only run "
        "these against code the user owns."
    ),
)


def _backend(name: str | None):
    return get_backend(name or os.environ.get("MODEL_BACKEND", "ollama"))


def _finding_dict(ai, verification=None) -> dict:
    f = ai.finding
    out = {
        "tool": f.tool, "rule_id": f.rule_id, "file": f.file, "line": f.line,
        "severity": f.severity.value, "explanation": ai.explanation,
        "likely_false_positive": ai.likely_false_positive, "confidence": ai.confidence,
        "suggested_fix": ai.suggested_fix,
    }
    if verification is not None and verification.attempted:
        out["proof"] = verification.badge
        out["exploit_confirmed"] = verification.exploit_confirmed
        out["fix_verified"] = verification.fix_verified
    return out


@server.tool(description="Scan a path and triage findings with Gemma 4. Returns findings with "
                         "plain-English explanations, false-positive flags, and suggested fixes.")
def scan(path: str, backend: str | None = None) -> dict:
    result = scanners_mod.run_all(path)
    if not result.findings:
        return {"findings": [], "warnings": result.warnings}
    try:
        llm = _backend(backend)
    except LLMError as e:
        return {"error": str(e), "raw_findings": len(result.findings)}
    base = Path(path).resolve()
    base = base if base.is_dir() else base.parent
    ai_findings = engine_mod.triage(result.findings, llm, base)
    real = [a for a in ai_findings if not a.likely_false_positive]
    return {
        "total": len(ai_findings),
        "filtered_false_positives": len(ai_findings) - len(real),
        "to_review": len(real),
        "engine": f"{llm.name}:{llm.model}",
        "findings": [_finding_dict(a) for a in real],
        "warnings": result.warnings,
    }


@server.tool(description="Scan, triage, and PROVE critical findings in an isolated sandbox. "
                         "Returns each finding with a proof badge and whether its fix verified. "
                         "`gate_failed` is true if a critical issue was proven exploitable.")
def verify(path: str, backend: str | None = None) -> dict:
    ready, detail = verify_mod.runtime_ready(path)
    if not ready:
        return {"error": f"cannot verify: {detail}"}
    result = scanners_mod.run_all(path)
    if not result.findings:
        return {"findings": [], "gate_failed": False}
    try:
        llm = _backend(backend)
    except LLMError as e:
        return {"error": str(e)}
    base = Path(path).resolve()
    base = base if base.is_dir() else base.parent
    ai_findings = engine_mod.triage(result.findings, llm, base)
    verifications = verify_mod.verify_all(ai_findings, base)
    report = Report(ai_findings=ai_findings, verifications=verifications, backend=f"{llm.name}:{llm.model}")
    return {
        "gate_failed": report.gate_failed,
        "proven": sum(1 for v in verifications.values() if v.exploit_confirmed),
        "fix_verified": sum(1 for v in verifications.values() if v.fix_verified),
        "findings": [_finding_dict(a, verifications.get(a.finding.key)) for a in report.real_findings],
    }


@server.tool(description="Read an architecture image (jpg/png) into a threat model: a list of "
                         "specific threats, each with a severity and a suggested check.")
def threat_model(image_path: str, backend: str | None = None) -> dict:
    p = Path(image_path)
    if not p.exists():
        return {"error": f"image not found: {image_path}"}
    try:
        llm = _backend(backend)
    except LLMError as e:
        return {"error": str(e)}
    tm = engine_mod.threat_model(p.read_bytes(), llm)
    return {
        "summary": tm.summary,
        "threats": [
            {"title": t.title, "description": t.description,
             "severity": t.severity.value, "suggested_check": t.suggested_check}
            for t in tm.threats
        ],
    }


def main() -> None:
    server.run()


if __name__ == "__main__":
    main()
