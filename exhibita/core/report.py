"""Turn a Report into the artifacts CI consumes: SARIF, a Markdown summary, and
inline PR suggestion comments.

SARIF lands in GitHub's Security tab; the Markdown is posted as the job summary and
the PR comment; inline comments carry one-click ```suggestion fixes on the exact
lines. Evidence is labelled honestly — "proven" only when the sandbox confirmed it.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..models import AIFinding, Report, Severity, Verification

_SARIF_LEVEL = {
    Severity.CRITICAL: "error", Severity.HIGH: "error",
    Severity.MEDIUM: "warning", Severity.LOW: "note", Severity.INFO: "note",
}


def _evidence(v: Verification | None) -> str:
    if v is None:
        return "explained"
    if v.fix_verified:
        return "proven + fix verified"
    if v.exploit_confirmed:
        return "proven exploitable"
    if v.fix_checked:
        return "fix checked (re-scan clean)"
    return "explained"


def to_sarif(report: Report) -> dict:
    """SARIF 2.1.0 for upload to the GitHub Security tab."""
    rules: dict[str, dict] = {}
    results = []
    for ai in report.real_findings:
        f = ai.finding
        if f is None:
            continue
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f"{f.tool}: {f.rule_id}"},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(f.severity, "warning")},
            }
        v = report.verifications.get(f.key)
        results.append({
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f"{ai.explanation}  [evidence: {_evidence(v)}]"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.file},
                    "region": {"startLine": max(1, f.line)},
                }
            }],
            "partialFingerprints": {"exhibitaKey": f.key},
            "properties": {
                "severity": f.severity.value,
                "evidence": _evidence(v),
                "proofBadge": v.badge if v else "not verified",
            },
        })
    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "ExhibitA",
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _suggestion_block(ai: AIFinding) -> str:
    """A GitHub ```suggestion block when the fix maps to concrete lines."""
    if not (ai.suggested_fix and ai.fix_start_line and ai.fix_end_line):
        return ""
    return f"\n\n```suggestion\n{ai.suggested_fix.rstrip()}\n```\n"


def inline_comments(report: Report) -> list[dict]:
    """Per-finding inline review comments: {path, line, body}."""
    out = []
    for ai in report.real_findings:
        f = ai.finding
        if f is None:
            continue
        v = report.verifications.get(f.key)
        header = f"**ExhibitA — {f.severity.value.upper()} · {f.rule_id}** ({_evidence(v)})"
        body = f"{header}\n\n{ai.explanation}"
        if v and v.attempted:
            body += f"\n\n**Proof:** `{v.badge}`"
        body += _suggestion_block(ai)
        out.append({"path": f.file, "line": max(1, f.line), "body": body})
    return out


def to_markdown(report: Report) -> str:
    """Summary comment / job summary."""
    real = report.real_findings
    filtered = [a for a in report.ai_findings if a.likely_false_positive]
    proven = [a for a in real if (v := report.verifications.get(a.finding.key)) and v.exploit_confirmed]
    fixed = [a for a in real if (v := report.verifications.get(a.finding.key)) and v.fix_verified]

    lines = [
        "## 🔎 ExhibitA security review",
        "",
        f"- **{len(report.ai_findings)}** scanner finding(s)",
        f"- **{len(filtered)}** filtered as likely false positives by Gemma 4",
        f"- **{len(real)}** to review",
        f"- **{len(proven)}** proven exploitable in the sandbox · **{len(fixed)}** with a verified fix",
        f"- engine: `{report.backend}`",
        "",
    ]
    if report.gate_failed:
        lines.append("> ❌ **Build gate: FAILED** — a critical issue was proven exploitable. No proof, no block — but this one has proof.")
    else:
        lines.append("> ✅ **Build gate: passed** — no critical issue was proven exploitable.")
    lines.append("")

    for ai in sorted(real, key=lambda a: -(a.finding.severity.rank if a.finding else 0)):
        f = ai.finding
        v = report.verifications.get(f.key)
        lines.append(f"### {f.severity.value.upper()} · `{f.rule_id}` — {f.file}:{f.line}")
        lines.append(f"{ai.explanation}")
        lines.append(f"*Evidence: {_evidence(v)}*" + (f" — `{v.badge}`" if v and v.attempted else ""))
        lines.append("")

    for chain in report.attack_chains:
        lines.append(f"### ⛓️ Attack chain: {chain.title}")
        lines.append(chain.narrative)
        lines.append("")
        lines.append("```mermaid")
        lines.append(chain.mermaid)
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def write_outputs(report: Report, sarif_path: str | None = None, markdown_path: str | None = None) -> None:
    if sarif_path:
        Path(sarif_path).write_text(json.dumps(to_sarif(report), indent=2), encoding="utf-8")
    if markdown_path:
        Path(markdown_path).write_text(to_markdown(report), encoding="utf-8")
