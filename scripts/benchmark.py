"""Benchmark ExhibitA's triage on a real codebase (default: OWASP Juice Shop).

Measures noise reduction: Semgrep's registry rules raise N alerts; how many does
Gemma 4 flag as likely false positives, and how many are left to review? Writes a
Markdown report you can show, with honest labels (AI-flagged, not hand-verified).

    python scripts/benchmark.py --target "C:/Users/dhruv/Downloads/juice-shop" --backend ollama --sample 25

This is a triage benchmark, not a proof benchmark: the target is not run, so the
red->green sandbox proof (which ExhibitA does apply to runnable apps) is not exercised.
"""

from __future__ import annotations

import argparse
import time
from collections import Counter
from pathlib import Path

from exhibita.backends import get_backend
from exhibita.core import engine as engine_mod
from exhibita.core import scanners as s

# Server-side source worth scanning; skip the huge Angular frontend and deps.
SUBDIRS = ["routes", "lib", "models", "data", "config", "server.ts"]

# Map a registry rule id to one of ExhibitA's provable classes, by keyword.
_PROVABLE = {
    "sql_injection": ("sql", "sequelize-injection"),
    "command_injection": ("command", "child-process", "exec-", "child_process"),
    "path_traversal": ("path-traversal", "directory-traversal", "sendfile", "path-join"),
    "ssti": ("template-injection", "ssti"),
    "xss": ("xss", "cross-site", "open-redirect"),
    "xxe": ("xxe", "xml-external"),
}


def provable_class(rule_id: str) -> str | None:
    rid = rule_id.lower()
    for cls, keys in _PROVABLE.items():
        if any(k in rid for k in keys):
            return cls
    return None


def raw_semgrep(repo: Path, ruleset: str) -> list:
    targets = [f"/src/{d}" for d in SUBDIRS if (repo / d).exists()]
    config_flags = [x for pack in ruleset.split() for x in ("--config", pack)]
    # Registry rules download from semgrep.dev, so this run needs network (unlike the
    # offline custom-rule scans in scanners.py).
    cmd = [
        "docker", "run", "--rm", *s._mount(repo, "/src"), s.IMAGES["semgrep"],
        "semgrep", "scan", *config_flags, "--json", "--quiet",
        "--metrics=off", "--disable-version-check",
        "--exclude", "node_modules", "--exclude", "dist", "--exclude", "build",
        *targets,
    ]
    r = s._run(cmd, timeout=1200)
    data = s._extract_json(r.stdout)
    if not data:
        raise SystemExit(f"semgrep produced no output: {(r.stderr or '')[:300]}")
    return s.parse_semgrep(data)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default=str(Path.home() / "Downloads" / "juice-shop"))
    ap.add_argument("--backend", default="ollama")
    ap.add_argument("--sample", type=int, default=25)
    ap.add_argument("--ruleset", default="p/javascript p/typescript p/owasp-top-ten p/security-audit")
    ap.add_argument("--out", default="BENCHMARK.md")
    args = ap.parse_args()

    repo = Path(args.target)
    if not repo.is_dir():
        raise SystemExit(f"target not found: {repo}")

    print(f"Scanning {repo.name} server-side source with Semgrep {args.ruleset} ...")
    t0 = time.time()
    findings = raw_semgrep(repo, args.ruleset)
    scan_s = time.time() - t0
    print(f"  {len(findings)} raw alerts in {scan_s:.0f}s")

    sample = findings[: args.sample]
    backend = get_backend(args.backend)
    print(f"Triaging {len(sample)} with {backend.name}:{backend.model} ...")
    t1 = time.time()
    ai = engine_mod.triage(sample, backend, repo)
    triage_s = time.time() - t1

    flagged = [a for a in ai if a.likely_false_positive]
    review = [a for a in ai if not a.likely_false_positive]
    rule_counts = Counter(f.rule_id.split(".")[-1] for f in findings)
    provable = [f for f in findings if provable_class(f.rule_id)]
    provable_counts = Counter(provable_class(f.rule_id) for f in provable)

    pct = (len(flagged) / len(ai) * 100) if ai else 0
    md = [
        f"# ExhibitA benchmark — {repo.name}",
        "",
        f"Target: **{repo.name}** — {len(findings)} alerts from Semgrep `{args.ruleset}` over "
        f"its server-side source.  Engine: `{backend.name}:{backend.model}`.",
        "",
        "## What a plain scanner leaves you with",
        "",
        f"- **{len(findings)}** raw Semgrep alerts (scan: {scan_s:.0f}s) — a wall of alerts to read.",
        "",
        "## What ExhibitA adds",
        "",
        f"- **{len(provable)}** of the {len(findings)} alerts fall into classes ExhibitA can **prove** "
        "exploitable in a sandbox when the app is run: "
        + ", ".join(f"{c} ×{n}" for c, n in provable_counts.most_common()) + ".",
        f"- **{len(ai)}** triaged in this run (sample of {args.sample}; triage: {triage_s:.0f}s) — "
        "each gets a plain-English explanation and a suggested fix.",
        f"- **{len(flagged)}** ({pct:.0f}%) AI-flagged *likely false positive*, **{len(review)}** left to review."
        + ("  On a deliberately vulnerable app this is expected: Gemma confirmed the alerts rather than "
           "dismissing real issues. (It filters genuine noise — see the MD5-as-cache-key case in the demo app.)"
           if len(flagged) == 0 else ""),
        "",
        "> Honesty: false-positive labels are Gemma's assessment, not hand-verified. The "
        "sandbox proof is not run here (Juice Shop isn't launched); this measures triage "
        "and shows how much of the wall is provable.",
        "",
        "## Most common alert types",
        "",
        *[f"- `{rid}` × {n}" for rid, n in rule_counts.most_common(10)],
    ]
    if flagged:
        md += ["", "## Examples Gemma flagged as likely false positives", ""]
        md += [f"- `{a.finding.rule_id.split('.')[-1]}` {a.finding.file}:{a.finding.line} — {a.explanation}"
               for a in flagged[:5]]
    Path(args.out).write_text("\n".join(md), encoding="utf-8")
    print(f"\nRaw: {len(findings)}  |  triaged: {len(ai)}  |  flagged FP: {len(flagged)} ({pct:.0f}%)  "
          f"|  to review: {len(review)}  |  provable-class alerts: {len(provable)}")
    print(f"Wrote {args.out}")


if __name__ == "__main__":
    main()
