"""ExhibitA command-line interface."""

from __future__ import annotations

import os

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

import fnmatch

from . import __version__
from .backends import get_backend
from .backends.base import LLMError
from .config import ExhibitaConfig
from .core import engine as engine_mod
from .core import gitscope
from .core import report as report_mod
from .core import scanners as scanners_mod
from .core import verify as verify_mod
from .models import AIFinding, Report, Severity, Verification

app = typer.Typer(
    add_completion=False,
    help="ExhibitA — AI security reviewer that proves the fix, not just the finding.",
)
console = Console()

SEV_STYLE = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


def _version_cb(value: bool):
    if value:
        console.print(f"ExhibitA {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    _version: bool = typer.Option(
        False, "--version", callback=_version_cb, is_eager=True, help="Show version and exit."
    ),
):
    """ExhibitA root command."""


@app.command()
def scan(
    path: str = typer.Argument(..., help="File or directory to scan."),
    scanner: list[str] = typer.Option(None, "--scanner", "-s", help="Limit to these scanners."),
    explain: bool = typer.Option(True, "--explain/--no-explain", help="Run Gemma 4 triage on findings."),
    verify: bool = typer.Option(False, "--verify", help="Prove critical findings in the sandbox."),
    backend: str = typer.Option(None, "--backend", "-b", help="auto | ollama | gemini (default: auto — local model, else API key)."),
    lang: str = typer.Option("en", "--lang", "-l", help="Language for explanations (en, te, hi, ...)."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Ignore the response cache."),
    sarif: str = typer.Option(None, "--sarif", help="Write SARIF results to this path."),
    markdown: str = typer.Option(None, "--markdown", help="Write a Markdown summary to this path."),
    comments: str = typer.Option(None, "--comments", help="Write inline PR comments (JSON) to this path."),
    changed: str = typer.Option(None, "--changed", help="Only triage/prove findings in files changed since this git ref (PR mode)."),
):
    """Scan a path, explain and triage with Gemma 4, and optionally prove the fixes."""
    _pipeline(path, scanner, explain, verify, backend, lang, no_cache, sarif, markdown, comments, changed)


@app.command("verify")
def verify_cmd(
    path: str = typer.Argument(..., help="File or directory to scan and prove."),
    backend: str = typer.Option(None, "--backend", "-b", help="ollama | gemini."),
    lang: str = typer.Option("en", "--lang", "-l", help="Language for explanations."),
    no_cache: bool = typer.Option(False, "--no-cache", help="Ignore the response cache."),
):
    """Scan, triage, and prove critical findings end-to-end in the sandbox."""
    _pipeline(path, None, True, True, backend, lang, no_cache)


@app.command()
def doctor(
    install: bool = typer.Option(False, "--install", help="Open the official Docker installer for your OS if Docker is missing."),
):
    """Check the environment (Docker + a model) and start Docker if it's installed."""
    import os as _os
    import platform as _platform
    import webbrowser
    from .backends import OllamaBackend
    from .core import runtime as rt

    ok = True
    console.print("[bold]ExhibitA environment check[/]\n")
    if rt.docker_running():
        console.print("[green]OK[/]  Docker is running")
    elif rt.docker_installed():
        console.print("[yellow]..[/] Docker is installed but not running — starting it")
        rt.start_docker_desktop()
        if rt.wait_for_docker():
            console.print("[green]OK[/]  Docker started")
        else:
            ok = False
            console.print("[red]X[/]  Docker did not start — open Docker Desktop manually")
    else:
        ok = False
        hint = rt.INSTALL_HINT.get(_platform.system(), rt.INSTALL_HINT["Linux"])
        console.print(f"[red]X[/]  Docker not installed. {hint}")
        url = hint.split(": ", 1)[-1]
        if install:
            console.print(f"[dim]Opening the official Docker installer: {url}[/]")
            try:
                webbrowser.open(url)
            except Exception:  # noqa: BLE001
                pass
            console.print("[dim]Install Docker, start it, then re-run `exhibita doctor`.[/]")
        else:
            console.print("[dim]Re-run with `exhibita doctor --install` to open the official installer.[/]")

    ready, detail = OllamaBackend().available()
    if ready:
        console.print(f"[green]OK[/]  Local model — {detail}")
    elif _os.environ.get("GEMINI_API_KEY"):
        console.print("[green]OK[/]  Cloud model — GEMINI_API_KEY is set")
    else:
        ok = False
        console.print("[red]X[/]  No model. Run `ollama pull gemma4:e4b` (offline) or set GEMINI_API_KEY (cloud)")

    if ok:
        console.print("\n[bold green]Ready.[/] Try: exhibita verify demo/vulnerable_app")
    else:
        console.print("\n[bold red]Not ready[/] — fix the items marked X above.")
        raise typer.Exit(1)


@app.command("threat-model")
def threat_model_cmd(
    image: str = typer.Argument(..., help="Photo or sketch of the architecture (jpg/png)."),
    audio: str = typer.Option(None, "--audio", help="Optional spoken description (wav); local backend only."),
    backend: str = typer.Option(None, "--backend", "-b", help="ollama | gemini."),
    lang: str = typer.Option("en", "--lang", "-l", help="Language for the threat descriptions."),
):
    """Read an architecture image (and optional voice note) into a threat model with Gemma 4."""
    from pathlib import Path
    img_path = Path(image)
    if not img_path.exists():
        console.print(f"[red]x[/] Image not found: {image}")
        raise typer.Exit(2)
    image_bytes = img_path.read_bytes()
    audio_bytes = None
    if audio:
        ap = Path(audio)
        if not ap.exists():
            console.print(f"[red]x[/] Audio not found: {audio}")
            raise typer.Exit(2)
        audio_bytes = ap.read_bytes()

    llm = _resolve_backend(backend)
    if audio_bytes and llm.name != "ollama":
        console.print("[yellow]![/] Audio input is supported on the local (ollama) backend only; ignoring the clip.")
        audio_bytes = None

    with console.status(f"[bold]Reading the architecture with {llm.name} ({llm.model})..."):
        tm = engine_mod.threat_model(image_bytes, llm, audio=audio_bytes, lang=lang)

    console.print(f"\n[bold]Threat model[/] — {tm.summary}\n")
    if not tm.threats:
        if "model error" in tm.summary and llm.name == "ollama":
            console.print("[yellow]![/] Local image analysis can be unstable; try [bold]--backend gemini[/] for images.")
        else:
            console.print("[dim]No threats identified.[/]")
        return
    for t in sorted(tm.threats, key=lambda x: -x.severity.rank):
        style = SEV_STYLE.get(t.severity, "white")
        body = Text()
        body.append(t.description + "\n")
        body.append(f"\ncheck: {t.suggested_check}", style="dim")
        console.print(Panel(body, title=f"[{style}]{t.severity.value.upper()}[/] {t.title}",
                            title_align="left", border_style=style))


def _pipeline(path, scanner, explain, verify, backend, lang, no_cache, sarif=None, markdown=None,
              comments=None, changed=None):
    cfg = ExhibitaConfig.load(path)
    if cfg.source:
        console.print(f"[dim]config: {cfg.source}[/]")
    scanners_used = scanner or cfg.scanners  # explicit -s wins over config
    if lang == "en" and cfg.lang != "en":
        lang = cfg.lang

    console.print(f"[bold]ExhibitA[/] scanning [cyan]{path}[/] ...")
    result = scanners_mod.run_all(path, scanners=scanners_used or None)
    if cfg.ignore:
        result.findings = [f for f in result.findings
                           if not any(fnmatch.fnmatch(f.file, pat) for pat in cfg.ignore)]
    if changed:
        cf = gitscope.changed_files(path, changed)
        if cf is None:
            console.print(f"[yellow]![/] Could not diff against {changed}; reviewing all findings.")
        else:
            before = len(result.findings)
            result.findings = gitscope.filter_to_changed(result.findings, cf)
            console.print(f"[dim]PR mode: {len(result.findings)}/{before} findings in files changed since {changed}[/]")
    for w in result.warnings:
        console.print(f"[yellow]![/] {w}")

    if not result.findings:
        console.print("[green]No findings.[/]")
        _print_status(result)
        raise typer.Exit()

    if not explain:
        _print_table(result.findings)
        _print_status(result)
        console.print(f"\n[bold]{len(result.findings)}[/] finding(s).")
        raise typer.Exit()

    llm = _resolve_backend(backend)
    base = _scan_base(path)
    cache = engine_mod.Cache(enabled=not no_cache)

    with console.status(f"[bold]Triaging {len(result.findings)} finding(s) with {llm.name} ({llm.model})..."):
        ai_findings = engine_mod.triage(result.findings, llm, base, lang=lang, cache=cache)

    verifications: dict[str, Verification] = {}
    if verify:
        verifications = _run_verification(ai_findings, base, cfg)

    chains = []
    real_count = sum(1 for a in ai_findings if not a.likely_false_positive)
    if real_count >= 2:
        with console.status("[bold]Linking findings into attack chains..."):
            chains = engine_mod.attack_chains(ai_findings, llm)

    report = Report(ai_findings=ai_findings, verifications=verifications,
                    attack_chains=chains, backend=f"{llm.name}:{llm.model}")
    _render_triage(ai_findings, verifications, backend_name=report.backend)
    for chain in chains:
        console.print(f"\n[bold]⛓ Attack chain:[/] {chain.title}\n[dim]{chain.narrative}[/]")
    _print_status(result)
    if sarif or markdown:
        report_mod.write_outputs(report, sarif_path=sarif, markdown_path=markdown)
    if comments:
        import json as _json
        from pathlib import Path as _Path
        _Path(comments).write_text(_json.dumps(report_mod.inline_comments(report), indent=2), encoding="utf-8")
    for label, p in (("SARIF", sarif), ("Markdown", markdown), ("comments", comments)):
        if p:
            console.print(f"[dim]wrote {label}: {p}[/]")
    if verify:
        _print_gate(report)


def _run_verification(ai_findings, base, cfg):
    ready, detail = verify_mod.runtime_ready(base)
    if not ready:
        console.print(f"[yellow]![/] Cannot verify: {detail}")
        return {}
    targets = [a for a in ai_findings if a.finding and a.finding.severity.rank >= 4
               and verify_mod.recipe_for(a.finding, a.exploit_class)]
    if not targets:
        console.print("[dim]No critical findings with a verification recipe.[/]")
        return {}
    console.print(f"[dim]Verification {detail}.[/]")
    with console.status(f"[bold]Proving {len(targets)} critical finding(s) (building runtime if needed)..."):
        return verify_mod.verify_all(ai_findings, base, config=cfg)


def _print_gate(report: Report):
    if report.gate_failed:
        n = sum(1 for v in report.verifications.values() if v.exploit_confirmed)
        console.print(f"\n[bold white on red] BUILD GATE: FAILED [/] "
                      f"{n} critical issue(s) proven exploitable in the sandbox.")
        raise typer.Exit(1)
    console.print("\n[bold white on green] BUILD GATE: PASSED [/] "
                  "no critical issue was proven exploitable.")


def _resolve_backend(name: str | None):
    try:
        llm = get_backend(name)
    except LLMError as e:
        console.print(f"[red]x[/] {e}")
        raise typer.Exit(2)
    ready, detail = llm.available() if hasattr(llm, "available") else (True, "")
    if not ready:
        console.print(f"[red]x[/] Backend not ready: {detail}")
        console.print("[dim]Tip: use --no-explain to scan without AI, or --backend to switch.[/]")
        raise typer.Exit(2)
    return llm


def _scan_base(path: str):
    from pathlib import Path
    p = Path(path).resolve()
    return p if p.is_dir() else p.parent


def _render_triage(ai_findings: list[AIFinding], verifications: dict, backend_name: str):
    real = [f for f in ai_findings if not f.likely_false_positive]
    filtered = [f for f in ai_findings if f.likely_false_positive]
    real.sort(key=lambda f: (-(f.finding.severity.rank if f.finding else 0), -f.confidence))

    console.print()
    for f in real:
        v = verifications.get(f.finding.key) if f.finding else None
        console.print(_finding_panel(f, v))

    if filtered:
        console.print("\n[dim]Filtered as likely false positives:[/]")
        for f in filtered:
            loc = f"{f.finding.file}:{f.finding.line}" if f.finding else "?"
            console.print(f"  [dim]- {f.finding.rule_id if f.finding else '?'} at {loc} "
                          f"(confidence {f.confidence:.0%}) — {f.explanation}[/]")

    console.print(
        f"\n[bold]{len(ai_findings)}[/] finding(s) -> "
        f"[dim]{len(filtered)} likely false positive(s) filtered[/] -> "
        f"[bold]{len(real)}[/] to review   [dim](engine: {backend_name})[/]"
    )


def _finding_panel(f: AIFinding, v: Verification | None = None) -> Panel:
    fnd = f.finding
    sev = fnd.severity if fnd else Severity.MEDIUM
    style = SEV_STYLE.get(sev, "white")
    body = Text()
    body.append(f.explanation + "\n")
    body.append(f"\nconfidence {f.confidence:.0%}", style="dim")
    if f.exploit_class:
        body.append(f"   class: {f.exploit_class}", style="dim")
    if v and v.attempted:
        if v.fix_verified:
            evidence_style = "bold green"
        elif v.exploit_confirmed:
            evidence_style = "bold red"
        else:
            evidence_style = "yellow"
        body.append(f"\n\nPROOF: {v.badge}", style=evidence_style)
        if v.detail:
            body.append(f"\n{v.detail}", style="dim")
    elif v and v.fix_checked:
        body.append("\n\nFIX CHECKED: re-scan clean", style="bold green")
        if v.detail:
            body.append(f"\n{v.detail}", style="dim")
    if f.suggested_fix:
        body.append("\n\nsuggested fix:\n", style="bold green")
        body.append(f.suggested_fix.rstrip(), style="green")
    loc = f"{fnd.file}:{fnd.line}" if fnd else "?"
    title = f"[{style}]{sev.value.upper()}[/] {fnd.tool}:{fnd.rule_id}  [dim]{loc}[/]"
    return Panel(body, title=title, title_align="left", border_style=style)


def _print_table(findings):
    table = Table(show_lines=False, header_style="bold")
    table.add_column("Sev", no_wrap=True)
    table.add_column("Tool", no_wrap=True)
    table.add_column("Rule", no_wrap=True, max_width=28)
    table.add_column("Location", no_wrap=True)
    table.add_column("Message", overflow="fold")
    for f in findings:
        style = SEV_STYLE.get(f.severity, "white")
        table.add_row(f"[{style}]{f.severity.value}[/]", f.tool, f.rule_id, f"{f.file}:{f.line}", f.message)
    console.print(table)


def _print_status(result):
    if result.tool_status:
        parts = [f"{k} ({v})" for k, v in result.tool_status.items()]
        console.print("[dim]scanners: " + ", ".join(parts) + "[/]")


if __name__ == "__main__":
    app()
