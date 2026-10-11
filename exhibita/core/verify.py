"""Red -> green -> still-works verification against the app's real runtime.

For a critical finding with a known recipe:
  1. RED   — run the target and confirm the bug with a generic black-box oracle.
  2. PATCH — apply the AI's fix to a staged copy; it must still compile.
  3. GREEN — run the patched copy; the oracle must no longer fire.
  4. STILL WORKS — a benign request must still return the right answer.

The target runs through its OWN Dockerfile when the repo has one (any framework,
any language), otherwise through the generic sandbox image (self-contained Python
apps). Either way it is driven black-box over HTTP; the sandbox decides the outcome.
Containers run with dropped capabilities, no new privileges, and resource limits.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path

from ..models import AIFinding, Verification
from . import fixcheck, oracle, runtime
from .locate import locate
from .patch import apply_fix, compiles
from .recipes import Recipe, build_plan, recipe_for

SANDBOX_IMAGE = "exhibita-sandbox:latest"
IGNORE = shutil.ignore_patterns(".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".exhibita_cache")


@dataclass
class HarnessResult:
    health: bool = False
    confirmed: bool = False
    oracle: str = ""
    evidence: str = ""
    benign_ok: bool = False
    detail: str = ""


@dataclass
class RuntimeSpec:
    """How to run a given code version as a container that serves the app."""
    image: str
    container_port: int
    mount_target: str
    cmd: list[str] | None


def sandbox_available(image: str = SANDBOX_IMAGE) -> bool:
    try:
        r = subprocess.run(["docker", "image", "inspect", image], capture_output=True, timeout=30)
        return r.returncode == 0
    except Exception:
        return False


def runtime_ready(app_dir: str | Path) -> tuple[bool, str]:
    """Whether a target can be run: via its own Dockerfile, or the sandbox image."""
    if runtime.has_dockerfile(app_dir):
        return True, "runs the target via its own Dockerfile"
    if sandbox_available() or runtime.docker_running():
        return True, "runs the target via the exhibita-sandbox image (auto-built if missing)"
    return False, "Docker is not running — start Docker Desktop and retry"


def _find_entry(app_dir: Path, finding_file: str) -> str:
    stem = Path(finding_file).stem
    cand = app_dir / finding_file
    if cand.exists() and "Flask(" in cand.read_text(encoding="utf-8", errors="replace"):
        return stem
    for py in app_dir.glob("*.py"):
        if "Flask(" in py.read_text(encoding="utf-8", errors="replace"):
            return py.stem
    return stem


def _runtime_spec(app_dir: Path, finding_file: str, prebuilt_image: str | None) -> RuntimeSpec:
    """Docker-from-repo when a Dockerfile exists, else the generic sandbox image."""
    if runtime.has_dockerfile(app_dir):
        image = prebuilt_image or runtime.build_target_image(app_dir)
        return RuntimeSpec(image, runtime._exposed_port(app_dir), "/app", None)
    if not runtime.ensure_sandbox_image(SANDBOX_IMAGE):
        raise RuntimeError("could not build the exhibita-sandbox image (is Docker running?)")
    entry = _find_entry(app_dir, finding_file)
    launcher = (f"import {entry} as m; "
                "m.app.run(host='0.0.0.0', port=8000, use_reloader=False, threaded=True)")
    return RuntimeSpec(SANDBOX_IMAGE, 8000, "/app", ["python", "-c", launcher])


def _stage(app_dir: Path) -> tuple[tempfile.TemporaryDirectory, Path]:
    tmp = tempfile.TemporaryDirectory(prefix="exhibita-verify-")
    dest = Path(tmp.name) / "app"
    shutil.copytree(app_dir, dest, ignore=IGNORE)
    return tmp, dest


def _prove(code_dir: Path, plan: dict, spec: RuntimeSpec) -> HarnessResult:
    """Run one code version as a container and drive the oracle over HTTP."""
    try:
        ctx = runtime.running_container(spec.image, code_dir, spec.container_port,
                                        mount_target=spec.mount_target, cmd=spec.cmd)
    except RuntimeError as e:
        return HarnessResult(detail=str(e)[:200])
    with ctx as url:
        if url is None:
            return HarnessResult(detail="target did not become healthy")
        confirmed, which, evidence = oracle.run_oracles(url, plan, plan["benign_value"])
        bstatus, bbody, _ = oracle.send_request(url, plan, plan["benign_value"])
        marker = plan.get("benign_marker", "")
        benign_ok = (bstatus == plan.get("benign_expect_status", 200)) and (not marker or marker in bbody)
        return HarnessResult(health=True, confirmed=confirmed, oracle=which,
                             evidence=evidence, benign_ok=benign_ok, detail="ok")


def _pytest_text(recipe: Recipe, plan: dict) -> str:
    kinds = ", ".join(sorted({c["type"] for c in recipe.checks}))
    return (
        f"def test_{recipe.name}_is_blocked(client):\n"
        f"    # black-box proof on {plan['method']} {plan['path']} using the {kinds} oracle(s)\n"
        f"    # the attack input must not succeed; a benign request must still work\n"
        f"    assert not exhibita_oracle_fires(client, {plan['path']!r})\n"
    )


def verify_finding(ai: AIFinding, app_dir: str | Path, *, prebuilt_image: str | None = None,
                   route_hint=None) -> Verification:
    finding = ai.finding
    if finding is None:
        return Verification(attempted=False, detail="no finding attached")
    recipe = recipe_for(finding, ai.exploit_class)
    if recipe is None:
        return Verification(attempted=False, detail="no verification recipe for this class")

    app_dir = Path(app_dir)
    v = Verification(attempted=True, exploit_class=recipe.name)
    # A declared route (from .exhibita.yml) wins over the Flask-only AST locator,
    # so verification works on any framework the user can describe.
    if route_hint is not None:
        loc = {"path": route_hint.path, "param": route_hint.param}
    else:
        loc = locate(app_dir, finding)
    if loc is None:
        v.detail = "could not locate the HTTP entry point (declare it in .exhibita.yml)"
        return v
    if recipe.needs_param and not loc["param"]:
        v.detail = "could not find the request parameter for this finding"
        return v

    plan = build_plan(recipe, loc["path"], loc["param"] or "")
    v.exploit_test = _pytest_text(recipe, plan)
    try:
        spec = _runtime_spec(app_dir, finding.file, prebuilt_image)
    except RuntimeError as e:
        v.detail = f"could not build the target's runtime: {e}"
        return v

    # 1. RED — confirm the bug on the original code.
    vuln_tmp, vuln_copy = _stage(app_dir)
    try:
        red = _prove(vuln_copy, plan, spec)
    finally:
        vuln_tmp.cleanup()
    if not red.health:
        v.detail = f"target did not run in sandbox: {red.detail}"
        return v
    v.red_passed = red.confirmed
    if not v.red_passed:
        v.detail = "proof did not confirm on the original code (not exploitable as flagged)"
        return v
    v.detail = f"exploit confirmed via {red.oracle} oracle: {red.evidence}"

    # 2. PATCH — apply the AI fix to a copy.
    if not (ai.suggested_fix and ai.fix_start_line and ai.fix_end_line):
        v.detail += " | no usable fix suggested to verify"
        return v
    patch_tmp, patch_copy = _stage(app_dir)
    try:
        target = patch_copy / finding.file
        original = target.read_text(encoding="utf-8", errors="replace")
        try:
            patched = apply_fix(original, ai.fix_start_line, ai.fix_end_line, ai.suggested_fix)
        except ValueError as e:
            v.detail += f" | fix could not be applied ({e})"
            return v
        if finding.file.endswith(".py") and not compiles(patched, finding.file):
            v.detail += " | fix did not compile"
            return v
        target.write_text(patched, encoding="utf-8")
        v.patch_applied = True

        # 3 + 4. GREEN and STILL WORKS.
        green = _prove(patch_copy, plan, spec)
    finally:
        patch_tmp.cleanup()

    if not green.health:
        v.detail += " | patched app failed to start"
        return v
    v.green_passed = not green.confirmed
    v.still_works_passed = green.benign_ok
    v.detail = "fix verified" if v.fix_verified else v.detail + " | fix incomplete"
    return v


def verify_all(ai_findings: list[AIFinding], app_dir: str | Path, *,
               only_critical: bool = True, config=None, progress=None) -> dict[str, Verification]:
    app_dir = Path(app_dir)
    targets = [a for a in ai_findings if a.finding and recipe_for(a.finding, a.exploit_class)
               and (not only_critical or a.finding.severity.rank >= 4)]
    prebuilt = None
    if targets and runtime.has_dockerfile(app_dir):
        try:
            prebuilt = runtime.build_target_image(app_dir)  # build once, reuse per finding
        except RuntimeError:
            prebuilt = None
    out: dict[str, Verification] = {}
    for a in targets:
        hint = config.route_for(a.finding, a.exploit_class) if config else None
        out[a.finding.key] = verify_finding(a, app_dir, prebuilt_image=prebuilt, route_hint=hint)
        if progress:
            progress()

    if config is None or config.fix_check:
        _fix_check_pass(ai_findings, app_dir, out, progress)
    return out


_FIX_CHECK_CAP = 15  # bound the number of re-scans so a big repo doesn't stall


def _fix_check_pass(ai_findings, app_dir, out, progress) -> None:
    """Give non-proven real findings (with a fix) lighter 're-scan clean' evidence."""
    checked = 0
    for a in ai_findings:
        if checked >= _FIX_CHECK_CAP:
            break
        f = a.finding
        if f is None or a.likely_false_positive or f.key in out:
            continue
        if not (a.suggested_fix and a.fix_start_line and a.fix_end_line):
            continue
        ok, detail = fixcheck.check(a, app_dir)
        out[f.key] = Verification(attempted=False, fix_checked=ok, detail=detail)
        checked += 1
        if progress:
            progress()
