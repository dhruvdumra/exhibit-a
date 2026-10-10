"""Run the target app through its OWN runtime so ExhibitA works on real repos.

The winning move for generality: instead of importing the app (Flask-only), build
the repo's Dockerfile once to get its real base image and dependencies, then run it
with the code bind-mounted — so we can swap in the original code (to confirm the
bug) or the patched code (to prove the fix) without rebuilding. The app is driven
black-box over HTTP, so the language and framework don't matter.

The target container runs with dropped capabilities, no new privileges, and
memory/pid limits. It keeps a network namespace only so its port can be reached.
"""

from __future__ import annotations

import hashlib
import re
import subprocess
import time
import urllib.error
import urllib.request
from contextlib import contextmanager
from pathlib import Path

_TARGET_LIMITS = [
    "--memory=768m", "--pids-limit=512", "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
]


def has_dockerfile(app_dir: str | Path) -> bool:
    return (Path(app_dir) / "Dockerfile").exists()


def _exposed_port(app_dir: Path, default: int = 8000) -> int:
    df = app_dir / "Dockerfile"
    try:
        for line in df.read_text(encoding="utf-8", errors="replace").splitlines():
            m = re.match(r"\s*EXPOSE\s+(\d+)", line, re.IGNORECASE)
            if m:
                return int(m.group(1))
    except OSError:
        pass
    return default


def build_target_image(app_dir: str | Path, timeout: int = 600) -> str:
    """Build the repo's Dockerfile once; return the image tag."""
    app_dir = Path(app_dir).resolve()
    tag = "exhibita-target-" + hashlib.sha256(app_dir.as_posix().encode()).hexdigest()[:12]
    r = subprocess.run(
        ["docker", "build", "-q", "-t", tag, app_dir.as_posix()],
        capture_output=True, text=True, timeout=timeout,
    )
    if r.returncode != 0:
        raise RuntimeError(f"docker build failed: {(r.stderr or r.stdout).strip()[:400]}")
    return tag


def _wait_healthy(base_url: str, cid: str, timeout: float) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        ps = subprocess.run(["docker", "inspect", "-f", "{{.State.Running}}", cid],
                            capture_output=True, text=True)
        if ps.stdout.strip() != "true":
            return False
        for path in ("/health", "/"):
            try:
                with urllib.request.urlopen(base_url + path, timeout=5) as resp:
                    if resp.status < 500:
                        return True
            except urllib.error.HTTPError as e:
                if e.code < 500:
                    return True
            except Exception:  # noqa: BLE001
                pass
        time.sleep(0.5)
    return False


@contextmanager
def running_container(image: str, code_dir: Path, container_port: int, *,
                      mount_target: str = "/app", cmd: list[str] | None = None,
                      health_timeout: float = 40.0):
    """Run `image` with `code_dir` mounted over `mount_target`; yield its base URL.

    With `cmd` the launch command is overridden (used to serve a self-contained app
    from the generic sandbox image); without it the image's own CMD runs (the repo's
    declared runtime). Yields None if the app never became healthy.
    """
    run = subprocess.run(
        ["docker", "run", "-d", "--rm", *_TARGET_LIMITS,
         "-p", f"127.0.0.1::{container_port}",
         "--mount", f"type=bind,source={code_dir.resolve().as_posix()},target={mount_target},readonly",
         image, *(cmd or [])],
        capture_output=True, text=True,
    )
    if run.returncode != 0:
        raise RuntimeError(f"docker run failed: {(run.stderr or '').strip()[:300]}")
    cid = run.stdout.strip()
    try:
        port_out = subprocess.run(["docker", "port", cid, str(container_port)],
                                  capture_output=True, text=True).stdout.strip()
        if not port_out:
            yield None
            return
        host_port = port_out.splitlines()[0].rsplit(":", 1)[-1]
        base_url = f"http://127.0.0.1:{host_port}"
        healthy = _wait_healthy(base_url, cid, health_timeout)
        yield (base_url if healthy else None)
    finally:
        subprocess.run(["docker", "stop", "-t", "2", cid], capture_output=True, text=True)
