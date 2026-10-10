"""Scoping a run to a PR's changed files."""

import shutil
import subprocess

import pytest

from exhibita.core import gitscope
from exhibita.models import Finding, Severity


def finding(file):
    return Finding(tool="semgrep", rule_id="r", file=file, line=1, severity=Severity.HIGH)


def test_filter_to_changed_keeps_only_changed_files():
    findings = [finding("app.py"), finding("util.py"), finding("k8s/deploy.yaml")]
    kept = gitscope.filter_to_changed(findings, {"app.py", "k8s/deploy.yaml"})
    assert [f.file for f in kept] == ["app.py", "k8s/deploy.yaml"]


def test_filter_to_changed_empty_set_keeps_nothing():
    assert gitscope.filter_to_changed([finding("app.py")], set()) == []


def test_changed_files_returns_none_outside_a_repo(tmp_path):
    assert gitscope.changed_files(tmp_path, "HEAD~1") is None


@pytest.mark.skipif(shutil.which("git") is None, reason="git not available")
def test_changed_files_maps_repo_paths_to_scan_root(tmp_path):
    repo = tmp_path / "repo"
    app = repo / "demo" / "app"
    app.mkdir(parents=True)
    def git(*a):
        subprocess.run(["git", "-C", str(repo), *a], check=True, capture_output=True)
    git("init", "-q")
    git("config", "user.email", "t@e.st")
    git("config", "user.name", "t")
    (app / "server.py").write_text("x = 1\n", encoding="utf-8")
    (app / "stable.py").write_text("y = 2\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "base")
    base = subprocess.run(["git", "-C", str(repo), "rev-parse", "HEAD"],
                          capture_output=True, text=True).stdout.strip()
    (app / "server.py").write_text("x = 2  # changed\n", encoding="utf-8")
    git("add", "-A")
    git("commit", "-qm", "change server")

    # scan root is demo/app; the changed path demo/app/server.py maps to "server.py"
    changed = gitscope.changed_files(app, base)
    assert changed == {"server.py"}
