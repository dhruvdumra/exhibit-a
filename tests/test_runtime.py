"""Auto-building the sandbox image from the embedded recipe (no Docker needed here)."""

from exhibita.core import runtime


def _raise(*a, **k):
    raise AssertionError("should not have been called")


def test_ensure_sandbox_is_noop_when_image_present(monkeypatch):
    monkeypatch.setattr(runtime, "image_exists", lambda image: True)
    monkeypatch.setattr(runtime.subprocess, "run", _raise)  # must not build
    assert runtime.ensure_sandbox_image("exhibita-sandbox:latest") is True


def test_ensure_sandbox_builds_when_missing(monkeypatch):
    monkeypatch.setattr(runtime, "image_exists", lambda image: False)
    seen = {}

    class _Result:
        returncode = 0
        stdout = ""
        stderr = ""

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return _Result()

    monkeypatch.setattr(runtime.subprocess, "run", fake_run)
    assert runtime.ensure_sandbox_image("exhibita-sandbox:latest") is True
    assert "build" in seen["cmd"] and "exhibita-sandbox:latest" in seen["cmd"]


def test_ensure_sandbox_reports_build_failure(monkeypatch):
    monkeypatch.setattr(runtime, "image_exists", lambda image: False)

    class _Fail:
        returncode = 1
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr(runtime.subprocess, "run", lambda cmd, **kw: _Fail())
    assert runtime.ensure_sandbox_image("exhibita-sandbox:latest") is False


def test_embedded_dockerfile_has_the_runtime_deps():
    assert "flask" in runtime.SANDBOX_DOCKERFILE and "lxml" in runtime.SANDBOX_DOCKERFILE
