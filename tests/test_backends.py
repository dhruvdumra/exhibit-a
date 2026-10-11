"""Backend selection, including the 'auto' fallback (local model → cloud key)."""

import pytest

from exhibita import backends
from exhibita.backends.base import LLMError


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    monkeypatch.delenv("MODEL_BACKEND", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)


def test_auto_prefers_local_model_when_available(monkeypatch):
    monkeypatch.setattr(backends.OllamaBackend, "available", lambda self: (True, "ready"))
    assert backends.get_backend().name == "ollama"


def test_auto_falls_back_to_api_key(monkeypatch):
    monkeypatch.setattr(backends.OllamaBackend, "available", lambda self: (False, "no model"))
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert backends.get_backend().name == "gemini"


def test_auto_errors_when_neither_available(monkeypatch):
    monkeypatch.setattr(backends.OllamaBackend, "available", lambda self: (False, "no model"))
    with pytest.raises(LLMError, match="No model backend available"):
        backends.get_backend()


def test_explicit_backend_overrides_auto():
    assert backends.get_backend("gemini").name == "gemini"
    assert backends.get_backend("ollama").name == "ollama"


def test_unknown_backend_raises():
    with pytest.raises(LLMError, match="Unknown backend"):
        backends.get_backend("gpt5")
