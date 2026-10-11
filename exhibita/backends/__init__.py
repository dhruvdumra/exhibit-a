"""Backend selection. MODEL_BACKEND=auto|ollama|gemini picks the provider.

'auto' (the default) prefers the local Ollama model if it's available and falls
back to the Gemini API when a key is set — so a user with no local model just
needs GEMINI_API_KEY, and a user offline just needs Ollama.
"""

from __future__ import annotations

import os

from .base import LLMBackend, LLMError, extract_json
from .gemini import GeminiBackend
from .ollama import OllamaBackend

__all__ = ["LLMBackend", "LLMError", "extract_json", "get_backend", "OllamaBackend", "GeminiBackend"]

_BACKENDS = {"ollama": OllamaBackend, "gemini": GeminiBackend}


def get_backend(name: str | None = None, **kwargs) -> LLMBackend:
    name = (name or os.environ.get("MODEL_BACKEND") or "auto").lower()
    if name == "auto":
        return _auto_backend()
    if name not in _BACKENDS:
        raise LLMError(f"Unknown backend '{name}'. Choose from: auto, {', '.join(_BACKENDS)}")
    return _BACKENDS[name](**kwargs)


def _auto_backend() -> LLMBackend:
    """Local model if it's ready, else the cloud key, else a clear error."""
    ollama = OllamaBackend()
    if ollama.available()[0]:
        return ollama
    gemini = GeminiBackend()
    if gemini.available()[0]:
        return gemini
    raise LLMError(
        "No model backend available. Either start Ollama and run `ollama pull gemma4:e4b`, "
        "or set GEMINI_API_KEY to use the cloud. (Force one with --backend ollama|gemini.)"
    )
