"""Backend selection. MODEL_BACKEND=ollama|gemini picks the provider."""

from __future__ import annotations

import os

from .base import LLMBackend, LLMError, extract_json
from .gemini import GeminiBackend
from .ollama import OllamaBackend

__all__ = ["LLMBackend", "LLMError", "extract_json", "get_backend", "OllamaBackend", "GeminiBackend"]

_BACKENDS = {"ollama": OllamaBackend, "gemini": GeminiBackend}


def get_backend(name: str | None = None, **kwargs) -> LLMBackend:
    name = (name or os.environ.get("MODEL_BACKEND", "ollama")).lower()
    if name not in _BACKENDS:
        raise LLMError(f"Unknown backend '{name}'. Choose from: {', '.join(_BACKENDS)}")
    return _BACKENDS[name](**kwargs)
