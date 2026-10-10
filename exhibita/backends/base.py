"""Backend protocol shared by every Gemma 4 provider.

One env var, MODEL_BACKEND=ollama|gemini, picks the provider. Both receive the
*identical* prompt and JSON schema; only the transport differs. Every backend
asks the model to emit JSON matching a schema, and the engine validates it.
"""

from __future__ import annotations

import json
import re
from typing import Protocol, runtime_checkable


class LLMError(RuntimeError):
    """Raised when a backend cannot produce a usable response."""


@runtime_checkable
class LLMBackend(Protocol):
    name: str
    model: str
    max_concurrency: int

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        schema: dict | None = None,
        image: bytes | None = None,
        audio: bytes | None = None,
    ) -> str:
        """Return the model's text response (JSON string when `schema` is given)."""
        ...


def extract_json(text: str) -> dict | list | None:
    """Pull the first JSON value out of a response that may have stray prose/fences."""
    text = (text or "").strip()
    if not text:
        return None
    if text.startswith("```"):
        text = re.sub(r"^```[a-zA-Z]*\n?", "", text).removesuffix("```").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    depth = 0
    start = -1
    for i, ch in enumerate(text):
        if ch in "{[":
            if depth == 0:
                start = i
            depth += 1
        elif ch in "}]" and depth:
            depth -= 1
            if depth == 0 and start >= 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    start = -1
    return None
