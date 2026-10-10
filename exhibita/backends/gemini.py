"""Cloud Gemma 4 via the Gemini API — the backend GitHub Actions uses.

Reads GEMINI_API_KEY from the environment. Retries on the transient 503
"high demand" responses Gemma's shared endpoint returns, and can fall back from
the 31B model to a smaller one if the primary stays unavailable.
"""

from __future__ import annotations

import base64
import os
import time

import httpx

from .base import LLMError

BASE_URL = "https://generativelanguage.googleapis.com/v1beta/models"


class GeminiBackend:
    name = "gemini"
    max_concurrency = 4

    def __init__(
        self,
        model: str | None = None,
        api_key: str | None = None,
        fallback_model: str | None = "gemma-4-26b-a4b-it",
        timeout: float = 200.0,
        max_retries: int = 3,
    ):
        self.model = model or os.environ.get("GEMINI_MODEL", "gemma-4-31b-it")
        self.fallback_model = fallback_model
        self.api_key = api_key or os.environ.get("GEMINI_API_KEY", "")
        self.timeout = timeout
        self.max_retries = max_retries

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        schema: dict | None = None,
        image: bytes | None = None,
        audio: bytes | None = None,
    ) -> str:
        if not self.api_key:
            raise LLMError("GEMINI_API_KEY is not set")

        parts: list[dict] = [{"text": prompt}]
        if image is not None:
            parts.append({"inline_data": {"mime_type": "image/jpeg",
                                          "data": base64.b64encode(image).decode()}})
        if audio is not None:
            parts.append({"inline_data": {"mime_type": "audio/wav",
                                          "data": base64.b64encode(audio).decode()}})

        body: dict = {"contents": [{"role": "user", "parts": parts}]}
        if system:
            body["systemInstruction"] = {"parts": [{"text": system}]}
        gen: dict = {"temperature": 0}
        if schema:
            gen["responseMimeType"] = "application/json"
            gen["responseSchema"] = schema
        body["generationConfig"] = gen

        last = ""
        for model in filter(None, [self.model, self.fallback_model]):
            for attempt in range(1, self.max_retries + 1):
                try:
                    r = httpx.post(
                        f"{BASE_URL}/{model}:generateContent",
                        headers={"x-goog-api-key": self.api_key, "Content-Type": "application/json"},
                        json=body, timeout=self.timeout,
                    )
                except httpx.HTTPError as e:
                    last = str(e)
                    time.sleep(2 * attempt)
                    continue
                if r.status_code == 200:
                    return self._text(r.json())
                last = f"HTTP {r.status_code}: {r.text[:160]}"
                if r.status_code in (429, 500, 503) and attempt < self.max_retries:
                    time.sleep(3 * attempt)
                    continue
                break  # non-retryable on this model; try the fallback model
        raise LLMError(f"Gemini failed after retries: {last}")

    @staticmethod
    def _text(data: dict) -> str:
        candidates = data.get("candidates") or []
        if not candidates:
            raise LLMError(f"Gemini returned no candidates (blocked? {data.get('promptFeedback')})")
        parts = candidates[0].get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts if not p.get("thought"))
        if not text.strip():
            raise LLMError("Gemini returned an empty response")
        return text

    def available(self) -> tuple[bool, str]:
        if not self.api_key:
            return False, "GEMINI_API_KEY is not set"
        return True, f"{self.model} (key present)"
