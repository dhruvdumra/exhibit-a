"""Local Gemma 4 via Ollama — the offline backend.

Runs entirely on the machine (http://localhost:11434). Nothing leaves the laptop,
which is the whole point: a security reviewer you can run with the Wi-Fi off.
"""

from __future__ import annotations

import base64
import os
import time

import httpx

from .base import LLMError

# llama.cpp's multimodal projector occasionally crashes the server (a known gemma4
# instability on image/audio input). The crash is intermittent and the server
# restarts on the next request, so we retry rather than fail.
_CRASH_MARKERS = ("terminated", "exit status", "llama runner", "EOF")
_CRASH_RETRIES = 3


class OllamaBackend:
    name = "ollama"
    # One local model instance; concurrent requests to it only queue and can OOM.
    max_concurrency = 1

    def __init__(self, model: str | None = None, host: str | None = None, timeout: float = 300.0):
        self.model = model or os.environ.get("OLLAMA_MODEL", "gemma4:e4b")
        self.host = (host or os.environ.get("OLLAMA_HOST", "http://localhost:11434")).rstrip("/")
        self.timeout = timeout

    def complete(
        self,
        prompt: str,
        *,
        system: str | None = None,
        schema: dict | None = None,
        image: bytes | None = None,
        audio: bytes | None = None,
    ) -> str:
        message: dict = {"role": "user", "content": prompt}
        # Gemma on Ollama takes image AND audio in the `images` field; audio first
        # improves stability (see the e4b modality-ordering workaround).
        blobs = [b for b in (audio, image) if b is not None]
        if blobs:
            message["images"] = [base64.b64encode(b).decode() for b in blobs]

        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append(message)

        body: dict = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "think": False,
            "options": {"temperature": 0, "num_ctx": 8192},
        }
        if schema:
            body["format"] = schema

        multimodal = bool(blobs)
        last = ""
        for attempt in range(1, _CRASH_RETRIES + 1 if multimodal else 2):
            try:
                r = httpx.post(f"{self.host}/api/chat", json=body, timeout=self.timeout)
            except httpx.HTTPError as e:
                raise LLMError(f"Ollama unreachable at {self.host}: {e}") from e
            if r.status_code == 200:
                content = r.json().get("message", {}).get("content", "")
                if not content.strip():
                    raise LLMError("Ollama returned an empty response")
                return content
            last = f"Ollama HTTP {r.status_code}: {r.text[:200]}"
            # Only a projector crash on multimodal input is worth retrying; the
            # server restarts on the next request, so give it a moment.
            if multimodal and any(m in r.text for m in _CRASH_MARKERS) and attempt < _CRASH_RETRIES:
                time.sleep(2)
                continue
            break
        raise LLMError(last)

    def available(self) -> tuple[bool, str]:
        """(ready, detail) — whether the model is pulled and the server is up."""
        try:
            r = httpx.get(f"{self.host}/api/tags", timeout=10)
            tags = [m["name"] for m in r.json().get("models", [])]
        except httpx.HTTPError as e:
            return False, f"Ollama not running at {self.host} ({e})"
        if not any(t == self.model or t.startswith(self.model + ":") for t in tags):
            return False, f"Model {self.model} not pulled. Run: ollama pull {self.model}"
        return True, f"{self.model} ready on {self.host}"
