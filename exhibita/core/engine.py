"""The Gemma 4 triage engine.

For each scanner finding, ask the model to explain it, judge whether it is a real
problem, and suggest a minimal fix — as strict JSON validated against AIFinding.
Malformed output is retried once; if it still fails we fall back to the scanner's
own message so the pipeline never crashes. Responses are cached by content hash,
so reruns are instant and an offline demo has a warm path.
"""

from __future__ import annotations

import hashlib
import json
import re
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pydantic import ValidationError

from ..backends.base import LLMBackend, LLMError, extract_json
from ..models import AIFinding, AttackChain, Finding, Severity, ThreatModel

LANGUAGES = {"en": "English", "te": "Telugu", "hi": "Hindi", "es": "Spanish", "fr": "French"}

SYSTEM = """You are ExhibitA, a precise application-security reviewer. You are given one
finding from a static scanner plus the surrounding code, and you judge whether it is a
real, exploitable problem in THIS code.

Rules:
- Return ONLY a JSON object matching the schema. No prose, no markdown fences.
- explanation: 2-3 sentences, specific to this code, no generic boilerplate.
- likely_false_positive: true ONLY when the flagged code is genuinely not exploitable
  here (for example the input is a constant, or it never reaches the dangerous sink).
- confidence: 0..1, your confidence that this is a true positive.
- suggested_fix: corrected code for the affected lines only, minimal and drop-in, or null.
  Never invent APIs; keep imports and style consistent with the surrounding code.
- fix_start_line / fix_end_line: the inclusive line range your fix replaces.
- exploit_class: the vulnerability class, or "none" if it is not an exploitable code bug.

Note on configuration findings (Docker, Kubernetes, CI workflows) and hardcoded
secrets: these are real misconfigurations, not dataflow bugs. Judge them on the
resource's actual settings, which are shown in full. Do NOT mark one a false
positive just because the reported line is a header such as `apiVersion` — the
scanner anchors a whole-resource issue to the top of the block.
"""


class Cache:
    """Content-addressed response cache under .exhibita_cache/."""

    def __init__(self, root: str | Path = ".exhibita_cache", enabled: bool = True):
        self.dir = Path(root)
        self.enabled = enabled
        if enabled:
            self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / f"{key}.json"

    def get(self, key: str) -> str | None:
        if not self.enabled:
            return None
        p = self._path(key)
        if p.exists():
            try:
                return json.loads(p.read_text(encoding="utf-8"))["response"]
            except (OSError, ValueError, KeyError):
                return None
        return None

    def put(self, key: str, response: str) -> None:
        if self.enabled:
            try:
                self._path(key).write_text(json.dumps({"response": response}), encoding="utf-8")
            except OSError:
                pass


# Config/IaC findings are whole-resource issues anchored to a header line, so the
# model needs the entire (small) file, not a window around the anchor.
_WHOLE_FILE_TOOLS = {"checkov", "hadolint"}
_WHOLE_FILE_MAX_LINES = 160


def code_context(base: Path, finding: Finding, radius: int = 6) -> str:
    """Numbered source lines around the finding; '>>' marks the flagged line."""
    try:
        lines = (base / finding.file).read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return finding.snippet or "(source unavailable)"
    if finding.line <= 0 and finding.tool not in _WHOLE_FILE_TOOLS:
        return finding.snippet or "(no line reported)"
    if finding.tool in _WHOLE_FILE_TOOLS and len(lines) <= _WHOLE_FILE_MAX_LINES:
        lo, hi = 1, len(lines)
    else:
        lo = max(1, finding.line - radius)
        hi = min(len(lines), finding.line + radius)
    out = []
    for n in range(lo, hi + 1):
        marker = ">>" if n == finding.line else "  "
        out.append(f"{marker}{n:4} | {lines[n - 1]}")
    return "\n".join(out)


def build_prompt(finding: Finding, base: Path, lang: str = "en") -> tuple[str, str]:
    system = SYSTEM
    if lang != "en":
        language = LANGUAGES.get(lang, lang)
        system += (
            f"\n- Write the `explanation` field in {language}. "
            "Keep every other field, and all code, in English."
        )
    user = (
        f"Tool: {finding.tool}   Rule: {finding.rule_id}   Severity: {finding.severity.value}\n"
        f"File: {finding.file}:{finding.line}\n"
        f"Scanner message: {finding.message}\n\n"
        f"Code (line numbers shown, >> marks the flagged line):\n{code_context(base, finding)}"
    )
    return system, user


def _cache_key(backend: LLMBackend, system: str, user: str, schema: dict) -> str:
    blob = "\x00".join([backend.name, backend.model, system, user, json.dumps(schema, sort_keys=True)])
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:40]


def _fallback(finding: Finding) -> AIFinding:
    """When the model can't give valid JSON, keep the scanner's own information."""
    confidence = {Severity.CRITICAL: 0.8, Severity.HIGH: 0.7}.get(finding.severity, 0.5)
    return AIFinding(
        explanation=finding.message or "Flagged by scanner; no AI explanation available.",
        likely_false_positive=False,
        confidence=confidence,
        finding=finding,
    )


def triage_one(finding: Finding, backend: LLMBackend, base: Path, cache: Cache, lang: str = "en") -> AIFinding:
    schema = AIFinding.json_schema_for_prompt()
    system, user = build_prompt(finding, base, lang)
    key = _cache_key(backend, system, user, schema)

    raw = cache.get(key)
    if raw is None:
        try:
            raw = backend.complete(user, system=system, schema=schema)
        except LLMError:
            try:
                raw = backend.complete(
                    user + "\n\nReturn ONLY valid JSON matching the schema.",
                    system=system, schema=schema,
                )
            except LLMError:
                return _fallback(finding)
        cache.put(key, raw)

    ai = _parse(raw, finding)
    if ai is None:
        try:
            raw = backend.complete(
                user + "\n\nYour last reply was not valid JSON. Return ONLY the JSON object.",
                system=system, schema=schema,
            )
            cache.put(key, raw)
            ai = _parse(raw, finding)
        except LLMError:
            ai = None
    return ai or _fallback(finding)


def _parse(raw: str, finding: Finding) -> AIFinding | None:
    data = extract_json(raw)
    if not isinstance(data, dict):
        return None
    if data.get("exploit_class") == "none":
        data["exploit_class"] = None
    try:
        ai = AIFinding.model_validate(data)
    except ValidationError:
        return None
    ai.finding = finding
    return ai


THREAT_SYSTEM = """You are a security architect. You are given a photo or sketch of a
system's architecture, and optionally a spoken description of it. Identify concrete,
specific security threats in the design and, for each, a check that would catch it.

Rules:
- Return ONLY a JSON object matching the schema. No prose, no markdown fences.
- summary: one or two sentences on what the system appears to be.
- threats: each has a title, a specific description (not generic advice), a severity
  (critical/high/medium/low), and a suggested_check (a scanner, rule, or test to run).
- Prefer threats tied to what is actually shown (data stores, trust boundaries,
  external inputs, auth, secrets) over boilerplate.
"""


def threat_model(image: bytes, backend: LLMBackend, *, audio: bytes | None = None, lang: str = "en") -> ThreatModel:
    """Read an architecture image (and optional spoken notes) into a ThreatModel."""
    schema = ThreatModel.json_schema_for_prompt()
    system = THREAT_SYSTEM
    if lang != "en":
        system += f"\n- Write each threat's title and description in {LANGUAGES.get(lang, lang)}."
    prompt = "Analyze this architecture and list its security threats as JSON."
    try:
        raw = backend.complete(prompt, system=system, schema=schema, image=image, audio=audio)
    except LLMError as e:
        return ThreatModel(summary=f"(model error: {e})")
    data = extract_json(raw)
    if not isinstance(data, dict):
        try:
            raw = backend.complete(prompt + "\n\nReturn ONLY valid JSON matching the schema.",
                                   system=system, schema=schema, image=image, audio=audio)
            data = extract_json(raw)
        except LLMError:
            data = None
    if not isinstance(data, dict):
        return ThreatModel(summary="(could not parse a threat model from the model output)")
    try:
        return ThreatModel.model_validate(data)
    except ValidationError:
        return ThreatModel(summary="(model output did not match the schema)")


CHAIN_SYSTEM = """You are a security analyst. You are given a list of confirmed findings in
one codebase. Connect the ones that could be combined into an attacker's path and
describe each path.

Rules:
- Return ONLY a JSON object matching the schema. No prose, no markdown fences.
- chains: 1 to 3 paths. Only link findings that plausibly combine; do not force it.
- Each chain has: a short title, a 1-2 sentence narrative, and a `mermaid` graph.
- mermaid MUST be a valid Mermaid flowchart starting with "flowchart TD", with short
  node labels in square brackets and --> edges. Reference the findings by file.
"""

_CHAIN_SCHEMA = {
    "type": "object",
    "properties": {"chains": {"type": "array", "items": {
        "type": "object",
        "properties": {"title": {"type": "string"}, "narrative": {"type": "string"},
                       "mermaid": {"type": "string"}},
        "required": ["title", "narrative", "mermaid"]}}},
    "required": ["chains"],
}


def _clean_mermaid(text: str) -> str | None:
    """Return a valid Mermaid flowchart body, or None if it can't be salvaged."""
    s = (text or "").strip()
    if s.startswith("```"):
        s = re.sub(r"^```[a-zA-Z]*\n?", "", s).removesuffix("```").strip()
    head = s.split("\n", 1)[0].strip().lower()
    if not (head.startswith("graph ") or head.startswith("flowchart ")):
        return None
    return s


def attack_chains(ai_findings: list[AIFinding], backend: LLMBackend) -> list[AttackChain]:
    """Link findings into attacker paths with Mermaid graphs (best-effort)."""
    real = [a for a in ai_findings if not a.likely_false_positive and a.finding]
    if len(real) < 2:
        return []
    listing = "\n".join(
        f"- {a.finding.severity.value} {a.finding.rule_id} at {a.finding.file}:{a.finding.line} "
        f"({a.exploit_class or 'n/a'}) — {a.explanation[:120]}"
        for a in real
    )
    try:
        raw = backend.complete(f"Findings:\n{listing}\n\nReturn the attack chains as JSON.",
                               system=CHAIN_SYSTEM, schema=_CHAIN_SCHEMA)
    except LLMError:
        return []
    data = extract_json(raw)
    if not isinstance(data, dict):
        return []
    out = []
    for c in data.get("chains", []):
        mermaid = _clean_mermaid(c.get("mermaid", ""))
        if mermaid and c.get("title"):
            out.append(AttackChain(title=c["title"], narrative=c.get("narrative", ""), mermaid=mermaid))
    return out


def triage(
    findings: list[Finding],
    backend: LLMBackend,
    base: str | Path,
    *,
    lang: str = "en",
    cache: Cache | None = None,
    progress=None,
) -> list[AIFinding]:
    base = Path(base)
    cache = cache if cache is not None else Cache()
    results: list[AIFinding | None] = [None] * len(findings)

    def work(i: int, f: Finding) -> None:
        results[i] = triage_one(f, backend, base, cache, lang)
        if progress:
            progress()

    workers = max(1, getattr(backend, "max_concurrency", 1))
    if workers == 1:
        for i, f in enumerate(findings):
            work(i, f)
    else:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(lambda p: work(*p), enumerate(findings)))
    return [r for r in results if r is not None]
