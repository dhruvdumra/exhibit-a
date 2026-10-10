"""Core data model for ExhibitA.

Every object the pipeline passes around is a validated Pydantic model. The LLM
engine must return JSON that parses into AIFinding; the sandbox fills in
Verification. Nothing is trusted until it validates.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
        return order[self.value]


class Finding(BaseModel):
    """Raw scanner output, normalized across every tool."""

    tool: str
    rule_id: str
    file: str
    line: int = 0
    severity: Severity = Severity.MEDIUM
    message: str = ""
    snippet: str = ""

    @property
    def key(self) -> str:
        """Stable identity for caching and cross-referencing."""
        return f"{self.tool}:{self.rule_id}:{self.file}:{self.line}"


class AIFinding(BaseModel):
    """Gemma's verdict on one finding. This is the strict-JSON contract."""

    explanation: str = Field(description="Plain-English, 2-3 sentences.")
    likely_false_positive: bool = False
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    suggested_fix: str | None = Field(
        default=None, description="Replacement code block for the flagged lines, or null."
    )
    fix_start_line: int | None = None
    fix_end_line: int | None = None
    exploit_class: str | None = Field(
        default=None,
        description="The vulnerability class, or 'none' if it is not an exploitable code bug.",
    )

    # Populated after validation; not part of the LLM contract.
    finding: Finding | None = None

    @staticmethod
    def json_schema_for_prompt() -> dict:
        """The schema we hand to the model (no back-reference to Finding)."""
        return {
            "type": "object",
            "properties": {
                "explanation": {"type": "string"},
                "likely_false_positive": {"type": "boolean"},
                "confidence": {"type": "number"},
                "suggested_fix": {"type": "string"},
                "fix_start_line": {"type": "integer"},
                "fix_end_line": {"type": "integer"},
                "exploit_class": {
                    "type": "string",
                    "enum": [
                        "sql_injection", "command_injection", "path_traversal",
                        "ssti", "xss", "xxe", "ssrf", "none",
                    ],
                },
            },
            "required": ["explanation", "likely_false_positive", "confidence"],
        }


class Verification(BaseModel):
    """Result of the red -> green -> still-works proof in the sandbox."""

    attempted: bool = False
    exploit_class: str | None = None
    exploit_test: str | None = Field(default=None, description="The pytest file content.")
    red_passed: bool = False  # exploit succeeded against the vulnerable code (as expected)
    patch_applied: bool = False  # the AI fix applied cleanly to a copy of the code
    green_passed: bool = False  # exploit blocked after the fix
    still_works_passed: bool = False  # a normal request still succeeds after the fix
    fix_checked: bool = False  # fix re-scanned clean (lighter evidence than a sandbox proof)
    detail: str = ""

    @property
    def exploit_confirmed(self) -> bool:
        """The sandbox showed the bug is real. This alone is enough to block a merge."""
        return self.red_passed

    @property
    def fix_verified(self) -> bool:
        """The fix is trustworthy: exploit confirmed, then blocked, and nothing broke."""
        return self.red_passed and self.patch_applied and self.green_passed and self.still_works_passed

    @property
    def badge(self) -> str:
        if not self.attempted:
            return "not verified"
        steps = [
            ("Exploited", self.red_passed),
            ("Patched", self.patch_applied),
            ("Blocked", self.green_passed),
            ("Still works", self.still_works_passed),
        ]
        return " -> ".join(f"{name} {'OK' if ok else 'X'}" for name, ok in steps)


class AttackChain(BaseModel):
    """A linked path an attacker could walk, rendered as a Mermaid graph."""

    title: str
    narrative: str
    mermaid: str


class Threat(BaseModel):
    """One threat read off an architecture sketch by Gemma 4."""

    title: str
    description: str
    severity: Severity = Severity.MEDIUM
    suggested_check: str = Field(description="A concrete check, rule, or test to run for this threat.")


class ThreatModel(BaseModel):
    summary: str = ""
    threats: list[Threat] = Field(default_factory=list)

    @staticmethod
    def json_schema_for_prompt() -> dict:
        return {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "threats": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "severity": {"type": "string", "enum": [s.value for s in Severity]},
                            "suggested_check": {"type": "string"},
                        },
                        "required": ["title", "description", "suggested_check"],
                    },
                },
            },
            "required": ["summary", "threats"],
        }


class Report(BaseModel):
    ai_findings: list[AIFinding] = Field(default_factory=list)
    verifications: dict[str, Verification] = Field(default_factory=dict)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    backend: str = "unknown"

    @property
    def real_findings(self) -> list[AIFinding]:
        return [f for f in self.ai_findings if not f.likely_false_positive]

    @property
    def gate_failed(self) -> bool:
        """Block the merge only on a critical finding the sandbox confirmed. No proof, no block.

        Proof beats opinion: a confirmed exploit blocks even if the model labeled the
        finding a likely false positive, and even if its suggested fix did not work.
        """
        for f in self.ai_findings:
            if f.finding and f.finding.severity == Severity.CRITICAL:
                v = self.verifications.get(f.finding.key)
                if v and v.exploit_confirmed:
                    return True
        return False
