"""Fast, Docker-free tests for the verification building blocks."""

import textwrap

import pytest

from exhibita.core import recipes
from exhibita.core.locate import locate
from exhibita.core.patch import apply_fix, compiles
from exhibita.models import Finding, Severity

FLASK_APP = '''\
from flask import Flask, request
app = Flask(__name__)

@app.route("/api/notes")
def notes():
    owner = request.args.get("owner", "alice")
    return run("SELECT * FROM n WHERE o = '%s'" % owner)

@app.route("/api/hello")
def hello():
    name = request.args.get("name", "world")
    return run("echo " + name)
'''


def _write(tmp_path, body=FLASK_APP):
    (tmp_path / "app.py").write_text(body, encoding="utf-8")
    return tmp_path


def finding(line, rule_id="exhibita-sql-injection", file="app.py"):
    return Finding(tool="semgrep", rule_id=rule_id, file=file, line=line, severity=Severity.CRITICAL)


def test_locate_resolves_route_and_param(tmp_path):
    _write(tmp_path)
    assert locate(tmp_path, finding(7)) == {"path": "/api/notes", "param": "owner", "function": "notes"}
    assert locate(tmp_path, finding(12))["param"] == "name"


def test_locate_returns_none_outside_any_view(tmp_path):
    _write(tmp_path)
    assert locate(tmp_path, finding(2)) is None  # the app = Flask(...) line


def test_locate_handles_missing_file(tmp_path):
    assert locate(tmp_path, finding(5)) is None


def test_every_detectable_class_has_a_recipe():
    # the six classes ExhibitA claims it can prove
    want = {"sql_injection", "command_injection", "path_traversal", "ssti", "xss", "xxe"}
    assert want <= {r.name for r in recipes.REGISTRY}
    # each recipe's detection rule maps back to it
    for r in recipes.REGISTRY:
        for rid in r.rule_ids:
            assert recipes.recipe_for(finding(1, rule_id=rid)) is r


def test_xxe_recipe_is_body_based_and_needs_no_param():
    xxe = next(r for r in recipes.REGISTRY if r.name == "xxe")
    assert xxe.send_as == "raw_body" and xxe.method == "POST" and not xxe.needs_param
    plan = recipes.build_plan(xxe, "/api/xml", "")
    assert plan["content_type"] == "application/xml"
    assert any("SYSTEM" in c.get("payload", "") for c in plan["checks"])  # external-entity proof input


def test_oracles_are_generic_not_canary_based():
    # no recipe relies on a planted secret/env var; every check is a black-box oracle
    valid = {"diff", "signature", "time", "expr", "reflect"}
    for r in recipes.REGISTRY:
        assert r.checks, f"{r.name} has no oracle checks"
        assert all(c["type"] in valid for c in r.checks)
    passwd_users = [r.name for r in recipes.REGISTRY
                    if any("etc/passwd" in c.get("payload", "") for c in r.checks)]
    assert set(passwd_users) == {"path_traversal", "xxe"}


def test_recipe_for_prefers_rule_id_then_alias():
    sqli = finding(1, rule_id="exhibita-sql-injection")
    assert recipes.recipe_for(sqli).name == "sql_injection"
    unknown = finding(1, rule_id="some-other-rule")
    assert recipes.recipe_for(unknown, "command_injection").name == "command_injection"
    assert recipes.recipe_for(unknown, "nonsense") is None


def test_build_plan_carries_checks_and_benign():
    r = recipes.recipe_for(finding(1))
    plan = recipes.build_plan(r, "/api/notes", "owner")
    assert plan["param"] == "owner"
    assert plan["checks"] == r.checks
    assert plan["benign_marker"] == r.benign_marker


def test_apply_fix_reindents_to_the_replaced_block():
    src = "def f():\n    x = bad()\n    return x\n"
    out = apply_fix(src, 2, 2, "x = good()")
    assert "    x = good()\n" in out
    assert compiles(out)


def test_apply_fix_dedents_then_reindents_multiline():
    src = "def f():\n    a = 1\n    b = 2\n    return a\n"
    out = apply_fix(src, 2, 3, "a = 10\nb = 20")
    assert "    a = 10\n    b = 20\n" in out
    assert compiles(out)


def test_apply_fix_preserves_crlf():
    src = "def f():\r\n    x = 1\r\n"
    out = apply_fix(src, 2, 2, "x = 2")
    assert "    x = 2\r\n" in out


def test_apply_fix_rejects_out_of_range():
    with pytest.raises(ValueError):
        apply_fix("a = 1\n", 5, 9, "a = 2")


def test_compiles_detects_broken_python():
    assert not compiles("def oops(:\n")
