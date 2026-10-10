"""Find the HTTP entry point for a finding by reading the Flask source with AST.

Given the file and line of a sink (e.g. a SQL execute), find the view function
that contains it, its route path, and the request parameter it reads. Deterministic
and offline — no guessing, so the proof targets exactly the flagged code.
"""

from __future__ import annotations

import ast
from pathlib import Path

from ..models import Finding

_ROUTE_ATTRS = {"route", "get", "post", "put", "delete", "patch"}
_PARAM_GETTERS = {"args", "form", "values"}


def _const_str(node: ast.AST) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _route_path(func: ast.FunctionDef) -> str | None:
    for dec in func.decorator_list:
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and dec.func.attr in _ROUTE_ATTRS:
            if dec.args:
                return _const_str(dec.args[0])
    return None


def _first_param(func: ast.FunctionDef) -> str | None:
    """The first request.args/form/values parameter name read in the function."""
    found: list[str] = []
    for node in ast.walk(func):
        # request.args.get("x") / request.values.get("x")
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and node.func.attr == "get" and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr in _PARAM_GETTERS and node.args):
            name = _const_str(node.args[0])
            if name:
                found.append(name)
        # request.args["x"]
        elif (isinstance(node, ast.Subscript) and isinstance(node.value, ast.Attribute)
              and node.value.attr in _PARAM_GETTERS):
            name = _const_str(node.slice)
            if name:
                found.append(name)
    return found[0] if found else None


def locate(app_dir: Path, finding: Finding) -> dict | None:
    """Return {"path", "param"} for the finding, or None if it can't be resolved."""
    src_path = app_dir / finding.file
    try:
        source = src_path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source)
    except (OSError, SyntaxError):
        return None

    enclosing: ast.FunctionDef | None = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            end = node.end_lineno or node.lineno
            if node.lineno <= finding.line <= end:
                # keep the innermost (smallest span) function containing the line
                if enclosing is None or (end - node.lineno) < ((enclosing.end_lineno or 0) - enclosing.lineno):
                    enclosing = node
    if enclosing is None:
        return None
    path = _route_path(enclosing)
    if not path:
        return None
    # param may be None for body-based endpoints (e.g. XXE reads request.get_data()).
    return {"path": path, "param": _first_param(enclosing), "function": enclosing.name}
