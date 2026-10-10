"""Apply an AI-suggested fix to a copy of the source and check it still parses.

We never touch the user's working tree here — the fix is applied to a staged copy
used only for verification. Indentation is normalized to the replaced block so a
model that emits the fix at column 0 still lands correctly inside a function.
"""

from __future__ import annotations

import textwrap


def _leading_ws(line: str) -> str:
    return line[: len(line) - len(line.lstrip())]


def apply_fix(source: str, start: int, end: int, replacement: str) -> str:
    """Replace inclusive lines [start, end] with `replacement`, re-indented to match."""
    lines = source.splitlines(keepends=True)
    if start < 1 or end > len(lines) or start > end:
        raise ValueError(f"fix line range {start}-{end} is out of bounds (file has {len(lines)} lines)")

    base_indent = _leading_ws(lines[start - 1])
    block = textwrap.indent(textwrap.dedent(replacement.strip("\n")), base_indent)
    if not block.endswith("\n"):
        block += "\n"

    newline = "\r\n" if lines[start - 1].endswith("\r\n") else "\n"
    if newline == "\r\n":
        block = block.replace("\n", "\r\n")

    return "".join(lines[: start - 1]) + block + "".join(lines[end:])


def compiles(source: str, filename: str = "patched.py") -> bool:
    try:
        compile(source, filename, "exec")
        return True
    except SyntaxError:
        return False
