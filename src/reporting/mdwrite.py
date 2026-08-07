"""
Writing Markdown safely from generated data.

The renderer's job is Markdown -> document. This module is the step before it: turning
values the system produced — repository names, package specs, timestamps, model prose —
into Markdown that says what it means.

It lives in `reporting` rather than beside its first caller because escaping has to have
exactly one definition. Two escapers drift, and the way they drift is silent: a pipe
that one of them misses does not raise, it shifts every column in a table one place to
the left and the reader has no way to tell.

Scope note: this escapes *generated* text. Authored Markdown — a model's analysis prose,
a hand-written playbook — must pass through untouched, because escaping it is what turns
a heading into a literal `##` on the page.
"""

from __future__ import annotations

import re
from typing import Any, Iterable, List

# Characters that would be read as markup if they survive into the document. The set is
# deliberately narrow: these strings are assembled from package names, repository names
# and timestamps, so an over-broad escape would litter the output with backslashes in
# front of ordinary punctuation.
_MD_SPECIAL = re.compile(r"([\\`*_\[\]|])")

# A line that opens with one of these would start a list, heading, quote or code fence.
_MD_LINE_START = re.compile(r"^(\s*)([#>+]|-(?=\s)|\d+\.(?=\s))")


def as_str(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def md_text(value: Any) -> str:
    """Escape generated text so it renders as prose, not as markup."""
    text = as_str(value)
    if not text:
        return ""
    text = _MD_SPECIAL.sub(r"\\\1", text)
    return _MD_LINE_START.sub(r"\1\\\2", text)


def md_cell(value: Any) -> str:
    """
    Escape a value for a table cell.

    A newline inside a cell terminates the row in GFM table syntax, so embedded newlines
    collapse to spaces rather than silently truncating the table.
    """
    return " ".join(md_text(value).split())


def md_table(headers: Iterable[Any], rows: Iterable[Iterable[Any]]) -> List[str]:
    """Render a GFM table, padding or trimming rows to the header width."""
    headers = [md_cell(h) for h in headers]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        cells = [md_cell(c) for c in row]
        # Pad or trim so a malformed row cannot shift every later column.
        cells = (cells + [""] * len(headers))[:len(headers)]
        lines.append("| " + " | ".join(cells) + " |")
    return lines
