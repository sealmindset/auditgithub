"""
Excerpt a Markdown document to a character budget without lying about it.

Written for the architecture report, which runs to roughly 14,000 characters
while the call sites that consume it truncate to 2,000 and 3,000 with a bare
slice. Two things go wrong with a bare slice, and both are silent:

1. **It cuts mid-sentence**, often mid-word, so the model reads a fragment whose
   last clause is unfinished and has no way to tell that from prose that simply
   ended. Models complete what looks unfinished; a truncated "the service
   authenticates via" invites an invention.

2. **It does not say anything was dropped.** A model handed 2,000 of 14,000
   characters believes it has seen the architecture. Every conclusion it draws
   about attack surface is then drawn from an eighth of the document while
   reading as though drawn from all of it.

This module cuts on a heading boundary where it can, and always states what it
removed. `[... N of M sections omitted ...]` is a small amount of text that
converts a hidden gap into a visible one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

# ATX headings only. The architecture generator emits these; setext underlines
# are not produced by it and matching them would risk cutting on a table rule.
_HEADING_RE = re.compile(r"^(#{1,6})\s+\S", re.MULTILINE)

# Never emit a fragment so small the note is most of it. Applied to the
# character-cut fallback, and relative to the budget rather than absolutely --
# a whole-section result is judged by how much of the budget it used, not by
# whether it clears a fixed length, or a short-sectioned document would be cut
# mid-section for no reason.
_MIN_USEFUL_CHARS = 200


@dataclass(frozen=True)
class Excerpt:
    """An excerpt and an honest account of what it left out."""

    text: str
    is_truncated: bool
    sections_included: int
    sections_total: int
    chars_original: int

    @property
    def chars_kept(self) -> int:
        return len(self.text)

    def note(self) -> str:
        """One line stating the omission, for a prompt or a report footnote."""
        if not self.is_truncated:
            return ""
        omitted = self.sections_total - self.sections_included
        if self.sections_total > 1:
            return (f"[... {omitted} of {self.sections_total} sections omitted; "
                    f"{self.chars_kept:,} of {self.chars_original:,} characters shown ...]")
        return (f"[... truncated; {self.chars_kept:,} of "
                f"{self.chars_original:,} characters shown ...]")


def _split_sections(text: str) -> list[str]:
    """Split on ATX headings, keeping each heading with the body beneath it."""
    starts = [m.start() for m in _HEADING_RE.finditer(text)]
    if not starts:
        return [text]
    sections = []
    # Anything before the first heading is its own leading section.
    if starts[0] > 0:
        sections.append(text[:starts[0]])
    for i, start in enumerate(starts):
        end = starts[i + 1] if i + 1 < len(starts) else len(text)
        sections.append(text[start:end])
    return sections


def excerpt_markdown(text: str | None, budget: int) -> Excerpt:
    """Return at most `budget` characters, cut on a section boundary if possible.

    Whole sections are taken in order until the next one would not fit. If not
    even the first section fits, the text is cut at the last paragraph or
    sentence break inside the budget rather than mid-word -- still truncated,
    but not mid-thought.

    A budget that fits the whole document returns it untouched with
    `is_truncated` False, so a caller can tell "this is everything" from "this
    is what fit".
    """
    if not text:
        return Excerpt("", False, 0, 0, 0)
    if budget <= 0:
        raise ValueError("budget must be positive")

    original_len = len(text)
    sections = _split_sections(text)
    total = len(sections)

    if original_len <= budget:
        return Excerpt(text, False, total, total, original_len)

    kept: list[str] = []
    used = 0
    for section in sections:
        if used + len(section) > budget:
            break
        kept.append(section)
        used += len(section)

    # Take the section-boundary result whenever it fills a fair share of the
    # budget. Falling through to the character cut is only worth it when whole
    # sections would waste most of the budget -- one short section ahead of a
    # very long one.
    if kept and used * 2 >= budget:
        body = "".join(kept).rstrip()
        result = Excerpt(body, True, len(kept), total, original_len)
        return Excerpt(f"{body}\n\n{result.note()}", True, len(kept), total, original_len)

    # The first section alone exceeds the budget. Cut inside it, preferring a
    # paragraph break, then a sentence end, then a space -- never mid-word.
    window = text[:budget]
    min_cut = min(_MIN_USEFUL_CHARS, budget // 2)
    for separator in ("\n\n", ". ", "\n", " "):
        cut = window.rfind(separator)
        if cut > min_cut:
            window = window[:cut + (1 if separator == ". " else 0)]
            break
    body = window.rstrip()
    result = Excerpt(body, True, 0, total, original_len)
    return Excerpt(f"{body}\n\n{result.note()}", True, 0, total, original_len)
