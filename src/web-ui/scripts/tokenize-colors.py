#!/usr/bin/env python3
"""
Rewrite hardcoded Tailwind palette classes to AuditGH design tokens.

Before this ran, the UI carried 1,912 raw palette utilities (bg-red-500,
text-green-600, border-blue-200 ...), counted by `audit-ui.py` against the tree
at the branch point. They were the reason light and dark mode disagreed with
each other and why "High" severity was three different colours in three
different tables.

The mapping is by colour family and shade role, not by literal string:

    family   red/rose -> danger        orange/amber/yellow -> warning
             green/emerald/lime/teal -> success
             blue/sky/cyan/indigo    -> info
             purple/violet/fuchsia   -> ai
             gray/slate/zinc/neutral/stone -> neutral surfaces

    role     backgrounds at the pale and very dark ends -> -soft
             backgrounds mid-range                      -> solid fill
             all text                                   -> -text
             borders                                    -> -line (or solid)

Any `dark:` variant that lands on the same class as its light counterpart is
dropped: the token already adapts, so the override is dead weight.

Usage:  python3 scripts/tokenize-colors.py [--check] [paths...]
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys
from collections import Counter

ROOT = pathlib.Path(__file__).resolve().parent.parent

FAMILY = {
    "red": "danger",
    "rose": "danger",
    "orange": "warning",
    "amber": "warning",
    "yellow": "warning",
    "green": "success",
    "emerald": "success",
    "lime": "success",
    "teal": "success",
    "blue": "info",
    "sky": "info",
    "cyan": "info",
    "indigo": "info",
    "violet": "ai",
    "purple": "ai",
    "fuchsia": "ai",
    "pink": "ai",
}

NEUTRALS = {"gray", "slate", "zinc", "neutral", "stone"}

# Utility prefixes we rewrite. Anything else (e.g. divide-, outline-, decoration-)
# is left alone and reported so it can be handled deliberately.
PROPS = ("bg", "text", "border", "ring", "fill", "stroke", "from", "to", "via",
         "shadow", "accent", "caret", "divide", "outline")

SHADES = ("50", "100", "200", "300", "400", "500", "600", "700", "800", "900", "950")


def role_for(prop: str, family: str, shade: str) -> str | None:
    """Return the token suffix for a (property, family, shade) triple."""
    n = int(shade)

    if prop in ("text", "fill", "stroke", "caret", "decoration"):
        # Text always wants the contrast-tuned on-canvas value.
        return f"{family}-text"

    if prop in ("bg", "accent"):
        # Pale tints (50-200) and very dark tints (800-950, i.e. dark-mode
        # surfaces) are both "a tinted panel"; the token handles both themes.
        if n <= 200 or n >= 800:
            return f"{family}-soft"
        return family

    if prop in ("border", "divide", "outline", "ring"):
        if n <= 300 or n >= 800:
            return f"{family}-line"
        return family

    if prop in ("from", "to", "via", "shadow"):
        if n <= 200:
            return f"{family}-soft"
        return family

    return None


def neutral_role(prop: str, shade: str) -> str | None:
    """Neutrals map onto the existing surface tokens, not a colour family."""
    n = int(shade)

    if prop in ("text", "fill", "stroke"):
        # 800+ is body copy; everything lighter was being used as secondary text.
        return "foreground" if n >= 800 else "muted-foreground"

    if prop == "bg":
        if 400 <= n <= 600:
            return "muted-foreground"  # status dots and avatars
        return "muted"

    if prop in ("border", "divide", "outline", "ring"):
        return "border" if n <= 300 or n >= 700 else "border-strong"

    if prop in ("from", "to", "via"):
        return "muted"

    return None


# Matches e.g. `dark:hover:bg-red-500/20` and captures the pieces.
CLASS_RE = re.compile(
    r"(?P<variants>(?:[a-z0-9-]+(?:\[[^\]]*\])?:)*)"
    r"(?P<prop>" + "|".join(PROPS) + r")"
    r"-(?P<family>" + "|".join(list(FAMILY) + list(NEUTRALS)) + r")"
    r"-(?P<shade>" + "|".join(SHADES) + r")"
    r"(?P<alpha>/(?:\d{1,3}|\[[^\]]*\]))?"
    r"(?![\w-])"
)

stats: Counter[str] = Counter()
unmapped: Counter[str] = Counter()


def rewrite_class(m: re.Match[str]) -> str:
    variants = m.group("variants")
    prop = m.group("prop")
    family = m.group("family")
    shade = m.group("shade")
    alpha = m.group("alpha") or ""

    if family in NEUTRALS:
        token = neutral_role(prop, shade)
        if token is None:
            unmapped[m.group(0)] += 1
            return m.group(0)
        # `text-foreground` / `bg-muted` already carry their own property name.
        out = f"{variants}{prop}-{token}{alpha}"
    else:
        token = role_for(prop, FAMILY[family], shade)
        if token is None:
            unmapped[m.group(0)] += 1
            return m.group(0)
        out = f"{variants}{prop}-{token}{alpha}"

    stats[f"{m.group(0)} -> {out}"] += 1
    return out


# After rewriting, `text-danger-text dark:text-danger-text` is redundant: the
# token already carries its own dark value, so the override is dead weight.
#
# This runs one line at a time and only removes whole class words. It must never
# span a newline — an earlier version used a multi-line quoted-string match and
# reflowed source files it had no business touching.
DARK_DUP_RE = re.compile(r"(?<=\s)dark:((?:[a-z-]+:)*)([a-z]+-[a-z0-9-]+(?:/(?:\d{1,3}|\[[^\]]*\]))?)(?=\s|$)")


def drop_redundant_dark(text: str) -> str:
    """Remove `dark:X` when the identical un-prefixed `X` sits on the same line."""
    out_lines: list[str] = []

    for line in text.split("\n"):
        # Cheap guard: nothing to do unless the line has both forms.
        if "dark:" not in line:
            out_lines.append(line)
            continue

        words = set(re.findall(r"[a-z0-9:/\[\]._-]+", line))

        def maybe_drop(m: re.Match[str]) -> str:
            bare = m.group(1) + m.group(2)
            if bare in words:
                stats[f"drop dark:{bare}"] += 1
                return ""
            return m.group(0)

        # Collapse only the doubled space left behind; never touch indentation.
        # The whitespace cleanup runs only on lines we actually edited, so the
        # codemod reports no diff for files it has nothing to say about.
        new_line = DARK_DUP_RE.sub(maybe_drop, line)
        if new_line != line:
            new_line = re.sub(r"(?<=\S)  +(?=\S)", " ", new_line)
            new_line = re.sub(r" +(?=[\"'`])", "", new_line)
        out_lines.append(new_line)

    return "\n".join(out_lines)


def process(path: pathlib.Path, check: bool) -> bool:
    original = path.read_text(encoding="utf-8")
    updated = CLASS_RE.sub(rewrite_class, original)
    updated = drop_redundant_dark(updated)
    if updated == original:
        return False
    if not check:
        path.write_text(updated, encoding="utf-8")
    return True


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="*", default=None)
    ap.add_argument("--check", action="store_true",
                    help="report without writing")
    args = ap.parse_args()

    roots = [pathlib.Path(p) for p in args.paths] or [ROOT / "app", ROOT / "components"]
    files = [
        f
        for root in roots
        for f in (root.rglob("*.tsx") if root.is_dir() else [root])
        if "node_modules" not in f.parts and ".next" not in f.parts
    ]

    changed = [f for f in files if process(f, args.check)]

    print(f"{len(changed)} of {len(files)} files {'would change' if args.check else 'changed'}")
    total = sum(v for k, v in stats.items() if not k.startswith("drop "))
    dropped = sum(v for k, v in stats.items() if k.startswith("drop "))
    print(f"{total} class rewrites, {dropped} redundant dark: variants removed")

    if unmapped:
        print("\nUnmapped (left as-is, handle by hand):")
        for k, v in unmapped.most_common(20):
            print(f"  {v:>4}  {k}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
