#!/usr/bin/env python3
"""
Measure WCAG contrast for every foreground/background token pair in globals.css.

The design system claims "light-mode body text clears 4.5:1" and "every -text
token is readable on the canvas it is used on". This script is how that claim is
checked rather than asserted: it parses the OKLCH values straight out of
app/globals.css, converts them to sRGB, and prints the measured ratio for each
pair in both themes.

Pairs are declared below because the relationship is a design decision, not
something derivable from the CSS: `--danger-text` is meant to sit on
`--background` and on `--danger-soft`, never on `--danger`.

Usage:  python3 scripts/check-contrast.py [--min 4.5] [--json]

Exit code is 1 if any pair marked required=True falls below its threshold, so
this can run in CI.
"""

from __future__ import annotations

import argparse
import json
import math
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
CSS = ROOT / "app" / "globals.css"

# (foreground token, background token, minimum ratio, label)
#
# 4.5 is WCAG AA for normal text. 3.0 is AA for large text (>=18.66px bold or
# >=24px) and for non-text UI boundaries such as borders and focus rings.
PAIRS: list[tuple[str, str, float, str]] = [
    # Core reading surfaces
    ("foreground", "background", 4.5, "body text on canvas"),
    ("foreground", "card", 4.5, "body text on card"),
    ("muted-foreground", "background", 4.5, "secondary text on canvas"),
    ("muted-foreground", "card", 4.5, "secondary text on card"),
    ("muted-foreground", "muted", 4.5, "secondary text on muted fill"),
    ("card-foreground", "card", 4.5, "card text"),
    ("popover-foreground", "popover", 4.5, "popover text"),
    ("sidebar-foreground", "sidebar", 4.5, "sidebar text"),
    # On-fill pairs: white-ish text on a saturated button
    ("primary-foreground", "primary", 4.5, "text on primary fill"),
    ("success-foreground", "success", 4.5, "text on success fill"),
    ("warning-foreground", "warning", 4.5, "text on warning fill"),
    ("danger-foreground", "danger", 4.5, "text on danger fill"),
    ("info-foreground", "info", 4.5, "text on info fill"),
    ("ai-foreground", "ai", 4.5, "text on AI fill"),
    ("secondary-foreground", "secondary", 4.5, "text on secondary fill"),
    ("sidebar-primary-foreground", "sidebar-primary", 4.5, "text on sidebar brand"),
    # On-canvas status text
    ("primary-text", "background", 4.5, "brand text on canvas"),
    ("success-text", "background", 4.5, "success text on canvas"),
    ("warning-text", "background", 4.5, "warning text on canvas"),
    ("danger-text", "background", 4.5, "danger text on canvas"),
    ("info-text", "background", 4.5, "info text on canvas"),
    ("ai-text", "background", 4.5, "AI text on canvas"),
    # Soft badges: the house style, so these carry most of the status meaning
    ("primary-text", "primary-soft", 4.5, "brand badge"),
    ("success-text", "success-soft", 4.5, "success badge"),
    ("warning-text", "warning-soft", 4.5, "warning badge"),
    ("danger-text", "danger-soft", 4.5, "danger badge"),
    ("info-text", "info-soft", 4.5, "info badge"),
    ("ai-text", "ai-soft", 4.5, "AI badge"),
    # Severity ramp, soft form
    ("sev-critical-text", "sev-critical-soft", 4.5, "critical badge"),
    ("sev-high-text", "sev-high-soft", 4.5, "high badge"),
    ("sev-medium-text", "sev-medium-soft", 4.5, "medium badge"),
    ("sev-low-text", "sev-low-soft", 4.5, "low badge"),
    ("sev-info-text", "sev-info-soft", 4.5, "info badge"),
    ("sev-critical-text", "background", 4.5, "critical text on canvas"),
    ("sev-high-text", "background", 4.5, "high text on canvas"),
    ("sev-medium-text", "background", 4.5, "medium text on canvas"),
    ("sev-low-text", "background", 4.5, "low text on canvas"),
    ("sev-info-text", "background", 4.5, "info text on canvas"),
    # Severity ramp, solid form
    ("sev-critical-foreground", "sev-critical", 4.5, "text on critical fill"),
    ("sev-high-foreground", "sev-high", 4.5, "text on high fill"),
    ("sev-medium-foreground", "sev-medium", 4.5, "text on medium fill"),
    ("sev-low-foreground", "sev-low", 4.5, "text on low fill"),
    ("sev-info-foreground", "sev-info", 4.5, "text on info fill"),
    # Non-text boundaries that WCAG 1.4.11 governs: 3.0, not 4.5.
    #
    # 1.4.11 covers "visual information required to identify user interface
    # components and states". A text field's edge qualifies — take the edge away
    # and nothing on screen says it is a field. So --input and --ring are
    # enforced at 3:1 against both surfaces they are drawn on.
    ("input", "card", 3.0, "text field edge on card"),
    ("input", "background", 3.0, "text field edge on canvas"),
    ("ring", "background", 3.0, "focus ring on canvas"),
    ("ring", "card", 3.0, "focus ring on card"),
    # `destructive` is not listed: it exists only as `--color-destructive:
    # var(--danger)` for shadcn compatibility, so measuring it would just
    # restate the `danger` rows above.
]

# Measured and printed, but not enforced.
#
# --border and --border-strong separate adjacent containers: a card from the
# canvas, one table row from the next. Nothing is identified by them — the card
# is a card because of its content, and removing the hairline costs grouping,
# not meaning. 1.4.11 explicitly does not reach that case, and forcing these to
# 3:1 would draw every panel in mid-grey. They are reported so the numbers stay
# on the record rather than being quietly dropped from the table.
INFORMATIONAL: list[tuple[str, str, str]] = [
    ("border", "background", "divider on canvas (decorative)"),
    ("border", "card", "divider on card (decorative)"),
    ("border-strong", "background", "emphasised divider on canvas (decorative)"),
    ("border-strong", "card", "emphasised divider on card (decorative)"),
]


# --- OKLCH -> sRGB -------------------------------------------------------
# Straight port of the CSS Color 4 conversion: OKLab -> linear sRGB -> sRGB.

def oklch_to_srgb(L: float, C: float, h_deg: float) -> tuple[float, float, float]:
    h = math.radians(h_deg)
    a = C * math.cos(h)
    b = C * math.sin(h)

    l_ = L + 0.3963377774 * a + 0.2158037573 * b
    m_ = L - 0.1055613458 * a - 0.0638541728 * b
    s_ = L - 0.0894841775 * a - 1.2914855480 * b

    l, m, s = l_ ** 3, m_ ** 3, s_ ** 3

    r = +4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s
    g = -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s
    bb = -0.0041960863 * l - 0.7034186147 * m + 1.7076147010 * s

    def gamma(u: float) -> float:
        u = max(0.0, min(1.0, u))
        return 1.055 * (u ** (1 / 2.4)) - 0.055 if u > 0.0031308 else 12.92 * u

    return gamma(r), gamma(g), gamma(bb)


def relative_luminance(rgb: tuple[float, float, float]) -> float:
    def lin(c: float) -> float:
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (lin(c) for c in rgb)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast(fg: tuple[float, float, float], bg: tuple[float, float, float]) -> float:
    l1, l2 = relative_luminance(fg), relative_luminance(bg)
    if l2 > l1:
        l1, l2 = l2, l1
    return (l1 + 0.05) / (l2 + 0.05)


# --- globals.css parsing -------------------------------------------------

DECL_RE = re.compile(
    r"^\s*--([a-z0-9-]+):\s*oklch\(\s*([0-9.]+)\s+([0-9.]+)\s+([0-9.]+)\s*\)\s*;",
    re.MULTILINE,
)


def parse_blocks(css: str) -> dict[str, dict[str, tuple[float, float, float]]]:
    """Return {theme: {token: (L, C, h)}} for the :root and .dark blocks."""
    themes: dict[str, dict[str, tuple[float, float, float]]] = {}

    for selector, theme in ((":root {", "light"), (".dark {", "dark")):
        start = css.find(selector)
        if start == -1:
            continue
        depth, i = 0, css.index("{", start)
        end = i
        for end in range(i, len(css)):
            if css[end] == "{":
                depth += 1
            elif css[end] == "}":
                depth -= 1
                if depth == 0:
                    break
        block = css[i:end]
        themes[theme] = {
            m.group(1): (float(m.group(2)), float(m.group(3)), float(m.group(4)))
            for m in DECL_RE.finditer(block)
        }

    return themes


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args()

    css = CSS.read_text(encoding="utf-8")
    themes = parse_blocks(css)

    # `.dark` only overrides what it redeclares; anything it omits inherits from
    # `:root`. Mirror that here or those tokens read as missing in dark mode.
    if "light" in themes and "dark" in themes:
        themes["dark"] = {**themes["light"], **themes["dark"]}

    results = []
    failures = 0
    missing: set[str] = set()

    checks = [(fg, bg, minimum, label) for fg, bg, minimum, label in PAIRS]
    checks += [(fg, bg, None, label) for fg, bg, label in INFORMATIONAL]

    for theme, tokens in themes.items():
        for fg, bg, minimum, label in checks:
            if fg not in tokens or bg not in tokens:
                missing.add(f"{theme}: {fg} / {bg}")
                continue
            ratio = contrast(oklch_to_srgb(*tokens[fg]), oklch_to_srgb(*tokens[bg]))
            ok = True if minimum is None else ratio >= minimum
            failures += 0 if ok else 1
            results.append(
                {
                    "theme": theme,
                    "label": label,
                    "foreground": fg,
                    "background": bg,
                    "ratio": round(ratio, 2),
                    "required": minimum,
                    "pass": ok,
                }
            )

    if args.json:
        print(json.dumps({"results": results, "missing": sorted(missing)}, indent=2))
    else:
        for theme in ("light", "dark"):
            rows = [r for r in results if r["theme"] == theme]
            if not rows:
                continue
            print(f"\n{theme.upper()}  ({len(rows)} pairs)")
            print("-" * 72)
            for r in sorted(rows, key=lambda r: r["ratio"]):
                if r["required"] is None:
                    mark, req = "--  ", "not enforced"
                else:
                    mark, req = ("ok  " if r["pass"] else "FAIL"), f"min {r['required']}"
                print(
                    f"  {mark} {r['ratio']:>5.2f}:1  ({req})  "
                    f"{r['label']}  [--{r['foreground']} on --{r['background']}]"
                )
        if missing:
            print("\nTokens not found in globals.css:")
            for m in sorted(missing):
                print(f"  {m}")
        enforced = sum(1 for r in results if r["required"] is not None)
        print(
            f"\n{len(results)} pairs measured, {enforced} enforced, "
            f"{failures} below threshold"
        )

    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
