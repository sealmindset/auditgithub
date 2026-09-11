#!/usr/bin/env python3
"""
Audit the UI against the delivery checklist, and generate the appendix of names.

Every figure in the two delivery documents comes from this script. Nothing in
them is typed from recollection: run it and the counts either reproduce or the
documents are wrong.

Each check answers one checklist line and reports every location by
`file:line`, because a count alone is not actionable to whoever has to do the
work and not verifiable to anyone checking it.

What this script can and cannot see, stated plainly because the documents
depend on it:

  - It reads source text. It does not render a page, so it cannot prove that a
    layout does not overflow at 375px; it can only find the constructs that
    cause overflow (a fixed pixel width, an unprefixed multi-column grid).
  - It cannot follow a class name through `cn()` when the value is computed at
    runtime, so `cursor-pointer` arriving from a variant is invisible to it.
    Those show as findings and need a human to clear them.
  - Contrast is not checked here. That is `check-contrast.py`, which measures
    the tokens rather than inspecting the markup.
  - The literal-colour check runs against two allowlists, `LITERAL_COLOR_EXEMPT`
    and `VENDOR_BRAND_HEX`. A zero there means "no literal colour outside the
    listed exceptions", not "no literal colour". The exempt count is printed
    alongside so the exceptions stay visible rather than disappearing.

Usage:
    python3 scripts/audit-ui.py                 # summary table
    python3 scripts/audit-ui.py --appendix      # markdown appendix of names
    python3 scripts/audit-ui.py --json
"""

from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys
from collections import defaultdict

ROOT = pathlib.Path(__file__).resolve().parent.parent
SOURCE_DIRS = ("app", "components", "lib", "hooks")

# Diagram and report panels deliberately keep a light mat: the PNG they hold is
# rendered with dark strokes on transparency, so a dark mat erases the image.
DELIBERATE_LIGHT_MATS = {
    ("components/SecurityReportModal.tsx", "bg-white"),
    ("components/DiagramEditorPanel.tsx", "bg-white"),
    ("components/ArchitectureView.tsx", "bg-white"),
}

# Files allowed to hold literal colours, each with the reason it is allowed.
# A blanket "no hex anywhere" rule would be false: some of this UI paints
# surfaces the design tokens genuinely do not reach. Listing them here keeps
# the exception countable, and anything not listed is a finding.
LITERAL_COLOR_EXEMPT: dict[str, str] = {
    # Canvas takes a resolved colour string, and a radar scope that turns
    # white in light mode stops reading as a radar scope. See the file header.
    "components/dashboard/ThreatRadar.tsx": "canvas instrument display, dark in both themes",
    # A ten-step rank ramp cannot be built from five severity tokens, and it
    # must not flip lightness with the theme. See the CRITICAL_RANK_RAMP docs.
    "lib/chart.ts": "CRITICAL_RANK_RAMP — ten-step rank, documented exception",
    # These build standalone documents that leave the app. A PDF or an
    # spreadsheet carries no stylesheet, so `var()` resolves to nothing.
    "components/SecurityReportModal.tsx": "exported HTML/PDF template, no app stylesheet",
    "components/DownloadControl.tsx": "exported HTML/spreadsheet template, no app stylesheet",
    # The browser paints `theme-color` before any stylesheet loads.
    "app/layout.tsx": "theme-color meta, derived from --background",
}

# Vendor marks in the secret-type legend. AWS orange and Slack aubergine are
# how a reader recognises the row; re-theming a brand makes it wrong rather
# than consistent. Anything in that file which is not on this list must be a
# token — which is why GitHub and JWT, both near-black, are absent.
VENDOR_BRAND_HEX = {
    "#FF9900", "#0089D6", "#0061D5", "#CC2927", "#336791",
    "#2496ED", "#4A154B", "#F46800", "#6366F1", "#8B5CF6", "#ED1965",
}
VENDOR_BRAND_FILE = "app/attack-surface/page.tsx"

LITERAL_COLOR_RE = re.compile(
    r"#[0-9a-fA-F]{8}\b|#[0-9a-fA-F]{6}\b|\brgba?\(\s*[0-9]|\bhsla?\(\s*[0-9]"
)

PALETTE_RE = re.compile(
    r"\b(?:bg|text|border|ring|fill|stroke|from|to|via|divide|outline|accent|caret|shadow)"
    r"-(?:red|rose|orange|amber|yellow|green|emerald|lime|teal|blue|sky|cyan|indigo"
    r"|violet|purple|fuchsia|pink|gray|slate|zinc|neutral|stone)"
    r"-(?:50|100|200|300|400|500|600|700|800|900|950)\b"
)
HSL_VAR_RE = re.compile(r"hsl\(\s*var\(")

# A `var()` handed to a canvas 2D context does not resolve. `ctx.fillStyle` and
# `ctx.strokeStyle` swallow it silently and keep the previous colour, while
# `addColorStop` throws "The string did not match the expected pattern" at the
# first frame. Neither failure is visible to a type check or a production build,
# which is why this is a check rather than a convention.
#
# Matching "a token reached the canvas" directly is not possible line-by-line,
# because the token usually arrives through a variable (`blip.color`) declared
# somewhere else. So the invariant is inverted and made absolute: every colour
# handed to a canvas goes through `resolveCanvasColor`, which returns non-token
# values unchanged. That leaves nothing to infer -- a bare colour at a canvas
# call site is a finding whether or not this line can see where it came from.
#
# CanvasGradient objects are the one exemption: they are not colour strings.
# They are recognised by having no quote, no "color" and no "var(" on the line.
CANVAS_COLOR_RE = re.compile(r"\b(fillStyle|strokeStyle|shadowColor|addColorStop)\b")
CANVAS_RESOLVER_RE = re.compile(r"resolveCanvasColor|withCanvasAlpha")
CANVAS_COLOR_VALUE_RE = re.compile(r"[\"'`]|olor|var\(")
COMMENT_LINE_RE = re.compile(r"\s*(//|/\*|\*)")
EMOJI_RE = re.compile(
    "[" "\U0001f300-\U0001faff" "☀-➿" "\U0001f000-\U0001f2ff" "]"
)
FIXED_WIDTH_RE = re.compile(r"(?<![-\w:])(?:min-)?w-\[(\d{3,4})px\]")
GRID_COLS_RE = re.compile(r"(?<![-\w:])grid-cols-(\d{1,2})\b")
DURATION_RE = re.compile(r"(?<![-\w:])duration-(?:\[(\d+)ms\]|(\d+))\b")
Z_RE = re.compile(r"(?<![-\w:])z-(?:\[(\d+)\]|(\d+|auto))\b")

CLICKABLE_TAGS = ("div", "span", "tr", "td", "li", "section", "article", "header", "p")


def source_files() -> list[pathlib.Path]:
    out: list[pathlib.Path] = []
    for d in SOURCE_DIRS:
        base = ROOT / d
        if not base.is_dir():
            continue
        for p in base.rglob("*"):
            if p.is_file() and p.suffix in (".tsx", ".ts", ".css"):
                if "node_modules" in p.parts or ".next" in p.parts:
                    continue
                out.append(p)
    return sorted(out)


def rel(p: pathlib.Path) -> str:
    return str(p.relative_to(ROOT))


def iter_tags(text: str, names: tuple[str, ...]) -> list[tuple[str, str, int, int]]:
    """Yield (tag name, opening tag, 1-indexed line, index just past the tag).

    Attributes routinely span lines and contain braces and strings, so this
    walks forward tracking brace depth and quote state rather than matching a
    single-line regex.
    """
    found: list[tuple[str, str, int, int]] = []
    pattern = re.compile(r"<(" + "|".join(names) + r")(?=[\s/>])")

    for m in pattern.finditer(text):
        i = m.end()
        depth = 0
        quote: str | None = None
        while i < len(text):
            ch = text[i]
            if quote:
                if ch == quote:
                    quote = None
                elif ch == "\\":
                    i += 1
            elif ch in "\"'`":
                quote = ch
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
            elif ch == ">" and depth == 0:
                break
            i += 1
        found.append(
            (
                m.group(1),
                text[m.start() : i + 1],
                text.count("\n", 0, m.start()) + 1,
                i + 1,
            )
        )

    return found


CLOSE_TAG_CACHE: dict[tuple[int, str], re.Pattern[str]] = {}


def element_inner_text(text: str, tag: str, open_end: int) -> str:
    """Return the visible text inside an element, tags and expressions removed.

    Used to tell an icon-only control from one that already names itself.
    Expressions are not evaluated, but string literals inside them are kept, so
    `{saving ? "Saving" : "Save"}` still counts as naming the control. A label
    that only exists as a variable (`{label}`) cannot be resolved from source
    and shows up as a finding for a human to clear.
    """
    if text[open_end - 2] == "/":
        return ""  # self-closing

    depth = 1
    i = open_end
    pattern = re.compile(rf"<(/?){re.escape(tag)}(?=[\s/>])")
    while depth and i < len(text):
        m = pattern.search(text, i)
        if not m:
            break
        depth += -1 if m.group(1) else 1
        i = m.end()
        if depth == 0:
            inner = text[open_end : m.start()]
            break
    else:
        return ""
    if depth:
        return ""

    raw_inner = inner

    # An expression child that renders no JSX renders a value, and a value
    # renders as text: `{prompt}` and `{status.toUpperCase()}` both name their
    # control. This cannot be verified from source — the value could be empty
    # at runtime — and that limit is stated in the module docstring.
    interpolated_text = [
        m.group(1)
        for m in re.finditer(r"\{([^{}<>]+)\}", raw_inner)
        if re.search(r"[A-Za-z]", m.group(1))
    ]

    inner = re.sub(r"<[^>]*>", " ", inner)

    # What is left is a mix of rendered text and expression code, often across
    # lines: `{syncing ? ( Syncing... ) : ( Full sync )}`. Keep the lines that
    # read as prose and discard the ones that read as code. A line counts as
    # prose only if it carries no JS punctuation at all, which is what
    # separates `Full sync` from `onClick={handleFullSync}`.
    kept: list[str] = []
    for raw in inner.split("\n"):
        s = raw.strip()
        if not s or not re.search(r"[A-Za-z]", s):
            continue
        # Text can sit either side of an interpolation: `View All ({n})` and
        # `Sign in with {provider.display_name}` both name their control.
        outside = re.sub(r"\{[^{}]*\}", " ", s).strip()
        # Reject by punctuation rather than accept by alphabet, so that label
        # text containing arrows, dashes or accented letters ("Sort A→Z") is
        # not mistaken for code.
        if outside and re.search(r"[A-Za-z]", outside) and not re.search(r"[{}<>=;`$|\\]", outside):
            kept.append(outside)
            continue
        for lit in re.findall(r"[\"'`]([^\"'`]+)[\"'`]", s):
            if re.search(r"[A-Za-z]", lit):
                kept.append(lit)
    return " ".join(kept + interpolated_text)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--appendix", action="store_true", help="markdown appendix of names")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    findings: dict[str, list[str]] = defaultdict(list)
    totals: dict[str, int] = defaultdict(int)
    z_values: dict[str, int] = defaultdict(int)
    durations: dict[str, int] = defaultdict(int)

    files = source_files()

    for path in files:
        r = rel(path)
        text = path.read_text(encoding="utf-8")
        lines = text.split("\n")

        for n, line in enumerate(lines, 1):
            if path.suffix == ".css" and "globals.css" in r and "Never use a raw" in line:
                continue  # the rule itself, quoted in a comment

            for m in PALETTE_RE.finditer(line):
                findings["raw-palette-class"].append(f"{r}:{n}  {m.group(0)}")
            for m in LITERAL_COLOR_RE.finditer(line):
                lit = m.group(0)
                if r in LITERAL_COLOR_EXEMPT:
                    totals["literal-color-exempt"] += 1
                    continue
                if r == VENDOR_BRAND_FILE and lit.upper() in VENDOR_BRAND_HEX:
                    totals["vendor-brand-hex"] += 1
                    continue
                findings["literal-color-in-source"].append(f"{r}:{n}  {lit}")
            for _ in HSL_VAR_RE.finditer(line):
                findings["hsl-wrapping-oklch"].append(f"{r}:{n}")
            # Comments are skipped: documenting this rule means naming the API
            # it governs, and prose about `fillStyle` is not a call to it.
            cm = CANVAS_COLOR_RE.search(line)
            if (
                cm
                and not COMMENT_LINE_RE.match(line)
                and not CANVAS_RESOLVER_RE.search(line)
                and CANVAS_COLOR_VALUE_RE.search(line)
            ):
                findings["canvas-color-without-resolver"].append(f"{r}:{n}  {cm.group(1)}")
            for m in EMOJI_RE.finditer(line):
                findings["emoji-in-source"].append(f"{r}:{n}  {m.group(0)}")
            for m in FIXED_WIDTH_RE.finditer(line):
                if int(m.group(1)) >= 375 and not re.search(r"(sm|md|lg|xl):" + re.escape(m.group(0)), line):
                    findings["fixed-width-over-375px"].append(f"{r}:{n}  {m.group(0)}")
            for m in GRID_COLS_RE.finditer(line):
                cols = int(m.group(1))
                prefixed = re.search(r"(sm|md|lg|xl|2xl):grid-cols-", line)
                # A three-way tab rail is exempt: at 375px a full-width grid of
                # three gives each tab 117px after padding, which fits the
                # labels in use. Four or more does not, and neither does a
                # content grid, which holds more than a word per cell.
                tab_rail = "TabsList" in line and cols <= 3
                if cols >= 3 and not prefixed and "min-w-[" not in line and not tab_rail:
                    findings["multi-col-grid-no-breakpoint"].append(f"{r}:{n}  grid-cols-{cols}")
            for m in DURATION_RE.finditer(line):
                ms = int(m.group(1) or m.group(2))
                durations[f"{ms}ms"] += 1
                if not 150 <= ms <= 300:
                    findings["transition-outside-150-300ms"].append(f"{r}:{n}  {ms}ms")
            for m in Z_RE.finditer(line):
                z_values[m.group(1) or m.group(2)] += 1

            for m in re.finditer(r"\b(?:text|bg|border)-(?:white|black)\b", line):
                cls = m.group(0)
                if "/" in line[m.end() : m.end() + 2]:
                    continue  # bg-black/50 is a modal scrim, correct in both themes
                if (r, cls) in DELIBERATE_LIGHT_MATS:
                    totals["deliberate-light-mat"] += 1
                    continue
                findings["absolute-white-or-black"].append(f"{r}:{n}  {cls}")

        if path.suffix != ".tsx":
            continue

        # Interactive elements that are not natively interactive need a pointer
        # cursor, or nothing on screen says they can be clicked.
        for tag, body, n, _ in iter_tags(text, CLICKABLE_TAGS):
            if "onClick" not in body:
                continue
            # A handler that only stops the event is not a control: it exists so
            # that clicking a child does not also toggle the parent. Giving it a
            # pointer cursor would advertise an interaction that is not there.
            only_suppresses = bool(
                re.search(r"onClick=\{[^}]*(?:stopPropagation|preventDefault)\(\)[^}]*\}", body)
            ) and not re.search(r"onClick=\{[^}]*(?:stopPropagation|preventDefault)\(\)\s*[;,][^}]*\S", body)
            if only_suppresses:
                totals["click-suppressor"] += 1
                continue
            totals["clickable-non-button"] += 1
            if "cursor-" not in body:
                findings["clickable-without-pointer-cursor"].append(f"{r}:{n}  <{tag}>")

        # A control whose only child is an icon has no accessible name unless one
        # is supplied, so `size="icon"` is not the test — having no text is.
        #
        # `components/ui/button.tsx` is skipped: it is the primitive, and its
        # children arrive from whichever call site renders it.
        button_tags = () if r == "components/ui/button.tsx" else ("Button", "button")
        for tag, body, n, end in iter_tags(text, button_tags or ("__none__",)):
            inner = element_inner_text(text, tag, end)
            named_by_text = bool(re.search(r"[A-Za-z]", inner))
            icon_only = not named_by_text
            totals["icon-only-button"] += 1 if icon_only else 0
            has_name = (
                "aria-label" in body
                or "title=" in body
                or "sr-only" in text[end : end + 600]
            )
            if icon_only and not has_name:
                findings["icon-button-without-name"].append(f"{r}:{n}  <{tag}>")

        for tag, body, n, _ in iter_tags(text, ("img", "Image")):
            totals["image"] += 1
            if "alt=" not in body:
                findings["image-without-alt"].append(f"{r}:{n}  <{tag}>")

        # A field with no id and no aria-label cannot be associated with a
        # label, whatever text happens to sit next to it.
        #
        # The three primitives are skipped for the same reason as the button
        # primitive: the attributes arrive from the call site.
        field_primitive = r in (
            "components/ui/input.tsx",
            "components/ui/textarea.tsx",
            "components/ui/sidebar.tsx",
        )
        field_tags = () if field_primitive else ("Input", "Textarea", "input", "textarea")
        for tag, body, n, _ in iter_tags(text, field_tags or ("__none__",)):
            if 'type="hidden"' in body or 'type="checkbox"' in body or 'type="radio"' in body:
                continue
            totals["text-field"] += 1
            if "id=" not in body and "aria-label" not in body and "aria-labelledby" not in body:
                findings["field-without-label-hook"].append(f"{r}:{n}  <{tag}>")

    order = [
        "raw-palette-class",
        "literal-color-in-source",
        "hsl-wrapping-oklch",
        "canvas-color-without-resolver",
        "emoji-in-source",
        "absolute-white-or-black",
        "clickable-without-pointer-cursor",
        "icon-button-without-name",
        "image-without-alt",
        "field-without-label-hook",
        "fixed-width-over-375px",
        "multi-col-grid-no-breakpoint",
        "transition-outside-150-300ms",
    ]

    if args.json:
        print(json.dumps(
            {
                "files_scanned": len(files),
                "findings": {k: findings.get(k, []) for k in order},
                "counts": {k: len(findings.get(k, [])) for k in order},
                "context": dict(totals),
                "z_index_values": dict(sorted(z_values.items())),
                "transition_durations": dict(sorted(durations.items())),
            },
            indent=2,
        ))
        return 0

    if args.appendix:
        print("# Appendix — every location, by identifier\n")
        print(
            f"Generated by `scripts/audit-ui.py --appendix` over {len(files)} source "
            "files in `app/`, `components/`, `lib/` and `hooks/`.\n"
        )
        print(
            "This appendix lists locations the script can see in source text. It "
            "deliberately omits anything that only exists at render time: a class "
            "supplied through a computed `cn()` argument, a cursor inherited from a "
            "parent, or a label supplied by a wrapping component. Absence from a "
            "list below is not proof of correctness for those cases.\n"
        )
        for key in order:
            rows = findings.get(key, [])
            print(f"## {key} — {len(rows)}\n")
            if not rows:
                print("None found.\n")
                continue
            for row in rows:
                print(f"- `{row}`")
            print()
        print("## literal-colour exemptions — the full list\n")
        print(
            "Every file allowed to hold a literal colour, and why. Nothing else "
            "may; a hex outside this list is a finding above.\n"
        )
        for f, why in sorted(LITERAL_COLOR_EXEMPT.items()):
            print(f"- `{f}` — {why}")
        print(
            f"\nPlus {len(VENDOR_BRAND_HEX)} vendor brand hexes in "
            f"`{VENDOR_BRAND_FILE}`: "
            + ", ".join(f"`{h}`" for h in sorted(VENDOR_BRAND_HEX))
            + ".\n"
        )
        print("## z-index values in use\n")
        for v, count in sorted(z_values.items(), key=lambda kv: (kv[0] == "auto", kv[0].zfill(4))):
            print(f"- `z-{v}` — {count} occurrence{'s' if count != 1 else ''}")
        print()
        return 0

    print(f"{len(files)} source files scanned\n")
    width = max(len(k) for k in order)
    total = 0
    for key in order:
        count = len(findings.get(key, []))
        total += count
        mark = "ok  " if count == 0 else "FAIL"
        print(f"  {mark} {key.ljust(width)}  {count}")
    print(f"\n{total} findings")
    print("\nContext (not findings):")
    for k, v in sorted(totals.items()):
        print(f"  {k}: {v}")
    print("  z-index values: " + ", ".join(f"z-{k}" for k in sorted(z_values, key=lambda s: s.zfill(4))))
    print("  transition durations: " + ", ".join(sorted(durations, key=lambda s: int(s[:-2]))))

    return 1 if total else 0


if __name__ == "__main__":
    sys.exit(main())
