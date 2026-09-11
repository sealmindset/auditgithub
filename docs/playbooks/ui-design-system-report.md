# AuditGH Web UI — Design System Overhaul: Technical Companion

**Date:** 2026-09-11
**Scope:** `src/web-ui` — the AuditGH operator interface. 148 source files in `app/`,
`components/`, `lib/` and `hooks/` (`.tsx`, `.ts`, `.css`).
**Branch:** `deployment-topology-p1-p2`
**Leadership briefing:** `ui-design-system-plain-language.md`
**Generated appendix:** `ui-design-system-appendix.md` — every location by `file:line`, both
before and after, produced by `python3 scripts/report/build_ui_appendix.py`.
**Classification:** internal. Names source files. Contains no secrets and no customer data.

> **This is a completion report, not a proposal.** The work described here has been done and
> is in the working tree. Every figure below is emitted by a committed script and reproduces
> on demand; none of it is typed from recollection. The measurement work was done **without
> driving a browser** — layout behavior is inferred from source constructs, not observed — and
> §8 states what that does and does not license. The application was subsequently opened once,
> which immediately produced two runtime defects that every static check had passed. Those are
> §6a, and they are the evidence for §8 rather than an exception to it.

---

## Reproducing every number in this document

```bash
cd src/web-ui
python3 scripts/audit-ui.py            # checklist audit, 13 checks
python3 scripts/check-contrast.py      # WCAG contrast, both themes
cd ../..
./scripts/report/ui-baseline-compare.sh    # before/after, one ruler, two trees
python3 scripts/report/build_ui_appendix.py
```

`ui-baseline-compare.sh` extracts the tree at a git ref with `git archive`, copies today's
auditors into it, and runs them against both trees. The "before" column is therefore not a
memory of what the code used to look like — it is the same logic and the same thresholds
applied to the old tree.

---

## 1. What is the problem?

### 1.1 There was no design system, only 1,912 individual color decisions

The UI was built from raw Tailwind palette utilities applied per element: `bg-red-500`,
`text-green-600`, `border-slate-200`. The auditor counts **1,912** such utilities across the
baseline tree.

This is not an aesthetic complaint. Three concrete failures follow from it:

1. **The same concept had different colors in different places.** Six files each declared
   their own severity-to-color map, and they disagreed. "Low" was **green** in
   `SecurityReportModal.tsx` (`#16a34a`), `SecurityOverviewWidget.tsx` (`#22c55e`) and
   `FindingTrendsWidget.tsx` (`#22c55e`), and **blue** in `ContributorsView.tsx`
   (`bg-blue-500`) and `app/findings/page.tsx` (`bg-blue-500`, declared twice). Two of the
   three greens were not even the same green. A reader comparing two dashboards was comparing
   two different color languages.
2. **Dark mode was per-element guesswork.** Every element that needed to differ carried its own
   `dark:` variant, so dark mode was correct exactly where someone had remembered to write one.
3. **Contrast was unmeasurable.** With color chosen at 1,912 call sites, there is no set of
   values to test. You cannot prove a claim about a palette that does not exist as a palette.

### 1.2 Thirty-six color declarations were being silently discarded by the browser

The baseline stylesheet authored its tokens in OKLCH — `--background: oklch(1 0 0)` — but
thirty-six consumption sites wrapped them in `hsl()`:

```css
--rbc-today-bg: hsl(var(--accent) / 0.3);
```

`hsl()` cannot parse an OKLCH value. The declaration is invalid, the browser drops it, and the
property falls back to whatever it inherits. This is a live defect, not a style issue: the
scheduler calendar's "today" highlight, off-range day shading and off-range text color were
all producing **no color at all**.

One of the thirty-six referenced `var(--destructive)`, a token that was never declared
anywhere in the stylesheet. The only thing named `destructive` is `--color-destructive:
var(--danger)` inside `@theme inline`, which is a Tailwind alias, not a CSS custom property
available at that call site.

### 1.3 Seventeen emoji were doing the work of icons

`✓`, `✗`, `🔍`, `✅`, `⚠`, `🎯`, `🌐`, `📅`, `📂`, `📁` appeared as interface elements in six
components. Emoji render from the operating system's font, so they change appearance per
platform, cannot inherit `currentColor`, cannot be sized with the icon scale, and are read
aloud by screen readers with their Unicode names ("white heavy check mark") rather than the
meaning intended.

### 1.4 One hundred and three controls had no accessible name

- **46 icon-only buttons.** A button whose only child is an SVG icon has no accessible name.
  To a screen reader it announces as "button" with nothing else. Forty-six of the seventy-two
  icon-only buttons in the baseline tree were in this state.
- **57 form fields.** A field with no `id`, no `aria-label` and no `aria-labelledby` cannot be
  associated with a label, whatever text happens to sit next to it visually. Fifty-seven of
  the one hundred and fourteen text fields were in this state.

### 1.5 Five measured contrast pairs failed, and sixty-eight could not be measured at all

Running the contrast script against the baseline tokens: **34 pairs measurable, 30 enforced,
5 below threshold.** The remaining 68 of the 102 pairs the script checks could not be measured
because **the tokens did not exist**. There was no `--danger-text`, no `--sev-critical-soft`,
no `--warning-line`. Status color was invented at the call site, which is §1.1 restated as a
measurement.

The five measured failures in the baseline:

| Pair | Theme | Measured | Required |
|---|---|---|---|
| `--input` on `--card` | light | 1.26:1 | 3.0 (WCAG 1.4.11) |
| `--input` on `--background` | light | 1.26:1 | 3.0 |
| `--ring` on `--background` | light | 2.59:1 | 3.0 |
| `--ring` on `--card` | light | 2.59:1 | 3.0 |
| `--muted-foreground` on `--muted` | light | 4.34:1 | 4.5 (WCAG AA) |

A focus ring at 2.59:1 is the sharpest of these: keyboard users navigate by the ring, and in
light mode it was below the threshold at which a non-text indicator is reliably visible.

> **Caveat on the baseline dark figures.** The baseline dark theme declared
> `--border: oklch(1 0 0 / 10%)` — an alpha channel the contrast script does not composite. It
> reads that token as opaque white and reports 14.22:1 for `--input` on `--card` in dark mode.
> That number is wrong and is not used anywhere in this report. The correct statement is that
> the baseline dark border/input contrast **was not measured**, because measuring it requires
> alpha compositing the script does not do. Closing that gap requires no privilege or access —
> only extending `check-contrast.py` to composite `oklch(... / a)` against its background.

### 1.6 Fifteen layout constructs could not fit a 375px viewport

- **13 multi-column grids** with no responsive breakpoint — `grid-cols-4`, `grid-cols-5`,
  `grid-cols-6`, two at `grid-cols-12`. At 375px a `grid-cols-6` gives each cell 58px before
  padding.
- **2 fixed pixel widths at or above 375px** — a 420px dialog and a 500px sheet, neither with
  a smaller variant below the `sm` breakpoint.

Separately, **1 transition sat outside the 150–300ms band** — a 500ms `transition-all`. That
is motion, not layout, and is counted as its own check.

### 1.7 Two clickable elements with no pointer cursor

`components/data-table-advanced-filter.tsx:344` and
`components/data-table-column-header.tsx:562` — `<div>` elements carrying `onClick` with no
`cursor-` class. Nothing on screen indicated they could be clicked.

### 1.8 Five source modules were not in version control

Found while measuring the baseline, not while looking for it. Against the baseline commit,
`git archive e8b2899 src/web-ui/lib` fails with `pathspec 'src/web-ui/lib' did not match any
files`, and `git ls-tree -r --name-only e8b2899 -- src/web-ui/lib` returns nothing. The same
`ls-tree` against `HEAD` now returns all five paths, because the fix in §3 tracked them; the
baseline ref is what reproduces the finding.

> Use `git ls-tree`, not `git ls-files`, to ask this question. `git ls-files` reads the index
> and ignores a commit argument, so `git ls-files e8b2899 -- src/web-ui/lib` reports five
> files at the baseline too — a false negative for this finding.

The cause is a Python packaging block in the repository root `.gitignore`:

```
lib/
lib64/
```

Those two lines come from the standard Python `.gitignore` template, where `lib/` is a build
output. In this repository the pattern also matches `src/web-ui/lib/`, the Next.js source
directory. Five TypeScript modules were therefore untracked:

| File | What it holds |
|---|---|
| `lib/utils.ts` | `cn()` — the class-merge helper imported by essentially every component |
| `lib/api.ts` | `API_BASE` and `apiFetch` — the HTTP layer |
| `lib/rbac.ts` | Role and permission checks |
| `lib/severity.ts` | `SEVERITY_TONE`, `STATUS_TONE`, `normalizeSeverity` |
| `lib/chart.ts` | Chart palette and `CRITICAL_RANK_RAMP` |

A fresh clone of this repository does not build. These files exist only on the machines that
happen to have them.

**Fixed in this change.** A negation cannot reach inside an ignored directory, so the
directory itself is un-ignored, immediately after the Python block that caused it:

```
!src/web-ui/lib/
```

Verified with `git check-ignore -v src/web-ui/lib/severity.ts`, which now matches nothing.
The five files are staged as new because git is seeing them for the first time — their
content is not new, and their history starts here rather than being recoverable.

---

## 2. Where is the problem?

Every location is in the generated appendix, `ui-design-system-appendix.md`, §C, by
`file:line` as it stood before the change. The summary, produced by the same auditor against
both trees:

| Check | Before | After |
|---|---:|---:|
| `raw-palette-class` | 1912 | 0 |
| `literal-color-in-source` | 115 | 0 |
| `hsl-wrapping-oklch` | 36 | 0 |
| `canvas-color-without-resolver` | 27 | 0 |
| `emoji-in-source` | 17 | 0 |
| `absolute-white-or-black` | 56 | 0 |
| `clickable-without-pointer-cursor` | 2 | 0 |
| `icon-button-without-name` | 46 | 0 |
| `image-without-alt` | 0 | 0 |
| `field-without-label-hook` | 57 | 0 |
| `fixed-width-over-375px` | 2 | 0 |
| `multi-col-grid-no-breakpoint` | 13 | 0 |
| `transition-outside-150-300ms` | 1 | 0 |
| **Total findings** | **2284** | **0** |

> **One row in that table is not a defect count, and is marked as such rather than quietly
> included.** `canvas-color-without-resolver` is an invariant check, added after the browser
> errors described in §6a. The 27 baseline rows are `ThreatRadar` canvas calls that used hex
> literals — which *work* on a canvas. They are findings under the rule as it now stands, not
> faults that were live in the baseline tree. The other twelve rows are counts of things that
> were wrong at the time. Subtracting this row, the comparable baseline total is **2,257**.

| Contrast | Before | After |
|---|---|---|
| Pairs measurable | 34 of 102 | 102 of 102 |
| Pairs enforced | 30 | 94 |
| Pairs below threshold | 5 | 0 |

Source file count moved from 139 to 148. Four of the nine are new UI primitives (§3.5). The
other five are `src/web-ui/lib/` — `utils.ts`, `api.ts`, `rbac.ts`, `severity.ts`,
`chart.ts` — which are not new files at all. They are **files git has never tracked**; see
§1.8.

`image-without-alt` was already zero at baseline. It is listed because a check that has never
failed is still evidence, and dropping the row would make the table look like a list of things
that were wrong rather than a list of things that were tested.

---

## 3. How do we address the problem?

### 3.1 A token file with five roles per color family

`app/globals.css` grew from 137 lines to 611 and is now the single source of truth. **88 color
tokens per theme, declared in both themes — no token inherits across the light/dark boundary
by accident.**

Every semantic color family provides five roles:

| Role | Token | Used for |
|---|---|---|
| Fill | `--danger` | Solid button, filled badge, chart series |
| On-fill text | `--danger-foreground` | Text drawn on that fill |
| Tinted surface | `--danger-soft` | Badge background, callout panel |
| Border | `--danger-line` | Edge of a soft surface |
| On-canvas text | `--danger-text` | Colored text on the page background |

This split is what makes contrast testable. `--danger-foreground` is only ever drawn on
`--danger`; `--danger-text` is only ever drawn on `--background` or `--danger-soft`. The pair
list in `check-contrast.py` encodes those intentions, because the relationship is a design
decision and is not derivable from the CSS.

Severity is a first-class family separate from status tone: `--sev-critical`, `--sev-high`,
`--sev-medium`, `--sev-low`, `--sev-info`, each with the same five roles. A finding's severity
and a UI element's status are different concepts and no longer share a color vocabulary.

Colors are authored in OKLCH. Light and dark share a hue and differ in lightness and chroma,
so dark mode is a re-balance rather than an inversion:

```css
/* light */ --chart-1: oklch(0.55 0.19 267);
/* dark  */ --chart-1: oklch(0.66 0.17 267);
```

### 3.2 Six token values moved to clear WCAG, each carrying its measurement

The corrections are recorded in `globals.css` as comments next to the value, so the next
person to change one can see what the old value measured:

| Token | Theme | Was | Now | Before | After |
|---|---|---|---|---|---|
| `--sev-high-foreground` | light | white-ish text | `oklch(0.22 0.05 48)` | 3.22:1 | 5.24:1 |
| `--sev-low` | light | `oklch(0.61 …)` | `oklch(0.52 0.14 235)` | 3.56:1 | 5.06:1 |
| `--sev-info` | light | `oklch(0.6 …)` | `oklch(0.52 0.025 264)` | 3.84:1 | 5.36:1 |
| `--sev-critical` | dark | `oklch(0.6 …)` | `oklch(0.55 0.23 25)` | 4.28:1 | 5.16:1 |
| `--input` | light | `oklch(0.895 …)` | `oklch(0.64 0.008 264)` | 1.37:1 | 3.36:1 card / 3.22:1 canvas |
| `--input` | dark | `oklch(0.335 …)` | `oklch(0.52 0.016 264)` | 1.66:1 | 3.25:1 card / 3.50:1 canvas |

Current measured extremes, both themes, all 94 enforced pairs passing:

| | Light | Dark |
|---|---|---|
| Body text on canvas | 16.98:1 | 16.90:1 |
| Body text on card | 17.73:1 | 15.72:1 |
| Lowest enforced text pair (min 4.5) | 5.06:1 | 5.16:1 |
| Lowest enforced boundary (min 3.0) | 3.22:1 | 3.25:1 |

### 3.3 Which boundaries are enforced at 3:1, and which are measured but not enforced

WCAG 1.4.11 governs "visual information required to identify user interface components and
states". That phrase decides the threshold, and the two cases are genuinely different:

- **A text field's edge is the only thing that says it is a text field.** Take the edge away
  and there is nothing on screen identifying the control. `--input` and `--ring` are therefore
  enforced at 3:1 against **both** surfaces they are drawn on, card and canvas. Meeting this
  is what forced the `--input` moves in §3.2 — light 0.895 → 0.64 and dark 0.335 → 0.52 are
  large changes, and they are the honest cost of the rule.
- **A divider between two containers identifies nothing.** A card is a card because of its
  content; removing the hairline costs grouping, not meaning. 1.4.11 does not reach that case,
  and forcing `--border` to 3:1 would draw every panel edge in mid-grey.

So `--border` and `--border-strong` are **measured and printed but not enforced**, at 1.24:1
to 1.88:1 across the four combinations. They are reported rather than quietly dropped from the
pair list, because a threshold you remove silently is a threshold you have lowered. The
reasoning is written into `check-contrast.py` next to the list, not just here.

The script's footer states the split explicitly: `102 pairs measured, 94 enforced, 0 below
threshold`.

### 3.4 `hsl(var(--oklch))` replaced with `color-mix(in oklab, …)`

All 36 sites, across 3 files — `app/scheduler/calendar.css` (32),
`components/ui/sidebar.tsx` (2), `components/dashboard/FindingTrendsWidget.tsx` (2):

```css
/* was: dropped by the browser */
--rbc-today-bg: hsl(var(--accent) / 0.3);
/* now */
--rbc-today-bg: color-mix(in oklab, var(--accent) 30%, transparent);
```

`color-mix` is the OKLCH-safe way to express "this color at partial strength". Where the site
was a border drawn with a dropped shadow value, the fix was a real token reference:
`shadow-[0_0_0_1px_var(--sidebar-border)]`. The undeclared `var(--destructive)` was repointed
at `var(--danger)`, which is the token `--color-destructive` aliases anyway.

### 3.5 Four new primitives, so the pattern is cheaper than the exception

| File | Lines | Replaces |
|---|---:|---|
| `components/ui/page-header.tsx` | 143 | Per-page title/description/back-link markup |
| `components/ui/stat-card.tsx` | 154 | Per-dashboard metric tiles, including trend arrows and skeletons |
| `components/ui/severity-badge.tsx` | 152 | Per-view severity pills, each with its own color map |
| `components/ui/empty-state.tsx` | 110 | Ad-hoc "no results" blocks |

`lib/severity.ts` holds `SEVERITY_TONE`, `STATUS_TONE` and `normalizeSeverity`, so severity
naming is resolved once. `lib/chart.ts` routes every Recharts series through
`severityColor()` / `categoricalColor()`, which return `var(--token)` strings — Recharts hands
them to SVG attributes, so charts re-color on a theme switch instead of staying stuck in
whichever mode they were first painted in.

**Color is no longer the only indicator.** `severity-badge.tsx` pairs each tone with a
distinct Lucide icon (`AlertOctagon`, `AlertTriangle`, `Info`, `ShieldAlert`, `ShieldCheck`),
so severity survives a greyscale print and a red/green color vision deficiency.

### 3.6 The documented exceptions — literal color that is allowed, and why

A blanket "no literal color" rule would be false, so the auditor carries two allowlists and
counts what they exempt. **109 literal-color occurrences are exempt across 5 files, plus 14
vendor brand hexes in 1 file. Everything else is 0.**

| File | Occurrences | Why it is allowed |
|---|---:|---|
| `components/SecurityReportModal.tsx` | 61 | Builds a standalone HTML/PDF document that leaves the app. The export carries no stylesheet, so `var()` resolves to nothing. |
| `components/dashboard/ThreatRadar.tsx` | 24 | A canvas-drawn instrument display. `ctx.fillStyle` takes a resolved string, and a radar scope that turns white in light mode stops reading as a radar scope. Severity colors are the exception to the exception: they stay tokens and are resolved at the canvas boundary by `resolveCanvasColor`, because the same value is also emitted into the DOM legend. |
| `lib/chart.ts` | 20 | `CRITICAL_RANK_RAMP` — a ten-step rank ramp. Five severity tokens cannot express ten ranks, and the ramp must not flip lightness with the theme. |
| `components/DownloadControl.tsx` | 2 | Exported spreadsheet/HTML template, same reason as the report modal. |
| `app/layout.tsx` | 2 | `theme-color` meta. The browser paints it before any stylesheet loads. |
| `app/attack-surface/page.tsx` | 14 | Vendor brand marks: AWS orange, Slack aubergine, Docker blue and eight others. Re-theming a brand makes it wrong, not consistent. |

Each exception carries its reasoning in the source file, not only here. Two entries in the
secret-type legend were deliberately **removed** from the brand list: GitHub and JWT are both
near-black brands, which disappeared against the dark-mode canvas, so they follow
`--foreground` and flip with the theme.

`app/layout.tsx`'s two hexes are derived rather than chosen: `#f9fafc` and `#0c0e14` are
`--background` converted to sRGB, and the comment names `check-contrast.py`'s `oklch_to_srgb`
as the way to re-derive them if the token moves.

### 3.7 Accessible names: 107 added across 40 files

Measured as the difference between the baseline tree and the working tree:
`aria-label` occurrences went from **7 to 114**. Four of those are in the new primitives; the
remaining 103 were added to pre-existing files. Each name was taken from the adjacent `<Label>`
text or the field's placeholder, not invented — "Inactivity timeout in minutes", "Search
repositories", "Previous month", "Remove tag", "Copy API key".

The auditor's test is deliberately not `size="icon"`, which caught only 16 of the real cases.
It is *having no text child*, which required resolving what actually renders: a string literal
inside a ternary (`{saving ? "Saving" : "Save"}`) names its control; a bare variable
(`{label}`) cannot be resolved from source and is reported for a human to clear. Text either
side of an interpolation counts (`View All ({n})`). Prose is recognised by a punctuation
blacklist rather than an alphabet allowlist, so a label containing an arrow — `Sort A→Z` — is
not mistaken for code.

### 3.8 Layout and motion

- **13 grids** given breakpoints. Content grids go to one or two columns at 375px and step up
  at `sm`/`lg`: `grid-cols-1 … sm:grid-cols-3`, `grid-cols-2 … lg:grid-cols-4`. Three of the
  thirteen are tab rails, which take `h-auto` because `tabsListVariants`' segmented variant
  carries a fixed `h-9` that a wrapped two-row rail would clip.
- **2 fixed widths** made responsive: `w-[500px]` → `w-full sm:w-[500px] sm:max-w-[500px]`.
- **The WAF drift table** (two `grid-cols-12` rows) now scrolls inside its own card —
  `overflow-x-auto` on a wrapper with `min-w-[52rem]` on the grid — rather than pushing the
  whole page sideways. Six columns of rule comparison do not compress below ~52rem without
  clipping, so containing the scroll is the fix; collapsing the columns is not.
- **Transitions** are now 150ms, 200ms or 300ms and nothing else.
- **z-index** is now z-10 / z-20 / z-30 / z-50 and nothing else. The baseline had no z-30 tier,
  which is why overlay stacking was being resolved by source order.
- **`prefers-reduced-motion`** is honored globally in `globals.css`, in one block, rather than
  per component.

### 3.9 The two false positives, and what was done instead

Both `clickable-without-pointer-cursor` findings turned out to be
`onClick={e => e.stopPropagation()}` wrappers — elements that exist so clicking a child does
not also toggle the parent. They are not controls, and giving them a pointer cursor would
advertise an interaction that is not there. The auditor was taught to recognise
suppressor-only handlers and count them separately (`click-suppressor: 2`) rather than
silencing them.

A third suspected finding — a `<table>` in `DownloadControl.tsx` with no overflow ancestor —
was disproved: lines 119 and 136 are inside a template string that builds HTML for export, not
JSX. No change was made.

---

## 4. What keeps this from decaying

Three committed scripts, all runnable in CI, all exiting non-zero on failure:

| Script | What it enforces |
|---|---|
| `src/web-ui/scripts/check-contrast.py` | Every declared token pair meets its WCAG threshold, in both themes. Exits 1 on any enforced failure. |
| `src/web-ui/scripts/audit-ui.py` | Twelve checklist rules over source text. Exits 1 on any finding. |
| `src/web-ui/scripts/tokenize-colors.py` | The codemod that performed the palette-to-token conversion, kept so the mapping is inspectable rather than folded into a diff. |

`check-contrast.py` mirrors CSS cascade semantics before measuring: `.dark` overrides only what
it redeclares, so the dark theme map is built as `{**light, **dark}`. Without that, any token
the dark block legitimately inherits reads as missing.

---

## 5. Verification performed

| Gate | Result |
|---|---|
| `python3 scripts/audit-ui.py` | 148 files, 13 checks, **0 findings**, exit 0 |
| `python3 scripts/check-contrast.py` | **102 pairs measured, 94 enforced, 0 below threshold**, exit 0, no missing tokens |
| `npx tsc --noEmit` | clean |
| `npx next build` | green, all routes compiled |

Change size: **100 tracked files changed, 3,124 insertions, 2,340 deletions**, plus 12 files
git has not seen before — 4 new UI primitives, 3 new audit scripts, and the 5 modules in
`src/web-ui/lib/` that were untracked all along (§1.8). One modified `.gitignore`.

---

## 6. What was deliberately not changed

- **Component APIs.** No prop was renamed or removed. The diff is color, markup attributes and
  layout classes.
- **The dark-mode default.** Theme selection behavior is unchanged.
- **The export templates.** `SecurityReportModal` and `DownloadControl` produce documents that
  leave the app and must not depend on the app's stylesheet. Their literal colors are exempt,
  not overlooked — but they are also now the only place where an exported report's appearance
  can drift from the product's, which is a known and accepted seam.
- **`ThreatRadar`'s palette.** Documented as an instrument display in the file header.

---

## 6a. Two defects the static checks missed, found by running the application

This section exists because it is the counter-example to everything above. After the work in
§1–§5 was complete and the auditor reported **0 findings**, the application was opened in a
browser and threw two errors on the dashboard. Both were introduced by this change. Neither
was visible to `tsc --noEmit`, to `next build`, or to any of the twelve checks in place at
the time.

**Defect 1 — duplicate React key in the sidebar.** `components/app-sidebar.tsx:277` keyed the
navigation group map on `group.url`. All three groups carry `url: "#"` as a placeholder
(lines 78, 126, 159), so all three keys were `#`:

```
Encountered two children with the same key, `#`.
```

Fixed by keying on `group.title`, which is unique across the three groups. Every other key in
the file already used `title`; this one did not.

**Defect 2 — CSS custom properties handed to a canvas.** `ThreatRadar` was tokenized along
with everything else, but a canvas 2D context does not resolve `var()`. The symptom seen in
the browser:

```
SyntaxError: The string did not match the expected pattern.
    at addColorStop
    at ThreatRadar.useCallback[draw] (components/dashboard/ThreatRadar.tsx:681)
```

The trace names one line. The actual scope was **thirteen call sites**: four threw, because
they concatenated a hex alpha suffix onto the token string (`` `${glowColor}50` ``), and nine
failed *silently*, because `ctx.fillStyle = "var(--sev-low)"` is ignored and the context keeps
whatever color it last held. The tokens reached the canvas indirectly, through
`THREAT_TYPES[].color` → blip → missile → explosion → center impact, which is why the count is
larger than the trace suggests.

Reverting to hex literals was rejected: the same values are also rendered into the DOM legend
below the canvas, where `var()` is correct. Instead every canvas color now passes through
`resolveCanvasColor`, which resolves a token via a detached probe element and caches per theme,
and `withCanvasAlpha`, which replaces the hex-suffix concatenation with `rgba()`.

**What now prevents recurrence.** A thirteenth check, `canvas-color-without-resolver`. It does
not try to detect "a token reached a canvas" — that is not decidable line-by-line when the
value arrives through a variable. It inverts the requirement instead: every color handed to
`fillStyle`, `strokeStyle`, `shadowColor` or `addColorStop` must go through the resolver, which
returns non-token values unchanged. Run against the tree as committed in `0d05aa6`, the check
reports **27 findings**; against the current tree, **0**.

**What this says about §8.** The coverage limit stated there was not a formality. Driving the
application found two real defects in a tree that twelve static checks, a type check and a
production build all called clean — within minutes of opening it. Residual item 1 below is the generalization of this paragraph, and the two errors here
are the evidence for its priority.

---

## 7. Residual work

| # | Item | Why it is open | What closes it |
|---|---|---|---|
| 1 | Browser verification at 375 / 768 / 1024 / 1440px | No browser was driven in this work. See §8. | A Playwright run over the route list, or a person with the app running locally. Requires a running backend or a fixture set; no privilege is needed beyond the ability to start the dev server. |
| 2 | Alpha compositing in `check-contrast.py` | Tokens written `oklch(L C h / a)` are read as opaque. No current token uses alpha, so nothing is mis-measured today — but the guard is absent. | Extend `oklch_to_srgb` to composite against a named backdrop. No access required. |
| 3 | Screen-reader pass | The auditor proves a name **exists**. It cannot prove the name is the *right* name, or that reading order matches visual order. | A manual VoiceOver/NVDA pass over the primary flows. No privilege required. |
| 4 | Touch-target sizing (44×44px) | Not implemented as a check. Size arrives through `cn()` and variant composition, which the source-text auditor cannot resolve. | A rendered-DOM measurement, which is the same Playwright dependency as item 1. |
| 5 | Export-template drift | The two export templates now carry the only copy of "what a report looks like". | Either generate the export CSS from the token file, or accept the seam and review it when the palette changes. A decision, not a task. |

---

## 8. Coverage limits — what this report does not claim

**No browser was driven.** Everything in this document was measured by reading source text and
the token file. That is a real limit with a precise shape:

- The auditor **can** prove there is no fixed pixel width at or above 375px, and no
  multi-column grid without a breakpoint. It **cannot** prove a page does not overflow at
  375px — only that the constructs that most commonly cause overflow are absent.
- The auditor **can** prove every icon-only button has an accessible name. It **cannot** prove
  the name is accurate or that tab order matches visual order.
- The contrast script **can** prove the declared tokens meet their thresholds. It **cannot**
  prove a component uses the token the pair list assumes it uses, if that class arrives through
  a computed `cn()` argument.
- The auditor reads source text. A class supplied at runtime, a cursor inherited from a parent,
  or a label supplied by a wrapping component is invisible to it. **Absence from a finding list
  is not proof of correctness for those cases.**

"No findings" therefore means "no findings the committed auditors can see". It does not mean
"no defects". The two are different claims and this report only makes the first.

None of these gaps is blocked by access or privilege. Every one of them is closed by running
the application in a browser — which requires the ability to start the local dev server and a
backend or fixture set to point it at, and nothing more.
