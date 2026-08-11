#!/usr/bin/env python3
"""Generate the named appendix for the plain-language briefing and its deck.

The briefing itself is deliberately free of repository names - the audience does not
read them and they crowd out the argument. But "94 projects" is unactionable to the
person who has to go and fix 94 projects, and unverifiable to anyone who wants to
check us. So the names live here, generated from the same artifacts the report reads
rather than typed out, because a hand-copied list of 94 repositories is a list that is
wrong within a month.

Long lists are emitted as two-column tables in chunks. That is not cosmetic: pandoc
gives a table its own pptx slide, so chunking is what keeps the appendix readable as
slides and as a PDF section from one source.

    python3 scripts/report/build_appendix.py

Writes docs/playbooks/npm-supply-chain-exposure-appendix.md.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterable, Sequence

ROOT = Path(__file__).resolve().parents[2]
HUNT = ROOT / "exports" / "hunt"
OUT = ROOT / "docs" / "playbooks" / "npm-supply-chain-exposure-appendix.md"

# Rows per appendix slide. Two columns per row, so this is half the names on a slide.
# Tuned so the tallest table still fits one Letter-landscape page at the deck's font size:
# a table that overflows does not scroll, it silently loses its heading and clips a row.
CHUNK = 11
# Rows per slide for the wider tables, which carry long paths. Lower than CHUNK because
# a wrapped path costs two lines, and a table that runs past the page loses rows silently.
WIDE_CHUNK = 8


def paginate(items: Sequence, per_page: int) -> list[list]:
    """Split into the fewest pages that respect per_page, then even them out.

    Straight chunking leaves orphans - twelve rows at eleven per page gives a page of
    eleven and a page of one, which reads as an error rather than a continuation.
    """
    pages = max(1, -(-len(items) // per_page))
    base, extra = divmod(len(items), pages)
    out, start = [], 0
    for index in range(pages):
        size = base + (1 if index < extra else 0)
        out.append(list(items[start : start + size]))
        start += size
    return out


def short(name: str) -> str:
    """Compact a sink for display: the org prefix is constant, and `.github/workflows/`
    is noise once the prose has said where these files live. Keeps repo, file and ref,
    which is everything needed to find it."""
    return name.replace("SleepNumberInc/", "").replace("/.github/workflows/", " › ")


def read(name: str) -> dict:
    with (HUNT / name).open() as handle:
        return json.load(handle)


def two_column(items: Sequence[str], title: str, note: str = "") -> list[str]:
    """Emit a long list as chunked two-column tables, one heading per chunk.

    Each chunk gets its own `##` so it becomes its own slide; without that the deck
    ends up with one slide holding ninety-four rows that nobody can read.
    """
    lines: list[str] = []
    rows = [items[i : i + 2] for i in range(0, len(items), 2)]
    pages = paginate(rows, CHUNK)
    for index, page in enumerate(pages, start=1):
        suffix = f" ({index} of {len(pages)})" if len(pages) > 1 else ""
        lines.append(f"## {title}{suffix}")
        lines.append("")
        if note and index == 1:
            lines.append(note)
            lines.append("")
        lines.append("| | |")
        lines.append("|---|---|")
        for row in page:
            left = f"`{row[0]}`"
            right = f"`{row[1]}`" if len(row) > 1 else ""
            lines.append(f"| {left} | {right} |")
        lines.append("")
    return lines


def table(header: Sequence[str], rows: Iterable[Sequence[str]], title: str,
          note: str = "", chunk: int = WIDE_CHUNK) -> list[str]:
    """Emit a table, split across as many headings as it takes to fit a page.

    Alignment is declared in the markdown rather than the stylesheet: the first column
    is a name and the rest are counts, and a stylesheet rule keyed on column position
    would right-align the name column of the two-column lists too.

    The note rides on the first chunk only; repeating it on every continuation would
    read as a new claim each time.
    """
    materialised = [list(row) for row in rows]
    pages = paginate(materialised, chunk)
    lines: list[str] = []
    for index, page in enumerate(pages, start=1):
        suffix = f" ({index} of {len(pages)})" if len(pages) > 1 else ""
        lines += [f"## {title}{suffix}", ""]
        if note and index == 1:
            lines += [note, ""]
        lines.append("| " + " | ".join(header) + " |")
        lines.append("|" + "|".join(["---"] + ["---:"] * (len(header) - 1)) + "|")
        for row in page:
            lines.append("| " + " | ".join(str(cell) for cell in row) + " |")
        lines.append("")
    return lines


def main() -> None:
    install = read("install_prevention_r1.json")
    posture = read("actions_posture_r5_coverage.json")
    reusable = read("reusable_workflow_targets.json")
    feeds = read("azure_artifacts_feeds_r2.json")

    repos = install["repositories"]
    bulk = [row for row in reusable["rows"] if row.get("secrets_bulk_exposure")]
    bulk.sort(key=lambda row: -(row.get("consumer_count") or 0))

    # No YAML front matter on purpose: this file is concatenated onto the briefing and onto
    # the deck, and a second metadata block would fight the first one's title. The H1 gives
    # the briefing a page divider and the deck a section-break slide from the same line.
    out: list[str] = [
        "# Appendix — the specific names",
        "",
        "## How to read this appendix",
        "",
        "The briefing deliberately uses counts rather than names — the names crowd out the",
        "argument for a reader who does not own any of these repositories.",
        "",
        "This appendix is the other half: **every count in the briefing, resolved to the",
        "things a team would actually open and change.** It is generated from the same",
        "collector artifacts the technical report reads, not typed by hand, so it cannot",
        "drift from them.",
        "",
        "Anything listed here is something we read directly. Where a population could not",
        "be read at all, it is named at the end as a gap rather than left out.",
        "",
    ]

    # --- Problem 1: the whole keyring -------------------------------------------------
    # Three different things receive the whole secrets context, and they are not fixed the
    # same way, so they are not counted together. A composite action is handed the object
    # explicitly with toJSON(secrets); a called workflow gets it implicitly with
    # `secrets: inherit`; an inline shell step expands it into the runner's own shell.
    # Rolling them into one number hides which change a team is supposed to make.
    def classify(sink: str) -> str:
        if "/.github/workflows/" in sink:
            return "called_workflow"
        if "@" in sink:
            return "composite_action"
        return "inline_shell_step"

    sinks: dict[str, dict[str, dict]] = {
        "composite_action": {}, "called_workflow": {}, "inline_shell_step": {},
    }
    for row in bulk:
        for exposure in row["secrets_bulk_exposure"]:
            sink = exposure["sink"]
            entry = sinks[classify(sink)].setdefault(
                sink, {"refs": 0, "workflows": 0, "deploys": False, "mechanism": set()}
            )
            entry["refs"] += row.get("consumer_count") or 0
            entry["workflows"] += 1
            entry["deploys"] = entry["deploys"] or bool(row.get("is_deploying"))
            entry["mechanism"].add(exposure.get("mechanism"))

    def sink_rows(kind: str) -> list[list[str]]:
        return [
            [
                f"`{short(name)}`",
                f"**{data['refs']:,}**",
                data["workflows"],
                "yes" if data["deploys"] else "—",
            ]
            for name, data in sorted(sinks[kind].items(), key=lambda item: -item[1]["refs"])
        ]

    def total(kind: str) -> int:
        return sum(data["refs"] for data in sinks[kind].values())

    moving = {
        name: data for name, data in sinks["composite_action"].items()
        if len(name.split("@")[-1]) < 40  # a 40-char ref is a commit SHA, not a moving name
    }
    out += table(
        ["Build component handed every secret", "Pipeline refs", "Shared workflows", "Deploys"],
        sink_rows("composite_action"),
        "Problem 1a — build components handed the whole keyring",
        f"**{len(sinks['composite_action'])}** components are passed `toJSON(secrets)` — the "
        f"complete secrets object — across **{total('composite_action'):,}** pipeline references. "
        f"**{len(moving)}** of them are tracked by a moving name rather than an exact version, "
        f"covering **{sum(d['refs'] for d in moving.values()):,}** of those references. The one "
        "pinned to a long commit reference is safer against tampering but still receives "
        "everything.",
    )

    out += table(
        ["Shared process handed every secret", "Pipeline refs", "Callers", "Deploys"],
        sink_rows("called_workflow"),
        "Problem 1b — shared processes handed the whole keyring",
        f"A second mechanism, and a separate fix: **{len(sinks['called_workflow'])}** shared "
        f"processes are called with `secrets: inherit`, which passes everything the caller holds "
        f"without naming any of it. **{total('called_workflow'):,}** pipeline references. Almost "
        "all of these deploy.",
    )

    out += table(
        ["Step that expands secrets into the build shell", "Pipeline refs", "Deploys"],
        [[row[0], row[1], row[3]] for row in sink_rows("inline_shell_step")],
        "Problem 1c — steps that print the keyring into the shell",
        f"**{len(sinks['inline_shell_step'])}** steps expand the whole secrets object into the "
        f"runner's own command line in order to read the *names* off it — "
        f"**{total('inline_shell_step'):,}** pipeline references. Reading names never requires "
        "handling values, so this one is a rewrite rather than a narrowing.",
    )

    out += [
        "## Problem 1 — where the change lands",
        "",
        "Three mechanisms, three different edits. All of them live in",
        "`.github/workflows/<name>.yaml` in the shared repository, not in the consumers.",
        "For 1a and 1b there is a second step: pin the target to a commit reference instead of",
        "`@v1` / `@v2`, and turn on tag protection in the target's own repository so the name",
        "cannot be moved.",
        "",
        "| Mechanism | What to look for | What to replace it with |",
        "|---|---|---|",
        "| **1a** | `${{ toJSON(secrets) }}` in a `with:` block | the specific secrets that step reads, named one per line |",
        "| **1b** | `secrets: inherit` under a `uses:` call | a `secrets:` block naming only what the called process needs |",
        "| **1c** | `toJSON(secrets)` inside a `run:` script | an approach that lists secret names without expanding their values |",
        "",
    ]

    # --- The 46 definitions -----------------------------------------------------------
    out += table(
        ["Shared workflow", "Ref", "Consumers", "Deploys"],
        [
            [
                f"`{short(row['source_repo'] + '/' + row['workflow_path'])}`",
                f"`{row.get('ref') or '—'}`",
                f"**{row.get('consumer_count') or 0:,}**",
                "yes" if row.get("is_deploying") else "—",
            ]
            for row in bulk[:16]
        ],
        "Problem 1 — the shared workflows that pass it onward (largest of 46)",
        f"**{len(bulk)}** definitions pass the whole secrets context to whatever called them, "
        f"reaching **{sum(r.get('consumer_count') or 0 for r in bulk):,}** consumer references. "
        f"**{sum(1 for r in bulk if r.get('is_deploying'))}** of them deploy. The full 46 are in "
        "`exports/hunt/reusable_workflow_targets.json`; these are the largest.",
    )

    remainder = [f"{row['source_repo'].split('/')[-1]}@{row.get('ref') or '?'}" for row in bulk[16:]]
    out += two_column(
        remainder,
        "Problem 1 — the remaining shared workflows",
        "The other 30 definitions, each passing the whole secrets context onward. Smaller "
        "consumer counts, same mechanism.",
    )

    # --- Problem 2: install scripts ---------------------------------------------------
    enabled = sorted(repos["installs_with_scripts_enabled"])
    out += two_column(
        enabled,
        "Problem 2 — projects that run supplier code on sight",
        f"All **{len(enabled)}** of them. Each needs `--ignore-scripts` on its install command, "
        "or `ignore-scripts=true` in an `.npmrc` committed at the repository root.",
    )

    protected = sorted(repos["prevented_in_every_installing_workflow"] + repos["prevented_by_config"])
    out += table(
        ["Repository", "How it is protected"],
        [
            [
                f"`{name}`",
                "`.npmrc` config" if name in repos["prevented_by_config"] else "every installing workflow",
            ]
            for name in protected
        ],
        "Problem 2 — the projects that already refuse",
        f"**{len(protected)}** repositories are already protected, covering "
        f"**{install['counts']['Of those, refusing lifecycle scripts at every install']}** "
        "workflows. They are the pattern to copy — the change is already written and reviewed "
        "inside our own estate.",
    )

    out += [
        "## Problem 2 — where the change lands",
        "",
        "- **In a workflow:** `.github/workflows/<name>.yml` — add `--ignore-scripts` to the",
        "  `npm ci` / `npm install` / `yarn` / `pnpm` line",
        "- **Or, better, once per repository:** create `.npmrc` at the repository root",
        "  containing `ignore-scripts=true`, which covers every install including a",
        "  developer's laptop",
        "",
        "The second form is preferred: it is one file, it is reviewable, and it protects the",
        "surface the first form does not.",
        "",
    ]

    # --- Problem 3: dangling refs -----------------------------------------------------
    dangling = [
        "initi", "use-environment", "add-copilot-blocker", "feat/extra-node-ca-cert",
        "update-to-node-24-actions", "multipe-primary-image-versions",
        "update-provider-inputs", "dependabot-fixes",
    ]
    out += table(
        ["Branch name being called", "Status"],
        [[f"`{name}`", "deleted — claimable"] for name in dangling],
        "Problem 3 — the vacant addresses",
        "**9 references across 12 consumer calls** point at these branch names in central "
        "workflow repositories. The repositories exist; the branches were verified deleted. "
        "Two names carry more than one reference, which is why nine references map to eight "
        "distinct names.",
    )

    out += [
        "## Problem 3 — who is calling them, and what to do",
        "",
        "**Consumers that are not sandboxes** — these break today and are the escalation path:",
        "",
        "- `SleepNumberInc/snip-iics-mft-ops`",
        "- `SleepNumberInc/dot-env-to-env-var-action`",
        "- `SleepNumberInc/eslint-config-azure-integrations`",
        "",
        "The rest are sandbox and proof-of-concept repositories (`cldsvcs-test-*`,",
        "`devops-sandbox-*`, `ss_gh_poc`, `chads-github-actions-playground`).",
        "",
        "**Two more are ordinary breakage rather than risk:** `snip-iics-mft-ops` calls",
        "`iics_cd_workflow.yaml@main` where the file is now `iics_cd.yaml`, and two repos call",
        "`pr_lint.yml@v1` where the file is `pr_lint.yaml`.",
        "",
        "**The fix has two halves, and both are required.** Repoint the `uses:` line at a commit",
        "SHA on a branch that exists — then add a branch protection rule in the *central*",
        "repository matching each deleted name, and restrict branch creation to maintainers.",
        "Repointing alone leaves the door shut but unlocked.",
        "",
    ]

    # --- Problem 4: unpinned ----------------------------------------------------------
    unpinned = posture["most_common_unpinned_third_party_actions"][:12]
    out += table(
        ["Outside component tracked on a moving name", "References"],
        [[f"`{name}`", f"**{count:,}**"] for name, count in unpinned],
        "Problem 4 — the most-referenced moving targets",
        f"**{posture['counts']['action_refs_on_mutable_refs']:,}** references sit on a moving "
        f"name against **{posture['counts']['action_refs_pinned_to_sha']:,}** pinned to an exact "
        "version. These twelve are where pinning buys the most.",
        chunk=12,  # twelve short rows fit one slide; splitting them reads as an error
    )

    piped = posture["remote_code_piped_to_shell"]
    out += table(
        ["Repository", "File", "Occurrences"],
        [[f"`{short(row['repo'])}`", f"`{row['path']}`", row.get("occurrences", 1)] for row in piped],
        "Problem 4 — workflows that download and run code without checking it",
        "Four workflows fetch code from the internet and execute it immediately. This is "
        "deliberate in each case, but it is the same primitive the campaign relies on, so each "
        "should be pinned to a known version or replaced.",
    )

    # --- The front door ---------------------------------------------------------------
    out += table(
        ["Feed", "Connected to the public catalog", "Readable"],
        [
            [
                f"`{row['org']}/{row['feed']}`",
                "yes" if row.get("npmjs_upstream_configured") else "no",
                "yes" if row.get("identity_has_read_packages") else "**no**",
            ]
            for row in feeds["feeds"]
        ],
        "Fix E — the front door we already own",
        f"**{feeds['npm_packages_listed_total']}** relevant components flow through any of these, "
        f"against **{feeds['packages_by_protocol_all_feeds'].get('NuGet', 0)}** "
        "Microsoft-ecosystem components that do. The connection already exists on three of them.",
    )

    # --- Gaps -------------------------------------------------------------------------
    out += [
        "## What is deliberately not listed here",
        "",
        f"- **{len(repos['install_may_be_inside_a_called_action'])} projects** where the download",
        "  step happens inside something we did not read. They are neither safe nor unsafe in",
        "  this appendix, because we do not know.",
        f"- **{len(repos['no_ci_install_observed'])} projects** with no automated install at all,",
        f"  **{len(repos['no_workflow_file_at_all'])}** of them with no automation whatsoever.",
        "  Their components are only ever downloaded on a person's own laptop.",
        f"- **{len(repos['tree_truncated'])} repositories** whose file listing was cut short by",
        "  GitHub: `" + "`, `".join(repos["tree_truncated"]) + "`.",
        "- **One internal feed we could not read** — `SleepNumberIndigo/k8s-manifests` — for",
        "  permission reasons. A request naming the exact permission is in the technical report.",
        "- **The 838 workflows that put secret values into a command line.** The collector",
        "  records the first 200; listing a truncated set here would read as a complete one.",
        "",
        "*Generated by `scripts/report/build_appendix.py` from the collector artifacts in*",
        "*`exports/hunt/`. Re-run it rather than editing this file.*",
        "",
    ]

    OUT.write_text("\n".join(out))
    print(f"wrote {OUT.relative_to(ROOT)} ({len(out)} lines)")


if __name__ == "__main__":
    main()
