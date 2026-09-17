#!/usr/bin/env python3
"""Generate the names appendix for the issue-grouping status report.

The briefing and the technical companion both quote counts. A count is
unactionable to whoever has to do the work and unverifiable to anyone checking
it, so every count has its names listed here -- and generated from the database
rather than typed, because a hand-typed list drifts from the figure it belongs
to the first time either changes.

Run inside the api container, which is where the database credentials live:

    docker compose exec -T api python /app/scripts/generate_grouping_appendix.py

Writes docs/GRC_Filing_Grouping_Appendix.md and prints the same figures to
stdout so a report writer can copy them without re-querying (and so two
documents cannot end up quoting two different measurement runs).

Read-only. No writes, no AI calls, nothing sent to AuditBoard.
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "/app")

from sqlalchemy import text  # noqa: E402

from src.api.database import SessionLocal  # noqa: E402
from src.api.services import rule_equivalence as svc  # noqa: E402

OUT = Path("/app/docs/GRC_Filing_Grouping_Appendix.md")

#: How many rows each names table shows before it says how many it left out.
#: A list nobody scrolls is the same as no list, but a truncated list that
#: looks complete is worse than either.
CAP = 60


def scalar(db, sql, **params):
    return db.execute(text(sql), params).scalar()


def rows(db, sql, **params):
    return db.execute(text(sql), params).fetchall()


def main() -> None:
    db = SessionLocal()
    figures = {}
    try:
        figures["findings_total"] = scalar(db, "SELECT COUNT(*) FROM findings")
        figures["findings_with_rule"] = scalar(
            db, "SELECT COUNT(*) FROM findings WHERE rule_id IS NOT NULL AND rule_id <> ''"
        )
        figures["findings_excluded"] = scalar(
            db, "SELECT COUNT(*) FROM findings WHERE excluded_from_actionable IS TRUE"
        )
        figures["findings_scan_path"] = scalar(
            db, "SELECT COUNT(*) FROM findings WHERE file_path LIKE '/tmp/repo_scan_%'"
        )
        figures["repositories"] = scalar(db, "SELECT COUNT(*) FROM repositories")
        figures["scanners"] = scalar(
            db, "SELECT COUNT(DISTINCT scanner_name) FROM findings WHERE scanner_name IS NOT NULL"
        )
        figures["defects"] = scalar(
            db,
            """
            SELECT COUNT(*) FROM (
              SELECT DISTINCT scanner_name, rule_id FROM findings
              WHERE scanner_name IS NOT NULL AND rule_id IS NOT NULL
            ) d
            """,
        )
        figures["candidates_floor"] = svc.count_candidate_pairs(db)
        figures["candidates_all"] = svc.count_candidate_pairs(db, severities=[])
        figures["candidates_undecided"] = len(
            svc.find_candidate_pairs(db, limit=100_000, skip_decided=True)
        )

        equivalence_stats = svc.review_stats(db)
        figures.update({f"pairs_{k}": v for k, v in equivalence_stats.items()})

        # The old grouping key, so the problem being fixed has a size.
        old_key_worst = rows(
            db,
            """
            SELECT scanner_name,
                   regexp_replace(file_path, '^.*/', '') AS base_name,
                   COUNT(*) AS findings,
                   COUNT(DISTINCT rule_id) AS distinct_rules,
                   COUNT(DISTINCT repository_id) AS projects
            FROM findings
            WHERE scanner_name IS NOT NULL AND file_path IS NOT NULL
            GROUP BY 1, 2
            ORDER BY COUNT(*) DESC
            LIMIT :cap
            """,
            cap=CAP,
        )
        figures["worst_old_group_findings"] = (
            int(old_key_worst[0].findings) if old_key_worst else 0
        )
        figures["worst_old_group_rules"] = (
            int(old_key_worst[0].distinct_rules) if old_key_worst else 0
        )
        figures["worst_old_group_projects"] = (
            int(old_key_worst[0].projects) if old_key_worst else 0
        )

        # The single group that started this work, measured two ways, because
        # the two ways give different numbers and both have been quoted. Exact
        # path is what the retired key actually compared; file name is what a
        # reader assumes when they hear "the package-lock.json group".
        exact = rows(
            db,
            """
            SELECT COUNT(*) AS findings,
                   COUNT(DISTINCT rule_id) AS distinct_rules,
                   COUNT(DISTINCT repository_id) AS projects
            FROM findings
            WHERE scanner_name = 'grype' AND file_path = '/package-lock.json'
            """,
        )[0]
        figures["grype_lockfile_exact_findings"] = int(exact.findings)
        figures["grype_lockfile_exact_rules"] = int(exact.distinct_rules)
        figures["grype_lockfile_exact_projects"] = int(exact.projects)

        # The widest defects under the new key: these are the ones a single
        # issue now speaks for, and the ones that cross the escalation line.
        widest = rows(
            db,
            """
            SELECT f.scanner_name,
                   f.rule_id,
                   MAX(f.severity) AS a_severity,
                   COUNT(*) AS findings,
                   COUNT(DISTINCT f.repository_id) AS projects
            FROM findings f
            WHERE f.scanner_name IS NOT NULL AND f.rule_id IS NOT NULL
              AND f.excluded_from_actionable IS NOT TRUE
              AND LOWER(f.severity) IN ('critical', 'high', 'medium')
            GROUP BY 1, 2
            ORDER BY COUNT(DISTINCT f.repository_id) DESC, COUNT(*) DESC
            LIMIT :cap
            """,
            cap=CAP,
        )
        figures["defects_over_threshold"] = scalar(
            db,
            """
            SELECT COUNT(*) FROM (
              SELECT f.scanner_name, f.rule_id
              FROM findings f
              WHERE f.scanner_name IS NOT NULL AND f.rule_id IS NOT NULL
                AND f.excluded_from_actionable IS NOT TRUE
                AND LOWER(f.severity) IN ('critical', 'high', 'medium')
              GROUP BY 1, 2
              HAVING COUNT(DISTINCT f.repository_id) > 10
            ) w
            """,
        )
        figures["defects_fileable"] = scalar(
            db,
            """
            SELECT COUNT(*) FROM (
              SELECT DISTINCT f.scanner_name, f.rule_id
              FROM findings f
              WHERE f.scanner_name IS NOT NULL AND f.rule_id IS NOT NULL
                AND f.excluded_from_actionable IS NOT TRUE
                AND LOWER(f.severity) IN ('critical', 'high', 'medium')
            ) d
            """,
        )

        filings = rows(
            db,
            """
            SELECT issue_id, scope, scanner_name, rule_id, file_path,
                   occurrence_count, project_count, location_count,
                   locations_omitted, filed_by, created_at, issue_url
            FROM auditboard_issues
            ORDER BY issue_id
            """,
        )

        pairs = rows(
            db,
            """
            SELECT scanner_a, rule_a, scanner_b, rule_b, verdict, confidence,
                   review_decision, model, rationale
            FROM rule_equivalences
            ORDER BY verdict, confidence DESC NULLS LAST
            """,
        )

        candidates = svc.find_candidate_pairs(db, limit=CAP, skip_decided=True)

        body = render(figures, old_key_worst, widest, filings, pairs, candidates)
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(body)

        print(f"wrote {OUT}")
        print("\nFIGURES (quote these, do not re-derive):")
        for key, value in figures.items():
            print(f"  {key}: {value}")
    finally:
        db.close()


def render(figures, old_key_worst, widest, filings, pairs, candidates) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    out = []
    add = out.append

    add("# Appendix — Issue Grouping: names behind the counts")
    add("")
    add(f"Generated {stamp} by `scripts/generate_grouping_appendix.py` from the")
    add("`security_portal` database. Every table here is produced by that script;")
    add("nothing in it is typed by hand.")
    add("")
    add("**Companion documents:** `docs/GRC_Filing_Grouping_Status_Briefing.md`")
    add("(leadership) and `docs/GRC_Filing_Grouping_Status_Technical.md` (technical).")
    add("")
    add("**What this appendix deliberately omits.** No code snippets, and no")
    add("secret values: for the scanners whose finding *is* a credential, the")
    add("matched line is withheld everywhere outside AuditGitHub itself. File")
    add("paths are included, because a path is what an owner acts on. Findings")
    add("already marked not-actionable are excluded from the fileable counts and")
    add("are not listed.")
    add("")

    add("## Figures")
    add("")
    add("| Measure | Value |")
    add("| --- | --- |")
    labels = {
        "findings_total": "Findings in the database",
        "findings_with_rule": "Findings carrying a scanner rule identifier",
        "findings_excluded": "Findings already marked not-actionable",
        "findings_scan_path": "Findings whose recorded path is a temporary scan directory",
        "repositories": "Projects (repositories) known",
        "scanners": "Distinct scanners represented",
        "defects": "Distinct defects (scanner + rule) across all severities",
        "defects_fileable": "Distinct defects at Critical/High/Medium, actionable",
        "defects_over_threshold": "Of those, defects touching more than 10 projects",
        "candidates_floor": "Cross-scanner rule pairs worth checking (Critical/High/Medium)",
        "candidates_all": "Cross-scanner rule pairs worth checking (all severities)",
        "candidates_undecided": "Of those, still unchecked",
        "pairs_total": "Merge proposals recorded",
        "pairs_pending": "Proposals waiting on a person",
        "pairs_pending_equivalent": "Waiting proposals that propose a merge",
        "pairs_approved_equivalent": "Approved merges (these group findings today)",
        "pairs_approved_distinct": "Approved as separate",
        "pairs_rejected": "Rejected proposals",
        "worst_old_group_findings": "Largest group under the retired key, findings",
        "worst_old_group_rules": "Largest group under the retired key, distinct defects inside it",
        "worst_old_group_projects": "Largest group under the retired key, projects spanned",
        "grype_lockfile_exact_findings": "grype at exactly `/package-lock.json`: findings",
        "grype_lockfile_exact_rules": "grype at exactly `/package-lock.json`: distinct defects",
        "grype_lockfile_exact_projects": "grype at exactly `/package-lock.json`: projects",
    }
    for key, label in labels.items():
        if key in figures:
            add(f"| {label} | {figures[key]:,} |")
    add("")

    add("## A. The retired grouping key, worst groups first")
    add("")
    add("Grouping used to key on scanner plus file name. Each row is one group")
    add("under that key: `distinct defects inside it` is how many genuinely")
    add("different problems a single issue would have claimed to cover.")
    add("")
    add("Rows are grouped by file *name*, so a project with lock files in three")
    add("directories contributes all three. The retired key compared the whole")
    add("recorded path, which is stricter: for grype at exactly")
    add(f"`/package-lock.json` it is {figures['grype_lockfile_exact_findings']:,} findings, ")
    add(f"{figures['grype_lockfile_exact_rules']:,} distinct defects, ")
    add(f"{figures['grype_lockfile_exact_projects']:,} projects. Both figures are of the same")
    add("problem; the first row below is the file-name view of it.")
    add("")
    add("| Scanner | File name | Findings | Distinct defects inside | Projects |")
    add("| --- | --- | --- | --- | --- |")
    for r in old_key_worst:
        add(
            f"| {r.scanner_name} | `{r.base_name}` | {int(r.findings):,} | "
            f"{int(r.distinct_rules):,} | {int(r.projects):,} |"
        )
    add("")

    add("## B. Widest defects under the current key")
    add("")
    add("Critical, High and Medium only, not-actionable findings excluded — the")
    add("population that can be filed as a group. More than 10 projects is the")
    add("point at which an issue is recommended to be raised for the whole")
    add(f"organisation rather than one project. Showing {min(len(widest), CAP)}.")
    add("")
    add("| Scanner | Rule | Findings | Projects | Recommended scope |")
    add("| --- | --- | --- | --- | --- |")
    for r in widest:
        scope = "organisation" if int(r.projects) > 10 else "project"
        add(
            f"| {r.scanner_name} | `{r.rule_id}` | {int(r.findings):,} | "
            f"{int(r.projects):,} | {scope} |"
        )
    add("")

    add("## C. Issues filed to AuditBoard from this system")
    add("")
    add("`Findings covered` is the count measured when the issue was filed, not")
    add("today's count: findings deleted since then are not subtracted, because")
    add("the issue in AuditBoard still says what it said. A dash means the")
    add("column did not exist when that issue was filed — the first four were")
    add("filed under the retired grouping key, before per-project location lists")
    add("and defect identifiers were recorded. Issues raised in AuditBoard by")
    add("hand, or through its own screens, are not in this table; it records only")
    add("what this system filed.")
    add("")
    if not filings:
        add("None recorded.")
    else:
        add("| AuditBoard issue | Scope filed at | Scanner | Rule | Findings covered at filing | Projects | Locations listed | Locations omitted | Filed by | Filed |")
        add("| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |")
        for r in filings:
            add(
                f"| I#{r.issue_id} | {r.scope or '—'} | {r.scanner_name or '—'} | "
                f"`{r.rule_id or '—'}` | {r.occurrence_count or 0:,} | "
                f"{r.project_count or '—'} | {r.location_count or '—'} | "
                f"{r.locations_omitted or 0} | {r.filed_by or '—'} | "
                f"{r.created_at:%Y-%m-%d} |"
            )
    add("")

    add("## D. Cross-scanner merge decisions recorded")
    add("")
    add("A merge changes grouping only when it is both proposed as *equivalent*")
    add("and approved. Everything else in this table leaves the two scanners")
    add("reported separately.")
    add("")
    if not pairs:
        add("None recorded.")
    else:
        add("| Rule A | Rule B | Proposed | Confidence | Review | Groups findings today | Model |")
        add("| --- | --- | --- | --- | --- | --- | --- |")
        for r in pairs:
            merged = (
                "yes"
                if r.review_decision == "approved" and r.verdict == "equivalent"
                else "no"
            )
            confidence = f"{float(r.confidence):.2f}" if r.confidence is not None else "—"
            add(
                f"| `{r.scanner_a}::{r.rule_a}` | `{r.scanner_b}::{r.rule_b}` | "
                f"{r.verdict} | {confidence} | {r.review_decision or 'pending'} | "
                f"{merged} | {r.model or 'entered by hand'} |"
            )
    add("")

    add("## E. Rule pairs not yet checked")
    add("")
    add("Pairs from different scanners that report findings at the same file in")
    add("the same project. Co-location is why they are worth checking; it is not")
    add("evidence that they are the same problem.")
    add(
        f"Showing {len(candidates)} of {figures.get('candidates_undecided', 0):,} "
        "unchecked pairs, widest overlap first."
    )
    add("")
    add("| Rule A | Rule B | Shared places | Shared projects | Example path |")
    add("| --- | --- | --- | --- | --- |")
    for c in candidates:
        example = c.sample_paths[0] if c.sample_paths else "—"
        add(
            f"| `{c.identity_a.key}` | `{c.identity_b.key}` | {c.shared_locations:,} | "
            f"{c.shared_repos:,} | `{example}` |"
        )
    add("")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    main()
