#!/usr/bin/env python3
"""
Populate the finding knowledge base from the findings already in the database.

Three jobs, all idempotent, all re-runnable:

1. **Create the tables.** `--apply-schema` creates `finding_knowledge_base`,
   `finding_kb_versions` and `finding_kb_org_overlays` if absent. Migration 025
   is the documented path; this is the path that reaches a database with no
   `alembic_version` table. See spec §9.0.

2. **Derive the keys.** Groups actionable findings by the key precedence in
   `src/services/kb_key.py` and creates a stub entry per distinct key, carrying
   the measured occurrence count so authoring can be done in impact order. On
   the live corpus that is 2,639 entries, of which the top 10 cover half the
   estate and the top 166 cover 80%.

3. **Enrich the advisory keys.** For `ghsa:` entries, fetches the published
   advisory and fills CVE, CWE, EPSS, affected packages and first patched
   version — all fields the local database does not have. These are marked
   `source = 'import'` with the URL they came from. Nothing is generated here.

Entries are created as `draft`. Nothing renders into a report until a human
approves it, which is the point of the draft state and not an oversight.

Dry run is the default. Nothing is written without --commit.

Usage:
    python scripts/build_knowledge_base.py --apply-schema
    python scripts/build_knowledge_base.py                       # dry run, sizes the work
    python scripts/build_knowledge_base.py --commit
    python scripts/build_knowledge_base.py --commit --enrich --limit-enrich 50
    python scripts/build_knowledge_base.py --report-coverage
"""

import argparse
import logging
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy import text  # noqa: E402

from src.api.database import SessionLocal, engine  # noqa: E402
from src.api.models import Base, FindingKnowledgeBase  # noqa: E402
from src.api.constants.kb import KBKeyType, KBSource, KBStatus, MappingSource  # noqa: E402
from src.services.ghsa_enrichment import fetch_advisory, kb_fields_from_advisory  # noqa: E402
from src.services.kb_key import kb_key_for  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

_KB_TABLES = ("finding_knowledge_base", "finding_kb_versions", "finding_kb_org_overlays")


class _Row:
    """Adapter so kb_key_for() sees the attribute names it expects."""

    def __init__(self, row):
        self.scanner_name = row.scanner_name
        self.rule_id = row.rule_id
        self.rule_id_is_stable = row.rule_id_is_stable
        self.ghsa_id = row.ghsa_id
        self.cve_id = row.cve_id
        self.cwe_id = row.cwe_id


def apply_schema() -> None:
    """Create the three KB tables if absent. Safe to re-run."""
    with engine.connect() as conn:
        existing = {
            r[0] for r in conn.execute(text(
                "SELECT table_name FROM information_schema.tables WHERE table_schema='public'"
            ))
        }
    missing = [t for t in _KB_TABLES if t not in existing]
    if not missing:
        logger.info("all knowledge base tables already present")
        return
    logger.info("creating tables: %s", ", ".join(missing))
    Base.metadata.create_all(
        bind=engine,
        tables=[Base.metadata.tables[t] for t in missing],
    )
    logger.info("created %d table(s)", len(missing))


def collect_keys() -> tuple[dict, dict]:
    """Group actionable findings by KB key.

    Returns (keys, unkeyed) where keys maps kb_key -> aggregate facts.
    """
    session = SessionLocal()
    keys: dict[str, dict] = {}
    unkeyed: dict[str, int] = defaultdict(int)
    try:
        rows = session.execute(text("""
            SELECT scanner_name, rule_id, rule_id_is_stable, ghsa_id, cve_id, cwe_id,
                   finding_type, remediation_category,
                   count(*) AS n,
                   count(DISTINCT repository_id) AS repos,
                   min(title) AS sample_title,
                   max(severity) AS a_severity
            FROM findings
            WHERE NOT excluded_from_actionable
            GROUP BY 1,2,3,4,5,6,7,8
        """)).fetchall()

        for row in rows:
            key = kb_key_for(_Row(row))
            if key is None:
                # Real state, reported rather than defaulted: an entry per
                # finding is not a knowledge base.
                unkeyed[f"{row.scanner_name}:{row.finding_type}"] += row.n
                continue
            entry = keys.setdefault(key.key, {
                "kb_key": key.key,
                "key_type": key.key_type.value,
                "identifier": key.identifier,
                "key_is_stable": key.is_stable,
                "scanner_name": row.scanner_name if key.key_type is KBKeyType.RULE else None,
                "rule_id": row.rule_id if key.key_type is KBKeyType.RULE else None,
                "ghsa_id": key.identifier if key.key_type is KBKeyType.GHSA else None,
                "cve_id": key.identifier if key.key_type is KBKeyType.CVE else None,
                "title": (row.sample_title or key.identifier)[:500],
                "findings_count": 0,
                "repos_count": 0,
                "categories": set(),
            })
            entry["findings_count"] += row.n
            entry["repos_count"] = max(entry["repos_count"], row.repos)
            if row.remediation_category:
                entry["categories"].add(row.remediation_category)
    finally:
        session.close()
    return keys, dict(unkeyed)


def _stub_summary(entry: dict) -> str:
    """The placeholder that occupies an unauthored entry.

    Deliberately says what is absent rather than reading like content. An entry
    whose summary looks written but is not is worse than an obviously empty one,
    because only the second gets fixed.
    """
    return (
        f"Knowledge base entry not yet authored. "
        f"Observed on {entry['findings_count']:,} findings across "
        f"{entry['repos_count']} repositor{'y' if entry['repos_count'] == 1 else 'ies'}."
    )


def upsert_entries(keys: dict, *, commit: bool) -> dict:
    """Create a draft entry per key. Never overwrites an existing entry."""
    session = SessionLocal()
    tally = {"created": 0, "existing": 0}
    try:
        present = {
            r[0] for r in session.execute(text("SELECT kb_key FROM finding_knowledge_base"))
        } if commit else set()

        for entry in keys.values():
            if entry["kb_key"] in present:
                tally["existing"] += 1
                continue
            tally["created"] += 1
            if not commit:
                continue
            session.add(FindingKnowledgeBase(
                kb_key=entry["kb_key"],
                key_type=entry["key_type"],
                cve_id=entry["cve_id"],
                ghsa_id=entry["ghsa_id"],
                rule_id=entry["rule_id"],
                scanner_name=entry["scanner_name"],
                key_is_stable=entry["key_is_stable"],
                title=entry["title"],
                summary=_stub_summary(entry),
                reference_ids=[],
                # No published CWE -> CAPEC -> ATT&CK mapping is available for a
                # scanner-rule key, and findings.cwe_id carries none. Recorded
                # as 'none' rather than left NULL so the absence is a stated
                # result rather than an unfinished field.
                ttp={"capec": [], "attack_tactics": [], "attack_techniques": [],
                     "mapping_source": MappingSource.NONE.value,
                     "mapping_note": "no CWE recorded on the underlying findings"},
                mitigation_options=[],
                status=KBStatus.DRAFT.value,
                # Nobody has authored this row and nothing has been fetched into
                # it yet, so it is neither `ai` nor `import`. Advisory rows are
                # promoted to `import` by enrich_advisories() once the fetch
                # actually succeeds -- labelling them `import` at creation would
                # claim a provenance for content that does not exist.
                source=KBSource.UNAUTHORED.value,
                ai_confidence=None,
            ))
        if commit:
            session.commit()
    finally:
        session.close()
    return tally


def enrich_advisories(*, commit: bool, limit: int | None, force: bool) -> dict:
    """Fill advisory entries from the published advisory."""
    session = SessionLocal()
    tally = {"attempted": 0, "enriched": 0, "failed": 0, "withdrawn": 0,
             "with_cwe": 0, "with_fix": 0, "with_summary": 0}
    failures: list[str] = []
    try:
        q = """
            SELECT id, ghsa_id FROM finding_knowledge_base
            WHERE key_type = 'ghsa'
        """
        if not force:
            q += " AND source_fetched_at IS NULL"
        q += " ORDER BY kb_key"
        if limit:
            q += f" LIMIT {int(limit)}"
        rows = session.execute(text(q)).fetchall()

        for row in rows:
            tally["attempted"] += 1
            facts = fetch_advisory(row.ghsa_id)
            if not facts.ok:
                tally["failed"] += 1
                if len(failures) < 10:
                    failures.append(f"{row.ghsa_id}: {facts.error}")
                continue

            fields = kb_fields_from_advisory(facts)
            tally["enriched"] += 1
            if facts.cwes:
                tally["with_cwe"] += 1
            if any(a.get("first_patched_version") for a in facts.affected):
                tally["with_fix"] += 1
            if facts.is_withdrawn:
                tally["withdrawn"] += 1
            if fields["summary"]:
                tally["with_summary"] += 1

            if not commit:
                continue
            session.execute(text("""
                UPDATE finding_knowledge_base SET
                    cve_id = :cve_id, cwe_id = :cwe_id,
                    title = :title, reference_ids = CAST(:reference_ids AS jsonb),
                    -- Only overwrite the summary when the advisory supplied one
                    -- and the existing text is still the unauthored placeholder.
                    -- A human-written summary is never replaced by a fetch.
                    summary = CASE
                        WHEN :summary IS NULL THEN summary
                        WHEN source = 'human' THEN summary
                        ELSE :summary
                    END,
                    target_asset_type = :target_asset_type,
                    target_asset_detail = :target_asset_detail,
                    exploitability = CAST(:exploitability AS jsonb),
                    upstream_severity = :upstream_severity,
                    is_withdrawn = :is_withdrawn,
                    affected_packages = CAST(:affected_packages AS jsonb),
                    source = :source, ai_confidence = NULL,
                    source_url = :source_url, source_fetched_at = :now,
                    updated_at = :now
                WHERE id = :id
            """), {
                "id": row.id,
                "cve_id": fields["cve_id"],
                "cwe_id": fields["cwe_id"],
                "title": fields["title"][:500],
                "summary": fields["summary"],
                "reference_ids": _json(fields["reference_ids"]),
                "target_asset_type": fields["target_asset_type"],
                "target_asset_detail": fields["target_asset_detail"],
                "exploitability": _json(fields["exploitability"]),
                "upstream_severity": fields["upstream_severity"],
                "is_withdrawn": fields["is_withdrawn"],
                "affected_packages": _json(fields["affected_packages"]),
                "source": fields["source"],
                "source_url": fields["source_url"],
                "now": datetime.now(timezone.utc),
            })
            if tally["enriched"] % 50 == 0:
                session.commit()
                logger.info("enriched %d advisories", tally["enriched"])
        if commit:
            session.commit()
    finally:
        session.close()
    tally["failure_samples"] = failures
    return tally


def _json(value):
    import json
    return json.dumps(value)


def report_coverage() -> str:
    """How much of the estate the authored entries actually cover.

    The number that matters is findings covered, not entries authored: an
    estate where 12 of 2,639 entries are approved sounds unfinished and may
    already cover half the findings.
    """
    session = SessionLocal()
    try:
        rows = session.execute(text("""
            SELECT status, key_type, count(*) FROM finding_knowledge_base
            GROUP BY 1,2 ORDER BY 1,2
        """)).fetchall()
    finally:
        session.close()
    lines = ["", "  knowledge base entries by status and key type:"]
    for status, key_type, n in rows:
        lines.append(f"    {status:<12} {key_type:<8} {n:>8,}")
    if not rows:
        lines.append("    (none — run with --commit first)")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply-schema", action="store_true",
                        help="create the knowledge base tables, then exit")
    parser.add_argument("--commit", action="store_true",
                        help="write. Without this, nothing is modified.")
    parser.add_argument("--enrich", action="store_true",
                        help="fetch published advisories for ghsa: entries")
    parser.add_argument("--limit-enrich", type=int,
                        help="stop after this many advisory fetches")
    parser.add_argument("--force-refetch", action="store_true",
                        help="re-fetch advisories already fetched")
    parser.add_argument("--report-coverage", action="store_true",
                        help="print current entry counts and exit")
    args = parser.parse_args()

    if args.apply_schema:
        apply_schema()
        return 0

    if args.report_coverage:
        print(report_coverage())
        return 0

    keys, unkeyed = collect_keys()
    tally = upsert_entries(keys, commit=args.commit)

    by_type: dict[str, int] = defaultdict(int)
    findings_by_type: dict[str, int] = defaultdict(int)
    for entry in keys.values():
        by_type[entry["key_type"]] += 1
        findings_by_type[entry["key_type"]] += entry["findings_count"]

    top = sorted(keys.values(), key=lambda e: -e["findings_count"])[:10]
    total_findings = sum(e["findings_count"] for e in keys.values())

    mode = "WROTE" if args.commit else "DRY RUN — nothing was written"
    out = [f"\n{mode}", "",
           f"  distinct knowledge base keys   {len(keys):,}",
           f"  entries created                {tally['created']:,}",
           f"  entries already present        {tally['existing']:,}",
           f"  findings covered               {total_findings:,}", "",
           "  by key type:"]
    for key_type, n in sorted(by_type.items(), key=lambda kv: -kv[1]):
        out.append(f"    {key_type:<8} {n:>6,} entries  "
                   f"{findings_by_type[key_type]:>9,} findings")
    if unkeyed:
        out.append("")
        out.append("  findings with no derivable key:")
        for label, n in sorted(unkeyed.items(), key=lambda kv: -kv[1]):
            out.append(f"    {label:<32} {n:>8,}")
    out.append("")
    out.append("  ten entries covering the most findings:")
    running = 0
    for entry in top:
        running += entry["findings_count"]
        out.append(f"    {entry['findings_count']:>8,}  "
                   f"({running / total_findings:5.1%} cumulative)  {entry['kb_key'][:70]}")

    if args.enrich:
        e = enrich_advisories(commit=args.commit, limit=args.limit_enrich,
                              force=args.force_refetch)
        out += ["", "  advisory enrichment:",
                f"    attempted                 {e['attempted']:,}",
                f"    enriched                  {e['enriched']:,}",
                f"    failed                    {e['failed']:,}",
                f"    of those, carried a CWE   {e['with_cwe']:,}",
                f"    of those, a fixed version {e['with_fix']:,}",
                f"    withdrawn upstream        {e['withdrawn']:,}"]
        for sample in e["failure_samples"]:
            out.append(f"      ! {sample}")

    print("\n".join(out) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
