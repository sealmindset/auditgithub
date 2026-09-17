#!/usr/bin/env python3
"""
Recover rule identity and assign remediation categories on existing findings.

Two jobs, both idempotent, both re-runnable:

1. **Rule identity.** Several scanners in this estate write their rule ID only
   into the finding title, and ingest discarded it. This reads it back out with
   src/services/remediation_classifier.py and writes rule_id, rule_id_is_stable
   and, for grype, ghsa_id. It does not touch cve_id, package_name or
   package_version: those are empty because ingest does not write them, which is
   an ingest defect, and filling them here would hide it. The one exception is
   retirejs, whose title is the only surviving record of the package and version
   — those are written only when the column is currently NULL, and only with
   --with-retirejs-packages, so the decision is explicit rather than incidental.

2. **Remediation category.** Applies the deterministic rules. Findings no rule
   matches are left NULL with category_source 'none'; they are the input to the
   model pass, which is a separate command and a separate cost.

Dry run is the default. Nothing is written without --commit.

Usage:
    python scripts/backfill_rule_identity.py --apply-schema
    python scripts/backfill_rule_identity.py                  # dry run, reports counts
    python scripts/backfill_rule_identity.py --commit
    python scripts/backfill_rule_identity.py --commit --scanner whispers
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
from src.api.constants.remediation import CategorySource  # noqa: E402
from src.services.remediation_classifier import classify, extract_rule_id  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)


# The columns migration 023 adds. Repeated here because this database is
# created by Base.metadata.create_all, which creates missing tables but never
# adds a column to a table that already exists. Without this, 023 describes a
# schema the running system does not have.
_COLUMNS = (
    ("rule_id", "VARCHAR(512)"),
    ("rule_id_is_stable", "BOOLEAN"),
    ("ghsa_id", "VARCHAR(32)"),
    ("remediation_category", "VARCHAR(64)"),
    ("category_source", "VARCHAR(16) DEFAULT 'none'"),
    ("category_confidence", "DOUBLE PRECISION"),
    ("category_rationale", "TEXT"),
    ("category_assigned_at", "TIMESTAMP"),
    ("excluded_from_actionable", "BOOLEAN NOT NULL DEFAULT false"),
    ("exclusion_reason", "TEXT"),
)

_INDEXES = (
    ("idx_findings_scanner_rule", "findings (scanner_name, rule_id)"),
    ("idx_findings_ghsa", "findings (ghsa_id)"),
    ("idx_findings_repo_category", "findings (repository_id, remediation_category)"),
    ("idx_findings_category_source", "findings (category_source)"),
    ("idx_findings_excluded", "findings (excluded_from_actionable)"),
)


def apply_schema() -> None:
    """Add the columns and indexes if they are absent. Safe to re-run."""
    with engine.connect() as conn:
        existing = {
            row[0]
            for row in conn.execute(text(
                "SELECT column_name FROM information_schema.columns "
                "WHERE table_name = 'findings'"
            ))
        }
        for name, ddl_type in _COLUMNS:
            if name in existing:
                logger.info("column findings.%s already present", name)
                continue
            logger.info("adding column findings.%s %s", name, ddl_type)
            conn.execute(text(f"ALTER TABLE findings ADD COLUMN {name} {ddl_type}"))
            conn.commit()

        for name, target in _INDEXES:
            logger.info("ensuring index %s", name)
            # CONCURRENTLY needs its own transaction and cannot run inside one.
            conn.execute(text("COMMIT"))
            conn.exec_driver_sql(
                f"CREATE INDEX CONCURRENTLY IF NOT EXISTS {name} ON {target}"
            )


class Tally:
    """What the run did, broken down so the numbers can be checked per scanner."""

    def __init__(self) -> None:
        self.scanned = 0
        self.rule_recovered = 0
        self.rule_unstable = 0
        self.rule_absent = 0
        self.ghsa_recovered = 0
        self.retirejs_packages = 0
        self.classified = 0
        self.unclassified = 0
        self.excluded = 0
        self.by_scanner: dict[str, int] = defaultdict(int)
        self.by_category: dict[str, int] = defaultdict(int)
        self.actionable_by_category: dict[str, int] = defaultdict(int)
        self.excluded_by_rule: dict[str, int] = defaultdict(int)
        self.unclassified_by_type: dict[str, int] = defaultdict(int)

    def report(self) -> str:
        lines = [
            "",
            f"  findings scanned            {self.scanned:,}",
            f"  rule_id recovered           {self.rule_recovered:,}",
            f"    of which prose, unstable  {self.rule_unstable:,}",
            f"  rule_id not recoverable     {self.rule_absent:,}",
            f"  ghsa_id recovered           {self.ghsa_recovered:,}",
            f"  retirejs packages recovered {self.retirejs_packages:,}",
            f"  categorised by rule         {self.classified:,}",
            f"  left for the model pass     {self.unclassified:,}",
            f"  excluded from work list     {self.excluded:,}",
            "",
            "  by scanner:",
        ]
        for scanner, count in sorted(self.by_scanner.items(), key=lambda kv: -kv[1]):
            lines.append(f"    {scanner or '(none)':<24} {count:>10,}")
        lines.append("")
        lines.append("  by remediation category (all findings):")
        for category, count in sorted(self.by_category.items(), key=lambda kv: -kv[1]):
            lines.append(f"    {category:<24} {count:>10,}")
        lines.append("")
        lines.append("  by remediation category (actionable only):")
        for category, count in sorted(self.actionable_by_category.items(), key=lambda kv: -kv[1]):
            lines.append(f"    {category:<24} {count:>10,}")
        if self.excluded_by_rule:
            lines.append("")
            lines.append("  excluded, by rule:")
            for rule, count in sorted(self.excluded_by_rule.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {rule:<24} {count:>10,}")
        if self.unclassified_by_type:
            lines.append("")
            lines.append("  unclassified, by finding_type:")
            for ftype, count in sorted(self.unclassified_by_type.items(), key=lambda kv: -kv[1]):
                lines.append(f"    {ftype or '(none)':<24} {count:>10,}")
        return "\n".join(lines)


# Built rather than fixed, because a dry run must be possible before the columns
# exist: referencing rule_id in the WHERE clause would make the query fail to
# parse on a database that has not had --apply-schema run against it.
def _select_sql(only_missing: bool) -> str:
    clause = "AND rule_id IS NULL" if only_missing else ""
    return f"""
        SELECT id, scanner_name, title, finding_type, status, fixed_version,
               package_name, package_version,
               ai_triage_recommendation, ai_triage_confidence
        FROM findings
        WHERE (:scanner IS NULL OR scanner_name = :scanner)
        {clause}
        ORDER BY id
        LIMIT :limit OFFSET :offset
    """


class _Row:
    """Adapter so classify() sees the attribute names it expects."""

    def __init__(self, row):
        self.finding_type = row.finding_type
        self.scanner_name = row.scanner_name
        self.status = row.status
        self.fixed_version = row.fixed_version
        self.ai_triage_recommendation = row.ai_triage_recommendation
        self.ai_triage_confidence = row.ai_triage_confidence


def run(
    *,
    commit: bool,
    scanner: str | None,
    limit: int | None,
    batch_size: int,
    only_missing: bool,
    with_retirejs_packages: bool,
) -> Tally:
    tally = Tally()
    session = SessionLocal()
    now = datetime.now(timezone.utc)
    offset = 0

    try:
        while True:
            take = batch_size
            if limit is not None:
                remaining = limit - tally.scanned
                if remaining <= 0:
                    break
                take = min(batch_size, remaining)

            rows = session.execute(
                text(_select_sql(only_missing)),
                {"scanner": scanner, "limit": take, "offset": offset},
            ).fetchall()
            if not rows:
                break
            offset += len(rows)

            updates = []
            for row in rows:
                tally.scanned += 1
                tally.by_scanner[row.scanner_name] += 1

                identity = extract_rule_id(row.scanner_name, row.title)
                if identity.rule_id:
                    tally.rule_recovered += 1
                    if not identity.is_stable:
                        tally.rule_unstable += 1
                else:
                    tally.rule_absent += 1
                if identity.ghsa_id:
                    tally.ghsa_recovered += 1

                decision = classify(_Row(row), rule_id=identity.rule_id)
                if decision:
                    tally.classified += 1
                    tally.by_category[decision.category.value] += 1
                    if decision.excluded:
                        tally.excluded += 1
                        tally.excluded_by_rule[
                            f"{row.scanner_name}:{identity.rule_id}"
                        ] += 1
                    else:
                        tally.actionable_by_category[decision.category.value] += 1
                else:
                    tally.unclassified += 1
                    tally.unclassified_by_type[row.finding_type] += 1

                package_name = None
                package_version = None
                if with_retirejs_packages and identity.package_name:
                    # Only fill a column that is currently empty. Never overwrite
                    # something ingest recorded.
                    if not row.package_name:
                        package_name = identity.package_name
                    if not row.package_version:
                        package_version = identity.package_version
                    if package_name or package_version:
                        tally.retirejs_packages += 1

                updates.append({
                    "id": row.id,
                    "rule_id": identity.rule_id,
                    "rule_id_is_stable": identity.is_stable if identity.rule_id else None,
                    "ghsa_id": identity.ghsa_id,
                    "remediation_category": decision.category.value if decision else None,
                    "category_source": (decision.source.value if decision
                                        else CategorySource.NONE.value),
                    "category_confidence": decision.confidence if decision else None,
                    "category_rationale": decision.rationale if decision else None,
                    "category_assigned_at": now if decision else None,
                    "excluded_from_actionable": bool(decision and decision.excluded),
                    "exclusion_reason": decision.exclusion_reason if decision else None,
                    "package_name": package_name,
                    "package_version": package_version,
                })

            if commit:
                session.execute(text("""
                    UPDATE findings SET
                        rule_id = :rule_id,
                        rule_id_is_stable = :rule_id_is_stable,
                        ghsa_id = :ghsa_id,
                        remediation_category = :remediation_category,
                        category_source = :category_source,
                        category_confidence = :category_confidence,
                        category_rationale = :category_rationale,
                        category_assigned_at = :category_assigned_at,
                        excluded_from_actionable = :excluded_from_actionable,
                        exclusion_reason = :exclusion_reason,
                        package_name = COALESCE(:package_name, package_name),
                        package_version = COALESCE(:package_version, package_version)
                    WHERE id = :id
                """), updates)
                session.commit()

            logger.info("%s %s rows (%s total)",
                        "updated" if commit else "examined", len(rows), f"{tally.scanned:,}")
    finally:
        session.close()

    return tally


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply-schema", action="store_true",
                        help="add the columns and indexes, then exit")
    parser.add_argument("--commit", action="store_true",
                        help="write the results. Without this, nothing is modified.")
    parser.add_argument("--scanner", help="restrict to one scanner_name")
    parser.add_argument("--limit", type=int, help="stop after this many findings")
    parser.add_argument("--batch-size", type=int, default=5000)
    parser.add_argument("--only-missing", action="store_true",
                        help="skip findings that already have a rule_id")
    parser.add_argument("--with-retirejs-packages", action="store_true",
                        help="also fill empty package_name/package_version from retirejs titles")
    args = parser.parse_args()

    if args.apply_schema:
        apply_schema()
        logger.info("schema applied")
        return 0

    tally = run(
        commit=args.commit,
        scanner=args.scanner,
        limit=args.limit,
        batch_size=args.batch_size,
        only_missing=args.only_missing,
        with_retirejs_packages=args.with_retirejs_packages,
    )

    mode = "WROTE" if args.commit else "DRY RUN — nothing was written"
    print(f"\n{mode}{tally.report()}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
