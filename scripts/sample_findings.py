#!/usr/bin/env python3
"""
Draw a reproducible random sample of findings for manual review.

A rate quoted from a sample is only worth anything if someone else can draw the
same sample and check the same rows. So the ordering is a hash of the finding id
and a caller-supplied seed, not `ORDER BY random()`: the same seed returns the
same rows on every run, on any machine, without storing anything.

Sampling is stratified by title, and the per-stratum rate is reported separately
before being weighted into a combined figure. Two rules with different error
rates averaged into one number is how a clean rule ends up carrying the blame
for a noisy one.

Usage:
    python scripts/sample_findings.py --scanner whispers \\
        --title "Secret: comment" --title "Secret: file" --n 120 --seed 2026-09-14
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy import text  # noqa: E402

from src.api.database import SessionLocal  # noqa: E402

_SAMPLE = """
    SELECT f.id, f.title, f.severity, f.file_path, f.line_start,
           f.code_snippet, f.description, r.name AS repo
    FROM findings f
    LEFT JOIN repositories r ON r.id = f.repository_id
    WHERE f.scanner_name = :scanner AND f.title = :title
    ORDER BY md5(f.id::text || :seed)
    LIMIT :n
"""

_POPULATION = """
    SELECT count(*) FROM findings
    WHERE scanner_name = :scanner AND title = :title
"""


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--scanner", required=True)
    parser.add_argument("--title", action="append", required=True,
                        help="repeat for each stratum")
    parser.add_argument("--n", type=int, default=120, help="rows per stratum")
    parser.add_argument("--seed", required=True,
                        help="any string; the same seed returns the same rows")
    parser.add_argument("--truncate", type=int, default=160,
                        help="max characters of snippet to print")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()

    session = SessionLocal()
    out = []
    try:
        for title in args.title:
            population = session.execute(
                text(_POPULATION), {"scanner": args.scanner, "title": title}
            ).scalar()
            rows = session.execute(
                text(_SAMPLE),
                {"scanner": args.scanner, "title": title, "seed": args.seed, "n": args.n},
            ).fetchall()

            stratum = {
                "title": title,
                "population": population,
                "sampled": len(rows),
                "seed": args.seed,
                "rows": [
                    {
                        "id": str(row.id),
                        "repo": row.repo,
                        "path": row.file_path,
                        "line": row.line_start,
                        "severity": row.severity,
                        "snippet": (row.code_snippet or "")[: args.truncate].replace("\n", " "),
                        "description": (row.description or "")[: args.truncate].replace("\n", " "),
                    }
                    for row in rows
                ],
            }
            out.append(stratum)
    finally:
        session.close()

    if args.json:
        print(json.dumps(out, indent=1))
        return 0

    for stratum in out:
        print(f"\n=== {stratum['title']} — {stratum['sampled']} of "
              f"{stratum['population']:,} (seed {stratum['seed']}) ===")
        for i, row in enumerate(stratum["rows"], 1):
            print(f"{i:>3}. [{row['repo']}] {row['path']}:{row['line']}")
            print(f"     snip: {row['snippet']}")
            if row["description"] and row["description"] != row["snippet"]:
                print(f"     desc: {row['description']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
