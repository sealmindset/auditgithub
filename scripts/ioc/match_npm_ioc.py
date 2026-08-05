#!/usr/bin/env python3
"""
Match an npm IOC package list against the dependency inventory produced by scan_repos.py.

This is the version-precise layer of npm supply-chain detection. It belongs here rather
than in EDR telemetry for one reason: resolved package versions only exist in lockfiles.
A process command line shows what the developer typed ("npm ci"), not what npm resolved,
and node_modules paths carry a package name with no version. Endpoint detection therefore
has to key on behaviour and hashes; exact name@version matching happens against this table.

Two classes of result, and the distinction matters:

  EXACT   name and version both match a known-malicious release. Actionable, incident.
  ADJACENT
          the package is present at some other version. NOT an incident - keyv,
          cacheable-request, flat-cache and file-entry-cache are ubiquitous legitimate
          dependencies. It is a blast-radius measure: these are the repos that an
          unpinned upgrade would walk into the malicious version.

Alerting on package name alone is the failure mode this split exists to prevent.

Usage:
    python scripts/ioc/match_npm_ioc.py                          # all orgs, stdout
    python scripts/ioc/match_npm_ioc.py --target sleepnumberinc
    python scripts/ioc/match_npm_ioc.py --report exports/ioc-match.md --json out.json

Exit codes:
    0  no exact match
    2  at least one exact match (for scheduled/CI use)
    1  error
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Set, Tuple

import psycopg2
from psycopg2.extras import RealDictCursor

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_BUNDLE = REPO_ROOT / "github_conf" / "ioc" / "shai_hulud_2026_08.json"


def get_db_connection(database: str = None):
    """Connect using the same environment contract as the other scripts/ tools."""
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER", "postgres"),
        password=os.getenv("POSTGRES_PASSWORD", "postgres"),
        database=database or os.getenv("POSTGRES_DB", "security_portal"),
    )


def load_bundle(path: Path) -> dict:
    with open(path) as f:
        return json.load(f)


def load_package_list(bundle: dict, bundle_path: Path) -> Tuple[Set[Tuple[str, str]], Set[str]]:
    """
    Return (pairs, names) where pairs is {(lower_name, exact_version)} and names is
    {lower_name}. Versions are compared as exact strings: every npm version in the
    inventory is a resolved pin, so semver range logic would add risk, not coverage.
    """
    csv_rel = bundle.get("package_list", {}).get("file")
    if not csv_rel:
        raise SystemExit("IOC bundle has no package_list.file")

    csv_path = REPO_ROOT / csv_rel
    if not csv_path.exists():
        # tolerate a bundle-relative path too
        csv_path = bundle_path.parent / Path(csv_rel).name
    if not csv_path.exists():
        raise SystemExit(f"Package list not found: {csv_rel}")

    pairs: Set[Tuple[str, str]] = set()
    names: Set[str] = set()
    with open(csv_path, newline="") as f:
        for row in csv.DictReader(f):
            pkg = (row.get("Package") or "").strip()
            if not pkg:
                continue
            names.add(pkg.lower())
            for version in (row.get("Malicious Versions") or "").split(","):
                version = version.strip()
                if version:
                    pairs.add((pkg.lower(), version))

    # Seed packages are listed explicitly in the bundle as well; fold them in so a stale
    # CSV cannot drop the primary vectors.
    for pkg, versions in (bundle.get("seed_packages") or {}).items():
        names.add(pkg.lower())
        for version in versions:
            pairs.add((pkg.lower(), version))

    return pairs, names


def query_matches(conn, names: Set[str], target_org: str = None) -> List[dict]:
    """
    Pull every dependency row whose name is on the IOC list. Filtering by name in SQL and
    resolving the version match in Python keeps one round trip and avoids building a
    2000-row VALUES clause.
    """
    sql = """
        SELECT d.name,
               d.version,
               d.package_manager,
               r.name AS repo_name,
               r.url AS repo_url,
               r.last_scanned_at,
               o.name AS org_name
        FROM dependencies d
        LEFT JOIN repositories r ON r.id = d.repository_id
        -- Org is resolved through the repository, NOT through dependencies.organization_id:
        -- that column is NULL on every row the ingester writes. Joining on it filters the
        -- result set to nothing and reports a clean zero.
        LEFT JOIN organizations o ON o.id = r.organization_id
        WHERE lower(d.name) = ANY(%s)
    """
    params: List = [list(names)]
    if target_org:
        sql += " AND o.name = %s"
        params.append(target_org)

    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return [dict(row) for row in cur.fetchall()]


def inventory_scale(conn, target_org: str = None) -> dict:
    """Report what the zero result is a zero over. A clean result with no denominator is not evidence."""
    sql = """
        SELECT count(*) AS dep_rows,
               count(DISTINCT d.repository_id) AS repos,
               count(*) FILTER (WHERE d.package_manager = 'npm') AS npm_rows,
               count(*) FILTER (WHERE d.package_manager = 'npm'
                                  AND d.version ~ '^[0-9]') AS npm_pinned
        FROM dependencies d
        LEFT JOIN repositories r ON r.id = d.repository_id
        LEFT JOIN organizations o ON o.id = r.organization_id
        WHERE TRUE
    """
    params: List = []
    if target_org:
        sql += " AND o.name = %s"
        params.append(target_org)
    with conn.cursor(cursor_factory=RealDictCursor) as cur:
        cur.execute(sql, params)
        return dict(cur.fetchone())


def classify(rows: List[dict], pairs: Set[Tuple[str, str]]) -> Tuple[List[dict], Dict[str, dict]]:
    exact: List[dict] = []
    adjacent: Dict[str, dict] = defaultdict(lambda: {"versions": set(), "repos": set()})

    for row in rows:
        name = (row["name"] or "").lower()
        version = row["version"] or ""
        if (name, version) in pairs:
            exact.append(row)
        else:
            adjacent[row["name"]]["versions"].add(version)
            adjacent[row["name"]]["repos"].add(row.get("repo_name") or "?")

    return exact, adjacent


def render_report(bundle: dict, scale: dict, exact: List[dict],
                  adjacent: Dict[str, dict], pairs: Set[Tuple[str, str]],
                  target_org: str = None) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    seeds = bundle.get("seed_packages", {})
    out: List[str] = []

    out.append(f"# npm IOC match — {bundle.get('campaign')}")
    out.append("")
    out.append(f"Run: {now}  |  Scope: {target_org or 'all organizations'}")
    out.append(f"IOC list: {len(pairs)} package@version pairs "
               f"(compiled {bundle.get('compiled_at')})")
    out.append(f"Inventory: {scale['dep_rows']} dependency rows across {scale['repos']} repos "
               f"({scale['npm_rows']} npm, {scale['npm_pinned']} version-pinned)")
    out.append("")

    if exact:
        out.append(f"## EXACT MATCHES — {len(exact)} (incident)")
        out.append("")
        out.append("| Package | Version | Repo | Org |")
        out.append("|---|---|---|---|")
        for row in sorted(exact, key=lambda r: (r["name"], r.get("repo_name") or "")):
            out.append(f"| `{row['name']}` | `{row['version']}` | "
                       f"{row.get('repo_name') or '?'} | {row.get('org_name') or '?'} |")
    else:
        out.append("## EXACT MATCHES — none")
        out.append("")
        out.append("No dependency in the inventory resolves to a known-malicious release.")
        out.append("")
        out.append("This zero is only as current as two things: the IOC list "
                   "(the worm republishes continuously — re-pull before relying on it) and the "
                   "last scan of each repo (a lockfile changed after its scan is not represented).")
    out.append("")

    if adjacent:
        out.append(f"## ADJACENT — {len(adjacent)} IOC packages present at non-malicious versions")
        out.append("")
        out.append("Not findings. These are the repos an unpinned upgrade would walk into a "
                   "malicious version, i.e. where pinning and lockfile discipline pay off.")
        out.append("")
        out.append("| Package | Repos | Versions present | Malicious version(s) |")
        out.append("|---|---|---|---|")
        for name in sorted(adjacent, key=lambda n: -len(adjacent[n]["repos"])):
            info = adjacent[name]
            bad = ", ".join(f"`{v}`" for v in seeds.get(name, [])) or \
                  ", ".join(f"`{v}`" for n, v in sorted(pairs) if n == name.lower()) or "—"
            versions = ", ".join(f"`{v}`" for v in sorted(info["versions"]))
            out.append(f"| `{name}` | {len(info['repos'])} | {versions} | {bad} |")
    out.append("")

    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--bundle", type=Path, default=DEFAULT_BUNDLE,
                        help="IOC bundle JSON (default: github_conf/ioc/shai_hulud_2026_08.json)")
    parser.add_argument("--target", type=str, default=None,
                        help="Limit to one organization name as registered in the DB")
    parser.add_argument("--database", type=str, default=None,
                        help="Override POSTGRES_DB")
    parser.add_argument("--report", type=Path, default=None,
                        help="Write the markdown report to this path as well as stdout")
    parser.add_argument("--json", dest="json_out", type=Path, default=None,
                        help="Write machine-readable results here")
    args = parser.parse_args()

    if not args.bundle.exists():
        print(f"IOC bundle not found: {args.bundle}", file=sys.stderr)
        return 1

    bundle = load_bundle(args.bundle)
    pairs, names = load_package_list(bundle, args.bundle)

    try:
        conn = get_db_connection(args.database)
    except psycopg2.Error as exc:
        print(f"Database connection failed: {exc}", file=sys.stderr)
        return 1

    try:
        scale = inventory_scale(conn, args.target)
        rows = query_matches(conn, names, args.target)
    finally:
        conn.close()

    exact, adjacent = classify(rows, pairs)
    report = render_report(bundle, scale, exact, adjacent, pairs, args.target)
    print(report)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(report)
        print(f"\n[ioc] report -> {args.report}", file=sys.stderr)

    if args.json_out:
        payload = {
            "campaign": bundle.get("campaign"),
            "run_at": datetime.now(timezone.utc).isoformat(),
            "scope": args.target or "all",
            "ioc_pairs": len(pairs),
            "inventory": scale,
            "exact_matches": exact,
            "adjacent": {
                name: {"versions": sorted(info["versions"]), "repos": sorted(info["repos"])}
                for name, info in adjacent.items()
            },
        }
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(payload, indent=2, default=str))
        print(f"[ioc] json   -> {args.json_out}", file=sys.stderr)

    return 2 if exact else 0


if __name__ == "__main__":
    sys.exit(main())
