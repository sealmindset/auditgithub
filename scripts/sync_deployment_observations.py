#!/usr/bin/env python3
"""
Sync observed deployments (phase P2: GitHub Deployments API).

P1 recorded which environments each repository's CD contract is *wired* to reach.
P2 records which environments actually received a deploy, when, and who triggered
it, writing repo_deployment_map rows with method='github_deployment' alongside
the P1 rows so capability and observation can be compared.

Uses only the existing GITHUB_TOKEN / DATABASE_URL. Any permission denial is
reported at the end as a rights gap with the exact endpoint. GitHub throttling is
reported separately and is never a rights gap.

The run is resumable: repositories are probed oldest-observation-first and
committed as they complete, so a run stopped by the shared rate-limit floor
continues where it left off on the next invocation.

Examples:
    # Default: the repositories that already have a P1 map row
    python3 scripts/sync_deployment_observations.py --org SleepNumberInc

    # Preview which repositories would be probed and what it would cost
    python3 scripts/sync_deployment_observations.py --org SleepNumberInc --dry-run

    # Whole estate, deeper history, more status calls per repo
    python3 scripts/sync_deployment_observations.py --org SleepNumberInc \
        --all-repos --max-pages 2 --statuses-per-repo 6
"""
import argparse
import json
import logging
import os
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "src"))

from sqlalchemy import create_engine, text as sa_text  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from api.utils.deployment_observation_service import (  # noqa: E402
    DeploymentObservationService,
    per_repo_cost,
)

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
)
logger = logging.getLogger("sync_deployment_observations")


def load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from .env without overwriting the real environment."""
    if not path.exists():
        return
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


def normalize_db_url(url: str) -> str:
    """Make a docker-compose DATABASE_URL usable from the host."""
    url = url.replace("postgres://", "postgresql://", 1)
    if "@db:" in url and os.environ.get("TOPOLOGY_DB_HOST_PORT"):
        url = url.replace("@db:5432", f"@localhost:{os.environ['TOPOLOGY_DB_HOST_PORT']}")
    return url


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--org", required=True, help="GitHub organization login")
    parser.add_argument("--organization-id", help="Organization UUID; resolved from --org when omitted")
    parser.add_argument("--all-repos", action="store_true",
                        help="Probe every repository, not only those with an existing map row")
    parser.add_argument("--include-archived", action="store_true",
                        help="Also probe archived repositories")
    parser.add_argument("--refresh-days", type=int, default=7,
                        help="Skip repositories observed more recently than this (default 7)")
    parser.add_argument("--repo-limit", type=int, default=None,
                        help="Cap the number of repositories probed in this run")
    parser.add_argument("--max-pages", type=int, default=1,
                        help="Deployment history pages per repo, 100 records each (default 1)")
    parser.add_argument("--statuses-per-repo", type=int, default=4,
                        help="Status calls per repo, spent on the newest deploy of each environment (default 4)")
    parser.add_argument("--active-days", type=int, default=365,
                        help="Deploys older than this are marked stale (default 365)")
    parser.add_argument("--ignore-budget", action="store_true",
                        help="Do not stop at the shared on-demand budget floor (runs until GitHub 403s)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report candidates and estimated API cost; write nothing")
    parser.add_argument("--database-url", help="Override DATABASE_URL")
    parser.add_argument("--wait-for-rate-limit", type=int, default=0, metavar="SECONDS",
                        help="Max seconds to sleep waiting for a rate-limit reset (default 0: abort)")
    args = parser.parse_args()

    load_dotenv(REPO_ROOT / ".env")

    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        logger.error("GITHUB_TOKEN not set (checked environment and .env)")
        return 2

    db_url = normalize_db_url(args.database_url or os.environ.get("DATABASE_URL", ""))
    if not db_url:
        logger.error("DATABASE_URL not set")
        return 2

    engine = create_engine(db_url, future=True)
    session = sessionmaker(bind=engine, future=True)()
    service = DeploymentObservationService(token, max_rate_limit_wait=args.wait_for_rate_limit)

    org_id = args.organization_id
    if not org_id:
        row = session.execute(
            sa_text("SELECT id::text FROM organizations WHERE lower(name) = lower(:n)"),
            {"n": args.org},
        ).fetchone()
        if not row:
            logger.error("Organization %s not found; pass --organization-id", args.org)
            return 2
        org_id = row[0]
    logger.info("Organization %s -> %s", args.org, org_id)

    cost = per_repo_cost(args.max_pages, args.statuses_per_repo)

    if args.dry_run:
        candidates = service.select_candidates(
            session, org_id, only_mapped=not args.all_repos,
            include_archived=args.include_archived, refresh_days=args.refresh_days,
            limit=args.repo_limit,
        )
        budget = service.rate_limit_status()
        print(f"\n{len(candidates)} repositories would be probed "
              f"({'whole estate' if args.all_repos else 'only repos with an existing map row'})")
        print(f"Worst-case cost: {len(candidates)} x {cost} = {len(candidates) * cost} API calls")
        if budget.get("available"):
            print(f"Budget now: {budget.get('remaining')}/{budget.get('limit')} "
                  f"(source {budget.get('source')}), resets {budget.get('reset_utc')}")
            per_window = max(0, (budget.get("remaining") or 0) - 400) // max(1, cost)
            print(f"Repositories reachable this window above the on-demand floor: ~{per_window}")
        print("\nFirst 20 candidates (oldest observation first):")
        for repo_id, name in candidates[:20]:
            print(f"  {name}  ({repo_id})")
        return 0

    stats = service.sync(
        session,
        organization_id=org_id,
        org_login=args.org,
        only_mapped=not args.all_repos,
        include_archived=args.include_archived,
        refresh_days=args.refresh_days,
        repo_limit=args.repo_limit,
        max_pages=args.max_pages,
        statuses_per_repo=args.statuses_per_repo,
        active_days=args.active_days,
        respect_budget=not args.ignore_budget,
    )

    print("\n=== Deployment observation P2 sync ===")
    for key, value in stats.items():
        if key == "rights_gaps":
            continue
        print(f"  {key}: {value}")

    gaps = stats.get("rights_gaps") or {}
    if gaps:
        print("\n=== RIGHTS GAPS (submit access request) ===")
        print(json.dumps(gaps, indent=2))
    else:
        print("\nNo rights gaps encountered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
