#!/usr/bin/env python3
"""
Sync deployment topology (phase P1: reusable-workflow propagation).

Parses the centrally-shared reusable workflows once, then propagates each
deployment contract to every repository that calls it, resolving concrete
environments and Azure/AWS identifiers from per-repository GitHub Environments
and Actions variables.

Uses only the existing GITHUB_TOKEN / DATABASE_URL from .env. Any permission
denial is reported at the end as a rights gap with the exact endpoint, so an
access request can be raised with evidence instead of guesswork.

Examples:
    # Dry run: what would be parsed, and how far does each workflow reach
    python3 scripts/sync_deployment_topology.py --org SleepNumberInc --dry-run

    # Real run, only workflows with >= 50 consumers, capped at 100 repos
    python3 scripts/sync_deployment_topology.py --org SleepNumberInc \
        --min-consumers 50 --repo-limit 100
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

from api.utils.deployment_topology_service import DeploymentTopologyService  # noqa: E402

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
)
logger = logging.getLogger("sync_deployment_topology")


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
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--org", required=True, help="GitHub organization login, e.g. SleepNumberInc")
    parser.add_argument("--organization-id", help="Organization UUID; resolved from --org when omitted")
    parser.add_argument("--min-consumers", type=int, default=5,
                        help="Skip shared workflows with fewer consumers (default 5)")
    parser.add_argument("--repo-limit", type=int, default=None,
                        help="Cap (repo, contract) resolutions for an incremental run")
    parser.add_argument("--include-non-deploying", action="store_true",
                        help="Also resolve consumers of workflows that do not mutate cloud state")
    parser.add_argument("--dry-run", action="store_true",
                        help="Parse central workflows and report reach; write nothing")
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
    service = DeploymentTopologyService(token, max_rate_limit_wait=args.wait_for_rate_limit)

    budget = service.rate_limit_status()
    if budget.get("available"):
        logger.info(
            "GitHub core rate limit: %s/%s remaining, resets %s",
            budget.get("remaining"), budget.get("limit"), budget.get("reset_utc"),
        )
        if (budget.get("remaining") or 0) < 200:
            logger.warning(
                "Only %s calls left - this is throttling, not a permissions problem. "
                "Re-run after %s or pass --wait-for-rate-limit.",
                budget.get("remaining"), budget.get("reset_utc"),
            )

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

    if args.dry_run:
        groups = service.discover_central_workflows(session, org_id, min_consumers=args.min_consumers)
        print(f"\n{len(groups)} shared reusable workflows with >= {args.min_consumers} consumers\n")
        print(f"{'consumers':>9}  {'deploys':>7}  {'cloud':<10} {'resources':<40} workflow")
        deploying = 0
        for group in groups:
            parsed = service.fetch_and_parse(group["source_repo"], group["workflow_path"], group["ref"])
            if parsed["is_deploying"]:
                deploying += 1
            print(
                f"{group['consumer_count']:>9}  "
                f"{'yes' if parsed['is_deploying'] else 'no':>7}  "
                f"{','.join(parsed['cloud_providers']) or '-':<10} "
                f"{','.join(parsed['resource_types'])[:39] or '-':<40} "
                f"{group['source_repo'].split('/')[-1]}@{group['ref']} "
                f"[{parsed.get('fetch_status')}]"
            )
        print(f"\n{deploying} of {len(groups)} mutate cloud state.")
        if service.rate_limited:
            print("\nWARNING: GitHub rate limit hit during this dry run - rows marked "
                  "[rate_limited] were NOT read and are not conclusions.")
        if service.rights_gaps:
            print("\nRIGHTS GAPS:")
            print(json.dumps(service.rights_gaps, indent=2))
        return 0

    stats = service.sync(
        session,
        organization_id=org_id,
        org_login=args.org,
        min_consumers=args.min_consumers,
        deploying_only=not args.include_non_deploying,
        repo_limit=args.repo_limit,
    )

    print("\n=== Deployment topology P1 sync ===")
    for key, value in stats.items():
        if key == "rights_gaps":
            continue
        print(f"  {key}: {value}")

    gaps = stats.get("rights_gaps") or {}
    if gaps:
        print("\n=== RIGHTS GAPS (submit access request) ===")
        for key, gap in gaps.items():
            print(f"  {key}: HTTP {gap['status']} x{gap['occurrences']}")
            print(f"      endpoint: {gap['endpoint']}")
            print(f"      impact:   {gap['detail']}")
    else:
        print("\nNo rights gaps encountered.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
