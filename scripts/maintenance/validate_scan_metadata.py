#!/usr/bin/env python3
"""
Validate and update repository metadata after scans complete.

This script is designed to be run after scan_repos.py completes to ensure
all repository metadata is up-to-date and complete. It reads metadata from
_intel.json and _cloc.json files and updates the database.

Usage:
    python validate_scan_metadata.py [--org ORG_NAME] [--repo REPO_NAME]

Examples:
    python validate_scan_metadata.py --org MyOrg --repo my-api
    python validate_scan_metadata.py --org my-org
    python validate_scan_metadata.py  # Validates all repositories
"""

import os
import sys
import logging
import argparse
from pathlib import Path
from datetime import datetime
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

# Import the metadata update function from ingest_reports
from ingest_reports import update_repository_metadata

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Database configuration
DB_HOST = os.getenv('POSTGRES_HOST', 'localhost')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')
DB_NAME = os.getenv('POSTGRES_DB', 'security_portal')
DB_USER = os.getenv('POSTGRES_USER', 'postgres')
DB_PASS = os.getenv('POSTGRES_PASSWORD', 'postgres')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"


def validate_all_repositories(org_name=None, repo_name=None):
    """
    Validate and update metadata for all repositories.

    Args:
        org_name: Optional organization name to filter by
        repo_name: Optional repository name to filter by (requires org_name)
    """
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        logger.info("=" * 80)
        logger.info("Repository Metadata Validation After Scan")
        logger.info("=" * 80)

        # Build query to get repositories
        query = """
            SELECT r.id, r.name, o.github_org
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
        """

        conditions = []
        params = {}

        if org_name:
            conditions.append("o.github_org = :org_name")
            params["org_name"] = org_name

        if repo_name:
            if not org_name:
                logger.error("--repo requires --org to be specified")
                return
            conditions.append("r.name = :repo_name")
            params["repo_name"] = repo_name

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY o.github_org, r.name"

        result = db.execute(text(query), params)
        repositories = result.fetchall()

        if not repositories:
            logger.warning(f"No repositories found" + (f" for {org_name}/{repo_name}" if org_name else ""))
            return

        logger.info(f"Target: {org_name or 'All organizations'}" + (f"/{repo_name}" if repo_name else ""))
        logger.info(f"Total Repositories: {len(repositories)}")
        logger.info("=" * 80)
        logger.info("")

        # Track statistics
        stats = {
            'total': len(repositories),
            'updated': 0,
            'no_metadata': 0,
            'errors': 0
        }

        for idx, (repo_id, name, github_org) in enumerate(repositories, 1):
            try:
                logger.debug(f"[{idx}/{stats['total']}] Validating {github_org}/{name}")

                # Update repository metadata
                success = update_repository_metadata(db, repo_id, github_org, name)

                if success:
                    stats['updated'] += 1
                else:
                    stats['no_metadata'] += 1

            except Exception as e:
                logger.error(f"Error validating {github_org}/{name}: {e}")
                stats['errors'] += 1
                db.rollback()

        # Print summary
        logger.info("")
        logger.info("=" * 80)
        logger.info("Validation Complete!")
        logger.info("=" * 80)
        logger.info(f"Total Repositories: {stats['total']}")
        logger.info(f"Updated: {stats['updated']}")
        logger.info(f"No metadata found: {stats['no_metadata']}")
        logger.info(f"Errors: {stats['errors']}")
        logger.info("=" * 80)

        # Show repositories that still need metadata
        if stats['no_metadata'] > 0:
            logger.info("")
            logger.info("Repositories without metadata files:")
            logger.info("  - These repos may not have been scanned yet")
            logger.info("  - Or _intel.json/_cloc.json files may be missing")
            logger.info("")

    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description='Validate and update repository metadata after scans',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --org MyOrg --repo my-api             # Validate specific repo
  %(prog)s --org my-org                          # Validate all repos in org
  %(prog)s                                       # Validate all repositories
        """
    )

    parser.add_argument(
        '--org',
        type=str,
        help='Organization name to validate (e.g., MyOrg, my-org)'
    )

    parser.add_argument(
        '--repo',
        type=str,
        help='Repository name to validate (requires --org)'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    validate_all_repositories(org_name=args.org, repo_name=args.repo)


if __name__ == "__main__":
    main()
