#!/usr/bin/env python3
"""
Fix misleading dates for archived repositories.

For repos that are archived (deleted from GitHub), we should not show
fake commit dates. Clear pushed_at and ensure they're properly archived.
"""

import os
import sys
import logging
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

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

def fix_archived_repo_dates():
    """Fix dates for archived repositories."""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        logger.info("=" * 80)
        logger.info("Fixing Archived Repository Dates")
        logger.info("=" * 80)

        # Find archived repos with misleading dates
        result = db.execute(text("""
            SELECT r.id, r.name, r.full_name, r.pushed_at, o.github_org
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
            WHERE r.is_archived = true
            ORDER BY r.name
        """))

        archived_repos = result.fetchall()

        if not archived_repos:
            logger.info("No archived repositories found")
            return

        logger.info(f"Found {len(archived_repos)} archived repositories")
        logger.info("")
        logger.info("These repos are deleted from GitHub but have findings.")
        logger.info("Clearing pushed_at dates to avoid showing misleading commit info.")
        logger.info("")

        # Show examples
        logger.info("Repositories to fix:")
        for repo_id, name, full_name, pushed_at, org in archived_repos[:10]:
            logger.info(f"  - {full_name or name}")
            if pushed_at:
                logger.info(f"    Current pushed_at: {pushed_at} (will be cleared)")
        if len(archived_repos) > 10:
            logger.info(f"  ... and {len(archived_repos) - 10} more")
        logger.info("")

        # Clear pushed_at for archived repos
        repo_ids = [r[0] for r in archived_repos]

        result = db.execute(text("""
            UPDATE repositories
            SET pushed_at = NULL,
                github_updated_at = NULL,
                updated_at = NOW()
            WHERE id = ANY(:repo_ids)
            RETURNING id
        """), {'repo_ids': repo_ids})

        updated_count = result.rowcount
        db.commit()

        logger.info("=" * 80)
        logger.info("Fix Complete!")
        logger.info("=" * 80)
        logger.info(f"✓ Updated {updated_count} archived repositories")
        logger.info("")
        logger.info("Changes made:")
        logger.info("  - Set pushed_at = NULL (no misleading dates)")
        logger.info("  - Set github_updated_at = NULL (no misleading dates)")
        logger.info("  - Kept is_archived = true (correct status)")
        logger.info("  - Kept all findings data (historical security info)")
        logger.info("")
        logger.info("Result:")
        logger.info("  - UI will not show false 'last commit' dates")
        logger.info("  - Repos remain in database with their findings")
        logger.info("  - Archived status prevents future scanning")
        logger.info("=" * 80)

        # Show final stats
        result = db.execute(text("""
            SELECT
                o.github_org,
                COUNT(*) as total_repos,
                COUNT(CASE WHEN r.is_archived = true THEN 1 END) as archived,
                COUNT(CASE WHEN r.pushed_at IS NOT NULL THEN 1 END) as with_pushed_at
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
            GROUP BY o.github_org
            ORDER BY total_repos DESC
        """))

        logger.info("")
        logger.info("Final Repository Status:")
        logger.info("-" * 80)
        logger.info(f"{'Organization':<20} | {'Total':<6} | {'Archived':<10} | {'With Dates':<12}")
        logger.info("-" * 80)
        for org, total, archived, with_dates in result.fetchall():
            logger.info(f"{org:<20} | {total:<6} | {archived:<10} | {with_dates:<12}")
        logger.info("-" * 80)

    except Exception as e:
        logger.error(f"Error during fix: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    fix_archived_repo_dates()
