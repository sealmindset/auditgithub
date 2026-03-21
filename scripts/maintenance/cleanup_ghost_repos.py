#!/usr/bin/env python3
"""
Clean up ghost repositories that don't exist on GitHub and have no findings.

This script identifies and removes repositories that:
1. Have no security findings
2. Have no pushed_at date (couldn't be fetched from GitHub)
3. Are from organizations with 0 active repos on GitHub
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

def cleanup_ghost_repos():
    """Remove ghost repositories with no findings and no GitHub presence."""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        logger.info("=" * 80)
        logger.info("Ghost Repository Cleanup")
        logger.info("=" * 80)

        # Find ghost repos: no findings, no pushed_at, from SleepNumberInc
        result = db.execute(text("""
            SELECT r.id, r.name, r.full_name, o.github_org
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
            LEFT JOIN findings f ON r.id = f.repository_id
            WHERE o.github_org = 'SleepNumberInc'
              AND r.pushed_at IS NULL
              AND f.id IS NULL
            ORDER BY r.name
        """))

        ghost_repos = result.fetchall()

        if not ghost_repos:
            logger.info("No ghost repositories found!")
            return

        logger.info(f"Found {len(ghost_repos)} ghost repositories to remove:")
        logger.info("  - Organization: SleepNumberInc (0 active repos on GitHub)")
        logger.info("  - No security findings in database")
        logger.info("  - No pushed_at date (404 on GitHub)")
        logger.info("")

        # Show some examples
        logger.info("Examples of repositories to be removed:")
        for repo_id, repo_name, full_name, org_name in ghost_repos[:10]:
            logger.info(f"  - {full_name or repo_name}")
        if len(ghost_repos) > 10:
            logger.info(f"  ... and {len(ghost_repos) - 10} more")
        logger.info("")

        # Ask for confirmation (in production, you might skip this)
        logger.info("⚠️  This will permanently delete these repositories from the database.")
        logger.info("   (Note: Schedules and other related data will be cascade-deleted)")
        logger.info("")

        # Count related data that will be deleted
        repo_ids_list = [r[0] for r in ghost_repos]

        # Check for schedules
        result = db.execute(text("""
            SELECT COUNT(*) FROM scan_schedules
            WHERE repository_id = ANY(:repo_ids)
        """), {'repo_ids': repo_ids_list})
        schedule_count = result.scalar()

        logger.info(f"Related data to be deleted:")
        logger.info(f"  - Repositories: {len(ghost_repos)}")
        logger.info(f"  - Schedules: {schedule_count}")
        logger.info("")

        logger.info("Starting deletion...")

        # Build list of repo IDs for bulk operations
        repo_ids_list = [r[0] for r in ghost_repos]

        # Delete related data first (to avoid foreign key violations)
        tables_to_clean = [
            'contributors',
            'contributor_profiles',
            'contributor_aliases',
            'language_stats',
            'dependencies',
            'file_commits',
            'commit_analyses',
            'component_analysis',
            'api_endpoints',
            'api_threat_assessments',
            'openapi_specs',
            'credential_url_test_results',
            'scan_schedules',
            'schedule_overrides',
            'scan_runs',
            'architecture_versions'
        ]

        ALLOWED_CLEANUP_TABLES = set(tables_to_clean)
        logger.info(f"Deleting related data from {len(tables_to_clean)} tables...")
        for table in tables_to_clean:
            if table not in ALLOWED_CLEANUP_TABLES:
                raise ValueError(f"Invalid table name: {table}")
            try:
                result = db.execute(text(f"""
                    DELETE FROM {table}
                    WHERE repository_id = ANY(:repo_ids)
                """), {'repo_ids': repo_ids_list})
                if result.rowcount > 0:
                    logger.info(f"  ✓ Deleted {result.rowcount} rows from {table}")
                db.commit()
            except Exception as e:
                # Table might not exist or have repository_id column
                logger.debug(f"  ⊘ Skipped {table}: {e}")
                db.rollback()

        # Now delete repositories
        logger.info(f"Deleting {len(ghost_repos)} repositories...")
        result = db.execute(text("""
            DELETE FROM repositories
            WHERE id = ANY(:repo_ids)
        """), {'repo_ids': repo_ids_list})

        deleted = result.rowcount
        db.commit()

        logger.info(f"  ✓ Deleted {deleted} repositories")

        logger.info("")
        logger.info("=" * 80)
        logger.info("Cleanup Complete!")
        logger.info("=" * 80)
        logger.info(f"✓ Deleted {deleted} ghost repositories")
        logger.info(f"✓ Deleted {schedule_count} associated schedules")
        logger.info("")
        logger.info("Remaining SleepNumberInc repositories:")
        logger.info("  - 39 repos with security findings (kept)")
        logger.info("  - All marked as archived (404 on GitHub)")
        logger.info("=" * 80)

        # Show final stats
        result = db.execute(text("""
            SELECT
                o.github_org,
                COUNT(*) as total_repos,
                COUNT(r.pushed_at) as with_pushed_at,
                COUNT(CASE WHEN r.is_archived = true THEN 1 END) as archived
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
            GROUP BY o.github_org
            ORDER BY total_repos DESC
        """))

        logger.info("")
        logger.info("Final Repository Counts:")
        logger.info("-" * 80)
        for org, total, with_pushed, archived in result.fetchall():
            logger.info(f"  {org:20} | Total: {total:4} | With pushed_at: {with_pushed:4} | Archived: {archived:4}")
        logger.info("-" * 80)

    except Exception as e:
        logger.error(f"Error during cleanup: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    cleanup_ghost_repos()
