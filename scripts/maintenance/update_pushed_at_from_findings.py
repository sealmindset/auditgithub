#!/usr/bin/env python3
"""
Update pushed_at dates for non-existent repos using finding dates.

For repositories that no longer exist on GitHub (return 404), use the latest
finding date as a proxy for pushed_at so the scheduler has date information.
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

def update_pushed_at_from_findings():
    """Update pushed_at using finding dates for repos without it."""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Get repos missing pushed_at that have findings
        result = db.execute(text("""
            SELECT r.id, r.name, r.full_name,
                   MAX(f.created_at) as latest_finding,
                   COUNT(f.id) as finding_count
            FROM repositories r
            JOIN findings f ON r.id = f.repository_id
            WHERE r.pushed_at IS NULL
            GROUP BY r.id, r.name, r.full_name
            ORDER BY latest_finding DESC
        """))

        repos = result.fetchall()

        if not repos:
            logger.info("No repositories found that need updating")
            return

        logger.info(f"Found {len(repos)} repositories with findings but no pushed_at date")
        logger.info("These repos no longer exist on GitHub but have historical scan data")
        logger.info("Updating pushed_at to use latest finding date...\n")

        updated = 0
        for repo_id, repo_name, full_name, latest_finding, finding_count in repos:
            # Update pushed_at to the latest finding date
            # Also mark as archived since they don't exist on GitHub
            db.execute(text("""
                UPDATE repositories
                SET pushed_at = :pushed_at,
                    is_archived = true,
                    updated_at = NOW()
                WHERE id = :repo_id
            """), {
                'repo_id': repo_id,
                'pushed_at': latest_finding
            })

            logger.info(f"✓ {full_name or repo_name}")
            logger.info(f"  Set pushed_at: {latest_finding}")
            logger.info(f"  Findings: {finding_count}")
            logger.info(f"  Status: Marked as archived (404 on GitHub)\n")

            updated += 1

        db.commit()

        logger.info("=" * 60)
        logger.info(f"Update complete!")
        logger.info(f"  {updated} repositories updated")
        logger.info(f"  All marked as archived (don't exist on GitHub)")
        logger.info(f"  pushed_at set to latest finding date for scheduling")
        logger.info("=" * 60)

    except Exception as e:
        logger.error(f"Error during update: {e}")
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    update_pushed_at_from_findings()
