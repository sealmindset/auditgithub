#!/usr/bin/env python3
"""
Backfill missing pushed_at dates for repositories from GitHub API.

This script prioritizes repositories that have actual findings/scans.
"""

import os
import sys
import time
import logging
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
import requests

# Setup logging with immediate flush
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
# Force unbuffered output
sys.stdout.reconfigure(line_buffering=True)
logger = logging.getLogger(__name__)

# Database configuration
DB_HOST = os.getenv('POSTGRES_HOST', 'localhost')
DB_PORT = os.getenv('POSTGRES_PORT', '5432')
DB_NAME = os.getenv('POSTGRES_DB', 'security_portal')
DB_USER = os.getenv('POSTGRES_USER', 'postgres')
DB_PASS = os.getenv('POSTGRES_PASSWORD', 'postgres')

DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# GitHub configuration
GITHUB_TOKEN = os.getenv('GITHUB_TOKEN')
GITHUB_API_BASE = "https://api.github.com"

def get_github_headers():
    """Get headers for GitHub API requests."""
    headers = {
        'Accept': 'application/vnd.github.v3+json'
    }
    if GITHUB_TOKEN:
        headers['Authorization'] = f'token {GITHUB_TOKEN}'
    return headers

def parse_github_datetime(date_str):
    """Parse GitHub API datetime string to Python datetime."""
    if not date_str:
        return None
    try:
        # GitHub uses ISO 8601 format: 2024-01-15T10:30:00Z
        return datetime.fromisoformat(date_str.replace('Z', '+00:00'))
    except Exception as e:
        logger.warning(f"Failed to parse datetime '{date_str}': {e}")
        return None

def fetch_repo_from_github(org_name, repo_name):
    """Fetch repository metadata from GitHub API."""
    url = f"{GITHUB_API_BASE}/repos/{org_name}/{repo_name}"

    try:
        response = requests.get(url, headers=get_github_headers(), timeout=10)

        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            logger.warning(f"Repository not found on GitHub: {org_name}/{repo_name}")
            return None
        elif response.status_code == 403:
            logger.error(f"GitHub API rate limit exceeded or access forbidden")
            # Check rate limit
            if 'X-RateLimit-Remaining' in response.headers:
                remaining = response.headers['X-RateLimit-Remaining']
                reset_time = int(response.headers.get('X-RateLimit-Reset', 0))
                logger.error(f"Rate limit remaining: {remaining}, resets at: {datetime.fromtimestamp(reset_time)}")
            return None
        else:
            logger.error(f"GitHub API error {response.status_code}: {response.text[:200]}")
            return None

    except requests.RequestException as e:
        logger.error(f"Failed to fetch {org_name}/{repo_name}: {e}")
        return None

def backfill_pushed_at():
    """Backfill missing pushed_at dates, prioritizing repos with findings."""
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Priority 1: Get repos with findings that are missing pushed_at
        logger.info("=" * 60)
        logger.info("PRIORITY 1: Repos with findings missing pushed_at")
        logger.info("=" * 60)

        result = db.execute(text("""
            SELECT DISTINCT r.id, r.name, r.full_name, o.github_org,
                   COUNT(f.id) as finding_count
            FROM repositories r
            LEFT JOIN organizations o ON r.organization_id = o.id
            LEFT JOIN findings f ON r.id = f.repository_id
            WHERE r.pushed_at IS NULL
              AND f.id IS NOT NULL
            GROUP BY r.id, r.name, r.full_name, o.github_org
            ORDER BY finding_count DESC, r.name
        """))

        priority_repos = result.fetchall()
        logger.info(f"Found {len(priority_repos)} high-priority repositories")

        # Priority 2: Get remaining repos
        result = db.execute(text("""
            SELECT r.id, r.name, r.full_name, o.github_org
            FROM repositories r
            LEFT JOIN organizations o ON r.organization_id = o.id
            LEFT JOIN findings f ON r.id = f.repository_id
            WHERE r.pushed_at IS NULL
              AND f.id IS NULL
            ORDER BY r.name
        """))

        remaining_repos = result.fetchall()
        logger.info(f"Found {len(remaining_repos)} lower-priority repositories")
        logger.info("=" * 60)

        # Combine lists
        all_repos = [(repo[0], repo[1], repo[2], repo[3], True) for repo in priority_repos] + \
                    [(repo[0], repo[1], repo[2], repo[3], False) for repo in remaining_repos]

        total = len(all_repos)

        if total == 0:
            logger.info("No repositories missing pushed_at dates!")
            return

        logger.info(f"Starting backfill of {total} total repositories...")
        sys.stdout.flush()

        updated = 0
        skipped = 0
        errors = 0

        for idx, (repo_id, repo_name, full_name, org_name, is_priority) in enumerate(all_repos, 1):
            priority_marker = "🔴" if is_priority else "⚪"
            logger.info(f"{priority_marker} [{idx}/{total}] Processing: {full_name or f'{org_name}/{repo_name}'}")
            sys.stdout.flush()

            # Determine org and repo name
            if not org_name and full_name and '/' in full_name:
                org_name, repo_name = full_name.split('/', 1)
            elif not org_name:
                logger.warning(f"Cannot determine organization for repo ID {repo_id}, skipping")
                skipped += 1
                continue

            # Fetch from GitHub
            repo_data = fetch_repo_from_github(org_name, repo_name)

            if not repo_data:
                errors += 1
                sys.stdout.flush()
                continue

            # Extract pushed_at
            pushed_at = parse_github_datetime(repo_data.get('pushed_at'))

            if pushed_at:
                # Update database
                db.execute(text("""
                    UPDATE repositories
                    SET pushed_at = :pushed_at,
                        updated_at = NOW(),
                        is_archived = :is_archived
                    WHERE id = :repo_id
                """), {
                    'repo_id': repo_id,
                    'pushed_at': pushed_at,
                    'is_archived': repo_data.get('archived', False)
                })
                db.commit()

                logger.info(f"  ✓ Updated pushed_at: {pushed_at} (archived: {repo_data.get('archived', False)})")
                updated += 1
            else:
                logger.warning(f"  ⊘ No pushed_at in GitHub response")
                skipped += 1

            sys.stdout.flush()

            # Rate limiting: sleep between requests
            if idx % 10 == 0:
                logger.info(f"Progress: {updated} updated, {skipped} skipped, {errors} errors")
                sys.stdout.flush()
                time.sleep(1)  # Brief pause every 10 requests
            else:
                time.sleep(0.1)  # Small delay between requests

        logger.info(f"\n{'='*60}")
        logger.info(f"Backfill complete!")
        logger.info(f"  Updated: {updated}")
        logger.info(f"  Skipped: {skipped}")
        logger.info(f"  Errors (404s): {errors}")
        logger.info(f"{'='*60}")
        sys.stdout.flush()

    except Exception as e:
        logger.error(f"Fatal error during backfill: {e}")
        import traceback
        traceback.print_exc()
        db.rollback()
        raise
    finally:
        db.close()

if __name__ == "__main__":
    if not GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN environment variable not set!")
        logger.error("Please set it to avoid rate limiting: export GITHUB_TOKEN=your_token")
        logger.info("\nContinuing without token (limited to 60 requests/hour)...\n")

    backfill_pushed_at()
