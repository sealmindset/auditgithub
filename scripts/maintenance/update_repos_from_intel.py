#!/usr/bin/env python3
"""
Update repository metadata from intel.json and cloc.json files.

This script reads metadata from existing scan reports and updates the database
with commit dates, languages, descriptions, and other GitHub metadata.

Usage:
    python update_repos_from_intel.py [--org ORG_NAME] [--dry-run]

Examples:
    python update_repos_from_intel.py --org SleepNumberInc
    python update_repos_from_intel.py --org sleepnumberlabs --dry-run
    python update_repos_from_intel.py  # Updates all organizations
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime
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

# Reports directory
REPORTS_DIR = Path(os.getenv('REPORTS_DIR', '/app/vulnerability_reports'))
if not REPORTS_DIR.exists():
    REPORTS_DIR = Path('vulnerability_reports')


def get_repo_metadata_from_files(org_name, repo_name):
    """
    Extract repository metadata from intel.json and cloc.json files.

    Returns dict with: pushed_at, language, description, default_branch, total_commits, contributor_count
    """
    metadata = {
        'pushed_at': None,
        'language': None,
        'description': None,
        'default_branch': None,
        'total_commits': None,
        'contributor_count': None
    }

    # Try to find intel.json in different locations
    intel_paths = [
        REPORTS_DIR / org_name / repo_name / f"{repo_name}_intel.json",
        REPORTS_DIR / repo_name / f"{repo_name}_intel.json",
    ]

    intel_data = None
    for intel_path in intel_paths:
        if intel_path.exists():
            try:
                with open(intel_path, 'r') as f:
                    intel_data = json.load(f)
                logger.debug(f"Found intel.json at {intel_path}")
                break
            except json.JSONDecodeError as e:
                logger.warning(f"Invalid JSON in {intel_path}: {e}")
            except Exception as e:
                logger.warning(f"Error reading {intel_path}: {e}")

    if not intel_data:
        logger.debug(f"No intel.json found for {org_name}/{repo_name}")
        return metadata

    # Extract last commit date from contributors
    if "contributors" in intel_data:
        contributors = intel_data["contributors"]

        # Get total commits and contributor count
        if "total_commits" in contributors:
            metadata['total_commits'] = contributors["total_commits"]
        if "total_contributors" in contributors:
            metadata['contributor_count'] = contributors["total_contributors"]

        # Get latest commit date from top contributors
        if "top_contributors" in contributors:
            for contributor in contributors["top_contributors"]:
                if "last_commit_at" in contributor and contributor["last_commit_at"]:
                    try:
                        # Parse ISO format datetime
                        commit_date_str = contributor["last_commit_at"]
                        # Handle both with and without timezone
                        if commit_date_str.endswith('Z'):
                            commit_date_str = commit_date_str.replace('Z', '+00:00')
                        commit_date = datetime.fromisoformat(commit_date_str)

                        if metadata['pushed_at'] is None or commit_date > metadata['pushed_at']:
                            metadata['pushed_at'] = commit_date
                    except Exception as e:
                        logger.debug(f"Error parsing commit date '{contributor.get('last_commit_at')}': {e}")

    # Extract primary language from cloc.json if available
    cloc_paths = [
        REPORTS_DIR / org_name / repo_name / f"{repo_name}_cloc.json",
        REPORTS_DIR / repo_name / f"{repo_name}_cloc.json",
    ]

    for cloc_path in cloc_paths:
        if cloc_path.exists():
            try:
                with open(cloc_path, 'r') as f:
                    cloc_data = json.load(f)

                # Get language with most code lines (exclude SUM and header)
                langs = {
                    k: v for k, v in cloc_data.items()
                    if k not in ['SUM', 'header']
                    and isinstance(v, dict)
                    and 'code' in v
                }

                if langs:
                    # Get language with highest code count
                    metadata['language'] = max(langs.items(), key=lambda x: x[1]['code'])[0]
                    logger.debug(f"Found language '{metadata['language']}' from cloc.json")
                break
            except Exception as e:
                logger.debug(f"Error reading cloc.json from {cloc_path}: {e}")

    # Fallback to intel.json languages if cloc didn't work
    if not metadata['language'] and "languages" in intel_data and intel_data["languages"]:
        languages = intel_data["languages"]
        if isinstance(languages, dict):
            # Filter out non-numeric values and get max
            numeric_langs = {k: v for k, v in languages.items() if isinstance(v, (int, float))}
            if numeric_langs:
                metadata['language'] = max(numeric_langs.items(), key=lambda x: x[1])[0]
        elif isinstance(languages, list) and languages:
            # If it's a list, take the first language
            metadata['language'] = languages[0]

    # Extract description from repository metadata if available
    if "repository" in intel_data:
        repo_info = intel_data["repository"]
        if "description" in repo_info and repo_info["description"]:
            metadata['description'] = repo_info["description"]
        if "default_branch" in repo_info and repo_info["default_branch"]:
            metadata['default_branch'] = repo_info["default_branch"]

    return metadata


def update_repositories_from_intel(org_name=None, dry_run=False):
    """
    Update repository metadata from intel.json files.

    Args:
        org_name: Optional organization name to filter by
        dry_run: If True, don't actually update the database
    """
    engine = create_engine(DATABASE_URL)
    Session = sessionmaker(bind=engine)
    db = Session()

    try:
        # Build query to get repositories
        query = """
            SELECT r.id, r.name, r.full_name, o.github_org, r.pushed_at, r.language
            FROM repositories r
            JOIN organizations o ON r.organization_id = o.id
        """

        if org_name:
            query += " WHERE o.github_org = :org_name"
            result = db.execute(text(query), {"org_name": org_name})
        else:
            result = db.execute(text(query))

        repositories = result.fetchall()

        if not repositories:
            logger.warning(f"No repositories found" + (f" for organization '{org_name}'" if org_name else ""))
            return

        logger.info("=" * 80)
        logger.info(f"Repository Metadata Update from Intel Files")
        logger.info("=" * 80)
        if org_name:
            logger.info(f"Target Organization: {org_name}")
        else:
            logger.info(f"Target: All organizations")
        logger.info(f"Total Repositories: {len(repositories)}")
        logger.info(f"Mode: {'DRY RUN (no changes will be made)' if dry_run else 'LIVE UPDATE'}")
        logger.info("=" * 80)
        logger.info("")

        # Track statistics
        stats = {
            'total': len(repositories),
            'updated': 0,
            'no_metadata': 0,
            'already_complete': 0,
            'errors': 0,
            'pushed_at_added': 0,
            'language_added': 0,
            'description_added': 0,
            'default_branch_added': 0
        }

        for idx, (repo_id, repo_name, full_name, github_org, current_pushed_at, current_language) in enumerate(repositories, 1):
            try:
                # Get metadata from files
                metadata = get_repo_metadata_from_files(github_org, repo_name)

                # Check if we have any new metadata
                has_updates = False
                update_fields = []

                if metadata['pushed_at'] and not current_pushed_at:
                    has_updates = True
                    update_fields.append("pushed_at")
                    stats['pushed_at_added'] += 1

                if metadata['language'] and not current_language:
                    has_updates = True
                    update_fields.append("language")
                    stats['language_added'] += 1

                if metadata['description']:
                    has_updates = True
                    update_fields.append("description")
                    stats['description_added'] += 1

                if metadata['default_branch']:
                    has_updates = True
                    update_fields.append("default_branch")
                    stats['default_branch_added'] += 1

                if not has_updates:
                    if not metadata['pushed_at'] and not metadata['language']:
                        stats['no_metadata'] += 1
                        logger.debug(f"[{idx}/{stats['total']}] No metadata found: {github_org}/{repo_name}")
                    else:
                        stats['already_complete'] += 1
                        logger.debug(f"[{idx}/{stats['total']}] Already complete: {github_org}/{repo_name}")
                    continue

                # Log what will be updated
                logger.info(f"[{idx}/{stats['total']}] {github_org}/{repo_name}")
                logger.info(f"  Updating: {', '.join(update_fields)}")
                if metadata['pushed_at']:
                    logger.info(f"    pushed_at: {metadata['pushed_at']}")
                if metadata['language']:
                    logger.info(f"    language: {metadata['language']}")
                if metadata['total_commits']:
                    logger.info(f"    commits: {metadata['total_commits']}")
                if metadata['contributor_count']:
                    logger.info(f"    contributors: {metadata['contributor_count']}")

                if not dry_run:
                    # Update the database
                    db.execute(
                        text("""
                            UPDATE repositories
                            SET pushed_at = COALESCE(:pushed_at, pushed_at),
                                language = COALESCE(:language, language),
                                description = COALESCE(:description, description),
                                default_branch = COALESCE(:default_branch, default_branch),
                                updated_at = NOW()
                            WHERE id = :repo_id
                        """),
                        {
                            'repo_id': repo_id,
                            'pushed_at': metadata['pushed_at'],
                            'language': metadata['language'],
                            'description': metadata['description'],
                            'default_branch': metadata['default_branch']
                        }
                    )
                    db.commit()

                stats['updated'] += 1

            except Exception as e:
                logger.error(f"Error processing {github_org}/{repo_name}: {e}")
                stats['errors'] += 1
                if not dry_run:
                    db.rollback()

        # Print summary
        logger.info("")
        logger.info("=" * 80)
        logger.info("Update Complete!")
        logger.info("=" * 80)
        logger.info(f"Total Repositories: {stats['total']}")
        logger.info(f"Updated: {stats['updated']}")
        logger.info(f"  - Added pushed_at: {stats['pushed_at_added']}")
        logger.info(f"  - Added language: {stats['language_added']}")
        logger.info(f"  - Added description: {stats['description_added']}")
        logger.info(f"  - Added default_branch: {stats['default_branch_added']}")
        logger.info(f"No metadata found: {stats['no_metadata']}")
        logger.info(f"Already complete: {stats['already_complete']}")
        logger.info(f"Errors: {stats['errors']}")
        logger.info("=" * 80)

        if dry_run:
            logger.info("")
            logger.info("NOTE: This was a DRY RUN. No changes were made to the database.")
            logger.info("Remove --dry-run flag to actually update the database.")

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
        description='Update repository metadata from intel.json and cloc.json files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --org SleepNumberInc              # Update only SleepNumberInc repos
  %(prog)s --org sleepnumberlabs --dry-run   # Preview changes for sleepnumberlabs
  %(prog)s                                   # Update all organizations
        """
    )

    parser.add_argument(
        '--org',
        type=str,
        help='Organization name to update (e.g., SleepNumberInc, sleepnumberlabs). If omitted, updates all orgs.'
    )

    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Preview changes without actually updating the database'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose debug logging'
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    update_repositories_from_intel(org_name=args.org, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
