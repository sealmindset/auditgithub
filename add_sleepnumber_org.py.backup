#!/usr/bin/env python3
"""
Add the Sleep Number organization and import its repositories.

Usage:
    python add_sleepnumber_org.py [--import-repos]
"""

import sys
import os
import argparse
import requests
from datetime import datetime

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.api.database import SessionLocal, MULTI_TENANT_ENABLED
from src.api.database_router import database_router
from src.api import models
from src.api.config import settings


def create_sleepnumber_organization(db):
    """Create the Sleep Number organization in the database."""
    print("Checking if 'sleepnumber' organization already exists...")

    # Check if organization already exists
    existing_org = db.query(models.Organization).filter(
        models.Organization.name == "sleepnumber"
    ).first()

    if existing_org:
        print(f"✓ Organization 'sleepnumber' already exists (ID: {existing_org.id})")
        return existing_org

    # Create new organization
    print("Creating 'sleepnumber' organization...")
    new_org = models.Organization(
        name="sleepnumber",
        github_org="sleepnumber",
        display_name="Sleep Number",
        is_default=False,  # Don't make it default (sleepnumberlabs is default)
        is_active=True
    )

    db.add(new_org)
    db.commit()
    db.refresh(new_org)

    print(f"✓ Created organization 'sleepnumber' (ID: {new_org.id})")
    return new_org


def get_github_repos(org_name: str, token: str):
    """Fetch all repositories from GitHub organization."""
    print(f"Fetching repositories from GitHub organization '{org_name}'...")

    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AuditGH/1.0"
    }

    repos = []
    page = 1
    per_page = 100

    while True:
        url = f"https://api.github.com/orgs/{org_name}/repos"
        params = {
            "type": "all",  # all, public, private
            "per_page": per_page,
            "page": page,
            "sort": "updated",
            "direction": "desc"
        }

        try:
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            page_repos = response.json()

            if not page_repos:
                break

            repos.extend(page_repos)
            print(f"  Fetched {len(repos)} repositories so far...")

            # Check if there are more pages
            if len(page_repos) < per_page:
                break

            page += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                print(f"✗ Error: Organization '{org_name}' not found on GitHub")
                print(f"  Make sure you have access to the organization")
                return None
            elif e.response.status_code == 401:
                print(f"✗ Error: Invalid GitHub token")
                print(f"  Check that GITHUB_TOKEN is correct in .env")
                return None
            else:
                print(f"✗ Error fetching repositories: {e}")
                return None
        except Exception as e:
            print(f"✗ Error: {e}")
            return None

    print(f"✓ Found {len(repos)} repositories in '{org_name}' organization")
    return repos


def parse_github_datetime(dt_str: str):
    """Parse GitHub API datetime string."""
    if not dt_str:
        return None
    try:
        return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return None


def import_repository(db, org_id: str, github_repo: dict):
    """Import a single repository into the database."""
    repo_name = github_repo['name']

    # Check if repository already exists
    existing_repo = db.query(models.Repository).filter(
        models.Repository.organization_id == org_id,
        models.Repository.name == repo_name
    ).first()

    if existing_repo:
        # Update existing repository
        existing_repo.full_name = github_repo.get('full_name')
        existing_repo.url = github_repo.get('html_url')
        existing_repo.description = github_repo.get('description')
        existing_repo.default_branch = github_repo.get('default_branch', 'main')
        existing_repo.language = github_repo.get('language')
        existing_repo.pushed_at = parse_github_datetime(github_repo.get('pushed_at'))
        existing_repo.github_created_at = parse_github_datetime(github_repo.get('created_at'))
        existing_repo.github_updated_at = parse_github_datetime(github_repo.get('updated_at'))
        existing_repo.stargazers_count = github_repo.get('stargazers_count', 0)
        existing_repo.watchers_count = github_repo.get('watchers_count', 0)
        existing_repo.forks_count = github_repo.get('forks_count', 0)
        existing_repo.open_issues_count = github_repo.get('open_issues_count', 0)
        existing_repo.size_kb = github_repo.get('size', 0)
        existing_repo.is_fork = github_repo.get('fork', False)
        existing_repo.is_archived = github_repo.get('archived', False)
        existing_repo.is_disabled = github_repo.get('disabled', False)
        existing_repo.is_private = github_repo.get('private', True)
        existing_repo.visibility = github_repo.get('visibility')
        existing_repo.topics = github_repo.get('topics', [])

        # License
        license_info = github_repo.get('license')
        if license_info and isinstance(license_info, dict):
            existing_repo.license_name = license_info.get('spdx_id') or license_info.get('name')

        # Wiki/Pages/Discussions
        existing_repo.has_wiki = github_repo.get('has_wiki', False)
        existing_repo.has_pages = github_repo.get('has_pages', False)
        existing_repo.has_discussions = github_repo.get('has_discussions', False)

        return existing_repo, False  # False = updated, not created

    # Create new repository
    new_repo = models.Repository(
        organization_id=org_id,
        name=repo_name,
        full_name=github_repo.get('full_name'),
        url=github_repo.get('html_url'),
        description=github_repo.get('description'),
        default_branch=github_repo.get('default_branch', 'main'),
        language=github_repo.get('language'),
        pushed_at=parse_github_datetime(github_repo.get('pushed_at')),
        github_created_at=parse_github_datetime(github_repo.get('created_at')),
        github_updated_at=parse_github_datetime(github_repo.get('updated_at')),
        stargazers_count=github_repo.get('stargazers_count', 0),
        watchers_count=github_repo.get('watchers_count', 0),
        forks_count=github_repo.get('forks_count', 0),
        open_issues_count=github_repo.get('open_issues_count', 0),
        size_kb=github_repo.get('size', 0),
        is_fork=github_repo.get('fork', False),
        is_archived=github_repo.get('archived', False),
        is_disabled=github_repo.get('disabled', False),
        is_private=github_repo.get('private', True),
        visibility=github_repo.get('visibility'),
        topics=github_repo.get('topics', []),
        has_wiki=github_repo.get('has_wiki', False),
        has_pages=github_repo.get('has_pages', False),
        has_discussions=github_repo.get('has_discussions', False)
    )

    # License
    license_info = github_repo.get('license')
    if license_info and isinstance(license_info, dict):
        new_repo.license_name = license_info.get('spdx_id') or license_info.get('name')

    db.add(new_repo)
    return new_repo, True  # True = created new


def import_github_repositories(db, org, github_repos):
    """Import all GitHub repositories into the database."""
    print(f"\nImporting {len(github_repos)} repositories...")

    created_count = 0
    updated_count = 0
    failed_count = 0

    for i, github_repo in enumerate(github_repos, 1):
        repo_name = github_repo['name']
        try:
            repo, is_new = import_repository(db, org.id, github_repo)
            db.commit()

            if is_new:
                created_count += 1
                print(f"  [{i}/{len(github_repos)}] ✓ Created: {repo_name}")
            else:
                updated_count += 1
                print(f"  [{i}/{len(github_repos)}] ↻ Updated: {repo_name}")

        except Exception as e:
            failed_count += 1
            print(f"  [{i}/{len(github_repos)}] ✗ Failed: {repo_name} - {e}")
            db.rollback()

    print(f"\n" + "=" * 80)
    print(f"Import Summary:")
    print(f"  Created: {created_count}")
    print(f"  Updated: {updated_count}")
    print(f"  Failed: {failed_count}")
    print(f"  Total: {len(github_repos)}")
    print("=" * 80)


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Add Sleep Number organization and import its repositories"
    )
    parser.add_argument(
        "--import-repos",
        action="store_true",
        help="Import repositories from GitHub after creating the organization"
    )

    args = parser.parse_args()

    print("=" * 80)
    print("Add Sleep Number Organization")
    print("=" * 80)
    print()

    # Get database session
    if MULTI_TENANT_ENABLED:
        print("Multi-tenant mode enabled - using default tenant")
        db = database_router.get_session("default")
        if not db:
            print("✗ Error: Failed to get database session")
            sys.exit(1)
    else:
        db = SessionLocal()

    try:
        # Step 1: Create organization
        org = create_sleepnumber_organization(db)

        if not args.import_repos:
            print()
            print("Organization created successfully!")
            print()
            print("To import repositories from GitHub, run:")
            print("  python add_sleepnumber_org.py --import-repos")
            return

        # Step 2: Import repositories from GitHub
        print()
        github_token = settings.GITHUB_TOKEN or os.getenv("GITHUB_TOKEN")
        if not github_token:
            print("✗ Error: GITHUB_TOKEN not set in .env file")
            print("  Add GITHUB_TOKEN=your_token to .env")
            sys.exit(1)

        github_repos = get_github_repos("sleepnumber", github_token)
        if github_repos is None:
            print("✗ Failed to fetch repositories from GitHub")
            sys.exit(1)

        if len(github_repos) == 0:
            print("No repositories found in the 'sleepnumber' organization")
            return

        # Ask for confirmation
        print()
        response = input(f"Import {len(github_repos)} repositories? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            print("Cancelled.")
            return

        # Import repositories
        import_github_repositories(db, org, github_repos)

        print()
        print("✓ All done! You can now:")
        print("  1. View repositories in the UI")
        print("  2. Run batch architecture generation:")
        print("     ./gen-arch-batch-docker.sh \"sleepnumber\" --skip-if-exists --delay=60")

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
    finally:
        db.close()


if __name__ == "__main__":
    main()
