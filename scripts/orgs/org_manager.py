#!/usr/bin/env python3
"""
Organization Manager CLI Backend

Provides CLI functionality for organization management operations:
- Create, read, update, delete organizations
- Import and sync repositories
- Manage credentials
- Set default organization

Can be used directly or via shell wrappers (org.sh, manage-orgs.sh).
"""

import sys
import os
import argparse
import json
from typing import Optional, List, Dict, Any
from datetime import datetime
import requests

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.api.database import SessionLocal, MULTI_TENANT_ENABLED
from src.api.database_router import database_router
from src.api import models


class OrgManager:
    """Organization management backend."""

    def __init__(self):
        """Initialize organization manager."""
        self.db = None
        self._init_database()

    def _init_database(self):
        """Initialize database connection."""
        if MULTI_TENANT_ENABLED:
            self.db = database_router.get_session("default")
            if not self.db:
                raise RuntimeError("Failed to get database session")
        else:
            self.db = SessionLocal()

    def close(self):
        """Close database connection."""
        if self.db:
            self.db.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    # =========================================================================
    # Organization CRUD Operations
    # =========================================================================

    def list_organizations(self, include_inactive: bool = False, json_output: bool = False) -> List[Dict[str, Any]]:
        """
        List all organizations.

        Args:
            include_inactive: Include inactive organizations
            json_output: Return JSON instead of printing

        Returns:
            List of organization dictionaries
        """
        query = self.db.query(models.Organization)
        if not include_inactive:
            query = query.filter(models.Organization.is_active == True)

        orgs = query.order_by(
            models.Organization.is_default.desc(),
            models.Organization.name
        ).all()

        result = []
        for org in orgs:
            # Get counts
            repo_count = self.db.query(models.Repository).filter(
                models.Repository.organization_id == org.id
            ).count()

            finding_count = self.db.query(models.Finding).filter(
                models.Finding.organization_id == org.id
            ).count()

            org_dict = {
                "id": str(org.id),
                "api_id": org.api_id,
                "name": org.name,
                "display_name": org.display_name,
                "github_org": org.github_org,
                "is_active": org.is_active if org.is_active is not None else True,
                "is_default": org.is_default if org.is_default is not None else False,
                "total_repos": repo_count,
                "total_findings": finding_count,
                "created_at": org.created_at.isoformat() if org.created_at else None,
                "updated_at": org.updated_at.isoformat() if org.updated_at else None
            }
            result.append(org_dict)

        if json_output:
            return result

        # Print formatted output
        if not result:
            print("No organizations found")
            return result

        print(f"\n{'='*100}")
        print(f"{'Name':<20} {'GitHub Org':<20} {'Display Name':<25} {'Repos':<8} {'Active':<8} {'Default':<8}")
        print(f"{'='*100}")

        for org in result:
            name = org['name']
            github_org = org['github_org']
            display = org['display_name'] or '-'
            repos = org['total_repos']
            active = '✓' if org['is_active'] else '✗'
            default = '✓' if org['is_default'] else ''

            print(f"{name:<20} {github_org:<20} {display:<25} {repos:<8} {active:<8} {default:<8}")

        print(f"{'='*100}\n")
        return result

    def get_organization(self, org_name: str, json_output: bool = False) -> Optional[Dict[str, Any]]:
        """
        Get organization details by name.

        Args:
            org_name: Organization name
            json_output: Return JSON instead of printing

        Returns:
            Organization dictionary or None if not found
        """
        org = self.db.query(models.Organization).filter(
            models.Organization.name.ilike(org_name)
        ).first()

        if not org:
            print(f"✗ Organization '{org_name}' not found")
            return None

        # Get counts
        repo_count = self.db.query(models.Repository).filter(
            models.Repository.organization_id == org.id
        ).count()

        finding_count = self.db.query(models.Finding).filter(
            models.Finding.organization_id == org.id
        ).count()

        org_dict = {
            "id": str(org.id),
            "api_id": org.api_id,
            "name": org.name,
            "display_name": org.display_name,
            "github_org": org.github_org,
            "database_name": org.database_name,
            "is_active": org.is_active if org.is_active is not None else True,
            "is_default": org.is_default if org.is_default is not None else False,
            "total_repos": repo_count,
            "total_findings": finding_count,
            "created_at": org.created_at.isoformat() if org.created_at else None,
            "updated_at": org.updated_at.isoformat() if org.updated_at else None
        }

        if json_output:
            return org_dict

        # Print formatted output
        print(f"\n{'='*80}")
        print(f"Organization: {org.name}")
        print(f"{'='*80}")
        print(f"ID:           {org.id}")
        print(f"API ID:       {org.api_id}")
        print(f"Display Name: {org.display_name or '-'}")
        print(f"GitHub Org:   {org.github_org}")
        print(f"Database:     {org.database_name or '-'}")
        print(f"Active:       {'Yes' if org_dict['is_active'] else 'No'}")
        print(f"Default:      {'Yes' if org_dict['is_default'] else 'No'}")
        print(f"Repositories: {repo_count}")
        print(f"Findings:     {finding_count}")
        print(f"Created:      {org_dict['created_at'] or '-'}")
        print(f"Updated:      {org_dict['updated_at'] or '-'}")
        print(f"{'='*80}\n")

        return org_dict

    def create_organization(
        self,
        name: str,
        github_org: str,
        github_token: str,
        display_name: Optional[str] = None,
        set_as_default: bool = False
    ) -> Dict[str, Any]:
        """
        Create a new organization.

        Args:
            name: Internal name (lowercase, alphanumeric)
            github_org: GitHub organization name
            github_token: GitHub personal access token
            display_name: Human-readable display name
            set_as_default: Set as default organization

        Returns:
            Created organization dictionary
        """
        # Check if organization already exists
        existing = self.db.query(models.Organization).filter(
            models.Organization.name == name
        ).first()

        if existing:
            raise ValueError(f"Organization '{name}' already exists")

        # If setting as default, unset existing default
        if set_as_default:
            self.db.query(models.Organization).filter(
                models.Organization.is_default == True
            ).update({"is_default": False})

        # Create organization
        new_org = models.Organization(
            name=name,
            github_org=github_org,
            display_name=display_name or name.title(),
            is_default=set_as_default,
            is_active=True
        )

        self.db.add(new_org)
        self.db.commit()
        self.db.refresh(new_org)

        print(f"✓ Created organization '{name}' (ID: {new_org.id})")

        # Store credentials (simplified - in production use secrets manager)
        # For now, we'll just note that credentials should be set via environment
        print(f"✓ Note: Set GitHub credentials using environment variables or secrets manager")

        return {
            "id": str(new_org.id),
            "name": new_org.name,
            "github_org": new_org.github_org,
            "display_name": new_org.display_name,
            "is_default": new_org.is_default,
            "is_active": new_org.is_active
        }

    def update_organization(
        self,
        org_name: str,
        display_name: Optional[str] = None,
        is_active: Optional[bool] = None,
        set_as_default: Optional[bool] = None
    ) -> Dict[str, Any]:
        """
        Update organization properties.

        Args:
            org_name: Organization name
            display_name: New display name
            is_active: Set active status
            set_as_default: Set as default organization

        Returns:
            Updated organization dictionary
        """
        org = self.db.query(models.Organization).filter(
            models.Organization.name.ilike(org_name)
        ).first()

        if not org:
            raise ValueError(f"Organization '{org_name}' not found")

        # Update fields
        if display_name is not None:
            org.display_name = display_name

        if is_active is not None:
            org.is_active = is_active

        if set_as_default is not None and set_as_default:
            # Unset other defaults
            self.db.query(models.Organization).filter(
                models.Organization.is_default == True,
                models.Organization.id != org.id
            ).update({"is_default": False})
            org.is_default = True

        self.db.commit()
        self.db.refresh(org)

        print(f"✓ Updated organization '{org_name}'")

        return {
            "id": str(org.id),
            "name": org.name,
            "display_name": org.display_name,
            "is_active": org.is_active,
            "is_default": org.is_default
        }

    def delete_organization(self, org_name: str, force: bool = False) -> bool:
        """
        Delete an organization.

        Args:
            org_name: Organization name
            force: Skip confirmation

        Returns:
            True if deleted successfully
        """
        org = self.db.query(models.Organization).filter(
            models.Organization.name.ilike(org_name)
        ).first()

        if not org:
            print(f"✗ Organization '{org_name}' not found")
            return False

        # Check if it's the default org
        if org.is_default and not force:
            print(f"✗ Cannot delete default organization without --force flag")
            return False

        # Get counts for warning
        repo_count = self.db.query(models.Repository).filter(
            models.Repository.organization_id == org.id
        ).count()

        if repo_count > 0 and not force:
            print(f"✗ Organization has {repo_count} repositories")
            print(f"  Use --force to delete anyway")
            return False

        # Delete organization
        self.db.delete(org)
        self.db.commit()

        print(f"✓ Deleted organization '{org_name}'")
        return True

    # =========================================================================
    # Repository Operations
    # =========================================================================

    def import_repositories(self, org_name: str, github_token: Optional[str] = None) -> Dict[str, Any]:
        """
        Import all repositories from GitHub for an organization.

        Args:
            org_name: Organization name
            github_token: GitHub token (optional, uses env if not provided)

        Returns:
            Import result dictionary
        """
        org = self.db.query(models.Organization).filter(
            models.Organization.name.ilike(org_name)
        ).first()

        if not org:
            raise ValueError(f"Organization '{org_name}' not found")

        # Get GitHub token
        if not github_token:
            github_token = os.getenv("GITHUB_TOKEN")

        if not github_token:
            raise ValueError("GitHub token not provided and GITHUB_TOKEN env var not set")

        print(f"Fetching repositories from GitHub organization '{org.github_org}'...")

        # Fetch repos from GitHub API
        headers = {
            "Authorization": f"token {github_token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AuditGH/1.0"
        }

        repos = []
        page = 1
        per_page = 100

        while True:
            url = f"https://api.github.com/orgs/{org.github_org}/repos"
            params = {
                "type": "all",
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "direction": "desc"
            }

            try:
                response = requests.get(url, headers=headers, params=params, timeout=30)
                response.raise_for_status()
                page_repos = response.json()

                if not page_repos:
                    break

                repos.extend(page_repos)
                print(f"  Fetched {len(repos)} repositories so far...")

                if len(page_repos) < per_page:
                    break

                page += 1

            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 404:
                    raise ValueError(f"GitHub organization '{org.github_org}' not found")
                elif e.response.status_code == 401:
                    raise ValueError("Invalid GitHub token")
                else:
                    raise RuntimeError(f"GitHub API error: {str(e)}")

        if len(repos) == 0:
            print(f"No repositories found in GitHub organization '{org.github_org}'")
            return {
                "total": 0,
                "created": 0,
                "updated": 0,
                "failed": 0
            }

        print(f"✓ Found {len(repos)} repositories")
        print(f"\nImporting {len(repos)} repositories...")

        # Import repositories
        created_count = 0
        updated_count = 0
        failed_count = 0

        def parse_github_datetime(dt_str):
            if not dt_str:
                return None
            try:
                return datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
            except Exception:
                return None

        for i, github_repo in enumerate(repos, 1):
            repo_name = github_repo['name']
            try:
                # Check if repository already exists
                existing_repo = self.db.query(models.Repository).filter(
                    models.Repository.organization_id == org.id,
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
                    existing_repo.has_wiki = github_repo.get('has_wiki', False)
                    existing_repo.has_pages = github_repo.get('has_pages', False)
                    existing_repo.has_discussions = github_repo.get('has_discussions', False)

                    # License
                    license_info = github_repo.get('license')
                    if license_info and isinstance(license_info, dict):
                        existing_repo.license_name = license_info.get('spdx_id') or license_info.get('name')

                    updated_count += 1
                    print(f"  [{i}/{len(repos)}] ↻ Updated: {repo_name}")
                else:
                    # Create new repository
                    new_repo = models.Repository(
                        organization_id=org.id,
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

                    self.db.add(new_repo)
                    created_count += 1
                    print(f"  [{i}/{len(repos)}] ✓ Created: {repo_name}")

                self.db.commit()

            except Exception as e:
                failed_count += 1
                print(f"  [{i}/{len(repos)}] ✗ Failed: {repo_name} - {e}")
                self.db.rollback()

        print(f"\n{'='*80}")
        print(f"Import Summary:")
        print(f"  Created: {created_count}")
        print(f"  Updated: {updated_count}")
        print(f"  Failed: {failed_count}")
        print(f"  Total: {len(repos)}")
        print(f"{'='*80}\n")

        return {
            "total": len(repos),
            "created": created_count,
            "updated": updated_count,
            "failed": failed_count
        }


def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="Organization Manager CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all organizations
  python org_manager.py list

  # Get organization details
  python org_manager.py show sleepnumber

  # Create new organization
  python org_manager.py create myorg github-org-name ghp_token123

  # Update organization
  python org_manager.py update myorg --display-name "My Organization"

  # Import repositories
  python org_manager.py import sleepnumber

  # Delete organization
  python org_manager.py delete myorg --force
        """
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # List command
    list_parser = subparsers.add_parser("list", help="List all organizations")
    list_parser.add_argument("--include-inactive", action="store_true", help="Include inactive organizations")
    list_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Show command
    show_parser = subparsers.add_parser("show", help="Show organization details")
    show_parser.add_argument("name", help="Organization name")
    show_parser.add_argument("--json", action="store_true", help="Output as JSON")

    # Create command
    create_parser = subparsers.add_parser("create", help="Create new organization")
    create_parser.add_argument("name", help="Organization name (lowercase, alphanumeric)")
    create_parser.add_argument("github_org", help="GitHub organization name")
    create_parser.add_argument("github_token", help="GitHub personal access token")
    create_parser.add_argument("--display-name", help="Human-readable display name")
    create_parser.add_argument("--set-default", action="store_true", help="Set as default organization")

    # Update command
    update_parser = subparsers.add_parser("update", help="Update organization")
    update_parser.add_argument("name", help="Organization name")
    update_parser.add_argument("--display-name", help="New display name")
    update_parser.add_argument("--active", type=lambda x: x.lower() == 'true', help="Set active status (true/false)")
    update_parser.add_argument("--set-default", action="store_true", help="Set as default organization")

    # Delete command
    delete_parser = subparsers.add_parser("delete", help="Delete organization")
    delete_parser.add_argument("name", help="Organization name")
    delete_parser.add_argument("--force", action="store_true", help="Force deletion without confirmation")

    # Import command
    import_parser = subparsers.add_parser("import", help="Import repositories from GitHub")
    import_parser.add_argument("name", help="Organization name")
    import_parser.add_argument("--token", help="GitHub token (uses GITHUB_TOKEN env var if not provided)")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    # Execute command
    try:
        with OrgManager() as manager:
            if args.command == "list":
                manager.list_organizations(
                    include_inactive=args.include_inactive,
                    json_output=args.json
                )

            elif args.command == "show":
                result = manager.get_organization(args.name, json_output=args.json)
                if args.json and result:
                    print(json.dumps(result, indent=2))

            elif args.command == "create":
                result = manager.create_organization(
                    name=args.name,
                    github_org=args.github_org,
                    github_token=args.github_token,
                    display_name=args.display_name,
                    set_as_default=args.set_default
                )

            elif args.command == "update":
                result = manager.update_organization(
                    org_name=args.name,
                    display_name=args.display_name,
                    is_active=args.active,
                    set_as_default=args.set_default
                )

            elif args.command == "delete":
                manager.delete_organization(args.name, force=args.force)

            elif args.command == "import":
                manager.import_repositories(args.name, github_token=args.token)

    except Exception as e:
        print(f"✗ Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
