#!/usr/bin/env python3
"""
Script to manage the default organization setting in the database.

Usage:
    python scripts/manage_default_org.py --list                     # List all orgs and show which is default
    python scripts/manage_default_org.py --set ORG_NAME             # Set a specific org as default
    python scripts/manage_default_org.py --clear                    # Clear the default (no org is default)
    python scripts/manage_default_org.py --rename OLD_NAME NEW_NAME # Rename an organization
    python scripts/manage_default_org.py --sync                     # Sync default org from DEFAULT_GITHUB_ORG in .env
    python scripts/manage_default_org.py --delete ORG_NAME          # Delete an organization (requires --force)
"""

import argparse
import os
import sys
import uuid
from pathlib import Path

# Add parent directory to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

import psycopg2
from psycopg2.extras import RealDictCursor


def get_db_connection():
    """Get database connection using environment variables."""
    return psycopg2.connect(
        host=os.getenv("POSTGRES_HOST", "localhost"),
        port=os.getenv("POSTGRES_PORT", "5432"),
        user=os.getenv("POSTGRES_USER", "auditgh"),
        password=os.getenv("POSTGRES_PASSWORD", "auditgh_secret"),
        database=os.getenv("POSTGRES_DB", "auditgh_kb"),
    )


def list_organizations():
    """List all organizations and show which is default."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT name, github_org, is_default, created_at
                FROM organizations
                ORDER BY is_default DESC, name ASC
            """)
            orgs = cur.fetchall()

            # Show env config
            env_default = os.getenv("DEFAULT_GITHUB_ORG", "")
            print(f"\n.env DEFAULT_GITHUB_ORG: {env_default or '(not set)'}")

            if not orgs:
                print("\nNo organizations found in database.")
                if env_default:
                    print(f"\nRun --sync to create '{env_default}' from .env")
                return

            print("\nOrganizations in database:")
            print("-" * 60)
            for org in orgs:
                default_marker = " ★ DEFAULT" if org['is_default'] else ""
                print(f"  {org['name']:<30} (github: {org['github_org']}){default_marker}")
            print("-" * 60)
            print(f"Total: {len(orgs)} organization(s)\n")
    finally:
        conn.close()


def set_default_organization(org_name: str):
    """Set a specific organization as the default."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if org exists
            cur.execute("SELECT id, name FROM organizations WHERE name = %s", (org_name,))
            org = cur.fetchone()

            if not org:
                print(f"Error: Organization '{org_name}' not found.")
                print("\nAvailable organizations:")
                cur.execute("SELECT name FROM organizations ORDER BY name")
                for row in cur.fetchall():
                    print(f"  - {row['name']}")
                return False

            # Clear existing default
            cur.execute("UPDATE organizations SET is_default = false WHERE is_default = true")

            # Set new default
            cur.execute("UPDATE organizations SET is_default = true WHERE name = %s", (org_name,))
            conn.commit()

            print(f"✓ Set '{org_name}' as the default organization.")
            return True
    finally:
        conn.close()


def clear_default_organization():
    """Clear the default organization (no org will be default)."""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("UPDATE organizations SET is_default = false WHERE is_default = true")
            rows_affected = cur.rowcount
            conn.commit()

            if rows_affected > 0:
                print("✓ Cleared default organization. No organization is now set as default.")
            else:
                print("No default organization was set.")
            return True
    finally:
        conn.close()


def rename_organization(old_name: str, new_name: str):
    """Rename an organization (updates both name and github_org)."""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if old org exists
            cur.execute("SELECT id, name, github_org FROM organizations WHERE name = %s", (old_name,))
            org = cur.fetchone()

            if not org:
                print(f"Error: Organization '{old_name}' not found.")
                return False

            # Check if new name already exists
            cur.execute("SELECT id FROM organizations WHERE name = %s", (new_name,))
            if cur.fetchone():
                print(f"Error: Organization '{new_name}' already exists.")
                return False

            # Rename the organization
            cur.execute("""
                UPDATE organizations
                SET name = %s, github_org = %s, updated_at = NOW()
                WHERE name = %s
            """, (new_name, new_name, old_name))
            conn.commit()

            print(f"✓ Renamed organization '{old_name}' to '{new_name}'")
            return True
    finally:
        conn.close()


def sync_from_env():
    """
    Sync default organization from DEFAULT_GITHUB_ORG in .env.
    Creates the org if it doesn't exist, sets it as default.
    """
    default_org = os.getenv("DEFAULT_GITHUB_ORG", "").strip()

    if not default_org:
        print("Error: DEFAULT_GITHUB_ORG is not set in .env")
        print("\nAdd this to your .env file:")
        print("  DEFAULT_GITHUB_ORG=your-org-name")
        return False

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if org already exists
            cur.execute("SELECT id, name, is_default FROM organizations WHERE name = %s", (default_org,))
            org = cur.fetchone()

            if org:
                # Org exists, just set as default if not already
                if not org['is_default']:
                    cur.execute("UPDATE organizations SET is_default = false WHERE is_default = true")
                    cur.execute("UPDATE organizations SET is_default = true WHERE name = %s", (default_org,))
                    conn.commit()
                    print(f"✓ Set existing organization '{default_org}' as default.")
                else:
                    print(f"✓ Organization '{default_org}' is already the default.")
            else:
                # Create new organization
                org_id = str(uuid.uuid4())

                # Clear any existing default
                cur.execute("UPDATE organizations SET is_default = false WHERE is_default = true")

                # Insert new org as default and active
                cur.execute("""
                    INSERT INTO organizations (id, name, github_org, is_default, is_active, created_at, updated_at)
                    VALUES (%s, %s, %s, true, true, NOW(), NOW())
                """, (org_id, default_org, default_org))
                conn.commit()

                print(f"✓ Created new organization '{default_org}' and set as default.")

            return True
    finally:
        conn.close()


def delete_organization(org_name: str, force: bool = False):
    """Delete an organization and all its associated data."""
    if not force:
        print(f"Error: Deleting '{org_name}' requires --force flag.")
        print("This will permanently delete the organization and ALL associated data.")
        print(f"\nRun: python scripts/manage_default_org.py --delete {org_name} --force")
        return False

    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if org exists
            cur.execute("SELECT id, name FROM organizations WHERE name = %s", (org_name,))
            org = cur.fetchone()

            if not org:
                print(f"Error: Organization '{org_name}' not found.")
                return False

            org_id = org['id']

            # Try to delete associated data - use CASCADE or individual deletes
            # Each delete is in its own try block to handle missing tables/columns
            cleanup_queries = [
                ("repositories (and cascaded data)", "DELETE FROM repositories WHERE organization_id = %s"),
            ]

            for desc, query in cleanup_queries:
                try:
                    cur.execute(query, (org_id,))
                    deleted = cur.rowcount
                    if deleted > 0:
                        print(f"  Deleted {deleted} from {desc}")
                    conn.commit()
                except Exception as e:
                    conn.rollback()
                    print(f"  Note: {desc} - {e}")

            # Delete the organization itself
            try:
                cur.execute("DELETE FROM organizations WHERE id = %s", (org_id,))
                conn.commit()
                print(f"\n✓ Deleted organization '{org_name}'")
                return True
            except Exception as e:
                conn.rollback()
                print(f"Error deleting organization: {e}")
                return False
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Manage organizations in the database.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scripts/manage_default_org.py --list
  python scripts/manage_default_org.py --set myorg
  python scripts/manage_default_org.py --clear
  python scripts/manage_default_org.py --rename oldname newname
  python scripts/manage_default_org.py --sync
  python scripts/manage_default_org.py --delete oldorg --force
        """
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--list", action="store_true", help="List all organizations")
    group.add_argument("--set", metavar="ORG_NAME", help="Set organization as default")
    group.add_argument("--clear", action="store_true", help="Clear the default organization")
    group.add_argument("--rename", nargs=2, metavar=("OLD_NAME", "NEW_NAME"), help="Rename an organization")
    group.add_argument("--sync", action="store_true", help="Sync default org from DEFAULT_GITHUB_ORG in .env")
    group.add_argument("--delete", metavar="ORG_NAME", help="Delete an organization (requires --force)")

    parser.add_argument("--force", action="store_true", help="Force deletion without confirmation")

    args = parser.parse_args()

    try:
        if args.list:
            list_organizations()
        elif args.set:
            set_default_organization(args.set)
        elif args.clear:
            clear_default_organization()
        elif args.rename:
            rename_organization(args.rename[0], args.rename[1])
        elif args.sync:
            sync_from_env()
        elif args.delete:
            delete_organization(args.delete, args.force)
    except psycopg2.OperationalError as e:
        print(f"Error connecting to database: {e}")
        print("\nMake sure the database is running and .env has correct credentials.")
        sys.exit(1)


if __name__ == "__main__":
    main()
