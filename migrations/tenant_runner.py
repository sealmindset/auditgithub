#!/usr/bin/env python3
"""
Tenant Migration Runner for Multi-Tenant Architecture.

This script runs Alembic migrations across all tenant databases.

Usage:
    # Check migration status for all tenants
    python tenant_runner.py status
    
    # Upgrade all tenants to latest
    python tenant_runner.py upgrade head
    
    # Upgrade specific tenant
    python tenant_runner.py upgrade head --tenant org-a
    
    # Downgrade all tenants by one revision
    python tenant_runner.py downgrade -1
    
    # Retry failed migrations
    python tenant_runner.py retry-failed
"""
import argparse
import sys
import os
from datetime import datetime
from typing import List, Optional

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker


def get_metadata_db_url() -> str:
    """Get the metadata database URL from environment."""
    host = os.environ.get("POSTGRES_HOST", "localhost")
    port = os.environ.get("POSTGRES_PORT", "5432")
    user = os.environ.get("POSTGRES_USER", "auditgh")
    password = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")
    db = os.environ.get("POSTGRES_DB", "auditgh_kb")
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"


def get_tenants(filter_slug: Optional[str] = None, only_active: bool = True, only_provisioned: bool = True):
    """Fetch tenants from the metadata database."""
    engine = create_engine(get_metadata_db_url())
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        query = "SELECT id, slug, name, database_host, database_port, database_name, database_user, database_password, schema_version, migration_status, is_active, is_provisioned FROM tenants WHERE 1=1"
        
        if filter_slug:
            query += f" AND slug = '{filter_slug}'"
        if only_active:
            query += " AND is_active = true"
        if only_provisioned:
            query += " AND is_provisioned = true"
        
        query += " ORDER BY name"
        
        result = session.execute(text(query))
        tenants = []
        for row in result:
            tenants.append({
                "id": str(row[0]),
                "slug": row[1],
                "name": row[2],
                "database_host": row[3],
                "database_port": row[4],
                "database_name": row[5],
                "database_user": row[6],
                "database_password": row[7],
                "schema_version": row[8],
                "migration_status": row[9],
                "is_active": row[10],
                "is_provisioned": row[11],
            })
        return tenants
    finally:
        session.close()
        engine.dispose()


def update_tenant_status(tenant_slug: str, version: str, status: str, error: Optional[str] = None):
    """Update tenant migration status in metadata database."""
    engine = create_engine(get_metadata_db_url())
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        error_clause = f", migration_error = '{error}'" if error else ", migration_error = NULL"
        query = f"""
            UPDATE tenants 
            SET schema_version = '{version}', 
                migration_status = '{status}',
                last_migration_at = NOW()
                {error_clause}
            WHERE slug = '{tenant_slug}'
        """
        session.execute(text(query))
        session.commit()
    finally:
        session.close()
        engine.dispose()


def get_tenant_db_url(tenant: dict) -> str:
    """Generate database URL for a tenant."""
    return (
        f"postgresql://{tenant['database_user']}:{tenant['database_password']}"
        f"@{tenant['database_host']}:{tenant['database_port']}/{tenant['database_name']}"
    )


def get_current_revision(tenant: dict) -> Optional[str]:
    """Get the current Alembic revision for a tenant database."""
    try:
        engine = create_engine(get_tenant_db_url(tenant))
        with engine.connect() as conn:
            result = conn.execute(text("SELECT version_num FROM alembic_version LIMIT 1"))
            row = result.fetchone()
            return row[0] if row else None
    except Exception as e:
        return None
    finally:
        engine.dispose()


def run_migration(tenant: dict, command: str, revision: str) -> dict:
    """
    Run an Alembic migration command for a specific tenant.
    
    Returns dict with status and any error message.
    """
    try:
        from alembic.config import Config
        from alembic import command as alembic_command
        
        # Create Alembic config
        alembic_ini = os.path.join(os.path.dirname(__file__), 'alembic.ini')
        config = Config(alembic_ini)
        
        # Override the database URL
        config.set_main_option("sqlalchemy.url", get_tenant_db_url(tenant))
        
        # Run the command
        if command == "upgrade":
            alembic_command.upgrade(config, revision)
        elif command == "downgrade":
            alembic_command.downgrade(config, revision)
        
        # Get new revision
        new_revision = get_current_revision(tenant)
        
        return {
            "status": "success",
            "revision": new_revision,
            "error": None
        }
        
    except ImportError:
        return {
            "status": "error",
            "revision": None,
            "error": "Alembic not installed. Run: pip install alembic"
        }
    except Exception as e:
        return {
            "status": "error",
            "revision": None,
            "error": str(e)
        }


def cmd_status(args):
    """Show migration status for all tenants."""
    tenants = get_tenants(
        filter_slug=args.tenant,
        only_active=not args.include_inactive,
        only_provisioned=False
    )
    
    if not tenants:
        print("No tenants found.")
        return 0
    
    print(f"\n{'Tenant':<20} {'Name':<25} {'Status':<12} {'Version':<15} {'Provisioned':<12}")
    print("-" * 85)
    
    for tenant in tenants:
        status = tenant['migration_status'] or 'unknown'
        version = tenant['schema_version'] or 'none'
        provisioned = '✓' if tenant['is_provisioned'] else '✗'
        
        # Color coding
        if status == 'current':
            status_display = f"\033[92m{status}\033[0m"  # Green
        elif status == 'error':
            status_display = f"\033[91m{status}\033[0m"  # Red
        elif status == 'behind':
            status_display = f"\033[93m{status}\033[0m"  # Yellow
        else:
            status_display = status
        
        print(f"{tenant['slug']:<20} {tenant['name'][:24]:<25} {status_display:<20} {version:<15} {provisioned:<12}")
    
    print()
    return 0


def cmd_upgrade(args):
    """Upgrade tenants to specified revision."""
    tenants = get_tenants(filter_slug=args.tenant)
    
    if not tenants:
        print("No provisioned tenants found.")
        return 1
    
    if not args.tenant and not args.confirm:
        print(f"This will upgrade {len(tenants)} tenant database(s).")
        response = input("Continue? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return 0
    
    print(f"\nUpgrading to revision: {args.revision}")
    print("-" * 50)
    
    success_count = 0
    error_count = 0
    
    for tenant in tenants:
        print(f"  {tenant['slug']}: ", end="", flush=True)
        
        result = run_migration(tenant, "upgrade", args.revision)
        
        if result['status'] == 'success':
            print(f"\033[92m✓\033[0m {result['revision']}")
            update_tenant_status(tenant['slug'], result['revision'], 'current')
            success_count += 1
        else:
            print(f"\033[91m✗\033[0m {result['error']}")
            update_tenant_status(tenant['slug'], tenant['schema_version'], 'error', result['error'])
            error_count += 1
    
    print("-" * 50)
    print(f"Success: {success_count}, Errors: {error_count}")
    
    return 0 if error_count == 0 else 1


def cmd_downgrade(args):
    """Downgrade tenants to specified revision."""
    tenants = get_tenants(filter_slug=args.tenant)
    
    if not tenants:
        print("No provisioned tenants found.")
        return 1
    
    if not args.confirm:
        print(f"\033[93mWARNING: This will DOWNGRADE {len(tenants)} tenant database(s).\033[0m")
        response = input("Are you sure? [y/N]: ")
        if response.lower() != 'y':
            print("Aborted.")
            return 0
    
    print(f"\nDowngrading to revision: {args.revision}")
    print("-" * 50)
    
    success_count = 0
    error_count = 0
    
    for tenant in tenants:
        print(f"  {tenant['slug']}: ", end="", flush=True)
        
        result = run_migration(tenant, "downgrade", args.revision)
        
        if result['status'] == 'success':
            print(f"\033[92m✓\033[0m {result['revision']}")
            update_tenant_status(tenant['slug'], result['revision'], 'current')
            success_count += 1
        else:
            print(f"\033[91m✗\033[0m {result['error']}")
            update_tenant_status(tenant['slug'], tenant['schema_version'], 'error', result['error'])
            error_count += 1
    
    print("-" * 50)
    print(f"Success: {success_count}, Errors: {error_count}")
    
    return 0 if error_count == 0 else 1


def cmd_retry_failed(args):
    """Retry migrations for tenants with error status."""
    engine = create_engine(get_metadata_db_url())
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        result = session.execute(text(
            "SELECT slug FROM tenants WHERE migration_status = 'error' AND is_active = true"
        ))
        failed_slugs = [row[0] for row in result]
    finally:
        session.close()
        engine.dispose()
    
    if not failed_slugs:
        print("No failed tenants to retry.")
        return 0
    
    print(f"Retrying {len(failed_slugs)} failed tenant(s)...")
    
    # Simulate calling upgrade for each failed tenant
    for slug in failed_slugs:
        args.tenant = slug
        args.revision = "head"
        args.confirm = True
        cmd_upgrade(args)
    
    return 0


def main():
    parser = argparse.ArgumentParser(
        description="Run Alembic migrations across all tenant databases"
    )
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Status command
    status_parser = subparsers.add_parser("status", help="Show migration status")
    status_parser.add_argument("--tenant", help="Filter by tenant slug")
    status_parser.add_argument("--include-inactive", action="store_true", help="Include inactive tenants")
    
    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade tenant databases")
    upgrade_parser.add_argument("revision", help="Target revision (e.g., 'head', revision id)")
    upgrade_parser.add_argument("--tenant", help="Upgrade only this tenant")
    upgrade_parser.add_argument("--confirm", action="store_true", help="Skip confirmation prompt")
    
    # Downgrade command
    downgrade_parser = subparsers.add_parser("downgrade", help="Downgrade tenant databases")
    downgrade_parser.add_argument("revision", help="Target revision (e.g., '-1', revision id)")
    downgrade_parser.add_argument("--tenant", help="Downgrade only this tenant")
    downgrade_parser.add_argument("--confirm", action="store_true", help="Skip confirmation prompt")
    
    # Retry failed command
    retry_parser = subparsers.add_parser("retry-failed", help="Retry failed migrations")
    
    args = parser.parse_args()
    
    if args.command is None:
        parser.print_help()
        return 1
    
    if args.command == "status":
        return cmd_status(args)
    elif args.command == "upgrade":
        return cmd_upgrade(args)
    elif args.command == "downgrade":
        return cmd_downgrade(args)
    elif args.command == "retry-failed":
        return cmd_retry_failed(args)
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
