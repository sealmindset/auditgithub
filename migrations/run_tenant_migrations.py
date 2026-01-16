#!/usr/bin/env python3
"""
Run Alembic migrations across all tenant schemas.

Usage:
    python migrations/run_tenant_migrations.py upgrade head
    python migrations/run_tenant_migrations.py upgrade head --tenant acme
    python migrations/run_tenant_migrations.py status
"""

import argparse
import sys
from datetime import datetime
from typing import List, Dict
import concurrent.futures

sys.path.insert(0, '.')

from sqlalchemy import text
from alembic.config import Config
from alembic import command

from src.api.database import metadata_engine, SessionLocal
from src.api.models import Tenant

def get_all_tenants() -> List[Tenant]:
    """Fetch all active, provisioned tenants."""
    db = SessionLocal()
    try:
        return db.query(Tenant).filter(
            Tenant.is_active == True,
            Tenant.is_provisioned == True
        ).all()
    finally:
        db.close()


def migrate_tenant_schema(tenant_slug: str, revision: str = "head") -> Dict:
    """Run migrations for a single tenant schema."""
    schema_name = f"tenant_{tenant_slug}"

    try:
        # Configure Alembic
        alembic_cfg = Config("alembic.ini")
        alembic_cfg.set_main_option("sqlalchemy.url", str(metadata_engine.url))
        alembic_cfg.attributes['tenant_schema'] = schema_name

        # Set -x tenant flag for env.py
        alembic_cfg.set_main_option('x', f'tenant={schema_name}')

        # Run migration
        command.upgrade(alembic_cfg, revision)

        # Update tenant status
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
            if tenant:
                tenant.migration_status = "current"
                tenant.last_migration_at = datetime.utcnow()
                tenant.migration_error = None
                db.commit()
        finally:
            db.close()

        return {"slug": tenant_slug, "status": "success", "revision": revision}

    except Exception as e:
        # Update tenant status
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
            if tenant:
                tenant.migration_status = "error"
                tenant.migration_error = str(e)
                db.commit()
        finally:
            db.close()

        return {"slug": tenant_slug, "status": "error", "error": str(e)}


def cmd_upgrade(args):
    """Upgrade tenant schemas to specified revision."""
    if args.tenant:
        # Single tenant
        print(f"Upgrading tenant: {args.tenant}")
        result = migrate_tenant_schema(args.tenant, args.revision)

        if result['status'] == 'success':
            print(f"✓ {args.tenant}: Migration successful")
            return 0
        else:
            print(f"✗ {args.tenant}: {result['error']}")
            return 1
    else:
        # All tenants (parallel)
        tenants = get_all_tenants()
        print(f"Upgrading {len(tenants)} tenant schemas to {args.revision}...")

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(migrate_tenant_schema, t.slug, args.revision): t.slug
                for t in tenants
            }

            for future in concurrent.futures.as_completed(futures):
                result = future.result()
                results.append(result)

                if result['status'] == 'success':
                    print(f"✓ {result['slug']}")
                else:
                    print(f"✗ {result['slug']}: {result['error']}")

        success_count = sum(1 for r in results if r['status'] == 'success')
        error_count = sum(1 for r in results if r['status'] == 'error')

        print(f"\nMigrations complete: {success_count} succeeded, {error_count} failed")
        return 0 if error_count == 0 else 1


def cmd_status(args):
    """Show migration status for all tenants."""
    tenants = get_all_tenants()

    print(f"\n{'Tenant Slug':<20} {'Status':<12} {'Last Migration':<20}")
    print("-" * 55)

    for tenant in tenants:
        status = tenant.migration_status or "unknown"
        last_migration = tenant.last_migration_at.strftime("%Y-%m-%d %H:%M") if tenant.last_migration_at else "never"

        print(f"{tenant.slug:<20} {status:<12} {last_migration:<20}")

        if tenant.migration_error:
            print(f"  Error: {tenant.migration_error[:60]}...")

    print()
    return 0


def main():
    parser = argparse.ArgumentParser(description="Manage tenant schema migrations")
    subparsers = parser.add_subparsers(dest="command")

    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Upgrade tenant schemas")
    upgrade_parser.add_argument("revision", help="Target revision (e.g., 'head')")
    upgrade_parser.add_argument("--tenant", help="Upgrade only this tenant")

    # Status command
    status_parser = subparsers.add_parser("status", help="Show migration status")

    args = parser.parse_args()

    if args.command == "upgrade":
        return cmd_upgrade(args)
    elif args.command == "status":
        return cmd_status(args)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
