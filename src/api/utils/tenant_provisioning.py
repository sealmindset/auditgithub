"""
Tenant Schema Provisioning Utilities.

Provides secure schema provisioning for multi-tenant architecture.
Creates isolated PostgreSQL schemas for each tenant on demand.
"""
import logging
import re
from datetime import datetime
from typing import Optional

from sqlalchemy import text
from sqlalchemy.orm import Session
from psycopg2 import sql

logger = logging.getLogger(__name__)


def provision_tenant_schema(tenant_slug: str) -> bool:
    """
    Provision a new PostgreSQL schema for a tenant.

    Creates a new schema with the name "tenant_{slug}" and populates it with
    all tables from Base.metadata. Uses SQL injection-safe methods with
    psycopg2.sql.Identifier for schema names.

    Args:
        tenant_slug: The tenant's slug (must match ^[a-z0-9-]+$)

    Returns:
        bool: True if provisioning succeeded, False otherwise

    Security:
        - Uses psycopg2.sql.Identifier for schema names (prevents SQL injection)
        - Uses parameterized queries for SET search_path
        - Validates slug format before processing
    """
    from ..database import SessionLocal, engine, Base
    from ..models import Tenant

    # Validate slug format
    if not re.match(r'^[a-z0-9-]+$', tenant_slug):
        logger.error(f"Invalid tenant slug format: {tenant_slug}")
        raise ValueError(f"Invalid tenant slug format: {tenant_slug}")

    schema_name = f"tenant_{tenant_slug}"
    logger.info(f"Starting schema provisioning for tenant: {tenant_slug} (schema: {schema_name})")

    db = SessionLocal()
    try:
        # Step 1: Get raw connection for CREATE SCHEMA
        raw_conn = engine.raw_connection()
        cursor = raw_conn.cursor()

        try:
            # Create schema with safe SQL identifier quoting
            # NEVER use f-strings in SQL - use psycopg2.sql.Identifier
            query = sql.SQL("CREATE SCHEMA IF NOT EXISTS {}").format(sql.Identifier(schema_name))
            cursor.execute(query)
            raw_conn.commit()
            logger.info(f"Created schema: {schema_name}")

        finally:
            cursor.close()
            raw_conn.close()

        # Step 2: Set search_path and create tables
        conn = engine.connect()
        try:
            # Use parameterized query for SET search_path
            conn.execute(text("SET search_path TO :schema"), {"schema": schema_name})
            conn.commit()

            # Create all tables in the tenant schema
            Base.metadata.create_all(bind=conn)
            logger.info(f"Created tables in schema: {schema_name}")

        finally:
            conn.close()

        # Step 3: Update Tenant record
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
        if tenant:
            tenant.is_provisioned = True
            tenant.migration_status = "current"
            tenant.last_migration_at = datetime.utcnow()
            db.commit()
            logger.info(f"Updated tenant record: {tenant_slug}")
        else:
            logger.error(f"Tenant not found in database: {tenant_slug}")
            return False

        logger.info(f"Successfully provisioned tenant schema: {schema_name}")
        return True

    except Exception as e:
        logger.exception(f"Error provisioning tenant schema: {tenant_slug}")

        # Mark tenant as error status
        try:
            tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).first()
            if tenant:
                tenant.migration_status = "error"
                tenant.migration_error = str(e)
                db.commit()
        except Exception as update_error:
            logger.error(f"Failed to update tenant error status: {update_error}")

        return False

    finally:
        db.close()
