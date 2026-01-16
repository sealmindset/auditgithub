import os
import logging
from typing import Optional, Generator, Dict

from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.engine import Engine
from fastapi import Request, Depends

logger = logging.getLogger(__name__)

# Database Configuration (Metadata/Default Database)
POSTGRES_HOST = os.environ.get("POSTGRES_HOST", "localhost")
POSTGRES_PORT = os.environ.get("POSTGRES_PORT", "5432")
POSTGRES_USER = os.environ.get("POSTGRES_USER", "auditgh")
POSTGRES_PASSWORD = os.environ.get("POSTGRES_PASSWORD", "auditgh_secret")
POSTGRES_DB = os.environ.get("POSTGRES_DB", "auditgh_kb")

SQLALCHEMY_DATABASE_URL = f"postgresql://{POSTGRES_USER}:{POSTGRES_PASSWORD}@{POSTGRES_HOST}:{POSTGRES_PORT}/{POSTGRES_DB}"

engine = create_engine(SQLALCHEMY_DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Cache for organization database engines (kept for backward compatibility)
_org_engines: Dict[str, Engine] = {}
_org_sessions: Dict[str, sessionmaker] = {}

# Currently selected organization (set by /organizations/{name}/select)
# NOTE: We now use organization_id filtering instead of separate databases
_current_org_db: Optional[str] = None
_current_org_id: Optional[str] = None
_current_org_name: Optional[str] = None


def set_current_org_database(database_name: str, org_id: str = None, org_name: str = None):
    """
    Set the current organization context.
    
    NOTE: We no longer switch databases. All data is stored in the master DB (auditgh_kb)
    and filtered by organization_id. The database_name is kept for reference only.
    """
    global _current_org_db, _current_org_id, _current_org_name
    _current_org_db = database_name
    _current_org_id = org_id
    _current_org_name = org_name
    logger.info(f"Set organization context: {org_name} (id={org_id}, db={database_name})")


def get_current_org_database() -> Optional[str]:
    """Get the currently selected organization's database name (for reference)."""
    return _current_org_db


def get_current_org_id() -> Optional[str]:
    """Get the currently selected organization's ID for query filtering."""
    return _current_org_id


# Request-scoped organization context (set per-request from headers/params)
_request_org_id: Optional[str] = None


def set_request_org_id(org_id: Optional[str]):
    """Set the organization ID for the current request context."""
    global _request_org_id
    _request_org_id = org_id


def get_request_org_id() -> Optional[str]:
    """Get the organization ID from request context, falling back to global context."""
    return _request_org_id or _current_org_id


def get_current_org_name() -> Optional[str]:
    """Get the currently selected organization's name."""
    return _current_org_name


def get_org_session(database_name: str) -> Session:
    """
    Get a session for queries.
    
    NOTE: We now always use the master database (auditgh_kb) and filter by organization_id.
    This function returns a session to the master DB regardless of database_name parameter.
    """
    # Always use master database - data is filtered by organization_id
    db = SessionLocal()
    return db

Base = declarative_base()

# Multi-tenant configuration
MULTI_TENANT_ENABLED = os.environ.get("MULTI_TENANT_ENABLED", "false").lower() == "true"
DEFAULT_TENANT_SLUG = os.environ.get("DEFAULT_TENANT_SLUG", "default")


def get_db(request: Request = None) -> Generator[Session, None, None]:
    """
    Dependency for getting DB session.
    
    All queries use the master database (auditgh_kb). Organization-specific data
    is filtered using organization_id. Use get_current_org_id() to get the
    currently selected organization for filtering.
    
    Usage in routers:
        @router.get("/items")
        def get_items(db: Session = Depends(get_db)):
            org_id = get_current_org_id()
            if org_id:
                items = db.query(Item).filter(Item.organization_id == org_id).all()
            else:
                items = db.query(Item).all()
            ...
    """
    # If Multi-Tenant Mode is enabled and request has tenant context, use tenant DB
    if MULTI_TENANT_ENABLED and request and hasattr(request, "state") and getattr(request.state, "tenant_slug", None):
        try:
            from .database_router import database_router
            tenant_slug = request.state.tenant_slug
            tenant_session = database_router.get_session(tenant_slug)
            
            if tenant_session:
                logger.debug(f"Using tenant DB for: {tenant_slug}")
                try:
                    yield tenant_session
                finally:
                    tenant_session.close()
                return
            else:
                logger.warning(f"Could not get session for tenant {tenant_slug}, falling back to master DB")
        except Exception as e:
            logger.error(f"Error getting tenant session: {e}, falling back to master DB")

    # Always use master database - organization filtering is done via organization_id
    db = SessionLocal()
    current_org = get_current_org_name()
    if current_org:
        logger.debug(f"Using master DB with org filter: {current_org} (id={get_current_org_id()})")
    try:
        yield db
    finally:
        db.close()


def get_metadata_db() -> Generator[Session, None, None]:
    """
    Dependency for getting a session to the metadata database.
    
    This always connects to the main database (auditgh_kb) regardless of tenant context.
    Used for operations on the Tenant table and other metadata operations.
    
    Usage:
        @router.get("/tenants")
        def list_tenants(db: Session = Depends(get_metadata_db)):
            ...
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
