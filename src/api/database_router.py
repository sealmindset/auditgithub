"""
Database Router for Multi-Tenant Architecture.

This module provides:
- Connection pool management for multiple tenant databases
- Tenant-aware session factory
- Database provisioning utilities
"""
import logging
import re
from typing import Dict, Optional
from contextlib import contextmanager

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.pool import QueuePool
from psycopg2 import sql

from .database import Base, SessionLocal, engine as metadata_engine
from .models import Tenant

logger = logging.getLogger(__name__)


class DatabaseRouter:
    """
    Manages database connections for multiple tenants.
    
    Each tenant gets their own connection pool with configurable size.
    Connections are lazily initialized on first access.
    """
    
    def __init__(
        self,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        pool_recycle: int = 1800
    ):
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        
        # Cache of tenant engines: slug -> Engine
        self._engines: Dict[str, Engine] = {}
        # Cache of session factories: slug -> sessionmaker
        self._session_factories: Dict[str, sessionmaker] = {}
        # Cache of tenant configs: slug -> Tenant
        self._tenant_cache: Dict[str, Tenant] = {}
    
    def _get_tenant(self, slug: str) -> Optional[Tenant]:
        """Fetch tenant from metadata database (with caching)."""
        if slug in self._tenant_cache:
            return self._tenant_cache[slug]
        
        db = SessionLocal()
        try:
            tenant = db.query(Tenant).filter(
                Tenant.slug == slug,
                Tenant.is_active == True
            ).first()
            
            if tenant:
                self._tenant_cache[slug] = tenant
            return tenant
        finally:
            db.close()
    
    def _create_engine(self, tenant: Tenant) -> Engine:
        """Create a new SQLAlchemy engine for a tenant."""
        logger.info(f"Creating database engine for tenant: {tenant.slug}")
        
        engine = create_engine(
            tenant.database_url,
            poolclass=QueuePool,
            pool_size=self.pool_size,
            max_overflow=self.max_overflow,
            pool_timeout=self.pool_timeout,
            pool_recycle=self.pool_recycle,
            echo=False
        )
        
        return engine
    
    def get_engine(self, slug: str) -> Optional[Engine]:
        """Get or create an engine for the specified tenant."""
        if slug in self._engines:
            return self._engines[slug]
        
        tenant = self._get_tenant(slug)
        if not tenant:
            logger.warning(f"Tenant not found: {slug}")
            return None
        
        if not tenant.is_provisioned:
            logger.warning(f"Tenant database not provisioned: {slug}")
            return None
        
        engine = self._create_engine(tenant)
        self._engines[slug] = engine
        self._session_factories[slug] = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=engine
        )
        
        return engine
    
    def get_session(self, slug: str) -> Optional[Session]:
        """Get a new session for the specified tenant."""
        if slug not in self._session_factories:
            engine = self.get_engine(slug)
            if not engine:
                return None
        
        return self._session_factories[slug]()
    
    @contextmanager
    def session_scope(self, slug: str):
        """Provide a transactional scope for tenant database operations."""
        session = self.get_session(slug)
        if not session:
            raise ValueError(f"Could not create session for tenant: {slug}")
        
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()
    
    def provision_database(self, tenant: Tenant) -> bool:
        """
        Create a new database for the tenant and initialize schema.
        
        Returns True if successful, False otherwise.
        """
        logger.info(f"Provisioning database for tenant: {tenant.slug}")
        
        try:
            # Connect to default postgres database to create new database
            admin_url = (
                f"postgresql://{tenant.database_user}:{tenant.database_password}"
                f"@{tenant.database_host}:{tenant.database_port}/postgres"
            )
            admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
            
            with admin_engine.connect() as conn:
                # Validate database name format to prevent SQL injection
                if not re.match(r'^[a-z0-9_]+$', tenant.database_name):
                    raise ValueError(f"Invalid database name format: {tenant.database_name}")

                # Check if database already exists (using parameterized query)
                result = conn.execute(
                    text("SELECT 1 FROM pg_database WHERE datname = :db_name"),
                    {"db_name": tenant.database_name}
                )
                exists = result.scalar() is not None
                
                if not exists:
                    logger.info(f"Creating database: {tenant.database_name}")
                    # Use psycopg2.sql.Identifier for safe database name escaping
                    # Database names cannot be parameterized, must use Identifier()
                    create_db_query = sql.SQL("CREATE DATABASE {}").format(
                        sql.Identifier(tenant.database_name)
                    )
                    # Execute using raw connection (psycopg2)
                    conn.connection.cursor().execute(create_db_query)
                else:
                    logger.info(f"Database already exists: {tenant.database_name}")
            
            admin_engine.dispose()
            
            # Create schema in the new database
            tenant_engine = self._create_engine(tenant)
            Base.metadata.create_all(bind=tenant_engine)
            logger.info(f"Schema created for tenant: {tenant.slug}")
            
            # Cache the engine
            self._engines[tenant.slug] = tenant_engine
            self._session_factories[tenant.slug] = sessionmaker(
                autocommit=False,
                autoflush=False,
                bind=tenant_engine
            )
            
            # Update tenant status in metadata DB
            db = SessionLocal()
            try:
                db_tenant = db.query(Tenant).filter(Tenant.id == tenant.id).first()
                if db_tenant:
                    db_tenant.is_provisioned = True
                    db_tenant.migration_status = "current"
                    db.commit()
                    # Update cache
                    self._tenant_cache[tenant.slug] = db_tenant
            finally:
                db.close()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to provision database for tenant {tenant.slug}: {e}")
            return False
    
    def refresh_tenant_cache(self, slug: str = None):
        """Refresh the tenant cache, optionally for a specific tenant."""
        if slug:
            self._tenant_cache.pop(slug, None)
        else:
            self._tenant_cache.clear()
    
    def dispose_engine(self, slug: str):
        """Dispose of a tenant's engine and remove from cache."""
        if slug in self._engines:
            self._engines[slug].dispose()
            del self._engines[slug]
        if slug in self._session_factories:
            del self._session_factories[slug]
        if slug in self._tenant_cache:
            del self._tenant_cache[slug]
    
    def dispose_all(self):
        """Dispose of all tenant engines."""
        for slug in list(self._engines.keys()):
            self.dispose_engine(slug)


# Global database router instance
database_router = DatabaseRouter()


def get_tenant_db(slug: str):
    """
    Dependency function for getting a tenant database session.
    
    Usage in FastAPI routes:
        @app.get("/items")
        def get_items(db: Session = Depends(lambda: get_tenant_db(tenant_slug))):
            ...
    """
    session = database_router.get_session(slug)
    if not session:
        raise ValueError(f"Database not available for tenant: {slug}")
    
    try:
        yield session
    finally:
        session.close()
