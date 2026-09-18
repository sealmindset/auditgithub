"""
AI Organization Management Agent

Handles multi-organization orchestration including:
- Organization CRUD operations
- Database provisioning and schema synchronization
- Credential management via secrets manager
- Scan orchestration with automatic context switching

This agent ensures consistent schema across all organization databases
and provides intelligent error recovery and drift detection.
"""

import os
import re
import sys
import asyncio
import hashlib
import subprocess
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum

# Add execution directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secrets_manager import (
    get_secrets_manager,
    get_org_credentials,
    set_org_credentials,
    list_configured_orgs,
    initialize_secrets_from_env
)

try:
    import asyncpg
except ImportError:
    asyncpg = None
    print("[AIOrganizationAgent] Warning: asyncpg not installed, using psycopg2 fallback")

try:
    import psycopg2
    from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
except ImportError:
    psycopg2 = None


class OrgStatus(Enum):
    """Organization status states."""
    IDLE = "idle"
    SCANNING = "scanning"
    SYNCING = "syncing"
    QUEUED = "queued"
    ERROR = "error"


class SchemaSyncStatus(Enum):
    """Schema synchronization status."""
    SYNCED = "synced"
    DRIFT = "drift"
    ERROR = "error"
    UNKNOWN = "unknown"
    # A row with no database_name has nothing to sync. Distinct from ERROR,
    # which means a sync was attempted and failed.
    SKIPPED = "skipped"


# =============================================================================
# Database names
# =============================================================================
#
# Two prefixes were in use: create_organization() wrote "auditgithub_{name}"
# and _auto_register_orgs_from_env() wrote "auditgh_{name}", so the same
# organization got a different database name depending on which path
# registered it. Both now go through default_database_name().
DATABASE_NAME_PREFIX = "auditgithub_"

# Postgres identifiers are truncated at 63 bytes (NAMEDATALEN - 1), and every
# database name here is interpolated into DDL rather than passed as a
# parameter -- CREATE DATABASE takes an identifier, which cannot be bound. So
# the value is validated instead.
_VALID_DATABASE_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_$]{0,62}$")


def default_database_name(org_name: str) -> str:
    """Database name for an organization registered without one."""
    return f"{DATABASE_NAME_PREFIX}{org_name.lower().strip()}"


# Queries whose combined output is a database's schema fingerprint. Ordering
# is fixed in SQL so the hash does not depend on the server's chosen plan.
#
# Two deliberate insensitivities:
#
#   * Columns are ordered by name, not by ordinal_position. A table built by
#     one CREATE TABLE and a table built by CREATE TABLE plus later ADD COLUMN
#     hold their columns in different physical order while being the same
#     schema to everything that queries them. Ordering by position would call
#     that drift.
#   * Constraints are identified by their definition, not their name.
#     PostgreSQL generates names like '2200_16410_1_not_null' that differ
#     between databases holding identical constraints.
_SCHEMA_FINGERPRINT_QUERIES = (
    """
    SELECT table_schema, table_name, column_name, data_type,
           coalesce(character_maximum_length, -1),
           coalesce(numeric_precision, -1),
           coalesce(numeric_scale, -1),
           is_nullable,
           coalesce(column_default, '')
    FROM information_schema.columns
    WHERE table_schema NOT IN ('pg_catalog', 'information_schema')
    ORDER BY table_schema, table_name, column_name
    """,
    """
    SELECT n.nspname, c.relname, pg_get_constraintdef(k.oid)
    FROM pg_constraint k
    JOIN pg_class c ON c.oid = k.conrelid
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE n.nspname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY 1, 2, 3
    """,
    """
    SELECT schemaname, tablename, indexdef
    FROM pg_indexes
    WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
    ORDER BY 1, 2, 3
    """,
)


def split_sql_statements(sql: str) -> List[str]:
    """Split a schema file into executable statements.

    Splitting on ';' leaves each statement carrying the comment lines that
    preceded it, so a fragment reads:

        -- 1. Users & Authentication
        CREATE TABLE IF NOT EXISTS users (...)

    The previous filter was `if stmt and not stmt.startswith('--')`, which
    discarded that entire fragment as a comment. Every table in
    scripts/setup/schema.sql is preceded by a numbered comment, so all nine
    CREATE TABLE statements were skipped and only the seven comment-free
    fragments ran -- five of which were indexes on the tables that had just
    been skipped, producing 'relation "findings" does not exist'. The applier
    could create zero tables and report success.

    Leading comments are dropped rather than the statement; Postgres would
    accept them either way, but the emptiness check has to run against the
    code, not the commentary.

    Splitting on ';' is still wrong for dollar-quoted function bodies. The
    schema file this is used on contains none; a guard raises rather than
    silently truncating one if that changes.
    """
    if '$$' in sql:
        raise ValueError(
            "schema contains dollar-quoted text ($$), which splitting on ';' "
            "would cut in half. Apply this schema with psql, or add proper "
            "statement parsing before removing this guard."
        )

    statements = []
    for fragment in sql.split(';'):
        lines = fragment.splitlines()
        while lines and (not lines[0].strip() or lines[0].lstrip().startswith('--')):
            lines.pop(0)
        statement = '\n'.join(lines).strip()
        if statement:
            statements.append(statement)
    return statements


def _statement_label(statement: str) -> str:
    """First line of a statement, for error messages."""
    return statement.split('\n')[0][:120]


def validate_database_name(database_name: Optional[str], *, context: str) -> str:
    """Reject a database name that cannot safely be interpolated into DDL.

    A row with database_name NULL reached CREATE DATABASE as the empty
    string -- _row_to_org() coerces NULL to '' so the dataclass field stays a
    str -- and Postgres answered:

        zero-length delimited identifier
        LINE 1: CREATE DATABASE ""

    which was then stored in schema_sync_error and reported on every startup
    as a sync failure. The missing value is the fault; the DDL error is three
    frames downstream of it and names neither the organization nor the column.
    Callers that can legitimately have no database name should check before
    calling rather than rely on this.
    """
    name = (database_name or "").strip()
    if not name:
        raise ValueError(
            f"{context}: no database_name. The organizations row has NULL or an "
            "empty database_name, so there is no database to act on. Set one "
            f"(convention: {DATABASE_NAME_PREFIX}<org>) or skip this step."
        )
    if not _VALID_DATABASE_NAME.match(name):
        raise ValueError(
            f"{context}: {name!r} is not a usable PostgreSQL database name. "
            "Expected up to 63 characters of letters, digits, underscore or $, "
            "starting with a letter or underscore."
        )
    return name


# Every column _row_to_org() reads, in the order it reads them positionally.
#
# This is one constant rather than three copies because the copies diverged:
# list_organizations() selected all seventeen while get_organization() and
# get_default_organization() selected the first eight plus the timestamps. The
# dataclass defaults the rest, so the short queries did not fail -- they
# returned an Organization whose scan_status was None and whose total_repos
# was 0 for a row that said 'idle' and held real counts.
#
# That is what GET /organizations/{org}/scan/status served, since it reads
# get_organization(): a status field that could never report a scan, and a
# None passed to reconcile_stale(), which decides whether a scan the API lost
# track of should be cleared.
ORGANIZATION_COLUMNS = """id, api_id, name, display_name, github_org,
                   database_name, is_active, is_default, schema_version,
                   schema_version_name, schema_sync_status, last_scan_at,
                   scan_status, total_repos, total_findings, created_at,
                   updated_at"""


@dataclass
class Organization:
    """Organization data model."""
    id: str
    api_id: int
    name: str
    display_name: Optional[str]
    github_org: str
    database_name: str
    is_active: bool
    is_default: bool
    created_at: datetime
    updated_at: datetime
    # Optional fields with defaults (for backward compatibility with short queries)
    schema_version: Optional[str] = None
    schema_version_name: Optional[str] = None
    schema_sync_status: Optional[str] = None
    last_scan_at: Optional[datetime] = None
    scan_status: Optional[str] = None
    total_repos: int = 0
    total_findings: int = 0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable values."""
        d = asdict(self)
        for key, value in d.items():
            if isinstance(value, datetime):
                d[key] = value.isoformat() if value else None
        return d


@dataclass
class SchemaComparisonResult:
    """Result of schema comparison between master and org database."""
    is_synced: bool
    master_hash: str
    org_hash: str
    differences: List[str]
    migration_sql: Optional[str]
    error: Optional[str]


class AIOrganizationAgent:
    """
    AI-powered organization management agent.
    
    Handles multi-org orchestration with intelligent
    schema synchronization and credential management.
    
    Features:
    - Automatic schema sync on startup
    - Drift detection and reporting
    - Secure credential management
    - Context switching for scans
    """
    
    def __init__(
        self,
        master_db_url: Optional[str] = None,
        auto_sync: bool = True
    ):
        """
        Initialize the organization agent.
        
        Args:
            master_db_url: PostgreSQL connection URL for master database.
                          Defaults to POSTGRES_* environment variables or
                          DATABASE_URL environment variable.
            auto_sync: If True, sync schemas on startup (default: True)
        """
        # Prefer POSTGRES_* vars (container env) over DATABASE_URL (.env file)
        # This ensures container environment takes precedence
        if master_db_url:
            self.master_db_url = master_db_url
        elif os.environ.get('POSTGRES_HOST'):
            # Construct from individual POSTGRES_* environment variables
            pg_user = os.environ.get('POSTGRES_USER', 'postgres')
            pg_pass = os.environ.get('POSTGRES_PASSWORD', 'postgres')
            pg_host = os.environ.get('POSTGRES_HOST', 'localhost')
            pg_port = os.environ.get('POSTGRES_PORT', '5432')
            pg_db = os.environ.get('POSTGRES_DB', 'security_portal')
            self.master_db_url = f'postgresql://{pg_user}:{pg_pass}@{pg_host}:{pg_port}/{pg_db}'
        elif os.environ.get('DATABASE_URL'):
            self.master_db_url = os.environ.get('DATABASE_URL')
        else:
            # Fallback defaults
            self.master_db_url = 'postgresql://postgres:postgres@localhost:5432/security_portal'
        self.auto_sync = auto_sync

        # Whether organizations live in databases of their own. The API reads
        # the same variable (src/api/database.py, src/api/dependencies.py,
        # src/rbac/dependencies.py), and it defaults to false: one database,
        # rows separated by organization_id.
        #
        # The agent used to ignore it and point scans at a per-organization
        # database unconditionally. Since no such database was ever populated,
        # `scan_repos.py --target sleepnumberinc` -- which is what the
        # organization scan button runs -- rebound its session to a database
        # with no `repositories` table while the UI read the master.
        self.multi_tenant = (
            os.environ.get('MULTI_TENANT_ENABLED', 'false').lower() == 'true'
        )

        self._current_org: Optional[Organization] = None
        self._initialized = False
        self._db_pool = None
        
        # Parse master DB URL for connection params
        self._parse_db_url()
    
    def _parse_db_url(self):
        """Parse database URL into components."""
        # postgresql://user:pass@host:port/dbname
        url = self.master_db_url
        if url.startswith('postgresql://') or url.startswith('postgres://'):
            url = url.split('://', 1)[1]
        
        # user:pass@host:port/dbname
        if '@' in url:
            auth, rest = url.split('@', 1)
            if ':' in auth:
                self.db_user, self.db_password = auth.split(':', 1)
            else:
                self.db_user = auth
                self.db_password = ''
        else:
            self.db_user = 'postgres'
            self.db_password = ''
            rest = url
        
        # host:port/dbname
        if '/' in rest:
            host_port, self.master_db_name = rest.split('/', 1)
        else:
            host_port = rest
            self.master_db_name = 'security_portal'
        
        if ':' in host_port:
            self.db_host, port_str = host_port.split(':', 1)
            self.db_port = int(port_str)
        else:
            self.db_host = host_port
            self.db_port = 5432
    
    async def initialize(self):
        """
        Initialize the agent.
        
        - Initializes secrets manager (loads all ORG_* env vars)
        - Auto-registers organizations from env that aren't in database
        - Runs schema sync if auto_sync enabled
        - Loads default organization
        """
        if self._initialized:
            return
        
        print("[AIOrganizationAgent] Initializing...")
        
        # Initialize secrets from environment (loads ORG_* vars)
        await initialize_secrets_from_env()
        
        # Auto-register organizations from environment
        await self._auto_register_orgs_from_env()
        
        # Auto-sync schemas if enabled
        if self.auto_sync:
            try:
                await self.sync_all_schemas()
            except Exception as e:
                print(f"[AIOrganizationAgent] Schema sync warning: {e}")
        
        # Load default organization
        default_org = await self.get_default_organization()
        if default_org:
            self._current_org = default_org
            print(f"[AIOrganizationAgent] Default org: {default_org.name}")
        
        self._initialized = True
        print("[AIOrganizationAgent] Initialization complete")
    
    async def _auto_register_orgs_from_env(self):
        """
        Auto-register organizations that exist in env but not in database.
        
        Scans for ORG_{NAME}_TOKEN patterns and creates database entries
        for any organizations that don't already exist.
        """
        # Get list of orgs with credentials
        configured_orgs = await list_configured_orgs()
        
        for org_name in configured_orgs:
            # Check if org exists in database
            existing = await self.get_organization(org_name)
            if existing:
                continue
            
            # Get the GitHub org name from secrets
            credentials = await get_org_credentials(org_name)
            github_org = credentials.get('github_org', org_name)
            
            # Register in database
            try:
                # A database name only when this deployment gives each
                # organization a database. The comment here used to read
                # 'each org gets a unique database_name entry (even if
                # sharing the same DB)' -- but the entry is what the scan
                # path reads to decide where results go, so recording a name
                # for a database that does not exist is not a note about a
                # possible future, it is an instruction followed today.
                database_name = (
                    default_database_name(org_name) if self.multi_tenant else None
                )
                
                query = """
                    INSERT INTO organizations (
                        name, display_name, github_org, database_name,
                        is_active, is_default, schema_version, schema_version_name,
                        schema_sync_status
                    ) VALUES ($1, $2, $3, $4, true, false, '', 'v1.0.0', 'pending')
                    ON CONFLICT (name) DO NOTHING
                    RETURNING id
                """
                await self._execute_query(
                    query,
                    org_name,
                    org_name.replace('_', ' ').title(),
                    github_org,
                    database_name
                )
                print(f"[AIOrganizationAgent] Auto-registered org from env: {org_name}")
            except Exception as e:
                print(f"[AIOrganizationAgent] Warning: Could not register {org_name}: {e}")
    
    @property
    def ai_agent(self) -> Optional["AIAgent"]:
        """Lazy-loads and returns the AI Agent."""
        if self.ai_agent:
            return self.ai_agent
            
        from src.ai_agent.agent import AIAgent
        
        # Determine provider and model
        provider = os.environ.get('AI_PROVIDER', 'openai')
        
        # Model selection logic matches Config class
        if provider in ["claude", "anthropic", "anthropic_foundry"]:
            model = os.environ.get("ANTHROPIC_MODEL") or os.environ.get("AI_MODEL") or "claude-sonnet-4-20250514"
        elif provider == "openai":
            model = os.environ.get("OPENAI_MODEL") or os.environ.get("AI_MODEL") or "gpt-4o"
        elif provider in ["ollama", "docker"]:
            model = os.environ.get("AI_MODEL") or "llama3"
        else:
            model = os.environ.get("AI_MODEL") or "gpt-4o"
            
        try:
            self.ai_agent = AIAgent(
                openai_api_key=os.environ.get('OPENAI_API_KEY'),
                anthropic_api_key=os.environ.get('ANTHROPIC_API_KEY'),
                provider=provider,
                model=model,
                ollama_base_url=os.environ.get('OLLAMA_BASE_URL'),
                azure_foundry_endpoint=os.environ.get('AZURE_FOUNDRY_ENDPOINT'),
                azure_foundry_api_key=os.environ.get('AZURE_FOUNDRY_API_KEY'),
                gemini_api_key=os.environ.get('GEMINI_API_KEY'),
                enable_failover=os.environ.get("AI_FAILOVER_ENABLED", "false").lower() == "true",
                failover_model=os.environ.get("AI_FAILOVER_MODEL", "ai/qwen3")
            )
            print(f"[AIOrganizationAgent] Initialized AI Agent ({provider}/{model})")
        except Exception as e:
            print(f"[AIOrganizationAgent] Warning: Could not initialize AI Agent: {e}")
            self.ai_agent = None
            
        return self.ai_agent
    # =========================================================================
    # Organization CRUD
    # =========================================================================
    
    async def list_organizations(self, include_inactive: bool = False) -> List[Organization]:
        """
        List all registered organizations.

        Args:
            include_inactive: Include inactive organizations

        Returns:
            State of every Organization, including its scan tracking fields
        """
        query = f"""
            SELECT {ORGANIZATION_COLUMNS}
            FROM organizations
        """
        if not include_inactive:
            query += " WHERE is_active = true"
        query += " ORDER BY is_default DESC, name ASC"
        
        rows = await self._execute_query(query)
        return [self._row_to_org(row) for row in rows]
    
    async def get_organization(self, name: str) -> Optional[Organization]:
        """
        Get organization by name.

        Args:
            name: Organization name (case-insensitive)

        Returns:
            Organization or None if not found
        """
        query = f"""
            SELECT {ORGANIZATION_COLUMNS}
            FROM organizations
            WHERE LOWER(name) = LOWER($1)
        """
        rows = await self._execute_query(query, name)
        if rows:
            return self._row_to_org(rows[0])
        return None

    async def get_default_organization(self) -> Optional[Organization]:
        """Get the default organization."""
        query = f"""
            SELECT {ORGANIZATION_COLUMNS}
            FROM organizations
            WHERE is_default = true AND is_active = true
            LIMIT 1
        """
        rows = await self._execute_query(query)
        if rows:
            return self._row_to_org(rows[0])
        return None
    
    async def create_organization(
        self,
        name: str,
        github_org: str,
        github_token: str,
        display_name: Optional[str] = None,
        create_database: Optional[bool] = None,
        set_as_default: bool = False
    ) -> Organization:
        """
        Create a new organization, with a database of its own if this
        deployment uses one per organization.

        Steps:
        1. Validate inputs
        2. Create database from master schema (if create_database)
        3. Store credentials in secrets manager
        4. Register in organizations table

        Args:
            name: Internal organization name (lowercase, no spaces)
            github_org: GitHub organization name
            github_token: GitHub personal access token
            display_name: Human-readable display name
            create_database: Create a database for this organization. Default
                None means "whatever this deployment does" --
                MULTI_TENANT_ENABLED. It used to default to True regardless,
                so registering an organization on a single-database
                deployment created a database that nothing would ever read,
                and recorded its name on the row as though it were in use.
            set_as_default: Set as default organization

        Returns:
            Created Organization object
        """
        name = name.lower().strip()

        if create_database is None:
            create_database = self.multi_tenant

        # NULL, not a name, when there is no database of its own. A name on
        # the row is a claim that the database exists; the skip and fallback
        # paths both key off the column being empty.
        database_name = default_database_name(name) if create_database else None

        # Validate name
        if not name.isalnum() and '_' not in name:
            raise ValueError(f"Invalid organization name: {name}. Use alphanumeric and underscores only.")
        
        # Check if already exists
        existing = await self.get_organization(name)
        if existing:
            raise ValueError(f"Organization '{name}' already exists")
        
        print(f"[AIOrganizationAgent] Creating organization: {name}")
        
        # Create database if requested
        if create_database:
            await self._create_database(database_name)
            await self._apply_master_schema(database_name)
        
        # Store credentials
        await set_org_credentials(name, github_token, github_org)

        # Insert organization record
        # Insert organization record
        query = """
            INSERT INTO organizations (
                name, display_name, github_org, database_name,
                is_active, is_default
            ) VALUES ($1, $2, $3, $4, true, $5)
            RETURNING id, api_id, name, display_name, github_org, database_name,
                      is_active, is_default, created_at, updated_at
        """
        rows = await self._execute_query(
            query,
            name,
            display_name or name.replace('_', ' ').title(),
            github_org,
            database_name,
            set_as_default
        )
        
        org = self._row_to_org(rows[0])
        print(f"[AIOrganizationAgent] Created organization: {org.name} (db: {org.database_name})")
        
        return org
    
    async def update_organization(
        self,
        name: str,
        display_name: Optional[str] = None,
        is_active: Optional[bool] = None,
        is_default: Optional[bool] = None
    ) -> Organization:
        """Update organization properties."""
        org = await self.get_organization(name)
        if not org:
            raise ValueError(f"Organization '{name}' not found")
        
        updates = []
        params = []
        param_idx = 1
        
        if display_name is not None:
            updates.append(f"display_name = ${param_idx}")
            params.append(display_name)
            param_idx += 1
        
        if is_active is not None:
            updates.append(f"is_active = ${param_idx}")
            params.append(is_active)
            param_idx += 1
        
        if is_default is not None:
            updates.append(f"is_default = ${param_idx}")
            params.append(is_default)
            param_idx += 1
        
        if not updates:
            return org
        
        params.append(name)
        query = f"""
            UPDATE organizations
            SET {', '.join(updates)}
            WHERE LOWER(name) = LOWER(${param_idx})
            RETURNING id, api_id, name, display_name, github_org, database_name,
                      is_active, is_default, schema_version, schema_version_name,
                      schema_sync_status, last_scan_at, scan_status,
                      total_repos, total_findings, created_at, updated_at
        """
        
        rows = await self._execute_query(query, *params)
        return self._row_to_org(rows[0])
    
    async def delete_organization(self, name: str, drop_database: bool = False) -> bool:
        """
        Delete an organization.
        
        Args:
            name: Organization name
            drop_database: Also drop the organization's database
            
        Returns:
            True if deleted
        """
        org = await self.get_organization(name)
        if not org:
            return False
        
        if org.is_default:
            raise ValueError("Cannot delete the default organization")
        
        print(f"[AIOrganizationAgent] Deleting organization: {name}")
        
        # Delete from registry
        await self._execute_query(
            "DELETE FROM organizations WHERE LOWER(name) = LOWER($1)",
            name
        )
        
        # Drop database if requested
        if drop_database:
            await self._drop_database(org.database_name)
        
        # Remove credentials
        manager = get_secrets_manager()
        await manager.delete_secret(f"{name}/github_token")
        await manager.delete_secret(f"{name}/github_org")
        
        print(f"[AIOrganizationAgent] Deleted organization: {name}")
        return True
    
    # =========================================================================
    # Schema Synchronization
    # =========================================================================
    
    async def get_schema_hash(self, database_name: Optional[str] = None) -> str:
        """
        Get SHA-256 hash of database schema.

        Args:
            database_name: Database to hash (defaults to master)

        Returns:
            Schema hash string

        Raises:
            ValueError: the database does not exist. Returning a placeholder
                hash for an absent database is what let the old
                implementation compare master against nothing and call the
                difference drift.
        """
        db_name = database_name or self.master_db_name
        digest = await self._get_schema_hash(db_name)
        if digest is None:
            raise ValueError(f"Database '{db_name}' does not exist")
        return digest
    
    async def check_schema_drift(self) -> List[Dict[str, Any]]:
        """
        Check all organization databases for schema drift.
        
        Returns:
            List of drift reports per organization
        """
        orgs = await self.list_organizations()

        if not self.multi_tenant:
            # Nothing to drift from: every organization is in the master
            # database, whose schema is the reference.
            return [{
                'organization': org.name,
                'database': self.master_db_name,
                'is_synced': None,
                'status': 'skipped',
                'reason': 'MULTI_TENANT_ENABLED is false; all organizations '
                          'share the master database',
            } for org in orgs]

        master_hash = await self._get_schema_hash(self.master_db_name)

        results = []
        for org in orgs:
            if not (org.database_name or '').strip():
                # An unset database_name is not drift. The old code hashed the
                # empty string here and reported a difference between master
                # and a database that does not exist.
                results.append({
                    'organization': org.name,
                    'database': None,
                    'is_synced': None,
                    'status': 'skipped',
                    'reason': 'no database_name set',
                })
                continue

            try:
                org_hash = await self._get_schema_hash(org.database_name)

                if org_hash is None:
                    results.append({
                        'organization': org.name,
                        'database': org.database_name,
                        'is_synced': False,
                        'status': 'missing',
                        'reason': 'database does not exist',
                    })
                    continue

                is_synced = master_hash == org_hash

                results.append({
                    'organization': org.name,
                    'database': org.database_name,
                    'is_synced': is_synced,
                    'master_hash': master_hash[:12],
                    'org_hash': org_hash[:12],
                    'status': 'synced' if is_synced else 'drift'
                })

                # The status write that used to live here was commented out
                # with '(Skipped - columns not in schema)'. The columns exist
                # now -- migrations/025_organization_scan_columns.sql added
                # them -- but a function named check_* should not write, and
                # sync_schema() already records the status. Left out
                # deliberately rather than left commented.

            except Exception as e:
                results.append({
                    'organization': org.name,
                    'database': org.database_name,
                    'is_synced': False,
                    'status': 'error',
                    'error': str(e)
                })
        
        return results
    
    async def sync_schema(self, org_name: str) -> Dict[str, Any]:
        """
        Synchronize organization database schema with master.
        
        Args:
            org_name: Organization name
            
        Returns:
            Sync result with status and details
        """
        org = await self.get_organization(org_name)
        if not org:
            raise ValueError(f"Organization '{org_name}' not found")

        print(f"[AIOrganizationAgent] Syncing schema for: {org_name}")

        if not self.multi_tenant:
            # One database, rows separated by organization_id. There is no
            # per-organization schema to keep in step, and creating one would
            # produce a database nothing reads -- which is where the two empty
            # auditgithub_* databases on this host came from.
            await self._record_sync_skipped(org.id, org_name)
            return {
                'organization': org_name,
                'status': 'skipped',
                'reason': 'MULTI_TENANT_ENABLED is false; all organizations '
                          'share the master database',
            }

        if not (org.database_name or '').strip():
            # Nothing to sync, and nothing wrong. In single-database mode
            # (MULTI_TENANT_ENABLED=false, the default) every organization
            # lives in the master database and switch_organization() already
            # falls back to it when database_name is unset. Inventing a name
            # here would create an empty database that nothing reads, which is
            # how the two stray auditgithub_* databases on this host appeared.
            await self._record_sync_skipped(org.id, org_name)
            return {
                'organization': org_name,
                'status': 'skipped',
                'reason': 'no database_name set; organization uses the master database',
            }

        master_hash = await self._get_schema_hash(self.master_db_name)
        org_hash = await self._get_schema_hash(org.database_name)

        # org_hash is None when the database does not exist yet, which is not
        # equal to any master hash and so falls through to the apply below --
        # _apply_master_schema() creates it.
        if org_hash is not None and master_hash == org_hash:
            return {
                'organization': org_name,
                'status': 'already_synced',
                'schema_hash': master_hash[:12]
            }
        
        # Apply master schema to org database
        try:
            await self._apply_master_schema(org.database_name)

            # Verify, rather than assume. 'synced' was written whenever
            # _apply_master_schema() returned, and it returns after logging
            # per-statement failures as warnings -- so both organizations on
            # this host recorded schema_sync_status='synced' while holding one
            # table and zero tables respectively, against the master's 66. A
            # status that is written without being checked is not a status.
            new_hash = await self._get_schema_hash(org.database_name)
            if new_hash != master_hash:
                raise RuntimeError(
                    f"schema apply did not reproduce the master schema: "
                    f"master {master_hash[:12]}, "
                    f"{org.database_name} {('missing' if new_hash is None else new_hash[:12])} "
                    f"after applying. Check the per-statement warnings above."
                )

            await self._execute_query(
                """UPDATE organizations
                   SET schema_sync_status = 'synced',
                       schema_version = $1,
                       schema_sync_error = NULL,
                       last_schema_sync = NOW()
                   WHERE id = $2""",
                new_hash, org.id
            )

            return {
                'organization': org_name,
                'status': 'synced',
                'old_hash': 'missing' if org_hash is None else org_hash[:12],
                'new_hash': new_hash[:12]
            }

        except Exception as e:
            await self._execute_query(
                """UPDATE organizations 
                   SET schema_sync_status = 'error',
                       schema_sync_error = $1
                   WHERE id = $2""",
                str(e), org.id
            )
            raise
    
    async def _record_sync_skipped(self, org_id: str, org_name: str):
        """Mark an organization as having nothing to sync, and clear any error.

        The stale error matters: before the skip existed, this organization
        recorded 'zero-length delimited identifier' in schema_sync_error, and
        that text stayed on the row through every subsequent startup because
        nothing ever wrote over it. `--list-orgs` went on reporting
        'Schema: error' for a condition that was no longer being attempted.
        """
        try:
            await self._execute_query(
                """UPDATE organizations
                   SET schema_sync_status = 'skipped',
                       schema_sync_error = NULL,
                       last_schema_sync = NOW()
                   WHERE id = $1""",
                org_id
            )
        except Exception as e:
            print(f"[AIOrganizationAgent] Could not record skipped sync for "
                  f"{org_name}: {e}")

    async def sync_all_schemas(self) -> Dict[str, Any]:
        """
        Sync all organization schemas with master.

        Returns:
            Summary of sync results
        """
        print("[AIOrganizationAgent] Syncing all organization schemas...")

        orgs = await self.list_organizations()
        results = {
            'total': len(orgs),
            'synced': 0,
            'already_synced': 0,
            # Counted apart from errors. Folding the two together is what made
            # startup report '2 synced, 1 errors' for a configuration that has
            # nothing to sync.
            'skipped': 0,
            'errors': 0,
            'details': []
        }

        for org in orgs:
            try:
                result = await self.sync_schema(org.name)
                results['details'].append(result)

                if result['status'] == 'synced':
                    results['synced'] += 1
                elif result['status'] == 'already_synced':
                    results['already_synced'] += 1
                elif result['status'] == 'skipped':
                    results['skipped'] += 1

            except Exception as e:
                results['errors'] += 1
                results['details'].append({
                    'organization': org.name,
                    'status': 'error',
                    'error': str(e)
                })
        
        print(f"[AIOrganizationAgent] Schema sync complete: {results['synced']} synced, "
              f"{results['already_synced']} already synced, {results['skipped']} skipped, "
              f"{results['errors']} errors")
        
        return results
    
    # =========================================================================
    # Context Switching
    # =========================================================================
    
    async def select_organization(self, name: str) -> Organization:
        """
        Select organization as current context.
        
        Loads credentials and configures environment for scanning.
        
        Args:
            name: Organization name
            
        Returns:
            Selected Organization
        """
        org = await self.get_organization(name)
        if not org:
            raise ValueError(f"Organization '{name}' not found")
        
        if not org.is_active:
            raise ValueError(f"Organization '{name}' is not active")
        
        # Load credentials
        credentials = await get_org_credentials(name)
        
        if not credentials.get('github_token'):
            raise ValueError(f"No GitHub token configured for '{name}'")
        
        # Set environment variables for this context
        os.environ['GITHUB_TOKEN'] = credentials['github_token']
        os.environ['GITHUB_ORG'] = credentials.get('github_org', org.github_org)

        # Which database this organization's scan results belong in.
        #
        # Only a multi-tenant deployment has a database per organization. With
        # MULTI_TENANT_ENABLED false -- the default, and the setting here --
        # everything lives in the master database separated by
        # organization_id, and pointing a scan elsewhere sends its results to
        # a database the UI does not read. That is what was happening:
        # scan_repos.py rebinds SessionLocal to whatever this sets, and
        # auditgithub_sleepnumberinc has no `repositories` table at all, so an
        # organization scan raised 'relation "repositories" does not exist'
        # per repository while 2,540 repositories sat in the master.
        db_name = self._scan_database_name(org)

        # Set database URL for this organization
        org_db_url = f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{db_name}"
        os.environ['DATABASE_URL'] = org_db_url

        # Also set individual POSTGRES vars for compatibility
        os.environ['POSTGRES_DB'] = db_name

        # Update current org
        self._current_org = org

        print(f"[AIOrganizationAgent] Selected organization: {name} (GitHub: {org.github_org})")
        print(f"[AIOrganizationAgent] Database: {db_name}")
        
        return org
    
    def get_current_organization(self) -> Optional[Organization]:
        """Get currently selected organization."""
        return self._current_org

    def _scan_database_name(self, org: Organization) -> str:
        """The database an organization's scan results belong in.

        The master database unless this deployment is multi-tenant *and* the
        organization has a database of its own. Both conditions, not either:
        a database_name on the row means nothing if the deployment keeps all
        organizations in one database, and multi-tenancy means nothing for an
        organization whose row names no database.
        """
        if self.multi_tenant and (org.database_name or '').strip():
            return org.database_name.strip()
        return self.master_db_name
    
    async def get_database_url(self, org_name: Optional[str] = None) -> str:
        """
        Get database URL for an organization.
        
        Args:
            org_name: Organization name (uses current if None)
            
        Returns:
            PostgreSQL connection URL
        """
        if org_name:
            org = await self.get_organization(org_name)
        else:
            org = self._current_org
        
        if not org:
            return self.master_db_url

        # Same rule as select_organization(), through the same helper. An
        # empty database_name used to produce a URL ending in '/', which is a
        # valid libpq URL: it connects to the database named after the user.
        # Scan data would have landed in 'postgres' with no error anywhere.
        db_name = self._scan_database_name(org)
        if db_name == self.master_db_name:
            return self.master_db_url

        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{db_name}"
    
    # =========================================================================
    # Scan Orchestration
    # =========================================================================
    
    async def mark_scan_started(
        self,
        org_name: str,
        repos: Optional[List[str]] = None,
        scan_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Record that a scan of this organization has begun.

        This only moves the organization row to 'scanning' and loads the org's
        credentials into the agent context. It starts no process: the scan
        itself is owned by src.services.scan_runner. The method was previously
        named start_scan, which read as though it launched the scanner -- it
        never did, and the UI's progress bar polled a flag nothing advanced.

        Args:
            org_name: Organization name
            repos: Optional list of specific repos being scanned
            scan_type: Type of scan ('full', 'incremental', 'secrets')

        Returns:
            Scan context: which org, which GitHub org, which database
        """
        # Select organization (loads credentials)
        org = await self.select_organization(org_name)

        # Update scan status
        await self._execute_query(
            """UPDATE organizations
               SET scan_status = 'scanning', scan_progress = 0
               WHERE id = $1""",
            org.id
        )

        return {
            'organization': org_name,
            'github_org': org.github_org,
            'database': org.database_name,
            'repos': repos,
            'scan_type': scan_type,
            'status': 'scanning'
        }

    async def finish_scan(
        self,
        org_name: str,
        status: str = 'idle',
        error: Optional[str] = None
    ):
        """
        Record the end of a scan without touching the repository or finding
        totals.

        complete_scan() overwrites total_repos and total_findings, so a caller
        that does not already know both would have to invent them. Those two
        columns are maintained by repository import and by scan_repos.py's own
        ingestion step; a scan finishing is not the moment to guess at them.

        Args:
            org_name: Organization name
            status: Terminal scan_status ('idle', 'error', 'cancelled')
            error: Unused here, retained for logging symmetry with complete_scan
        """
        if error:
            print(f"[AIOrganizationAgent] Scan of {org_name} ended with error: {error}")
        await self._execute_query(
            """UPDATE organizations
               SET scan_status = $1,
                   scan_progress = 100,
                   last_scan_at = NOW(),
                   total_scans = total_scans + 1
               WHERE LOWER(name) = LOWER($2)""",
            status, org_name
        )

    async def update_scan_progress(self, org_name: str, progress: int, status: str = 'scanning'):
        """Update scan progress for organization."""
        await self._execute_query(
            """UPDATE organizations 
               SET scan_status = $1, scan_progress = $2
               WHERE LOWER(name) = LOWER($3)""",
            status, progress, org_name
        )
    
    async def complete_scan(
        self,
        org_name: str,
        repos_scanned: int,
        findings_count: int,
        error: Optional[str] = None
    ):
        """Mark scan as complete."""
        status = 'error' if error else 'idle'
        await self._execute_query(
            """UPDATE organizations 
               SET scan_status = $1, 
                   scan_progress = 100,
                   last_scan_at = NOW(),
                   total_scans = total_scans + 1,
                   total_repos = $2,
                   total_findings = $3
               WHERE LOWER(name) = LOWER($4)""",
            status, repos_scanned, findings_count, org_name
        )
    
    # =========================================================================
    # Private Helpers
    # =========================================================================
    
    def _row_to_org(self, row) -> Organization:
        """Convert database row to Organization object."""
        if isinstance(row, dict):
            # Handle None database_name
            row_copy = dict(row)
            if row_copy.get('database_name') is None:
                row_copy['database_name'] = ''
            return Organization(**row_copy)
        else:
            # Tuple from psycopg2 - handle both short (10 cols) and long (17 cols) queries
            if len(row) >= 17:
                # Long query with all fields
                return Organization(
                    id=str(row[0]),
                    api_id=row[1],
                    name=row[2],
                    display_name=row[3],
                    github_org=row[4],
                    database_name=row[5] or '',
                    is_active=row[6],
                    is_default=row[7],
                    created_at=row[15],
                    updated_at=row[16],
                    schema_version=row[8],
                    schema_version_name=row[9],
                    schema_sync_status=row[10],
                    last_scan_at=row[11],
                    scan_status=row[12],
                    total_repos=row[13] or 0,
                    total_findings=row[14] or 0,
                )
            else:
                # Short query (10 cols) - use defaults for optional fields
                return Organization(
                    id=str(row[0]),
                    api_id=row[1],
                    name=row[2],
                    display_name=row[3],
                    github_org=row[4],
                    database_name=row[5] or '',
                    is_active=row[6],
                    is_default=row[7],
                    created_at=row[8],
                    updated_at=row[9]
                )
    
    async def _execute_query(self, query: str, *params) -> List[Any]:
        """Execute a database query."""
        # Convert $1, $2 style to %s for psycopg2
        if psycopg2:
            psycopg_query = re.sub(r'\$(\d+)', r'%s', query)
            
            conn = psycopg2.connect(self.master_db_url)
            try:
                with conn.cursor() as cur:
                    cur.execute(psycopg_query, params)
                    if cur.description:
                        rows = cur.fetchall()
                    else:
                        rows = []
                    conn.commit()
                    return rows
            finally:
                conn.close()
        else:
            raise RuntimeError("No database driver available")
    
    async def _get_schema_hash(self, database_name: str) -> Optional[str]:
        """SHA-256 fingerprint of a database's schema, or None if it does not exist.

        This used to shell out to pg_dump. pg_dump is not installed in the api
        image -- neither is psql -- so every call raised FileNotFoundError and
        took the fallback arm, which returned:

            hashlib.sha256(database_name.encode()).hexdigest()

        the hash of the database *name*. Two consequences, both silent:

          * The master's name never equals an organization's name, so
            master_hash != org_hash always. sync_schema() therefore concluded
            drift and re-applied the entire master schema on every single
            agent startup, forever. The stored schema_version for
            sleepnumberinc was exactly sha256(b'auditgithub_sleepnumberinc').
          * A hash of a name cannot change when a schema changes, so the
            column documented as 'SHA-256 hash of current schema DDL for
            drift detection' could not detect drift either.

        Reading the catalog through psycopg2 removes the dependency on a
        client binary being present, which is what made the environment decide
        the algorithm. One algorithm, everywhere: two hosts using different
        ones would report permanent false drift -- today's bug wearing a
        different hat.
        """
        if not psycopg2:
            raise RuntimeError("psycopg2 required to fingerprint a schema")

        database_name = validate_database_name(
            database_name, context="Cannot fingerprint schema"
        )

        if not await self._database_exists(database_name):
            return None

        digest = hashlib.sha256()
        conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            password=self.db_password,
            database=database_name,
        )
        try:
            with conn.cursor() as cur:
                for query in _SCHEMA_FINGERPRINT_QUERIES:
                    cur.execute(query)
                    for row in cur.fetchall():
                        digest.update(
                            '\x1f'.join('' if v is None else str(v) for v in row).encode()
                        )
                        digest.update(b'\x1e')
        finally:
            conn.close()

        return digest.hexdigest()

    async def _database_exists(self, database_name: str) -> bool:
        """Whether a database exists, asked of the master connection."""
        conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            password=self.db_password,
            database=self.master_db_name,
        )
        try:
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s",
                    (database_name,),
                )
                return cur.fetchone() is not None
        finally:
            conn.close()


    async def _create_database(self, database_name: str):
        """Create a new database."""
        database_name = validate_database_name(
            database_name, context="Cannot create database"
        )
        print(f"[AIOrganizationAgent] Creating database: {database_name}")

        if psycopg2:
            # Connect to master database to create new db
            # Use master_db_name instead of 'postgres' for compatibility
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_password,
                database=self.master_db_name
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            try:
                with conn.cursor() as cur:
                    # Check if database exists
                    cur.execute(
                        "SELECT 1 FROM pg_database WHERE datname = %s",
                        (database_name,)
                    )
                    if cur.fetchone():
                        print(f"[AIOrganizationAgent] Database {database_name} already exists")
                        return
                    
                    # Create database
                    cur.execute(f'CREATE DATABASE "{database_name}"')
                    print(f"[AIOrganizationAgent] Created database: {database_name}")
            finally:
                conn.close()
    
    async def _drop_database(self, database_name: str):
        """Drop a database."""
        print(f"[AIOrganizationAgent] Dropping database: {database_name}")
        
        if database_name == self.master_db_name:
            raise ValueError("Cannot drop master database")
        
        if psycopg2:
            # Connect to master database instead of 'postgres' for compatibility
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                user=self.db_user,
                password=self.db_password,
                database=self.master_db_name
            )
            conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
            
            try:
                with conn.cursor() as cur:
                    # Terminate connections
                    cur.execute(f"""
                        SELECT pg_terminate_backend(pid) 
                        FROM pg_stat_activity 
                        WHERE datname = %s AND pid <> pg_backend_pid()
                    """, (database_name,))
                    
                    # Drop database
                    cur.execute(f'DROP DATABASE IF EXISTS "{database_name}"')
                    print(f"[AIOrganizationAgent] Dropped database: {database_name}")
            finally:
                conn.close()
    
    async def _apply_master_schema(self, database_name: str):
        """Apply master schema to a database."""
        print(f"[AIOrganizationAgent] Applying master schema to: {database_name}")
        
        # Get schema from master
        schema_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'scripts', 'setup',
            'schema.sql'
        )
        
        if not os.path.exists(schema_file):
            raise FileNotFoundError(f"Schema file not found: {schema_file}")
        
        # Check if psql is available
        try:
            subprocess.run(['which', 'psql'], capture_output=True, check=True)
        except (subprocess.CalledProcessError, FileNotFoundError):
            # psql not available, try using psycopg2 directly
            print(f"[AIOrganizationAgent] psql not available, using psycopg2 fallback")
            await self._apply_schema_via_psycopg2(database_name, schema_file)
            return
        
        # Apply schema using psql
        result = subprocess.run(
            [
                'psql',
                '-h', self.db_host,
                '-p', str(self.db_port),
                '-U', self.db_user,
                '-d', database_name,
                '-f', schema_file
            ],
            capture_output=True,
            text=True,
            env={**os.environ, 'PGPASSWORD': self.db_password}
        )
        
        if result.returncode != 0:
            print(f"[AIOrganizationAgent] Schema apply warnings: {result.stderr}")
        
        # Apply migrations
        migrations_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'migrations'
        )
        
        if os.path.exists(migrations_dir):
            for migration_file in sorted(os.listdir(migrations_dir)):
                if migration_file.endswith('.sql'):
                    migration_path = os.path.join(migrations_dir, migration_file)
                    subprocess.run(
                        [
                            'psql',
                            '-h', self.db_host,
                            '-p', str(self.db_port),
                            '-U', self.db_user,
                            '-d', database_name,
                            '-f', migration_path
                        ],
                        capture_output=True,
                        text=True,
                        env={**os.environ, 'PGPASSWORD': self.db_password}
                    )
        
        print(f"[AIOrganizationAgent] Schema applied to: {database_name}")
    
    async def _apply_schema_via_psycopg2(self, database_name: str, schema_file: str):
        """Apply schema using psycopg2 when psql is not available."""
        if not psycopg2:
            raise RuntimeError("Neither psql nor psycopg2 available for schema application")
        
        # First, ensure the database exists
        await self._ensure_database_exists(database_name)
        
        # Read schema file
        with open(schema_file, 'r') as f:
            schema_sql = f.read()
        
        # Connect to target database
        db_url = f'postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{database_name}'
        
        try:
            conn = psycopg2.connect(db_url)
            conn.autocommit = True
            
            failures = []
            statements = split_sql_statements(schema_sql)
            with conn.cursor() as cur:
                for stmt in statements:
                    try:
                        cur.execute(stmt)
                    except Exception as e:
                        # 'already exists' is the idempotent re-run case and is
                        # genuinely fine. Everything else is collected and
                        # raised below: these were printed as warnings and then
                        # the caller wrote schema_sync_status='synced'
                        # regardless.
                        if 'already exists' not in str(e).lower():
                            failures.append((_statement_label(stmt), str(e).strip()))

            conn.close()

            if failures:
                detail = '; '.join(f"{stmt!r}: {err}" for stmt, err in failures[:3])
                raise RuntimeError(
                    f"{len(failures)} of {len(statements)} statements failed "
                    f"applying the schema to {database_name}. First: {detail}"
                )

            print(f"[AIOrganizationAgent] Schema applied via psycopg2 to: {database_name}")

        except psycopg2.OperationalError as e:
            print(f"[AIOrganizationAgent] Database connection error: {e}")
            raise
    
    async def _ensure_database_exists(self, database_name: str):
        """Ensure a database exists, creating it if necessary."""
        if not psycopg2:
            raise RuntimeError("psycopg2 required for database creation")

        database_name = validate_database_name(
            database_name, context="Cannot ensure database exists"
        )

        # Connect to master database to check/create
        conn = psycopg2.connect(
            host=self.db_host,
            port=self.db_port,
            user=self.db_user,
            password=self.db_password,
            database=self.master_db_name
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        
        try:
            with conn.cursor() as cur:
                # Check if database exists
                cur.execute(
                    "SELECT 1 FROM pg_database WHERE datname = %s",
                    (database_name,)
                )
                if cur.fetchone():
                    return  # Database already exists
                
                # Create database
                cur.execute(f'CREATE DATABASE "{database_name}"')
                print(f"[AIOrganizationAgent] Created database: {database_name}")
        finally:
            conn.close()


# =============================================================================
# Global Instance
# =============================================================================

_agent: Optional[AIOrganizationAgent] = None


def get_org_agent() -> AIOrganizationAgent:
    """Get the global organization agent instance."""
    global _agent
    if _agent is None:
        _agent = AIOrganizationAgent()
    return _agent


async def initialize_org_agent():
    """Initialize the global organization agent."""
    agent = get_org_agent()
    await agent.initialize()
    return agent
