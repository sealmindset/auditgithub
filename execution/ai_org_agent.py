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
            # Each org gets a unique database_name entry (even if sharing the same DB)
            try:
                # Use org-specific database name for the record
                # This allows future isolation if needed
                database_name = f"auditgh_{org_name}"
                
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
            List of Organization objects
        """
        query = """
            SELECT id, api_id, name, display_name, github_org, database_name,
                   is_active, is_default, schema_version, schema_version_name,
                   schema_sync_status, last_scan_at, scan_status,
                   total_repos, total_findings, created_at, updated_at
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
        query = """
            SELECT id, api_id, name, display_name, github_org, database_name,
                   is_active, is_default, created_at, updated_at
            FROM organizations
            WHERE LOWER(name) = LOWER($1)
        """
        rows = await self._execute_query(query, name)
        if rows:
            return self._row_to_org(rows[0])
        return None
    
    async def get_default_organization(self) -> Optional[Organization]:
        """Get the default organization."""
        query = """
            SELECT id, api_id, name, display_name, github_org, database_name,
                   is_active, is_default, created_at, updated_at
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
        create_database: bool = True,
        set_as_default: bool = False
    ) -> Organization:
        """
        Create a new organization with isolated database.
        
        Steps:
        1. Validate inputs
        2. Create database from master schema (if create_database=True)
        3. Store credentials in secrets manager
        4. Register in organizations table
        
        Args:
            name: Internal organization name (lowercase, no spaces)
            github_org: GitHub organization name
            github_token: GitHub personal access token
            display_name: Human-readable display name
            create_database: Create new database (False to use existing)
            set_as_default: Set as default organization
            
        Returns:
            Created Organization object
        """
        name = name.lower().strip()
        database_name = f"auditgithub_{name}"
        
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
        
        # Get master schema version
        schema_hash = await self._get_schema_hash(self.master_db_name)
        
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
        """
        db_name = database_name or self.master_db_name
        return await self._get_schema_hash(db_name)
    
    async def check_schema_drift(self) -> List[Dict[str, Any]]:
        """
        Check all organization databases for schema drift.
        
        Returns:
            List of drift reports per organization
        """
        master_hash = await self._get_schema_hash(self.master_db_name)
        orgs = await self.list_organizations()
        
        results = []
        for org in orgs:
            try:
                org_hash = await self._get_schema_hash(org.database_name)
                is_synced = master_hash == org_hash
                
                results.append({
                    'organization': org.name,
                    'database': org.database_name,
                    'is_synced': is_synced,
                    'master_hash': master_hash[:12],
                    'org_hash': org_hash[:12],
                    'status': 'synced' if is_synced else 'drift'
                })
                
                # Update org status in database
                # Update org status in database (Skipped - columns not in schema)
                # status = 'synced' if is_synced else 'drift'
                # await self._execute_query(
                #    """UPDATE organizations 
                #       SET schema_sync_status = $1, schema_version = $2
                #       WHERE id = $3""",
                #    status, org_hash, org.id
                # )
                
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
        
        master_hash = await self._get_schema_hash(self.master_db_name)
        org_hash = await self._get_schema_hash(org.database_name)
        
        if master_hash == org_hash:
            return {
                'organization': org_name,
                'status': 'already_synced',
                'schema_hash': master_hash[:12]
            }
        
        # Apply master schema to org database
        try:
            await self._apply_master_schema(org.database_name)
            
            # Update org record
            new_hash = await self._get_schema_hash(org.database_name)
            await self._execute_query(
                """UPDATE organizations 
                   SET schema_sync_status = 'synced', 
                       schema_version = $1,
                       last_schema_sync = NOW()
                   WHERE id = $2""",
                new_hash, org.id
            )
            
            return {
                'organization': org_name,
                'status': 'synced',
                'old_hash': org_hash[:12],
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
                    
            except Exception as e:
                results['errors'] += 1
                results['details'].append({
                    'organization': org.name,
                    'status': 'error',
                    'error': str(e)
                })
        
        print(f"[AIOrganizationAgent] Schema sync complete: {results['synced']} synced, "
              f"{results['already_synced']} already synced, {results['errors']} errors")
        
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

        # Determine database name - use org-specific if set, otherwise fall back to env default
        db_name = org.database_name if org.database_name else os.getenv('POSTGRES_DB', 'security_portal')

        # Set database URL for this organization
        # This ensures scan results go to the org-specific database
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
        
        return f"postgresql://{self.db_user}:{self.db_password}@{self.db_host}:{self.db_port}/{org.database_name}"
    
    # =========================================================================
    # Scan Orchestration
    # =========================================================================
    
    async def start_scan(
        self,
        org_name: str,
        repos: Optional[List[str]] = None,
        scan_type: str = "full"
    ) -> Dict[str, Any]:
        """
        Start scan for organization.
        
        Args:
            org_name: Organization name
            repos: Optional list of specific repos to scan
            scan_type: Type of scan ('full', 'incremental', 'secrets')
            
        Returns:
            Scan job info
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
            'status': 'started'
        }
    
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
            import re
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
    
    async def _get_schema_hash(self, database_name: str) -> str:
        """Get SHA-256 hash of database schema DDL."""
        # Get schema DDL using pg_dump
        try:
            result = subprocess.run(
                [
                    'pg_dump',
                    '-h', self.db_host,
                    '-p', str(self.db_port),
                    '-U', self.db_user,
                    '-d', database_name,
                    '--schema-only',
                    '--no-owner',
                    '--no-privileges'
                ],
                capture_output=True,
                text=True,
                env={**os.environ, 'PGPASSWORD': self.db_password}
            )
            
            if result.returncode != 0:
                # Database might not exist yet
                return hashlib.sha256(b'').hexdigest()
            
            # Hash the schema DDL
            return hashlib.sha256(result.stdout.encode()).hexdigest()
            
        except FileNotFoundError:
            # pg_dump not available, use fallback
            return hashlib.sha256(database_name.encode()).hexdigest()
    
    async def _create_database(self, database_name: str):
        """Create a new database."""
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
            
            with conn.cursor() as cur:
                # Execute schema - split by semicolons and execute each statement
                # This is a simplified approach; complex schemas may need better parsing
                statements = [s.strip() for s in schema_sql.split(';') if s.strip()]
                for stmt in statements:
                    if stmt and not stmt.startswith('--'):
                        try:
                            cur.execute(stmt)
                        except Exception as e:
                            # Log but continue - some statements may fail if objects exist
                            if 'already exists' not in str(e).lower():
                                print(f"[AIOrganizationAgent] Statement warning: {e}")
            
            conn.close()
            print(f"[AIOrganizationAgent] Schema applied via psycopg2 to: {database_name}")
            
        except psycopg2.OperationalError as e:
            print(f"[AIOrganizationAgent] Database connection error: {e}")
            raise
    
    async def _ensure_database_exists(self, database_name: str):
        """Ensure a database exists, creating it if necessary."""
        if not psycopg2:
            raise RuntimeError("psycopg2 required for database creation")
        
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
