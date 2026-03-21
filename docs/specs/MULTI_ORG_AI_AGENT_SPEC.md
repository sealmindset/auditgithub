# Multi-Organization AI Agent Architecture Specification

## Overview

This specification defines an AI-orchestrated multi-organization management system that enables scanning multiple GitHub organizations with isolated databases, dynamic credential management, and intelligent schema synchronization.

## Problem Statement

Currently, the system uses a single `.env` configuration with:
- `GITHUB_TOKEN` - Single token for all operations
- `GITHUB_ORG` - Single organization target

This limits the system to one organization at a time and requires manual reconfiguration for each org.

## Proposed Solution

### 1. Organization Registry

#### Database Schema (`public.organizations`)

```sql
CREATE TABLE public.organizations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_id BIGSERIAL UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL UNIQUE,           -- e.g., 'example-org', 'example-orginc'
    display_name VARCHAR(255),                    -- e.g., 'Seal Mindset', 'Example Organization Inc'
    github_org VARCHAR(255) NOT NULL,             -- GitHub organization name
    database_name VARCHAR(255) NOT NULL UNIQUE,   -- e.g., 'auditgithub_example-org'
    database_host VARCHAR(255) DEFAULT 'localhost',
    database_port INTEGER DEFAULT 5432,
    is_active BOOLEAN DEFAULT true,
    schema_version VARCHAR(50),                   -- Track schema version for sync
    last_schema_sync TIMESTAMPTZ,
    last_scan_at TIMESTAMPTZ,
    scan_status VARCHAR(50) DEFAULT 'idle',       -- 'idle', 'scanning', 'error'
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Secrets stored separately with encryption
CREATE TABLE public.organization_secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id UUID NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
    secret_type VARCHAR(50) NOT NULL,             -- 'github_token', 'anthropic_key', etc.
    secret_value_encrypted BYTEA NOT NULL,        -- Encrypted with master key
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    UNIQUE(organization_id, secret_type)
);
```

#### Environment Variables

```bash
# Master database (stores organization registry)
MASTER_DATABASE_URL=postgresql://user:pass@localhost:5432/auditgithub_master

# Encryption key for secrets
SECRETS_MASTER_KEY=<32-byte-hex-key>

# Organization-specific credentials (loaded dynamically)
# Format: {ORG_NAME}_GITHUB_TOKEN, {ORG_NAME}_GITHUB_ORG
# These are stored encrypted in organization_secrets table

# Legacy fallback (optional)
GITHUB_TOKEN=<default-token>
GITHUB_ORG=<default-org>
```

### 2. AI Organization Agent

#### Agent Responsibilities

1. **Organization Lifecycle Management**
   - Create new organization entries
   - Provision isolated databases
   - Configure credentials securely
   - Deactivate/archive organizations

2. **Schema Synchronization**
   - Monitor master schema for changes
   - Detect schema drift across org databases
   - Apply migrations atomically
   - Rollback on failure
   - Report sync status

3. **Scan Orchestration**
   - Select target organization
   - Load appropriate credentials
   - Configure scanner context
   - Monitor scan progress
   - Handle failures gracefully

4. **Health Monitoring**
   - Check database connectivity
   - Validate credentials
   - Report schema versions
   - Alert on drift/errors

#### Agent Implementation (`execution/ai_org_agent.py`)

```python
"""
AI Organization Management Agent

Handles multi-organization orchestration including:
- Organization CRUD operations
- Database provisioning and schema sync
- Credential management
- Scan orchestration
"""

import os
import asyncio
import hashlib
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum
from cryptography.fernet import Fernet
import asyncpg

class OrgStatus(Enum):
    IDLE = "idle"
    SCANNING = "scanning"
    SYNCING = "syncing"
    ERROR = "error"

@dataclass
class Organization:
    id: str
    name: str
    display_name: str
    github_org: str
    database_name: str
    database_host: str
    database_port: int
    is_active: bool
    schema_version: Optional[str]
    last_scan_at: Optional[str]
    scan_status: str

class AIOrganizationAgent:
    """
    AI-powered organization management agent.
    
    Handles multi-org orchestration with intelligent
    schema synchronization and credential management.
    """
    
    def __init__(self, master_db_url: str, secrets_key: str):
        self.master_db_url = master_db_url
        self.cipher = Fernet(secrets_key.encode())
        self._current_org: Optional[Organization] = None
    
    # =========================================================================
    # Organization Management
    # =========================================================================
    
    async def list_organizations(self) -> List[Organization]:
        """List all registered organizations."""
        pass
    
    async def get_organization(self, name: str) -> Optional[Organization]:
        """Get organization by name."""
        pass
    
    async def create_organization(
        self,
        name: str,
        github_org: str,
        github_token: str,
        display_name: Optional[str] = None
    ) -> Organization:
        """
        Create a new organization with isolated database.
        
        Steps:
        1. Validate inputs
        2. Create database from master schema
        3. Store encrypted credentials
        4. Register in organizations table
        """
        pass
    
    async def delete_organization(self, name: str, drop_database: bool = False):
        """Delete organization and optionally drop its database."""
        pass
    
    # =========================================================================
    # Credential Management
    # =========================================================================
    
    async def get_credentials(self, org_name: str) -> Dict[str, str]:
        """
        Retrieve decrypted credentials for an organization.
        
        Returns dict with keys like 'github_token', 'anthropic_key', etc.
        """
        pass
    
    async def set_credential(self, org_name: str, secret_type: str, value: str):
        """Store encrypted credential for organization."""
        pass
    
    # =========================================================================
    # Schema Synchronization
    # =========================================================================
    
    async def get_master_schema_version(self) -> str:
        """Get current master schema version/hash."""
        pass
    
    async def check_schema_drift(self) -> List[Dict[str, Any]]:
        """
        Check all org databases for schema drift.
        
        Returns list of orgs with drift details.
        """
        pass
    
    async def sync_schema(self, org_name: str) -> bool:
        """
        Synchronize organization database schema with master.
        
        Uses AI to:
        1. Detect differences
        2. Generate migration SQL
        3. Apply safely with rollback
        """
        pass
    
    async def sync_all_schemas(self) -> Dict[str, bool]:
        """Sync all organization schemas with master."""
        pass
    
    # =========================================================================
    # Scan Orchestration
    # =========================================================================
    
    async def select_organization(self, name: str) -> Organization:
        """
        Select organization as current target.
        
        Loads credentials and configures environment.
        """
        pass
    
    async def get_current_organization(self) -> Optional[Organization]:
        """Get currently selected organization."""
        return self._current_org
    
    async def start_scan(
        self,
        org_name: str,
        repos: Optional[List[str]] = None,
        scan_type: str = "full"
    ) -> str:
        """
        Start scan for organization.
        
        Returns scan job ID.
        """
        pass
    
    async def get_scan_status(self, org_name: str) -> Dict[str, Any]:
        """Get current scan status for organization."""
        pass
```

### 3. CLI Interface

#### New Command-Line Arguments

```bash
# Scan with organization target
python scan.py --target example-org --repos repo1,repo2

# List organizations
python scan.py --list-orgs

# Create new organization
python scan.py --create-org example-orginc \
    --github-org example-orginc \
    --github-token ghp_xxx

# Sync schemas
python scan.py --sync-schemas
python scan.py --sync-schema example-org

# Check schema drift
python scan.py --check-drift
```

#### Implementation (`scan.py` additions)

```python
import argparse
from execution.ai_org_agent import AIOrganizationAgent

def add_org_arguments(parser: argparse.ArgumentParser):
    """Add organization management arguments."""
    org_group = parser.add_argument_group('Organization Management')
    
    org_group.add_argument(
        '--target', '-t',
        help='Target organization name (e.g., example-org)'
    )
    org_group.add_argument(
        '--list-orgs',
        action='store_true',
        help='List all registered organizations'
    )
    org_group.add_argument(
        '--create-org',
        metavar='NAME',
        help='Create new organization'
    )
    org_group.add_argument(
        '--github-org',
        help='GitHub organization name (for --create-org)'
    )
    org_group.add_argument(
        '--github-token',
        help='GitHub token (for --create-org)'
    )
    org_group.add_argument(
        '--sync-schemas',
        action='store_true',
        help='Sync all organization schemas with master'
    )
    org_group.add_argument(
        '--sync-schema',
        metavar='ORG',
        help='Sync specific organization schema'
    )
    org_group.add_argument(
        '--check-drift',
        action='store_true',
        help='Check for schema drift across organizations'
    )
```

### 4. Web UI Integration

#### Organization Selector Component

```tsx
// components/OrganizationSelector.tsx

interface Organization {
    id: string
    name: string
    display_name: string
    github_org: string
    is_active: boolean
    scan_status: string
    last_scan_at: string | null
    schema_version: string | null
}

export function OrganizationSelector() {
    const [organizations, setOrganizations] = useState<Organization[]>([])
    const [currentOrg, setCurrentOrg] = useState<Organization | null>(null)
    
    // Fetch organizations on mount
    useEffect(() => {
        fetchOrganizations()
    }, [])
    
    const selectOrganization = async (orgName: string) => {
        const response = await fetch(`${API_BASE}/organizations/${orgName}/select`, {
            method: 'POST'
        })
        if (response.ok) {
            const org = await response.json()
            setCurrentOrg(org)
            // Trigger data refresh for new org context
        }
    }
    
    return (
        <Select value={currentOrg?.name} onValueChange={selectOrganization}>
            <SelectTrigger>
                <SelectValue placeholder="Select Organization" />
            </SelectTrigger>
            <SelectContent>
                {organizations.map(org => (
                    <SelectItem key={org.id} value={org.name}>
                        <div className="flex items-center gap-2">
                            <Building2 className="h-4 w-4" />
                            {org.display_name || org.name}
                            {org.scan_status === 'scanning' && (
                                <Loader2 className="h-3 w-3 animate-spin" />
                            )}
                        </div>
                    </SelectItem>
                ))}
            </SelectContent>
        </Select>
    )
}
```

#### Organization Management Page

```tsx
// pages/Organizations.tsx

export function OrganizationsPage() {
    // CRUD operations for organizations
    // Schema sync controls
    // Credential management (masked)
    // Scan history per org
}
```

### 5. API Endpoints

#### New Router (`src/api/routers/organizations.py`)

```python
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/organizations", tags=["organizations"])

class CreateOrgRequest(BaseModel):
    name: str
    github_org: str
    github_token: str
    display_name: Optional[str] = None

class OrgResponse(BaseModel):
    id: str
    name: str
    display_name: Optional[str]
    github_org: str
    is_active: bool
    scan_status: str
    schema_version: Optional[str]
    last_scan_at: Optional[str]

@router.get("/")
async def list_organizations() -> List[OrgResponse]:
    """List all organizations."""
    pass

@router.post("/")
async def create_organization(request: CreateOrgRequest) -> OrgResponse:
    """Create new organization with isolated database."""
    pass

@router.get("/{org_name}")
async def get_organization(org_name: str) -> OrgResponse:
    """Get organization details."""
    pass

@router.post("/{org_name}/select")
async def select_organization(org_name: str) -> OrgResponse:
    """Select organization as current context."""
    pass

@router.delete("/{org_name}")
async def delete_organization(org_name: str, drop_database: bool = False):
    """Delete organization."""
    pass

@router.post("/{org_name}/sync-schema")
async def sync_organization_schema(org_name: str) -> Dict[str, Any]:
    """Sync organization schema with master."""
    pass

@router.get("/schema/drift")
async def check_schema_drift() -> List[Dict[str, Any]]:
    """Check schema drift across all organizations."""
    pass

@router.post("/{org_name}/scan")
async def start_scan(org_name: str, repos: Optional[List[str]] = None):
    """Start scan for organization."""
    pass
```

### 6. Database Provisioning

#### Schema Template

The master database schema serves as the template. When creating a new org:

1. Create new database: `CREATE DATABASE auditgithub_{org_name}`
2. Apply master schema via `pg_dump` / `pg_restore` or SQL files
3. Record schema version hash
4. Store in organization registry

#### Schema Sync Algorithm

```python
async def sync_schema(self, org_name: str) -> bool:
    """
    AI-powered schema synchronization.
    
    1. Get master schema DDL
    2. Get org schema DDL
    3. Use AI to diff and generate migration
    4. Validate migration safety
    5. Apply in transaction with rollback
    """
    master_ddl = await self._get_schema_ddl(self.master_db_url)
    org_ddl = await self._get_schema_ddl(org.database_url)
    
    if master_ddl == org_ddl:
        return True  # Already in sync
    
    # AI generates migration
    migration_sql = await self._ai_generate_migration(
        source_ddl=org_ddl,
        target_ddl=master_ddl
    )
    
    # Validate migration is safe
    if not await self._validate_migration(migration_sql):
        raise SchemaError("Migration validation failed")
    
    # Apply with transaction
    async with org_conn.transaction():
        await org_conn.execute(migration_sql)
        await self._update_schema_version(org_name)
    
    return True
```

### 7. Security Considerations

1. **Credential Encryption**: All tokens stored encrypted with Fernet (AES-128)
2. **Database Isolation**: Each org has separate database, no cross-access
3. **Audit Logging**: All org operations logged with actor/timestamp
4. **Token Rotation**: Support for credential rotation without downtime
5. **Least Privilege**: Org-specific DB users with minimal permissions

### 8. Implementation Phases

#### Phase 1: Foundation (Week 1)
- [ ] Create organization registry tables
- [ ] Implement AIOrganizationAgent core
- [ ] Add credential encryption/decryption
- [ ] CLI `--target` argument

#### Phase 2: Database Management (Week 2)
- [ ] Database provisioning from master
- [ ] Schema version tracking
- [ ] Schema drift detection
- [ ] Basic sync functionality

#### Phase 3: AI Enhancement (Week 3)
- [ ] AI-powered migration generation
- [ ] Migration validation
- [ ] Intelligent error recovery
- [ ] Health monitoring

#### Phase 4: UI Integration (Week 4)
- [ ] Organization selector component
- [ ] Organization management page
- [ ] Scan orchestration UI
- [ ] Schema sync dashboard

### 9. Example Usage

```bash
# Initial setup - create organizations
python scan.py --create-org example-org \
    --github-org example-org \
    --github-token ghp_seal_xxx

python scan.py --create-org example-orginc \
    --github-org example-orginc \
    --github-token ghp_sleep_xxx

# List organizations
python scan.py --list-orgs
# Output:
# Organizations:
#   example-org (active) - last scan: 2024-01-15
#   example-orginc (active) - last scan: 2024-01-14

# Scan specific org
python scan.py --target example-org --repos api-service,web-app

# Check schema drift
python scan.py --check-drift
# Output:
# Schema Drift Report:
#   example-org: IN SYNC (v2.3.0)
#   example-orginc: DRIFT DETECTED (v2.2.0 -> v2.3.0)

# Sync drifted schema
python scan.py --sync-schema example-orginc
```

### 10. Files to Create/Modify

#### New Files
- `execution/ai_org_agent.py` - AI Organization Agent
- `src/api/routers/organizations.py` - API endpoints
- `src/web-ui/components/OrganizationSelector.tsx` - UI selector
- `src/web-ui/pages/Organizations.tsx` - Management page
- `db/portal_init/020_organizations.sql` - Schema migration

#### Modified Files
- `scan.py` - Add org arguments
- `.env.example` - Add new variables
- `src/api/main.py` - Register new router
- `docker-compose.yml` - Multi-database support

---

## Design Decisions

1. **Database hosting**: Same PostgreSQL instance, securely segmented per organization
2. **Credential storage**: Mock external secrets manager (development) → Real secrets manager (production). Code uses same fetch/store workflow regardless of backend.
3. **Schema sync frequency**: Automatic on startup, with manual sync option for troubleshooting
4. **UI location**: Top nav selector for quick organization switching
5. **Migration strategy**: Convert existing database to `example-org` as the first organization
