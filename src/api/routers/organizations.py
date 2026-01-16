"""
Organization Management API Router

Provides REST endpoints for multi-organization management:
- List, create, update, delete organizations
- Schema synchronization
- Organization context switching
- Scan orchestration per organization
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field
from datetime import datetime
import os
import sys
import asyncio

# Add execution directory to path for imports
sys.path.insert(0, '/app/execution')

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions
from src.auth.dependencies import get_current_user
from src.auth.models import User

router = APIRouter(
    prefix="/organizations",
    tags=["organizations"]
)


# =============================================================================
# Pydantic Models
# =============================================================================

class CreateOrganizationRequest(BaseModel):
    """Request model for creating an organization."""
    name: str = Field(..., description="Internal name (lowercase, alphanumeric)")
    github_org: str = Field(..., description="GitHub organization name")
    github_token: str = Field(..., description="GitHub personal access token")
    display_name: Optional[str] = Field(None, description="Human-readable display name")
    create_database: bool = Field(True, description="Create new database for this org")
    set_as_default: bool = Field(False, description="Set as default organization")


class UpdateOrganizationRequest(BaseModel):
    """Request model for updating an organization."""
    display_name: Optional[str] = None
    is_active: Optional[bool] = None
    is_default: Optional[bool] = None


class UpdateCredentialsRequest(BaseModel):
    """Request model for updating organization credentials."""
    github_token: str = Field(..., description="GitHub personal access token")
    github_org: Optional[str] = Field(None, description="GitHub organization name (optional)")


class OrganizationResponse(BaseModel):
    """Response model for organization data."""
    id: str
    api_id: Optional[int] = None
    name: str
    display_name: Optional[str] = None
    github_org: str
    database_name: Optional[str] = None
    is_active: bool = True
    is_default: bool = False
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Computed fields (not in DB)
    total_repos: int = 0
    total_findings: int = 0

    class Config:
        from_attributes = True


class SchemaDriftReport(BaseModel):
    """Schema drift report for an organization."""
    organization: str
    database: str
    is_synced: bool
    master_hash: Optional[str] = None
    org_hash: Optional[str] = None
    status: str
    error: Optional[str] = None


class SchemaSyncResult(BaseModel):
    """Result of schema synchronization."""
    organization: str
    status: str
    old_hash: Optional[str] = None
    new_hash: Optional[str] = None
    schema_hash: Optional[str] = None
    error: Optional[str] = None


# =============================================================================
# Helper Functions
# =============================================================================

def get_org_agent():
    """Get the AI Organization Agent instance."""
    try:
        from ai_org_agent import get_org_agent as _get_agent
        return _get_agent()
    except ImportError:
        raise HTTPException(
            status_code=500,
            detail="Organization agent not available"
        )


async def ensure_agent_initialized():
    """Ensure the organization agent is initialized."""
    agent = get_org_agent()
    if not agent._initialized:
        await agent.initialize()
    return agent


# =============================================================================
# Organization CRUD Endpoints
# =============================================================================

@router.get("/", response_model=List[OrganizationResponse])
async def list_organizations(
    include_inactive: bool = Query(False, description="Include inactive organizations"),
    db: Session = Depends(get_tenant_db)
):
    """
    List all registered organizations.

    Returns organizations sorted by default status, then name.
    """
    # Direct database query - more reliable than agent
    query = db.query(models.Organization)
    if not include_inactive:
        query = query.filter(models.Organization.is_active == True)
    orgs = query.order_by(
        models.Organization.is_default.desc(),
        models.Organization.name
    ).all()

    # Build response with computed fields
    # Note: For orgs with dedicated databases, use /organizations/{org_name}/repositories
    # and /organizations/{org_name}/findings endpoints for actual counts
    result = []
    for org in orgs:
        result.append(OrganizationResponse(
            id=str(org.id),
            api_id=org.api_id,
            name=org.name,
            display_name=org.display_name,
            github_org=org.github_org,
            database_name=org.database_name,
            is_active=org.is_active if org.is_active is not None else True,
            is_default=org.is_default if org.is_default is not None else False,
            created_at=org.created_at,
            updated_at=org.updated_at,
            total_repos=0,  # Use org-specific endpoints for accurate counts
            total_findings=0
        ))

    return result


@router.get("/current")
async def get_current_organization(db: Session = Depends(get_tenant_db)):
    """
    Get the currently selected organization context.
    
    Returns the default organization or first available.
    """
    # Try to get default org first
    org = db.query(models.Organization).filter(
        models.Organization.is_default == True,
        models.Organization.is_active == True
    ).first()
    
    # If no default, get first active org
    if not org:
        org = db.query(models.Organization).filter(
            models.Organization.is_active == True
        ).first()
    
    if org:
        repo_count = db.query(models.Repository).filter(
            models.Repository.organization_id == org.id
        ).count()
        finding_count = db.query(models.Finding).filter(
            models.Finding.organization_id == org.id
        ).count()
        
        return OrganizationResponse(
            id=str(org.id),
            api_id=org.api_id,
            name=org.name,
            display_name=org.display_name,
            github_org=org.github_org,
            database_name=org.database_name,
            is_active=org.is_active if org.is_active is not None else True,
            is_default=org.is_default if org.is_default is not None else False,
            created_at=org.created_at,
            updated_at=org.updated_at,
            total_repos=repo_count,
            total_findings=finding_count
        )
    
    return {"message": "No organization configured", "organization": None}


@router.get("/{org_name}", response_model=OrganizationResponse)
async def get_organization(org_name: str, db: Session = Depends(get_tenant_db)):
    """
    Get organization details by name.
    
    Args:
        org_name: Organization name (case-insensitive)
    """
    org = db.query(models.Organization).filter(
        models.Organization.name.ilike(org_name)
    ).first()
    
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
    
    repo_count = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id
    ).count()
    finding_count = db.query(models.Finding).filter(
        models.Finding.organization_id == org.id
    ).count()
    
    return OrganizationResponse(
        id=str(org.id),
        api_id=org.api_id,
        name=org.name,
        display_name=org.display_name,
        github_org=org.github_org,
        database_name=org.database_name,
        is_active=org.is_active if org.is_active is not None else True,
        is_default=org.is_default if org.is_default is not None else False,
        created_at=org.created_at,
        updated_at=org.updated_at,
        total_repos=repo_count,
        total_findings=finding_count
    )


@router.post("/", response_model=OrganizationResponse)
async def create_organization(request: CreateOrganizationRequest):
    """
    Create a new organization with isolated database.
    
    This will:
    1. Create a new PostgreSQL database
    2. Apply the master schema
    3. Store credentials securely
    4. Register the organization
    """
    try:
        agent = await ensure_agent_initialized()
        org = await agent.create_organization(
            name=request.name,
            github_org=request.github_org,
            github_token=request.github_token,
            display_name=request.display_name,
            create_database=request.create_database,
            set_as_default=request.set_as_default
        )
        return org.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.patch("/{org_name}", response_model=OrganizationResponse)
async def update_organization(org_name: str, request: UpdateOrganizationRequest):
    """
    Update organization properties.
    
    Args:
        org_name: Organization name
        request: Fields to update
    """
    try:
        agent = await ensure_agent_initialized()
        org = await agent.update_organization(
            name=org_name,
            display_name=request.display_name,
            is_active=request.is_active,
            is_default=request.is_default
        )
        return org.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{org_name}")
async def delete_organization(
    org_name: str,
    drop_database: bool = Query(False, description="Also drop the organization's database")
):
    """
    Delete an organization.
    
    Args:
        org_name: Organization name
        drop_database: If True, also drops the PostgreSQL database
    """
    try:
        agent = await ensure_agent_initialized()
        success = await agent.delete_organization(org_name, drop_database=drop_database)
        if not success:
            raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
        return {"success": True, "message": f"Organization '{org_name}' deleted"}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Organization Selection Endpoints
# =============================================================================

@router.post("/{org_name}/select", response_model=OrganizationResponse)
async def select_organization(org_name: str, db: Session = Depends(get_tenant_db)):
    """
    Select organization as current context.
    
    This loads the organization's credentials and configures
    the environment for scanning operations. It also switches
    the database connection to the organization's database.
    
    Args:
        org_name: Organization name to select
    """
    org = db.query(models.Organization).filter(
        models.Organization.name.ilike(org_name)
    ).first()
    
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
    
    # Set organization context for query filtering
    # NOTE: We use master DB with organization_id filtering, not separate DBs
    from ..database import set_current_org_database
    set_current_org_database(
        database_name=org.database_name,
        org_id=str(org.id),
        org_name=org.name
    )
    
    repo_count = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id
    ).count()
    finding_count = db.query(models.Finding).filter(
        models.Finding.organization_id == org.id
    ).count()
    
    return OrganizationResponse(
        id=str(org.id),
        api_id=org.api_id,
        name=org.name,
        display_name=org.display_name,
        github_org=org.github_org,
        database_name=org.database_name,
        is_active=org.is_active if org.is_active is not None else True,
        is_default=org.is_default if org.is_default is not None else False,
        created_at=org.created_at,
        updated_at=org.updated_at,
        total_repos=repo_count,
        total_findings=finding_count
    )


# =============================================================================
# Schema Synchronization Endpoints
# =============================================================================

@router.get("/schema/drift", response_model=List[SchemaDriftReport])
async def check_schema_drift():
    """
    Check all organization databases for schema drift.
    
    Compares each organization's schema against the master schema
    and reports any differences.
    """
    try:
        agent = await ensure_agent_initialized()
        results = await agent.check_schema_drift()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{org_name}/sync-schema", response_model=SchemaSyncResult)
async def sync_organization_schema(org_name: str):
    """
    Synchronize organization schema with master.
    
    Applies any missing migrations and updates the schema
    to match the master database.
    
    Args:
        org_name: Organization name
    """
    try:
        agent = await ensure_agent_initialized()
        result = await agent.sync_schema(org_name)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/schema/sync-all")
async def sync_all_schemas():
    """
    Synchronize all organization schemas with master.
    
    Runs schema sync for every registered organization.
    """
    try:
        agent = await ensure_agent_initialized()
        results = await agent.sync_all_schemas()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Scan Orchestration Endpoints
# =============================================================================

@router.post("/{org_name}/scan")
async def start_organization_scan(
    org_name: str,
    repos: Optional[List[str]] = Query(None, description="Specific repos to scan"),
    scan_type: str = Query("full", description="Scan type: full, incremental, secrets")
):
    """
    Start a scan for an organization.
    
    Selects the organization context and initiates scanning
    for all or specified repositories.
    
    Args:
        org_name: Organization name
        repos: Optional list of specific repos to scan
        scan_type: Type of scan to perform
    """
    try:
        agent = await ensure_agent_initialized()
        result = await agent.start_scan(org_name, repos=repos, scan_type=scan_type)
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{org_name}/scan/status")
async def get_scan_status(org_name: str):
    """
    Get current scan status for an organization.
    
    Args:
        org_name: Organization name
    """
    try:
        agent = await ensure_agent_initialized()
        org = await agent.get_organization(org_name)
        if not org:
            raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
        
        return {
            "organization": org.name,
            "scan_status": org.scan_status,
            "last_scan_at": org.last_scan_at.isoformat() if org.last_scan_at else None,
            "total_repos": org.total_repos,
            "total_findings": org.total_findings
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Credential Management Endpoints
# =============================================================================

@router.get("/{org_name}/credentials/status")
async def get_credentials_status(org_name: str):
    """
    Check if credentials are configured for an organization.
    
    Does not return actual credential values for security.
    
    Args:
        org_name: Organization name
    """
    try:
        from secrets_manager import get_secrets_manager
        manager = get_secrets_manager()
        
        has_token = await manager.secret_exists(f"{org_name.lower()}/github_token")
        has_org = await manager.secret_exists(f"{org_name.lower()}/github_org")
        
        return {
            "organization": org_name,
            "github_token_configured": has_token,
            "github_org_configured": has_org,
            "fully_configured": has_token and has_org
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/{org_name}/credentials")
async def update_credentials(
    org_name: str,
    request: UpdateCredentialsRequest
):
    """
    Update credentials for an organization.
    
    Use this to rotate or update the GitHub PAT for an organization.
    The token is stored securely in the secrets manager.
    
    Args:
        org_name: Organization name
        request: JSON body with github_token and optional github_org
    """
    try:
        from secrets_manager import set_org_credentials
        
        # Verify organization exists
        agent = await ensure_agent_initialized()
        org = await agent.get_organization(org_name)
        if not org:
            raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
        
        await set_org_credentials(
            org_name, 
            request.github_token, 
            request.github_org or org.github_org
        )
        
        return {
            "success": True,
            "message": f"Credentials updated for '{org_name}'"
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Utility Endpoints
# =============================================================================

@router.get("/configured")
async def list_configured_organizations():
    """
    List organizations that have credentials configured.
    
    Returns organization names that have GitHub tokens stored
    in the secrets manager.
    """
    try:
        from secrets_manager import list_configured_orgs
        orgs = await list_configured_orgs()
        return {"configured_organizations": orgs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Organization Data Endpoints
# =============================================================================

@router.get("/{org_name}/repositories")
async def get_organization_repositories(
    org_name: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_tenant_db)
):
    """
    Get repositories for a specific organization.
    
    Queries the organization's dedicated database to fetch repositories.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Get organization
    org = db.query(models.Organization).filter(
        models.Organization.name == org_name
    ).first()
    
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
    
    if not org.database_name:
        raise HTTPException(status_code=400, detail=f"Organization '{org_name}' has no database configured")
    
    # Connect to org-specific database
    try:
        db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/security_portal')
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        org_db_url = db_url.rsplit('/', 1)[0] + '/' + org.database_name
        
        engine = create_engine(org_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
        OrgSession = sessionmaker(bind=engine)
        org_db = OrgSession()
        
        try:
            # Query repositories
            repos = org_db.query(models.Repository).order_by(
                models.Repository.last_scanned_at.desc().nullslast()
            ).offset(skip).limit(limit).all()
            
            result = []
            for repo in repos:
                # Count findings for each repo
                finding_count = org_db.query(models.Finding).filter(
                    models.Finding.repository_id == repo.id
                ).count()
                
                result.append({
                    "id": str(repo.id),
                    "name": repo.name,
                    "full_name": repo.full_name,
                    "url": repo.url,
                    "description": repo.description,
                    "language": repo.language,
                    "last_scanned_at": repo.last_scanned_at.isoformat() if repo.last_scanned_at else None,
                    "finding_count": finding_count,
                    "is_private": repo.is_private,
                    "is_archived": repo.is_archived
                })
            
            return result
        finally:
            org_db.close()
            engine.dispose()
    except Exception as e:
        import logging
        logging.error(f"Failed to query org database {org.database_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query organization database: {str(e)}")


@router.get("/{org_name}/findings")
async def get_organization_findings(
    org_name: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    repository_id: Optional[str] = Query(None, description="Filter by repository ID"),
    db: Session = Depends(get_tenant_db)
):
    """
    Get findings for a specific organization.
    
    Queries the organization's dedicated database to fetch findings.
    """
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    
    # Get organization
    org = db.query(models.Organization).filter(
        models.Organization.name == org_name
    ).first()
    
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
    
    if not org.database_name:
        raise HTTPException(status_code=400, detail=f"Organization '{org_name}' has no database configured")
    
    # Connect to org-specific database
    try:
        db_url = os.getenv('DATABASE_URL', 'postgresql://postgres:postgres@db:5432/security_portal')
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        org_db_url = db_url.rsplit('/', 1)[0] + '/' + org.database_name
        
        engine = create_engine(org_db_url, pool_pre_ping=True, pool_size=1, max_overflow=0)
        OrgSession = sessionmaker(bind=engine)
        org_db = OrgSession()
        
        try:
            # Build query
            query = org_db.query(models.Finding)
            
            if severity:
                query = query.filter(models.Finding.severity == severity.lower())
            
            if repository_id:
                query = query.filter(models.Finding.repository_id == repository_id)
            
            # Execute query with pagination
            findings = query.order_by(
                models.Finding.created_at.desc()
            ).offset(skip).limit(limit).all()
            
            result = []
            for finding in findings:
                result.append({
                    "id": str(finding.id),
                    "repository_id": str(finding.repository_id) if finding.repository_id else None,
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity,
                    "scanner_name": finding.scanner_name,
                    "file_path": finding.file_path,
                    "line_start": finding.line_start,
                    "line_end": finding.line_end,
                    "cwe_id": finding.cwe_id,
                    "cve_id": finding.cve_id,
                    "created_at": finding.created_at.isoformat() if finding.created_at else None
                })
            
            return result
        finally:
            org_db.close()
            engine.dispose()
    except Exception as e:
        import logging
        logging.error(f"Failed to query org database {org.database_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query organization database: {str(e)}")
