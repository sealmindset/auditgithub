"""
Organization Management API Router

Provides REST endpoints for multi-organization management:
- List, create, update, delete organizations
- Schema synchronization
- Organization context switching
- Scan orchestration per organization
"""

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from loguru import logger
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
from src.api.schemas.common import LIST_ERRORS, CRUD_ERRORS, CREATE_ERRORS, DELETE_ERRORS
from src.services.scan_runner import (
    OrgScanAlreadyRunning,
    ScanScriptNotFound,
    get_org_scan_runner,
)

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
    display_name: Optional[str] = Field(None, description="Human-readable display name for the organization")
    is_active: Optional[bool] = Field(None, description="Whether the organization is active and available for operations")
    is_default: Optional[bool] = Field(None, description="Whether to set this organization as the default context")


class UpdateCredentialsRequest(BaseModel):
    """Request model for updating organization credentials."""
    github_token: str = Field(..., description="GitHub personal access token")
    github_org: Optional[str] = Field(None, description="GitHub organization name (optional)")


class ImportRepositoryRequest(BaseModel):
    """Request model for importing a single repository."""
    repo_name: str = Field(..., description="Repository name as it appears on GitHub, without the owner")
    auto_scan: bool = Field(False, description="Queue a security scan of the repository once imported")


class GitHubRepoSearchResult(BaseModel):
    """One repository found on GitHub."""
    name: str = Field(..., description="Repository name without the owner")
    full_name: str = Field(..., description="owner/name as GitHub reports it")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary language GitHub detected")
    visibility: Optional[str] = Field(None, description="public, private or internal")
    is_archived: bool = Field(False, description="Whether the repository is archived on GitHub")
    updated_at: Optional[str] = Field(None, description="ISO timestamp of the last update on GitHub")
    already_imported: bool = Field(False, description="Whether this repository is already in the database")


class GitHubRepoSearchResponse(BaseModel):
    """Response model for a GitHub repository search."""
    results: List[GitHubRepoSearchResult] = Field(..., description="Repositories matching the query")
    total: int = Field(..., description="Total matches GitHub reports, which may exceed len(results)")
    truncated: bool = Field(..., description="True when GitHub has more matches than were returned")


class ImportRepositoryResponse(BaseModel):
    """Response model for a single-repository import."""
    repository: str = Field(..., description="Repository name that was imported")
    action: str = Field(..., description="What happened to the database row: created or updated")
    scan_started: bool = Field(..., description="Whether a scan was queued for the repository")
    scan_id: Optional[str] = Field(None, description="ScanRun UUID when a scan was queued")
    scan_error: Optional[str] = Field(None, description="Why no scan was queued, when auto_scan was asked for")


class OrganizationResponse(BaseModel):
    """Response model for organization data."""
    id: str = Field(..., description="Unique identifier for the organization (UUID)")
    api_id: Optional[int] = Field(None, description="Auto-incremented API identifier")
    name: str = Field(..., description="Internal name of the organization (lowercase, alphanumeric)")
    display_name: Optional[str] = Field(None, description="Human-readable display name")
    github_org: str = Field(..., description="GitHub organization name")
    database_name: Optional[str] = Field(None, description="Name of the isolated PostgreSQL database for this organization")
    is_active: bool = Field(True, description="Whether the organization is active and available for operations")
    is_default: bool = Field(False, description="Whether this is the default organization context")
    created_at: Optional[datetime] = Field(None, description="Timestamp when the organization was created")
    updated_at: Optional[datetime] = Field(None, description="Timestamp when the organization was last updated")
    # Computed fields (not in DB)
    total_repos: int = Field(0, description="Total number of repositories belonging to this organization")
    total_findings: int = Field(0, description="Total number of security findings across all repositories")

    class Config:
        from_attributes = True


class SchemaDriftReport(BaseModel):
    """Schema drift report for an organization."""
    organization: str = Field(..., description="Name of the organization being checked")
    database: str = Field(..., description="Name of the organization's PostgreSQL database")
    is_synced: bool = Field(..., description="Whether the organization schema matches the master schema")
    master_hash: Optional[str] = Field(None, description="SHA-256 hash of the master schema")
    org_hash: Optional[str] = Field(None, description="SHA-256 hash of the organization's current schema")
    status: str = Field(..., description="Human-readable sync status (e.g., 'synced', 'drifted', 'error')")
    error: Optional[str] = Field(None, description="Error message if schema check failed")


class SchemaSyncResult(BaseModel):
    """Result of schema synchronization."""
    organization: str = Field(..., description="Name of the organization whose schema was synchronized")
    status: str = Field(..., description="Result status of the sync operation (e.g., 'success', 'failed', 'no_changes')")
    old_hash: Optional[str] = Field(None, description="Schema hash before synchronization")
    new_hash: Optional[str] = Field(None, description="Schema hash after synchronization")
    schema_hash: Optional[str] = Field(None, description="Current schema hash after the operation")
    error: Optional[str] = Field(None, description="Error message if synchronization failed")


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

@router.get(
    "/",
    response_model=List[OrganizationResponse],
    summary="List all organizations",
    responses={**LIST_ERRORS},
)
async def list_organizations(
    include_inactive: bool = Query(False, description="Include inactive organizations"),
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    """
    List organizations the current user can access.

    Super admins and admins see all organizations.
    Manager, analyst, and user roles only see orgs they are assigned to.
    """
    from sqlalchemy import func

    query = db.query(models.Organization)
    if not include_inactive:
        query = query.filter(models.Organization.is_active == True)

    # Non-admin users: filter to assigned organizations only
    if current_user.role not in ("super_admin", "admin"):
        # Look up the DB user to get the UUID
        db_user = db.query(models.User).filter(models.User.email == current_user.email).first()
        if db_user:
            assigned_org_ids = [
                row.organization_id
                for row in db.query(models.UserOrganizationAccess.organization_id)
                .filter(models.UserOrganizationAccess.user_id == db_user.id)
                .all()
            ]
            if assigned_org_ids:
                query = query.filter(models.Organization.id.in_(assigned_org_ids))
            else:
                # No assignments → no orgs visible
                return []

    orgs = query.order_by(
        models.Organization.is_default.desc(),
        models.Organization.name
    ).all()

    # Get counts in bulk using efficient queries
    org_ids = [org.id for org in orgs]

    # Bulk repo counts
    repo_counts = dict(
        db.query(models.Repository.organization_id, func.count(models.Repository.id))
        .filter(models.Repository.organization_id.in_(org_ids))
        .group_by(models.Repository.organization_id)
        .all()
    )

    # Bulk finding counts
    finding_counts = dict(
        db.query(models.Finding.organization_id, func.count(models.Finding.id))
        .filter(models.Finding.organization_id.in_(org_ids))
        .group_by(models.Finding.organization_id)
        .all()
    )

    # Build response with computed fields
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
            total_repos=repo_counts.get(org.id, 0),
            total_findings=finding_counts.get(org.id, 0)
        ))

    return result


@router.get(
    "/current",
    summary="Get current organization context",
    responses={**CRUD_ERRORS},
)
async def get_current_organization(db: Session = Depends(get_tenant_db)):
    """
    Get the currently selected organization context.

    Returns the default organization if one is set, otherwise falls back to
    the first active organization. Includes repository and finding counts.
    No special permissions are required.
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


@router.get(
    "/configured",
    summary="List organizations with configured credentials",
    responses={**LIST_ERRORS},
)
async def list_configured_organizations():
    """
    List organizations that have credentials configured.

    Returns organization names that have GitHub tokens stored in the secrets
    manager. Useful for verifying which organizations are ready for scanning.
    No special permissions are required.
    """
    try:
        from secrets_manager import list_configured_orgs
        orgs = await list_configured_orgs()
        return {"configured_organizations": orgs}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# Every literal path under /organizations/ has to be declared above
# /{org_name}, which matches any single segment. Declared after it, this route
# was unreachable: a request for /organizations/configured was answered by
# get_organization() with 404 "Organization 'configured' not found", which
# reads as a missing organization rather than a missing route.
@router.get(
    "/{org_name}",
    response_model=OrganizationResponse,
    summary="Get organization by name",
    responses={**CRUD_ERRORS},
)
async def get_organization(org_name: str, db: Session = Depends(get_tenant_db)):
    """
    Get organization details by name.

    Performs a case-insensitive lookup and returns the organization along with
    computed repository and finding counts. No special permissions are required.

    Args:
        org_name: Organization name (case-insensitive)
    """
    from sqlalchemy import func

    org = db.query(models.Organization).filter(
        models.Organization.name.ilike(org_name)
    ).first()

    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")

    repo_count = db.query(func.count(models.Repository.id)).filter(
        models.Repository.organization_id == org.id
    ).scalar() or 0
    finding_count = db.query(func.count(models.Finding.id)).filter(
        models.Finding.organization_id == org.id
    ).scalar() or 0
    
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


@router.post(
    "/",
    response_model=OrganizationResponse,
    summary="Create a new organization",
    responses={**CREATE_ERRORS},
)
async def create_organization(request: CreateOrganizationRequest):
    """
    Create a new organization with isolated database.

    This will:
    1. Create a new PostgreSQL database
    2. Apply the master schema
    3. Store credentials securely
    4. Register the organization

    Requires administrative permissions to provision new organizations.
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


@router.patch(
    "/{org_name}",
    response_model=OrganizationResponse,
    summary="Update organization properties",
    responses={**CRUD_ERRORS},
)
async def update_organization(org_name: str, request: UpdateOrganizationRequest):
    """
    Update organization properties.

    Allows partial updates to an organization's display name, active status,
    or default flag. Requires administrative permissions.

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


@router.delete(
    "/{org_name}",
    summary="Delete an organization",
    responses={**DELETE_ERRORS, 400: {"description": "Cannot delete the last active organization"}},
)
async def delete_organization(
    org_name: str,
    drop_database: bool = Query(False, description="Also drop the organization's database")
):
    """
    Delete an organization.

    Removes the organization registration and optionally drops its isolated
    PostgreSQL database. This action is irreversible. Requires administrative
    permissions.

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

@router.post(
    "/{org_name}/select",
    response_model=OrganizationResponse,
    summary="Select organization as current context",
    responses={**CRUD_ERRORS},
)
async def select_organization(org_name: str, db: Session = Depends(get_tenant_db)):
    """
    Select organization as current context.

    This loads the organization's credentials and configures
    the environment for scanning operations. It also switches
    the database connection to the organization's database.
    No special permissions are required beyond being authenticated.

    Args:
        org_name: Organization name to select
    """
    from sqlalchemy import func

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

    repo_count = db.query(func.count(models.Repository.id)).filter(
        models.Repository.organization_id == org.id
    ).scalar() or 0
    finding_count = db.query(func.count(models.Finding.id)).filter(
        models.Finding.organization_id == org.id
    ).scalar() or 0

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

@router.get(
    "/schema/drift",
    response_model=List[SchemaDriftReport],
    summary="Check schema drift across all organizations",
    responses={**LIST_ERRORS},
)
async def check_schema_drift():
    """
    Check all organization databases for schema drift.

    Compares each organization's schema hash against the master schema
    and reports any differences. Requires administrative permissions
    to inspect database schemas.
    """
    try:
        agent = await ensure_agent_initialized()
        results = await agent.check_schema_drift()
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post(
    "/{org_name}/sync-schema",
    response_model=SchemaSyncResult,
    summary="Synchronize organization schema with master",
    responses={**CREATE_ERRORS, 404: {"description": "Organization not found"}},
)
async def sync_organization_schema(org_name: str):
    """
    Synchronize organization schema with master.

    Applies any missing migrations and updates the organization's database
    schema to match the master database. Requires administrative permissions
    to modify database schemas.

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


@router.post(
    "/schema/sync-all",
    summary="Synchronize all organization schemas with master",
    responses={**CREATE_ERRORS},
)
async def sync_all_schemas():
    """
    Synchronize all organization schemas with master.

    Runs schema sync for every registered organization in sequence.
    Requires administrative permissions to modify database schemas.
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

@router.post(
    "/{org_name}/scan",
    dependencies=[Depends(require_permissions("scans:execute"))],
    summary="Start a security scan for an organization",
    responses={
        **CREATE_ERRORS,
        403: {"description": "Insufficient permissions - scans:execute required"},
        404: {"description": "Organization not found"},
        409: {"description": "A scan of this organization is already running"},
        503: {"description": "The scanner could not be launched"},
    },
)
async def start_organization_scan(
    org_name: str,
    repos: Optional[List[str]] = Query(None, description="Specific repos to scan"),
    scan_type: str = Query("full", description="Scan type: full, incremental, secrets")
):
    """
    Start a security scan for an organization.

    Launches scan_repos.py against every repository in the organization, or
    against the repositories named in `repos`. The call returns as soon as the
    scanner is running -- poll GET /organizations/{org_name}/scan/status for
    progress, and DELETE /organizations/{org_name}/scan to stop it.

    Requires the **scans:execute** permission.

    Args:
        org_name: Organization name
        repos: Optional list of specific repos to scan
        scan_type: Type of scan to perform
    """
    agent = await ensure_agent_initialized()

    org = await agent.get_organization(org_name)
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")

    runner = get_org_scan_runner()

    async def _record_failure(error: str):
        """Write the terminal status, but never let that write become the
        error the caller sees.

        These columns went missing once already (see
        migrations/025_organization_scan_columns.sql). When they did, the
        failure handler raised UndefinedColumn on top of the original
        exception, so the response said the status column was absent and said
        nothing about why the scan had not started. The cause has to survive
        the attempt to record it.
        """
        try:
            await agent.finish_scan(org_name, status='error', error=error)
        except Exception as write_error:
            logger.error(
                f"Could not record scan failure for {org_name}: {write_error} "
                f"(original error: {error})"
            )

    async def _on_progress(run):
        await agent.update_scan_progress(org_name, run.progress or 0, 'scanning')

    async def _on_complete(run):
        await agent.finish_scan(org_name, status=run.status, error=run.error)

    try:
        # Mark the row 'scanning' before the process exists, so a status poll
        # racing the launch cannot read 'idle' and conclude nothing happened.
        context = await agent.mark_scan_started(org_name, repos=repos, scan_type=scan_type)
        run = await runner.start(
            org_name,
            repos=repos,
            scan_type=scan_type,
            on_progress=_on_progress,
            on_complete=_on_complete,
        )
    except OrgScanAlreadyRunning as e:
        raise HTTPException(status_code=409, detail=str(e))
    except ScanScriptNotFound as e:
        await _record_failure(str(e))
        raise HTTPException(status_code=503, detail=str(e))
    except ValueError as e:
        await _record_failure(str(e))
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        await _record_failure(str(e))
        raise HTTPException(status_code=500, detail=str(e))

    return {**context, **run.to_dict()}


@router.get(
    "/{org_name}/scan/status",
    summary="Get scan status for an organization",
    responses={**CRUD_ERRORS},
)
async def get_scan_status(org_name: str):
    """
    Get current scan status for an organization.

    Returns the latest scan state including status, timestamp, and aggregate
    counts for repositories and findings. When a scan is running in this API
    process, live fields are included: elapsed time, progress where it can be
    known, and the log file the scanner is writing to. No special permissions
    are required.

    Args:
        org_name: Organization name
    """
    try:
        agent = await ensure_agent_initialized()
        org = await agent.get_organization(org_name)
        if not org:
            raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")

        runner = get_org_scan_runner()
        scan_status = org.scan_status
        stale = False

        if runner.reconcile_stale(org_name, scan_status):
            # The row says a scan is running but this process owns no such run,
            # which means the API restarted and took the scanner with it. Say
            # so once and clear the row, rather than leaving a spinner turning
            # over a process that no longer exists.
            stale = True
            scan_status = 'error'
            await agent.finish_scan(
                org_name,
                status='error',
                error='Scan process was lost (API restarted); no results were ingested',
            )

        response = {
            "organization": org.name,
            "scan_status": scan_status,
            "last_scan_at": org.last_scan_at.isoformat() if org.last_scan_at else None,
            "total_repos": org.total_repos,
            "total_findings": org.total_findings,
            "stale": stale,
        }

        run = runner.get(org_name)
        if run is not None and not stale:
            response["run"] = run.to_dict()

        return response
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.delete(
    "/{org_name}/scan",
    dependencies=[Depends(require_permissions("scans:execute"))],
    summary="Stop a running organization scan",
    responses={
        **CRUD_ERRORS,
        403: {"description": "Insufficient permissions - scans:execute required"},
        404: {"description": "No scan is running for this organization"},
    },
)
async def stop_organization_scan(org_name: str):
    """
    Stop the scan currently running for an organization.

    Kills the scanner process. Repositories already scanned keep whatever was
    ingested for them; the rest are simply not scanned. Requires the
    **scans:execute** permission.

    Args:
        org_name: Organization name
    """
    runner = get_org_scan_runner()
    if not await runner.cancel(org_name):
        raise HTTPException(
            status_code=404,
            detail=f"No scan is running for '{org_name}'",
        )
    return {"organization": org_name, "status": "cancelled"}


# =============================================================================
# Credential Management Endpoints
# =============================================================================

@router.get(
    "/{org_name}/credentials/status",
    summary="Check credential configuration status",
    responses={**CRUD_ERRORS},
)
async def get_credentials_status(org_name: str):
    """
    Check if credentials are configured for an organization.

    Returns boolean flags indicating whether the GitHub token and org name
    are stored in the secrets manager. Does not return actual credential
    values for security. Requires read access to the organization.

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


@router.put(
    "/{org_name}/credentials",
    summary="Update organization GitHub credentials",
    responses={**CRUD_ERRORS},
)
async def update_credentials(
    org_name: str,
    request: UpdateCredentialsRequest
):
    """
    Update credentials for an organization.

    Use this to rotate or update the GitHub PAT for an organization.
    The token is stored securely in the secrets manager. Requires
    administrative permissions to manage credentials.

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
# Repository Import/Sync Endpoints
# =============================================================================

GITHUB_API_BASE = "https://api.github.com"


def _require_organization(db: Session, org_name: str) -> "models.Organization":
    org = db.query(models.Organization).filter(
        models.Organization.name.ilike(org_name)
    ).first()
    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")
    return org


async def _github_credentials(org_name: str, org) -> tuple:
    """
    Return (token, github_org) for an organization.

    Raises 400 rather than 500 when the token is simply not configured: a
    missing credential is the operator's to fix, and a 500 sends them looking
    for a server fault instead.
    """
    try:
        from secrets_manager import get_secrets_manager
        manager = get_secrets_manager()
        github_token = await manager.get_secret(f"{org_name.lower()}/github_token")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to retrieve credentials: {str(e)}")

    if not github_token:
        raise HTTPException(
            status_code=400,
            detail=(
                f"GitHub token not configured for '{org_name}'. "
                f"Use PUT /organizations/{org_name}/credentials"
            ),
        )
    return github_token, org.github_org


def _github_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3+json",
        "User-Agent": "AuditGH/1.0",
    }


def parse_github_datetime(dt_str):
    """GitHub sends 'Z'; fromisoformat before 3.11 does not accept it."""
    if not dt_str:
        return None
    from datetime import datetime as _datetime
    try:
        return _datetime.fromisoformat(dt_str.replace('Z', '+00:00'))
    except Exception:
        return None


def _raise_for_github_error(exc, *, github_org: str, repo_name: Optional[str] = None):
    """Translate a GitHub HTTPError into the status the caller should see."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    what = f"{github_org}/{repo_name}" if repo_name else f"organization '{github_org}'"
    if status == 404:
        raise HTTPException(status_code=404, detail=f"GitHub {what} not found")
    if status == 401:
        raise HTTPException(status_code=401, detail="Invalid GitHub token")
    if status == 403:
        # Distinguishable from 401: the token is valid, but the request is
        # refused -- rate limit, SAML enforcement or missing scope. Saying
        # "invalid token" here sends the operator to rotate a working PAT.
        raise HTTPException(
            status_code=403,
            detail=(
                "GitHub refused the request (rate limit, SSO authorization or "
                f"missing scope) for {what}"
            ),
        )
    raise HTTPException(status_code=502, detail=f"GitHub API error: {str(exc)}")


def apply_github_repo_fields(repo, github_repo: Dict[str, Any]) -> None:
    """
    Copy GitHub's repository payload onto a Repository row.

    This mapping was written out three times -- import, single-repo import and
    metadata sync -- which is three places for a new column to be added to two
    of. One function, so a row imported one way is the same row imported
    another way.
    """
    repo.full_name = github_repo.get('full_name')
    repo.url = github_repo.get('html_url')
    repo.description = github_repo.get('description')
    repo.default_branch = github_repo.get('default_branch', 'main')
    repo.language = github_repo.get('language')
    repo.pushed_at = parse_github_datetime(github_repo.get('pushed_at'))
    repo.github_created_at = parse_github_datetime(github_repo.get('created_at'))
    repo.github_updated_at = parse_github_datetime(github_repo.get('updated_at'))
    repo.stargazers_count = github_repo.get('stargazers_count', 0)
    repo.watchers_count = github_repo.get('watchers_count', 0)
    repo.forks_count = github_repo.get('forks_count', 0)
    repo.open_issues_count = github_repo.get('open_issues_count', 0)
    repo.size_kb = github_repo.get('size', 0)
    repo.is_fork = github_repo.get('fork', False)
    repo.is_archived = github_repo.get('archived', False)
    repo.is_disabled = github_repo.get('disabled', False)
    repo.is_private = github_repo.get('private', True)
    repo.visibility = github_repo.get('visibility')
    repo.topics = github_repo.get('topics', [])
    repo.has_wiki = github_repo.get('has_wiki', False)
    repo.has_pages = github_repo.get('has_pages', False)
    repo.has_discussions = github_repo.get('has_discussions', False)

    license_info = github_repo.get('license')
    if license_info and isinstance(license_info, dict):
        repo.license_name = license_info.get('spdx_id') or license_info.get('name')


@router.get(
    "/{org_name}/search-github-repos",
    response_model=GitHubRepoSearchResponse,
    dependencies=[Depends(require_permissions("repositories:read"))],
    summary="Search an organization's repositories on GitHub",
    responses={
        **LIST_ERRORS,
        400: {"description": "Query too short, or GitHub token not configured"},
        401: {"description": "Invalid GitHub token"},
        403: {"description": "GitHub refused the request"},
        404: {"description": "Organization not found"},
        502: {"description": "GitHub API returned an error"},
    },
)
async def search_github_repositories(
    org_name: str,
    q: str = Query(..., min_length=2, description="Repository name fragment to search for"),
    limit: int = Query(30, ge=1, le=100, description="Maximum results to return"),
    db: Session = Depends(get_tenant_db)
):
    """
    Search GitHub for repositories in this organization by name.

    Backs the repository picker on the Organizations admin page: type a
    fragment, get matching repositories, and see which are already in the
    database. Uses GitHub's search API rather than listing every repository,
    because an organization here can hold thousands.

    Two limits worth knowing. GitHub's search index lags a newly created
    repository by up to a few minutes, so a brand new repository may not appear
    -- POST /organizations/{org_name}/import-repo works regardless, by exact
    name. And GitHub never returns more than 1000 search results, so `total`
    can exceed what any paging could reach; `truncated` says when that applies.

    Args:
        org_name: Organization name
        q: Repository name fragment
        limit: Maximum results to return
    """
    import requests

    org = _require_organization(db, org_name)
    github_token, github_org = await _github_credentials(org_name, org)

    # in:name keeps this a name search -- without it GitHub also matches
    # descriptions and READMEs, which makes the picker return repositories the
    # operator did not type. fork:true and archived:true are needed because
    # search excludes both by default, and a fork or an archived repository is
    # exactly the kind of thing worth scanning.
    query = f"{q} in:name org:{github_org} fork:true archived:true"

    try:
        response = requests.get(
            f"{GITHUB_API_BASE}/search/repositories",
            headers=_github_headers(github_token),
            params={"q": query, "per_page": limit, "sort": "updated", "order": "desc"},
            timeout=30,
        )
        response.raise_for_status()
        payload = response.json()
    except requests.exceptions.HTTPError as e:
        _raise_for_github_error(e, github_org=github_org)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to search repositories: {str(e)}")

    items = payload.get("items", [])
    total = payload.get("total_count", len(items))

    # One query for the whole page rather than one per result.
    names = [item.get("name") for item in items if item.get("name")]
    imported = set()
    if names:
        imported = {
            row[0]
            for row in db.query(models.Repository.name)
            .filter(models.Repository.organization_id == org.id)
            .filter(models.Repository.name.in_(names))
            .all()
        }

    results = [
        GitHubRepoSearchResult(
            name=item["name"],
            full_name=item.get("full_name") or f"{github_org}/{item['name']}",
            description=item.get("description"),
            language=item.get("language"),
            visibility=item.get("visibility") or ("private" if item.get("private") else "public"),
            is_archived=bool(item.get("archived", False)),
            updated_at=item.get("updated_at"),
            already_imported=item["name"] in imported,
        )
        for item in items
        if item.get("name")
    ]

    return GitHubRepoSearchResponse(
        results=results,
        total=total,
        truncated=total > len(results),
    )


@router.post(
    "/{org_name}/import-repo",
    response_model=ImportRepositoryResponse,
    dependencies=[Depends(require_permissions("repositories:write"))],
    summary="Import a single repository from GitHub",
    responses={
        **CREATE_ERRORS,
        400: {"description": "GitHub token not configured"},
        401: {"description": "Invalid GitHub token"},
        403: {"description": "GitHub refused the request"},
        404: {"description": "Organization or repository not found"},
        502: {"description": "GitHub API returned an error"},
    },
)
async def import_repository(
    org_name: str,
    request: ImportRepositoryRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """
    Import or refresh one repository by name.

    Fetches the repository from GitHub by exact name and creates or updates its
    row. Use this instead of POST /organizations/{org_name}/import when you want
    one repository and not an organization-wide pass over thousands.

    With `auto_scan`, a scan of that repository is queued the same way POST
    /scans/ queues one, so it appears in the scan history with a ScanRun row.
    Queueing a scan is best-effort: if it cannot be queued the import still
    succeeded, and `scan_error` says why rather than failing the import.

    Args:
        org_name: Organization name
        request: Repository name and whether to scan it
    """
    import requests

    org = _require_organization(db, org_name)
    github_token, github_org = await _github_credentials(org_name, org)
    repo_name = request.repo_name.strip()

    if not repo_name or "/" in repo_name:
        raise HTTPException(
            status_code=400,
            detail="repo_name must be a repository name without the owner prefix",
        )

    try:
        response = requests.get(
            f"{GITHUB_API_BASE}/repos/{github_org}/{repo_name}",
            headers=_github_headers(github_token),
            timeout=30,
        )
        response.raise_for_status()
        github_repo = response.json()
    except requests.exceptions.HTTPError as e:
        _raise_for_github_error(e, github_org=github_org, repo_name=repo_name)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch repository: {str(e)}")

    # GitHub is the authority on capitalisation, and the row is looked up by
    # name elsewhere: store what GitHub calls it, not what was typed.
    canonical_name = github_repo.get("name") or repo_name

    existing = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id,
        models.Repository.name == canonical_name
    ).first()

    try:
        if existing:
            apply_github_repo_fields(existing, github_repo)
            action = "updated"
        else:
            repo = models.Repository(organization_id=org.id, name=canonical_name)
            apply_github_repo_fields(repo, github_repo)
            db.add(repo)
            action = "created"
        db.commit()
    except Exception as e:
        db.rollback()
        logger.error(f"Failed to import repository {canonical_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to save repository: {str(e)}")

    scan_id = None
    scan_error = None
    if request.auto_scan:
        try:
            import uuid as _uuid
            from .scans import run_scan_background

            scan_uuid = _uuid.uuid4()
            repo_row = existing or db.query(models.Repository).filter(
                models.Repository.organization_id == org.id,
                models.Repository.name == canonical_name
            ).first()
            db.add(models.ScanRun(
                id=scan_uuid,
                organization_id=org.id,
                repository_id=repo_row.id,
                scan_type="full",
                status="queued",
                # 'import' rather than 'api' so these are separable from scans
                # someone asked for directly.
                triggered_by="import",
                started_at=datetime.utcnow(),
            ))
            db.commit()
            background_tasks.add_task(
                run_scan_background, str(scan_uuid), canonical_name, "full", None, None
            )
            scan_id = str(scan_uuid)
        except Exception as e:
            db.rollback()
            logger.error(f"Imported {canonical_name} but could not queue a scan: {e}")
            scan_error = str(e)

    return ImportRepositoryResponse(
        repository=canonical_name,
        action=action,
        scan_started=scan_id is not None,
        scan_id=scan_id,
        scan_error=scan_error,
    )


@router.post(
    "/{org_name}/import",
    summary="Import repositories from GitHub",
    responses={**CREATE_ERRORS, 404: {"description": "Organization or GitHub org not found"}, 502: {"description": "GitHub API returned an error"}},
)
async def import_repositories(
    org_name: str,
    confirm: bool = Query(False, description="Set to true to skip confirmation"),
    db: Session = Depends(get_tenant_db)
):
    """
    Import all repositories from GitHub for an organization.

    Fetches repositories from the GitHub API and creates or updates them in the
    database. Requires valid GitHub credentials for the organization. Requires
    write permissions on repositories.

    Args:
        org_name: Organization name
        confirm: Skip confirmation prompt if true
    """
    import requests

    org = _require_organization(db, org_name)
    github_token, github_org = await _github_credentials(org_name, org)
    headers = _github_headers(github_token)

    repos = []
    page = 1
    per_page = 100

    try:
        while True:
            url = f"{GITHUB_API_BASE}/orgs/{github_org}/repos"
            params = {
                "type": "all",
                "per_page": per_page,
                "page": page,
                "sort": "updated",
                "direction": "desc"
            }

            response = requests.get(url, headers=headers, params=params, timeout=30)
            response.raise_for_status()
            page_repos = response.json()

            if not page_repos:
                break

            repos.extend(page_repos)

            if len(page_repos) < per_page:
                break

            page += 1

    except requests.exceptions.HTTPError as e:
        _raise_for_github_error(e, github_org=github_org)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to fetch repositories: {str(e)}")

    if len(repos) == 0:
        return {
            "success": True,
            "message": f"No repositories found in GitHub organization '{github_org}'",
            "total": 0,
            "created": 0,
            "updated": 0,
            "failed": 0
        }

    # Import repositories
    created_count = 0
    updated_count = 0
    failed_count = 0

    for github_repo in repos:
        repo_name = github_repo['name']
        try:
            existing_repo = db.query(models.Repository).filter(
                models.Repository.organization_id == org.id,
                models.Repository.name == repo_name
            ).first()

            if existing_repo:
                apply_github_repo_fields(existing_repo, github_repo)
                updated_count += 1
            else:
                new_repo = models.Repository(organization_id=org.id, name=repo_name)
                apply_github_repo_fields(new_repo, github_repo)
                db.add(new_repo)
                created_count += 1

            db.commit()

        except Exception as e:
            failed_count += 1
            logger.error(f"Failed to import repository {repo_name}: {e}")
            db.rollback()

    return {
        "success": True,
        "message": f"Imported {created_count + updated_count} repositories from '{github_org}'",
        "total": len(repos),
        "created": created_count,
        "updated": updated_count,
        "failed": failed_count
    }


@router.post(
    "/{org_name}/sync-repos",
    summary="Sync repository metadata from GitHub",
    responses={**CREATE_ERRORS, 404: {"description": "Organization not found"}},
)
async def sync_repositories(
    org_name: str,
    db: Session = Depends(get_tenant_db)
):
    """
    Sync existing repositories with GitHub metadata.

    Updates all repositories for an organization with latest data from the
    GitHub API. Does not create new repositories -- use
    POST /organizations/{org_name}/import instead. Requires write permissions
    on repositories.

    Args:
        org_name: Organization name
    """
    import requests

    org = _require_organization(db, org_name)

    repos = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id
    ).all()

    if len(repos) == 0:
        return {
            "success": True,
            "message": f"No repositories to sync for '{org_name}'",
            "total": 0,
            "synced": 0,
            "failed": 0
        }

    github_token, github_org = await _github_credentials(org_name, org)
    headers = _github_headers(github_token)

    synced_count = 0
    failed_count = 0

    for repo in repos:
        try:
            url = f"{GITHUB_API_BASE}/repos/{github_org}/{repo.name}"
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
            github_repo = response.json()

            apply_github_repo_fields(repo, github_repo)

            db.commit()
            synced_count += 1

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"Repository {repo.name} not found on GitHub (may have been deleted)")
            else:
                logger.error(f"Failed to sync repository {repo.name}: {e}")
            failed_count += 1
            db.rollback()
        except Exception as e:
            failed_count += 1
            logger.error(f"Failed to sync repository {repo.name}: {e}")
            db.rollback()

    return {
        "success": True,
        "message": f"Synced {synced_count} repositories for '{org_name}'",
        "total": len(repos),
        "synced": synced_count,
        "failed": failed_count
    }


# =============================================================================
# Organization Data Endpoints
# =============================================================================

@router.get(
    "/{org_name}/repositories",
    summary="List repositories for an organization",
    responses={
        **LIST_ERRORS,
        404: {"description": "Organization with the specified name was not found"},
    },
)
async def get_organization_repositories(
    org_name: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    db: Session = Depends(get_tenant_db)
):
    """
    Get repositories for a specific organization.

    Returns a paginated list of repositories filtered by organization_id in
    the shared database. Results are ordered by last scan date descending.
    No special permissions are required beyond being authenticated.
    """
    # Get organization
    org = db.query(models.Organization).filter(
        models.Organization.name == org_name
    ).first()

    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")

    try:
        # Query repositories from shared database, filtered by organization_id
        repos = db.query(models.Repository).filter(
            models.Repository.organization_id == org.id
        ).order_by(
            models.Repository.last_scanned_at.desc().nullslast()
        ).offset(skip).limit(limit).all()

        result = []
        for repo in repos:
            # Count findings for each repo
            finding_count = db.query(models.Finding).filter(
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
    except Exception as e:
        logger.error(f"Failed to query repositories for {org_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query repositories: {str(e)}")


@router.get(
    "/{org_name}/findings",
    summary="List security findings for an organization",
    responses={
        **LIST_ERRORS,
        404: {"description": "Organization with the specified name was not found"},
    },
)
async def get_organization_findings(
    org_name: str,
    skip: int = Query(0, ge=0),
    limit: int = Query(100, ge=1, le=1000),
    severity: Optional[str] = Query(None, description="Filter by severity (critical, high, medium, low)"),
    repository_id: Optional[str] = Query(None, description="Filter by repository ID"),
    db: Session = Depends(get_tenant_db)
):
    """
    Get security findings for a specific organization.

    Returns a paginated list of findings filtered by organization, with
    optional severity and repository filters. Results are ordered by
    creation date descending. No special permissions are required beyond
    being authenticated.
    """
    # Get organization
    org = db.query(models.Organization).filter(
        models.Organization.name == org_name
    ).first()

    if not org:
        raise HTTPException(status_code=404, detail=f"Organization '{org_name}' not found")

    try:
        # Build query - join with repositories to filter by organization
        query = db.query(models.Finding).join(
            models.Repository,
            models.Finding.repository_id == models.Repository.id
        ).filter(
            models.Repository.organization_id == org.id
        )

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
    except Exception as e:
        logger.error(f"Failed to query findings for {org_name}: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to query findings: {str(e)}")
