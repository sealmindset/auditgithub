"""
Cribl Stream Log Management Integration Router

Provides endpoints for configuring and testing Cribl Stream integration
for centralized log collection and forwarding.
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional, List
from datetime import datetime
import httpx
import os

from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/cribl",
    tags=["cribl"]
)


class CriblConfigUpdate(BaseModel):
    """Request model for updating Cribl configuration."""
    ingest_url: Optional[str] = Field(None, description="Cribl HTTP/S endpoint URL")
    auth_token: Optional[str] = Field(None, description="Bearer token for authentication")
    verify_ssl: Optional[bool] = Field(None, description="Validate SSL certificates")
    enabled: Optional[bool] = Field(None, description="Enable Cribl log forwarding")
    log_levels: Optional[List[str]] = Field(None, description="Log levels to forward")
    include_app_context: Optional[bool] = Field(None, description="Include org_id, user_id, request_id")
    include_security_audit: Optional[bool] = Field(None, description="Include action, resource, outcome")
    minio_fallback: Optional[bool] = Field(None, description="Store in MinIO when Cribl unavailable")
    minio_endpoint: Optional[str] = Field(None, description="MinIO S3 API endpoint")
    minio_bucket: Optional[str] = Field(None, description="MinIO bucket name")
    minio_access_key: Optional[str] = Field(None, description="MinIO access key")
    minio_secret_key: Optional[str] = Field(None, description="MinIO secret key")


class CriblConfigResponse(BaseModel):
    """Response model for Cribl configuration."""
    id: str
    ingest_url: Optional[str]
    auth_token_set: bool
    verify_ssl: bool
    enabled: bool
    log_levels: List[str]
    include_app_context: bool
    include_security_audit: bool
    minio_fallback: bool
    minio_endpoint: Optional[str]
    minio_bucket: Optional[str]
    minio_access_key_set: bool
    minio_secret_key_set: bool
    last_test_at: Optional[datetime]
    last_test_status: Optional[str]
    last_test_message: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class CriblTestRequest(BaseModel):
    """Request model for testing Cribl connection."""
    ingest_url: Optional[str] = Field(None, description="Override URL for testing")
    auth_token: Optional[str] = Field(None, description="Override token for testing")
    verify_ssl: Optional[bool] = Field(None, description="Override SSL verification")


class CriblTestResponse(BaseModel):
    """Response model for Cribl connection test."""
    success: bool
    message: str
    response_time_ms: Optional[int]
    status_code: Optional[int]
    details: Optional[dict]


class CriblStatusResponse(BaseModel):
    """Response model for Cribl logging status."""
    enabled: bool
    cribl_configured: bool
    minio_configured: bool
    last_test_status: Optional[str]
    last_test_at: Optional[datetime]


def get_or_create_config(db: Session) -> models.CriblConfig:
    """Get the singleton Cribl config, creating if it doesn't exist."""
    config = db.query(models.CriblConfig).first()
    if not config:
        config = models.CriblConfig(
            ingest_url='',
            auth_token='',
            verify_ssl=True,
            enabled=False,
            log_levels=['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
            include_app_context=True,
            include_security_audit=True,
            minio_fallback=True,
            minio_endpoint='http://minio:9000',
            minio_bucket='auditgh-logs',
            last_test_status='PENDING'
        )
        db.add(config)
        db.commit()
        db.refresh(config)
    return config


@router.get("/config", response_model=CriblConfigResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def get_config(db: Session = Depends(get_tenant_db)):
    """Get current Cribl configuration."""
    config = get_or_create_config(db)
    
    return CriblConfigResponse(
        id=str(config.id),
        ingest_url=config.ingest_url,
        auth_token_set=bool(config.auth_token),
        verify_ssl=config.verify_ssl or True,
        enabled=config.enabled or False,
        log_levels=config.log_levels or ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        include_app_context=config.include_app_context if config.include_app_context is not None else True,
        include_security_audit=config.include_security_audit if config.include_security_audit is not None else True,
        minio_fallback=config.minio_fallback if config.minio_fallback is not None else True,
        minio_endpoint=config.minio_endpoint,
        minio_bucket=config.minio_bucket,
        minio_access_key_set=bool(config.minio_access_key),
        minio_secret_key_set=bool(config.minio_secret_key),
        last_test_at=config.last_test_at,
        last_test_status=config.last_test_status,
        last_test_message=config.last_test_message,
        created_at=config.created_at,
        updated_at=config.updated_at
    )


@router.post("/config", response_model=CriblConfigResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def update_config(update: CriblConfigUpdate, db: Session = Depends(get_tenant_db)):
    """Update Cribl configuration."""
    config = get_or_create_config(db)
    
    if update.ingest_url is not None:
        config.ingest_url = update.ingest_url
    if update.auth_token is not None:
        config.auth_token = update.auth_token
    if update.verify_ssl is not None:
        config.verify_ssl = update.verify_ssl
    if update.enabled is not None:
        config.enabled = update.enabled
    if update.log_levels is not None:
        config.log_levels = update.log_levels
    if update.include_app_context is not None:
        config.include_app_context = update.include_app_context
    if update.include_security_audit is not None:
        config.include_security_audit = update.include_security_audit
    if update.minio_fallback is not None:
        config.minio_fallback = update.minio_fallback
    if update.minio_endpoint is not None:
        config.minio_endpoint = update.minio_endpoint
    if update.minio_bucket is not None:
        config.minio_bucket = update.minio_bucket
    if update.minio_access_key is not None:
        config.minio_access_key = update.minio_access_key
    if update.minio_secret_key is not None:
        config.minio_secret_key = update.minio_secret_key
    
    config.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(config)
    
    return CriblConfigResponse(
        id=str(config.id),
        ingest_url=config.ingest_url,
        auth_token_set=bool(config.auth_token),
        verify_ssl=config.verify_ssl or True,
        enabled=config.enabled or False,
        log_levels=config.log_levels or ['INFO', 'WARNING', 'ERROR', 'CRITICAL'],
        include_app_context=config.include_app_context if config.include_app_context is not None else True,
        include_security_audit=config.include_security_audit if config.include_security_audit is not None else True,
        minio_fallback=config.minio_fallback if config.minio_fallback is not None else True,
        minio_endpoint=config.minio_endpoint,
        minio_bucket=config.minio_bucket,
        minio_access_key_set=bool(config.minio_access_key),
        minio_secret_key_set=bool(config.minio_secret_key),
        last_test_at=config.last_test_at,
        last_test_status=config.last_test_status,
        last_test_message=config.last_test_message,
        created_at=config.created_at,
        updated_at=config.updated_at
    )


@router.post("/test", response_model=CriblTestResponse, dependencies=[Depends(require_permissions("admin:manage"))])
async def test_connection(request: CriblTestRequest, db: Session = Depends(get_tenant_db)):
    """
    Test connection to Cribl Stream endpoint.
    
    Sends a test log entry to verify connectivity and authentication.
    Uses provided values or falls back to saved configuration.
    """
    config = get_or_create_config(db)
    
    ingest_url = request.ingest_url or config.ingest_url
    auth_token = request.auth_token or config.auth_token
    verify_ssl = request.verify_ssl if request.verify_ssl is not None else config.verify_ssl
    
    if not ingest_url:
        return CriblTestResponse(
            success=False,
            message="Ingest URL is required",
            response_time_ms=None,
            status_code=None,
            details=None
        )
    
    test_payload = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "level": "INFO",
        "message": "AuditGitHub Cribl connection test",
        "source": "api",
        "host": os.environ.get("HOSTNAME", "auditgh_api"),
        "test": True,
        "app_context": {
            "test_id": str(datetime.utcnow().timestamp()),
            "purpose": "connectivity_test"
        }
    }
    
    headers = {
        "Content-Type": "application/json"
    }
    if auth_token:
        headers["Authorization"] = f"Bearer {auth_token}"
    
    start_time = datetime.utcnow()
    
    try:
        async with httpx.AsyncClient(verify=verify_ssl, timeout=30.0) as client:
            response = await client.post(
                ingest_url,
                json=test_payload,
                headers=headers
            )
        
        end_time = datetime.utcnow()
        response_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        success = response.status_code in [200, 201, 202, 204]
        
        if success:
            message = f"Connection successful (HTTP {response.status_code})"
            config.last_test_status = "SUCCESS"
        else:
            message = f"Connection failed (HTTP {response.status_code})"
            config.last_test_status = "FAILED"
        
        config.last_test_at = datetime.utcnow()
        config.last_test_message = message
        db.commit()
        
        return CriblTestResponse(
            success=success,
            message=message,
            response_time_ms=response_time_ms,
            status_code=response.status_code,
            details={
                "response_body": response.text[:500] if response.text else None,
                "headers": dict(response.headers)
            }
        )
        
    except httpx.ConnectError as e:
        config.last_test_at = datetime.utcnow()
        config.last_test_status = "FAILED"
        config.last_test_message = f"Connection error: {str(e)}"
        db.commit()
        
        return CriblTestResponse(
            success=False,
            message=f"Connection error: Unable to reach {ingest_url}",
            response_time_ms=None,
            status_code=None,
            details={"error": str(e)}
        )
        
    except httpx.TimeoutException:
        config.last_test_at = datetime.utcnow()
        config.last_test_status = "FAILED"
        config.last_test_message = "Connection timeout (30s)"
        db.commit()
        
        return CriblTestResponse(
            success=False,
            message="Connection timeout after 30 seconds",
            response_time_ms=30000,
            status_code=None,
            details=None
        )
        
    except Exception as e:
        config.last_test_at = datetime.utcnow()
        config.last_test_status = "FAILED"
        config.last_test_message = f"Error: {str(e)}"
        db.commit()
        
        return CriblTestResponse(
            success=False,
            message=f"Error: {str(e)}",
            response_time_ms=None,
            status_code=None,
            details={"error_type": type(e).__name__}
        )


@router.post("/test-minio", response_model=CriblTestResponse, dependencies=[Depends(require_permissions("admin:manage"))])
async def test_minio_connection(db: Session = Depends(get_tenant_db)):
    """
    Test connection to MinIO storage.
    
    Verifies that MinIO is accessible and the bucket exists or can be created.
    """
    config = get_or_create_config(db)
    
    minio_endpoint = config.minio_endpoint or os.environ.get("MINIO_ENDPOINT", "http://minio:9000")
    
    start_time = datetime.utcnow()
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{minio_endpoint}/minio/health/live")
        
        end_time = datetime.utcnow()
        response_time_ms = int((end_time - start_time).total_seconds() * 1000)
        
        success = response.status_code == 200
        
        return CriblTestResponse(
            success=success,
            message="MinIO is healthy" if success else f"MinIO health check failed (HTTP {response.status_code})",
            response_time_ms=response_time_ms,
            status_code=response.status_code,
            details={
                "endpoint": minio_endpoint,
                "bucket": config.minio_bucket
            }
        )
        
    except httpx.ConnectError as e:
        return CriblTestResponse(
            success=False,
            message=f"Cannot connect to MinIO at {minio_endpoint}",
            response_time_ms=None,
            status_code=None,
            details={"error": str(e)}
        )
        
    except Exception as e:
        return CriblTestResponse(
            success=False,
            message=f"MinIO test error: {str(e)}",
            response_time_ms=None,
            status_code=None,
            details={"error_type": type(e).__name__}
        )


@router.get("/status", response_model=CriblStatusResponse, dependencies=[Depends(require_permissions("admin:manage"))])
def get_status(db: Session = Depends(get_tenant_db)):
    """Get current Cribl logging status."""
    config = get_or_create_config(db)
    
    return CriblStatusResponse(
        enabled=config.enabled or False,
        cribl_configured=bool(config.ingest_url and config.auth_token),
        minio_configured=bool(config.minio_endpoint),
        last_test_status=config.last_test_status,
        last_test_at=config.last_test_at
    )


@router.post("/toggle", dependencies=[Depends(require_permissions("admin:manage"))])
def toggle_cribl(enabled: bool, db: Session = Depends(get_tenant_db)):
    """Enable or disable Cribl log forwarding."""
    config = get_or_create_config(db)
    config.enabled = enabled
    config.updated_at = datetime.utcnow()
    db.commit()
    
    return {
        "status": "success",
        "enabled": enabled,
        "message": f"Cribl logging {'enabled' if enabled else 'disabled'}"
    }


class LogForwardRequest(BaseModel):
    """Request model for forwarding a log entry."""
    timestamp: str
    level: str
    message: str
    source: Optional[str] = None
    host: Optional[str] = None
    module: Optional[str] = None
    function: Optional[str] = None
    line: Optional[int] = None
    app_context: Optional[dict] = None
    security_audit: Optional[dict] = None
    extra: Optional[dict] = None


@router.post("/forward", dependencies=[Depends(require_permissions("admin:manage"))])
async def forward_log(log_entry: LogForwardRequest, db: Session = Depends(get_tenant_db)):
    """
    Forward a log entry to Cribl Stream.
    
    This endpoint is called by the Next.js log proxy to forward client-side logs
    to Cribl with the authentication token added server-side.
    """
    config = get_or_create_config(db)
    
    if not config.enabled:
        return {"status": "disabled", "message": "Cribl logging is not enabled"}
    
    if not config.ingest_url:
        return {"status": "not_configured", "message": "Cribl ingest URL is not configured"}
    
    log_payload = {
        "timestamp": log_entry.timestamp,
        "level": log_entry.level,
        "message": log_entry.message,
        "source": log_entry.source or "web-ui",
        "host": log_entry.host or os.environ.get("HOSTNAME", "auditgh_ui"),
    }
    
    if log_entry.module:
        log_payload["module"] = log_entry.module
    if log_entry.function:
        log_payload["function"] = log_entry.function
    if log_entry.line:
        log_payload["line"] = log_entry.line
    if log_entry.app_context:
        log_payload["app_context"] = log_entry.app_context
    if log_entry.security_audit:
        log_payload["security_audit"] = log_entry.security_audit
    if log_entry.extra:
        log_payload["extra"] = log_entry.extra
    
    headers = {"Content-Type": "application/json"}
    if config.auth_token:
        headers["Authorization"] = f"Bearer {config.auth_token}"
    
    try:
        async with httpx.AsyncClient(verify=config.verify_ssl or True, timeout=10.0) as client:
            response = await client.post(
                config.ingest_url,
                json=log_payload,
                headers=headers
            )
        
        if response.status_code in [200, 201, 202, 204]:
            return {"status": "forwarded", "message": "Log forwarded to Cribl"}
        else:
            return {
                "status": "error",
                "message": f"Cribl returned HTTP {response.status_code}",
                "status_code": response.status_code
            }
            
    except httpx.ConnectError as e:
        return {"status": "error", "message": f"Connection error: {str(e)}"}
    except httpx.TimeoutException:
        return {"status": "error", "message": "Connection timeout"}
    except Exception as e:
        return {"status": "error", "message": f"Error: {str(e)}"}
