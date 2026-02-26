from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
import os
import requests
from ..dependencies import get_tenant_db
from .. import models
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/settings",
    tags=["settings"]
)

class SettingsUpdate(BaseModel):
    """Request model for updating application settings."""
    openai_api_key: Optional[str] = Field(None, description="OpenAI API key for AI-powered features")
    jira_api_token: Optional[str] = Field(None, description="Jira Cloud API token for integration")
    jira_url: Optional[str] = Field(None, description="Base URL of the Jira Cloud instance (e.g. https://org.atlassian.net)")
    jira_email: Optional[str] = Field(None, description="Email address associated with the Jira API token")

class VerifyRequest(BaseModel):
    """Request model for verifying an external service credential."""
    token: str = Field(..., description="API key or token to verify")
    url: Optional[str] = Field(None, description="Service base URL (required for Jira verification)")
    email: Optional[str] = Field(None, description="Account email (required for Jira verification)")

def update_env_file(key: str, value: str):
    """Update or add a key-value pair in the .env file."""
    env_path = "/app/.env"
    if not os.path.exists(env_path):
        # Try local path if not in container
        env_path = ".env"
    
    try:
        lines = []
        if os.path.exists(env_path):
            with open(env_path, "r") as f:
                lines = f.readlines()
        
        key_found = False
        new_lines = []
        for line in lines:
            if line.startswith(f"{key}="):
                new_lines.append(f"{key}={value}\n")
                key_found = True
            else:
                new_lines.append(line)
        
        if not key_found:
            if new_lines and not new_lines[-1].endswith("\n"):
                new_lines.append("\n")
            new_lines.append(f"{key}={value}\n")
            
        with open(env_path, "w") as f:
            f.writelines(new_lines)
            
    except Exception as e:
        print(f"Failed to update .env: {e}")

@router.get(
    "/",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Get application settings",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
    },
)
def get_settings(db: Session = Depends(get_tenant_db)):
    """Retrieve all stored application settings as key-value pairs.

    Requires the **admin:manage** permission. Returns configuration values
    persisted in the system config table.
    """
    configs = db.query(models.SystemConfig).all()
    settings = {}
    for config in configs:
        settings[config.key] = config.value
    return settings

@router.post(
    "/",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Save application settings",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        500: {"description": "Failed to persist settings to database or .env file"},
    },
)
def save_settings(settings: SettingsUpdate, db: Session = Depends(get_tenant_db)):
    """Persist application settings to the database and the .env file.

    Requires the **admin:manage** permission. Only fields with non-null values
    are updated; null fields are skipped. Changes take effect immediately.
    """
    updates = {
        "OPENAI_API_KEY": settings.openai_api_key,
        "JIRA_API_TOKEN": settings.jira_api_token,
        "JIRA_URL": settings.jira_url,
        "JIRA_EMAIL": settings.jira_email
    }
    
    for key, value in updates.items():
        if value is not None:
            # Update DB
            config = db.query(models.SystemConfig).filter(models.SystemConfig.key == key).first()
            if not config:
                config = models.SystemConfig(key=key, value=value)
                db.add(config)
            else:
                config.value = value
            
            # Update .env
            update_env_file(key, value)
            
            # Update current process env (for immediate use)
            os.environ[key] = value

    db.commit()
    return {"status": "success", "message": "Settings saved"}

@router.post(
    "/verify/openai",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Verify OpenAI API key",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        500: {"description": "Network or unexpected error during verification"},
    },
)
def verify_openai(req: VerifyRequest):
    """Test whether the provided OpenAI API key is valid.

    Requires the **admin:manage** permission. Sends a lightweight request to
    the OpenAI models endpoint and reports whether authentication succeeded.
    """
    try:
        headers = {"Authorization": f"Bearer {req.token}"}
        # List models is a cheap/free way to verify
        response = requests.get("https://api.openai.com/v1/models", headers=headers, timeout=10)
        if response.status_code == 200:
            return {"valid": True, "message": "OpenAI API Key is valid"}
        else:
            return {"valid": False, "message": f"Invalid API Key: {response.status_code}"}
    except Exception as e:
        return {"valid": False, "message": str(e)}

@router.post(
    "/verify/jira",
    dependencies=[Depends(require_permissions("admin:manage"))],
    summary="Verify Jira credentials",
    responses={
        400: {"description": "Jira URL and email are required but missing"},
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        500: {"description": "Network or unexpected error during verification"},
    },
)
def verify_jira(req: VerifyRequest):
    """Test whether the provided Jira credentials are valid.

    Requires the **admin:manage** permission. Authenticates against the Jira
    Cloud REST API using Basic Auth with the supplied email and API token.
    """
    if not req.url or not req.email:
        raise HTTPException(status_code=400, detail="Jira URL and Email are required")
        
    try:
        # Jira Cloud API uses Basic Auth with email and API token
        from requests.auth import HTTPBasicAuth
        
        api_url = f"{req.url.rstrip('/')}/rest/api/3/myself"
        auth = HTTPBasicAuth(req.email, req.token)
        headers = {"Accept": "application/json"}
        
        response = requests.get(api_url, auth=auth, headers=headers, timeout=10)
        
        if response.status_code == 200:
            user_data = response.json()
            return {
                "valid": True, 
                "message": f"Authenticated as {user_data.get('displayName', 'User')}"
            }
        else:
            return {"valid": False, "message": f"Authentication failed: {response.status_code}"}
    except Exception as e:
        return {"valid": False, "message": str(e)}
