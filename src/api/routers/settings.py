from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel, Field
from typing import Optional
import os
import requests
from ..dependencies import get_tenant_db
from .. import models
from .. import secrets_store
from src.rbac.dependencies import require_permissions
from src.auth.dependencies import require_super_admin

router = APIRouter(
    prefix="/settings",
    tags=["settings"]
)

# Keys whose values are credentials. These are encrypted at rest via secrets_store
# and masked on read. Everything else (URLs, email addresses) is stored plaintext,
# because it is not secret and operators need to see it to confirm configuration.
SECRET_SETTING_KEYS = {"OPENAI_API_KEY", "JIRA_API_TOKEN"}

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

    Values flagged `is_encrypted` are returned masked — length and last four
    characters only. Previously this endpoint returned every stored API key in
    cleartext to any caller holding admin:manage, which meant reading the settings
    page was equivalent to exfiltrating the credentials on it. Masked values are
    enough to confirm which key is loaded and to spot a truncated paste, which is
    the only thing the UI actually needs.
    """
    configs = db.query(models.SystemConfig).all()
    settings = {}
    for config in configs:
        if config.is_encrypted or config.key in SECRET_SETTING_KEYS:
            try:
                plaintext = secrets_store.decrypt(config.value) if config.value else None
            except (secrets_store.SecretsNotConfigured, secrets_store.SecretDecryptionError):
                # Unreadable is not the same as absent — report it as such rather
                # than showing an empty field the operator would try to "fix" by
                # re-pasting over a value that may still be in use elsewhere.
                settings[config.key] = {"present": True, "length": None, "preview": None,
                                        "unreadable": True}
                continue
            settings[config.key] = secrets_store.mask(plaintext)
        else:
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
        if value is None:
            # Null means "leave unchanged". The UI sends null for a blank credential
            # field so that not retyping a secret cannot erase it.
            continue

        is_secret = key in SECRET_SETTING_KEYS
        stored_value = value

        if is_secret:
            try:
                stored_value = secrets_store.encrypt(value)
            except secrets_store.SecretsNotConfigured as exc:
                # Fail closed. Writing the credential in cleartext because encryption
                # is unavailable is the failure mode this store exists to prevent.
                raise HTTPException(
                    status_code=503,
                    detail=(
                        f"Cannot store {key}: SECRETS_MASTER_KEY is not configured, and "
                        "credentials are not written in plaintext. Set it and restart the "
                        "API. Note that setting it later cannot recover values that were "
                        "never stored."
                    ),
                ) from exc

        config = db.query(models.SystemConfig).filter(models.SystemConfig.key == key).first()
        if not config:
            config = models.SystemConfig(key=key, value=stored_value, is_encrypted=is_secret)
            db.add(config)
        else:
            config.value = stored_value
            config.is_encrypted = is_secret

        # Update .env and the live process env with the plaintext — these are the
        # paths existing code reads from, and .env is already outside the DB trust
        # boundary. Encryption here protects the database copy and API responses,
        # not the operator's own .env file.
        update_env_file(key, value)
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


# ============================================================================
# Session Timeout Settings (SuperAdmin only)
# ============================================================================

# Bounds for session timeout settings
SESSION_BOUNDS = {
    "inactivity_timeout_minutes": {"min": 5, "max": 480},
    "absolute_timeout_hours": {"min": 1, "max": 72},
}


class SessionSettingsUpdate(BaseModel):
    """Request model for updating session timeout settings."""
    inactivity_timeout_minutes: Optional[int] = Field(
        None, ge=5, le=480,
        description="Session inactivity timeout in minutes (5-480)"
    )
    absolute_timeout_hours: Optional[int] = Field(
        None, ge=1, le=72,
        description="Maximum session duration in hours (1-72)"
    )


@router.get(
    "/session",
    dependencies=[Depends(require_super_admin)],
    summary="Get session timeout settings",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Super admin role required"},
    },
)
def get_session_settings(db: Session = Depends(get_tenant_db)):
    """Get current session timeout settings and allowed bounds.

    Requires **super_admin** role. Returns the current inactivity
    and absolute timeout values along with the min/max bounds.
    """
    from src.auth.config import settings as auth_settings

    # Check for DB-persisted override
    config = db.query(models.SystemConfig).filter(
        models.SystemConfig.key == "SESSION_SETTINGS"
    ).first()

    if config:
        import json
        stored = json.loads(config.value) if isinstance(config.value, str) else config.value
        inactivity = stored.get("inactivity_timeout_minutes", auth_settings.session_idle_timeout_minutes)
        absolute = stored.get("absolute_timeout_hours", auth_settings.session_absolute_timeout_hours)
    else:
        inactivity = auth_settings.session_idle_timeout_minutes
        absolute = auth_settings.session_absolute_timeout_hours

    return {
        "inactivity_timeout_minutes": inactivity,
        "absolute_timeout_hours": absolute,
        "bounds": SESSION_BOUNDS,
    }


@router.put(
    "/session",
    dependencies=[Depends(require_super_admin)],
    summary="Update session timeout settings",
    responses={
        400: {"description": "Values out of allowed bounds"},
        401: {"description": "Not authenticated"},
        403: {"description": "Super admin role required"},
    },
)
def update_session_settings(
    update: SessionSettingsUpdate,
    db: Session = Depends(get_tenant_db),
):
    """Update session timeout settings.

    Requires **super_admin** role. Persists to database and updates
    the in-memory auth config so changes take effect immediately.
    Validates values against allowed bounds.
    """
    import json
    from src.auth.config import settings as auth_settings

    # Load current values
    config = db.query(models.SystemConfig).filter(
        models.SystemConfig.key == "SESSION_SETTINGS"
    ).first()

    if config:
        current = json.loads(config.value) if isinstance(config.value, str) else config.value
    else:
        current = {
            "inactivity_timeout_minutes": auth_settings.session_idle_timeout_minutes,
            "absolute_timeout_hours": auth_settings.session_absolute_timeout_hours,
        }

    # Apply updates
    if update.inactivity_timeout_minutes is not None:
        current["inactivity_timeout_minutes"] = update.inactivity_timeout_minutes
    if update.absolute_timeout_hours is not None:
        current["absolute_timeout_hours"] = update.absolute_timeout_hours

    # Persist to DB
    if config:
        config.value = json.dumps(current)
    else:
        config = models.SystemConfig(key="SESSION_SETTINGS", value=json.dumps(current))
        db.add(config)
    db.commit()

    # Update in-memory auth settings so changes take effect immediately
    auth_settings.session_idle_timeout_minutes = current["inactivity_timeout_minutes"]
    auth_settings.session_absolute_timeout_hours = current["absolute_timeout_hours"]

    return {
        "inactivity_timeout_minutes": current["inactivity_timeout_minutes"],
        "absolute_timeout_hours": current["absolute_timeout_hours"],
        "bounds": SESSION_BOUNDS,
    }
