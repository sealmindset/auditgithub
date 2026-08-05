"""
Credential management endpoints.

Lets an operator give AuditGithub its own GitHub and Microsoft Graph credentials, with
the privilege each one holds recorded alongside it, instead of the tool reading whatever
happens to be exported in the environment of whoever started it.

Security properties of this router:

- Every route requires **admin:manage**.
- No route ever returns a stored secret. Responses carry length, last four characters,
  fingerprint of the encrypting master key, recorded privilege, and known gaps.
- Storing fails closed with 503 when SECRETS_MASTER_KEY is absent. It does not fall back
  to plaintext.
- Verification authenticates to the real provider, which generates a genuine sign-in and
  audit-log entry under the credential's owner. It happens only on explicit request, and
  the response says so.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import credentials as cred_service
from .. import models, secrets_store
from ..dependencies import get_tenant_db
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/credentials", tags=["credentials"])

ADMIN = Depends(require_permissions("admin:manage"))


class GitHubCredentialCreate(BaseModel):
    """Store a GitHub PAT for one organization, or tenant-wide when org is omitted."""
    organization: Optional[str] = Field(
        None,
        description="Organization internal name or GitHub login (e.g. 'sleepnumber'). "
                    "Omit to store a tenant-wide fallback credential.",
    )
    token: str = Field(..., min_length=8, description="GitHub personal access token")
    privilege_level: str = Field(
        "unknown",
        description="Recorded privilege: owner | member | outside_collaborator | unknown. "
                    "Use /credentials/github/verify to determine it from GitHub rather "
                    "than asserting it.",
    )
    name: str = Field("default", description="Label, to hold several credentials per org")
    description: Optional[str] = Field(None, description="Free-text note")
    verify: bool = Field(
        True,
        description="Authenticate to GitHub after storing, to record real scopes, org "
                    "role and access gaps. Produces an audit-log entry on GitHub.",
    )


class GraphCredentialCreate(BaseModel):
    """Store the Entra application credential used for Defender XDR hunting."""
    client_id: str = Field(..., description="Application (client) ID")
    client_secret: str = Field(..., min_length=8, description="Client secret value")
    tenant_id: str = Field(..., description="Directory (tenant) ID")
    app_roles: List[str] = Field(
        default_factory=list,
        description="Application permissions the registration actually holds, e.g. "
                    "['ThreatHunting.Read.All','SecurityAlert.Read.All']. Recorded "
                    "because an app-only call missing a role returns an empty result "
                    "that reads identically to 'nothing found'.",
    )
    name: str = Field("default")
    description: Optional[str] = Field(None)


class VerifyGitHubRequest(BaseModel):
    token: Optional[str] = Field(
        None,
        description="Token to verify. Omit to verify the credential already stored for "
                    "the organization.",
    )
    organization: Optional[str] = Field(None, description="Organization to check role against")
    persist: bool = Field(
        True, description="Write the discovered scopes, privilege and gaps to the stored row"
    )


@router.get(
    "/status",
    dependencies=[ADMIN],
    summary="Credential store status",
    responses={401: {"description": "Not authenticated"},
               403: {"description": "Missing admin:manage permission"}},
)
def credential_status(db: Session = Depends(get_tenant_db)) -> Dict[str, Any]:
    """Report whether encryption is configured and what is stored, without secrets.

    `encryption_configured: false` means credential storage is unavailable — writes
    will return 503 rather than persisting anything in cleartext.
    """
    stored = cred_service.list_credentials(db)
    orgs = db.query(models.Organization).all()

    # Per-org resolution, so an operator can see at a glance which organizations are
    # running on a credential the tool owns and which are still borrowing from the
    # environment.
    resolution = []
    for org in orgs:
        resolved = cred_service.resolve_github_token(db, org)
        resolution.append({
            "organization": org.github_org,
            "organization_id": str(org.id),
            **resolved.provenance(),
        })

    graph = cred_service.resolve_graph_credentials(db)

    return {
        "encryption_configured": secrets_store.is_configured(),
        "master_key_fingerprint": secrets_store.master_key_fingerprint(),
        "stored_credentials": stored,
        "github_resolution": resolution,
        "graph_resolution": graph.provenance(),
        "borrowed_count": sum(1 for r in resolution if not r["owned_by_auditgithub"]),
    }


@router.get(
    "/",
    dependencies=[ADMIN],
    summary="List stored credentials",
    responses={401: {"description": "Not authenticated"},
               403: {"description": "Missing admin:manage permission"}},
)
def list_credentials(
    organization_id: Optional[str] = Query(None),
    db: Session = Depends(get_tenant_db),
) -> List[Dict[str, Any]]:
    """List stored credentials. Values are never included."""
    return cred_service.list_credentials(db, organization_id=organization_id)


@router.post(
    "/github",
    dependencies=[ADMIN],
    summary="Store a GitHub token for an organization",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        404: {"description": "Unknown organization"},
        503: {"description": "SECRETS_MASTER_KEY not configured; refusing to store plaintext"},
    },
)
def store_github(
    payload: GitHubCredentialCreate,
    db: Session = Depends(get_tenant_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Store an encrypted GitHub PAT, optionally verifying it against GitHub."""
    try:
        summary = cred_service.store_github_token(
            db,
            org=payload.organization,
            token=payload.token,
            privilege_level=payload.privilege_level,
            name=payload.name,
            description=payload.description,
        )
    except secrets_store.SecretsNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=404 if "Unknown organization" in str(exc) else 400,
                            detail=str(exc)) from exc

    result: Dict[str, Any] = {"credential": summary}

    if payload.verify:
        org_login = None
        if payload.organization:
            org_row = cred_service._resolve_org(db, payload.organization)
            org_login = org_row.github_org if org_row else payload.organization
        verdict = cred_service.verify_github_token(payload.token, github_org=org_login)
        cred_service.record_verification(
            db, summary["id"], verdict["status"],
            detail=f"login={verdict.get('login')} token_type={verdict.get('token_type')}",
            scopes=verdict.get("scopes"),
            privilege_level=verdict.get("privilege_level") or None,
        )
        for gap in verdict.get("gaps", []):
            cred_service.record_gap(db, summary["id"], gap)
        result["verification"] = verdict
        result["credential"] = cred_service.list_credentials(db)  # refreshed view
        result["note"] = (
            "Verification authenticated to github.com; this produces an audit-log entry "
            "under the token owner."
        )

    return result


@router.post(
    "/graph",
    dependencies=[ADMIN],
    summary="Store the Microsoft Graph application credential",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        503: {"description": "SECRETS_MASTER_KEY not configured; refusing to store plaintext"},
    },
)
def store_graph(
    payload: GraphCredentialCreate,
    db: Session = Depends(get_tenant_db),
    user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Store the encrypted Graph client secret tenant-wide.

    Held tenant-wide rather than per-organization because all three GitHub
    organizations resolve to a single Entra tenant.
    """
    try:
        return cred_service.store_graph_credentials(
            db,
            client_id=payload.client_id,
            client_secret=payload.client_secret,
            tenant_id=payload.tenant_id,
            app_roles=payload.app_roles,
            name=payload.name,
            description=payload.description,
        )
    except secrets_store.SecretsNotConfigured as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc


@router.post(
    "/github/verify",
    dependencies=[ADMIN],
    summary="Verify a GitHub token and record its real privilege",
    responses={
        400: {"description": "No token supplied and none stored"},
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
    },
)
def verify_github(
    payload: VerifyGitHubRequest,
    db: Session = Depends(get_tenant_db),
) -> Dict[str, Any]:
    """Authenticate to GitHub to determine scopes, organization role, and access gaps.

    This is what turns an asserted privilege level into a recorded one. It performs a
    real authentication against github.com.
    """
    org_login = None
    if payload.organization:
        org_row = cred_service._resolve_org(db, payload.organization)
        org_login = org_row.github_org if org_row else payload.organization

    token = payload.token
    resolved = None
    if not token:
        resolved = cred_service.resolve_github_token(db, payload.organization)
        token = resolved.value
    if not token:
        raise HTTPException(
            status_code=400,
            detail="No token supplied and none resolvable for that organization.",
        )

    verdict = cred_service.verify_github_token(token, github_org=org_login)

    if payload.persist and (resolved is None or resolved.is_owned):
        row = cred_service._lookup_row(
            db, cred_service.GITHUB_PAT,
            organization_id=(cred_service._resolve_org(db, payload.organization).id
                             if payload.organization and
                             cred_service._resolve_org(db, payload.organization) else None),
        )
        if row:
            cred_service.record_verification(
                db, row.id, verdict["status"],
                detail=f"login={verdict.get('login')} token_type={verdict.get('token_type')}",
                scopes=verdict.get("scopes"),
                privilege_level=verdict.get("privilege_level") or None,
            )
            for gap in verdict.get("gaps", []):
                cred_service.record_gap(db, row.id, gap)

    verdict["note"] = (
        "Authenticated to github.com; an audit-log entry now exists under "
        f"{verdict.get('login') or 'the token owner'}."
    )
    return verdict


@router.delete(
    "/{credential_id}",
    dependencies=[ADMIN],
    summary="Delete a stored credential",
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Missing admin:manage permission"},
        404: {"description": "Credential not found"},
    },
)
def delete_credential(
    credential_id: str,
    db: Session = Depends(get_tenant_db),
) -> Dict[str, Any]:
    """Delete a stored credential.

    Deletes only AuditGithub's copy. It does not revoke the credential at the
    provider — a leaked or compromised token must additionally be revoked on GitHub or
    in Entra, which this endpoint cannot do.
    """
    row = db.query(models.OrganizationCredential).filter(
        models.OrganizationCredential.id == credential_id
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="Credential not found")
    summary = cred_service.describe(row)
    db.delete(row)
    db.commit()
    logger.info(f"Deleted credential {credential_id} ({summary['credential_type']}/{summary['name']})")
    return {
        "deleted": summary,
        "warning": "Local copy removed only. Revoke the credential at the provider if it "
                   "is no longer trusted.",
    }
