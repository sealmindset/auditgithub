"""
Credential resolution for AuditGithub.

This module is the single place that answers "what credential should I use for this
organization, and what is it allowed to reach?". Everything else should call it rather
than reading os.environ directly.

Resolution order, highest priority first:

  1. organization_credentials row for the specific organization
  2. organization_credentials row with organization_id IS NULL (tenant-wide)
  3. ORG_<NAME>_TOKEN environment variable  (pre-existing convention, kept working)
  4. GITHUB_TOKEN environment variable      (the borrowed-from-the-shell fallback)

The environment tiers are retained deliberately. Scanners run in containers where the
database may not be reachable, and removing the fallback would break them. What changes
is that the fallback is now *identified as* a fallback: resolve_github_token returns the
source it used, so a report can state whether it ran with a credential the tool owns and
whose privileges are recorded, or with whatever happened to be exported.

That distinction is not cosmetic. Three private repositories in the sleepnumber
organization are absent from scan results and org-level runner enumeration returns 403,
because the borrowed token holds member rather than owner. With no recorded privilege
level, those absences are indistinguishable from "nothing there" — which is precisely the
failure mode rule 0.1 of docs/playbooks/supply-chain-hunt-ttp.md exists to prevent.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from . import secrets_store

logger = logging.getLogger(__name__)

# Credential types
GITHUB_PAT = "github_pat"
GITHUB_APP = "github_app"
GRAPH_APP = "graph_app"

# Privilege levels for GitHub credentials, ordered least to most capable.
GITHUB_PRIVILEGE_LEVELS = ("unknown", "outside_collaborator", "member", "owner")


@dataclass
class ResolvedCredential:
    """
    A credential plus the provenance and limits of that credential.

    `source` is one of: db_org, db_global, env_org, env_default, none.
    """
    value: Optional[str]
    source: str
    credential_type: str
    organization: Optional[str] = None
    name: Optional[str] = None
    privilege_level: str = "unknown"
    scopes: List[str] = field(default_factory=list)
    known_gaps: List[str] = field(default_factory=list)
    last_verified_at: Optional[datetime] = None
    last_verification_status: str = "unverified"
    client_id: Optional[str] = None
    tenant_id: Optional[str] = None

    @property
    def found(self) -> bool:
        return bool(self.value)

    @property
    def is_owned(self) -> bool:
        """True when the credential came from AuditGithub's own store, not the shell."""
        return self.source in ("db_org", "db_global")

    def provenance(self) -> Dict[str, Any]:
        """
        Everything about the credential except the credential.

        Attach this to hunt results and reports so a reader can tell what the run was
        permitted to see. Contains no secret material.
        """
        return {
            "found": self.found,
            "source": self.source,
            "credential_type": self.credential_type,
            "organization": self.organization,
            "name": self.name,
            "privilege_level": self.privilege_level,
            "scopes": self.scopes,
            "known_gaps": self.known_gaps,
            "owned_by_auditgithub": self.is_owned,
            "last_verified_at": self.last_verified_at.isoformat() if self.last_verified_at else None,
            "last_verification_status": self.last_verification_status,
            "client_id": _truncate_id(self.client_id),
            "tenant_id": _truncate_id(self.tenant_id),
        }


def _truncate_id(value: Optional[str]) -> Optional[str]:
    """Identifiers are not secret, but full tenant/client GUIDs are unnecessary in
    reports that get shared. Show enough to recognize, not enough to copy."""
    if not value:
        return None
    return f"{value[:8]}…" if len(value) > 8 else value


def _row_to_resolved(row, source: str, org_name: Optional[str]) -> ResolvedCredential:
    try:
        value = secrets_store.decrypt(row.encrypted_value) if row.encrypted_value else None
    except (secrets_store.SecretsNotConfigured, secrets_store.SecretDecryptionError) as exc:
        logger.error(
            f"Credential {row.credential_type}/{row.name} for org={org_name} is stored but "
            f"unreadable: {exc}"
        )
        value = None
    return ResolvedCredential(
        value=value,
        source=source if value else "none",
        credential_type=row.credential_type,
        organization=org_name,
        name=row.name,
        privilege_level=row.privilege_level or "unknown",
        scopes=list(row.scopes or []),
        known_gaps=list(row.known_gaps or []),
        last_verified_at=row.last_verified_at,
        last_verification_status=row.last_verification_status or "unverified",
        client_id=row.client_id,
        tenant_id=row.tenant_id_value,
    )


def _lookup_row(db, credential_type: str, organization_id=None, name: Optional[str] = None):
    from . import models

    q = db.query(models.OrganizationCredential).filter(
        models.OrganizationCredential.credential_type == credential_type,
        models.OrganizationCredential.is_active.is_(True),
    )
    if organization_id is None:
        q = q.filter(models.OrganizationCredential.organization_id.is_(None))
    else:
        q = q.filter(models.OrganizationCredential.organization_id == organization_id)
    if name:
        q = q.filter(models.OrganizationCredential.name == name)
    # Prefer the most privileged credential when several exist for one org — a hunt
    # should use the widest access it legitimately has, not an arbitrary row.
    rows = q.all()
    if not rows:
        return None
    return max(rows, key=lambda r: _privilege_rank(r.privilege_level))


def _privilege_rank(level: Optional[str]) -> int:
    try:
        return GITHUB_PRIVILEGE_LEVELS.index(level or "unknown")
    except ValueError:
        return 0


def _resolve_org(db, org: Any):
    """Accept an Organization, its UUID, or its name/github_org string."""
    from . import models

    if org is None:
        return None
    if isinstance(org, models.Organization):
        return org
    org_str = str(org)
    return (
        db.query(models.Organization)
        .filter(
            (models.Organization.name == org_str)
            | (models.Organization.github_org == org_str)
        )
        .first()
        or db.query(models.Organization).filter(models.Organization.id == org).first()
    )


# =============================================================================
# GitHub
# =============================================================================

def resolve_github_token(db, org: Any = None) -> ResolvedCredential:
    """
    Resolve the GitHub token to use for an organization.

    `org` may be an Organization instance, its UUID, its internal name, or its
    github_org login. Pass None for the tenant-wide credential.
    """
    org_row = _resolve_org(db, org) if org is not None else None
    org_name = org_row.github_org if org_row else (str(org) if org else None)

    if org_row is not None:
        row = _lookup_row(db, GITHUB_PAT, organization_id=org_row.id)
        if row:
            resolved = _row_to_resolved(row, "db_org", org_name)
            if resolved.found:
                return resolved

    row = _lookup_row(db, GITHUB_PAT, organization_id=None)
    if row:
        resolved = _row_to_resolved(row, "db_global", org_name)
        if resolved.found:
            return resolved

    # Environment fallbacks. Privilege is genuinely unknown here — nothing recorded it.
    if org_name:
        for var in (f"ORG_{org_name.upper().replace('-', '_')}_TOKEN",
                    f"{org_name.upper().replace('-', '_')}_GITHUB_TOKEN"):
            env_value = os.environ.get(var, "").strip()
            if env_value:
                return ResolvedCredential(
                    value=env_value, source="env_org", credential_type=GITHUB_PAT,
                    organization=org_name, name=var,
                    known_gaps=["privilege level not recorded — absences are not "
                                "distinguishable from empty results"],
                )

    default = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if default:
        return ResolvedCredential(
            value=default, source="env_default", credential_type=GITHUB_PAT,
            organization=org_name, name="GITHUB_TOKEN",
            known_gaps=["privilege level not recorded — absences are not "
                        "distinguishable from empty results"],
        )

    return ResolvedCredential(value=None, source="none", credential_type=GITHUB_PAT,
                              organization=org_name)


def store_github_token(
    db,
    org: Any,
    token: str,
    privilege_level: str = "unknown",
    scopes: Optional[List[str]] = None,
    name: str = "default",
    description: Optional[str] = None,
    created_by=None,
) -> Dict[str, Any]:
    """
    Store (or replace) a GitHub PAT for an organization.

    Returns a non-secret summary. Never returns or logs the token.
    """
    from . import models

    if privilege_level not in GITHUB_PRIVILEGE_LEVELS:
        raise ValueError(
            f"privilege_level must be one of {GITHUB_PRIVILEGE_LEVELS}, got {privilege_level!r}"
        )

    org_row = _resolve_org(db, org) if org is not None else None
    if org is not None and org_row is None:
        raise ValueError(f"Unknown organization: {org!r}")

    return _upsert(
        db,
        credential_type=GITHUB_PAT,
        organization_id=org_row.id if org_row else None,
        name=name,
        value=token,
        description=description,
        privilege_level=privilege_level,
        scopes=scopes or [],
        created_by=created_by,
    )


# =============================================================================
# Microsoft Graph
# =============================================================================

def resolve_graph_credentials(db) -> ResolvedCredential:
    """
    Resolve the Microsoft Graph application credential.

    Held tenant-wide (organization_id IS NULL) because all three GitHub organizations
    map to one Entra tenant, so one app registration covers them.
    """
    row = _lookup_row(db, GRAPH_APP, organization_id=None)
    if row:
        resolved = _row_to_resolved(row, "db_global", None)
        if resolved.found:
            return resolved

    client_secret = os.environ.get("GRAPH_CLIENT_SECRET", "").strip()
    if client_secret:
        return ResolvedCredential(
            value=client_secret,
            source="env_default",
            credential_type=GRAPH_APP,
            name="GRAPH_CLIENT_SECRET",
            client_id=os.environ.get("GRAPH_CLIENT_ID", "").strip() or None,
            tenant_id=os.environ.get("GRAPH_TENANT_ID", "").strip() or None,
            known_gaps=["app roles not recorded — a query returning nothing may mean "
                        "no data or no permission"],
        )

    return ResolvedCredential(value=None, source="none", credential_type=GRAPH_APP)


def store_graph_credentials(
    db,
    client_id: str,
    client_secret: str,
    tenant_id: str,
    app_roles: Optional[List[str]] = None,
    name: str = "default",
    description: Optional[str] = None,
    created_by=None,
) -> Dict[str, Any]:
    """
    Store the Graph application credential tenant-wide.

    `app_roles` records the application permissions the app registration actually holds
    (e.g. ThreatHunting.Read.All, SecurityAlert.Read.All). Recording them matters because
    an app-only Graph call that lacks a role returns an empty result set or a 403 that is
    easy to read as "no findings" — the coverage-control problem again, on the identity
    side rather than the endpoint side.
    """
    return _upsert(
        db,
        credential_type=GRAPH_APP,
        organization_id=None,
        name=name,
        value=client_secret,
        description=description,
        privilege_level="app_only",
        scopes=app_roles or [],
        client_id=client_id,
        tenant_id_value=tenant_id,
        created_by=created_by,
    )


# =============================================================================
# Shared upsert / inspection
# =============================================================================

def _upsert(
    db,
    credential_type: str,
    organization_id,
    name: str,
    value: str,
    description: Optional[str] = None,
    privilege_level: str = "unknown",
    scopes: Optional[List[str]] = None,
    client_id: Optional[str] = None,
    tenant_id_value: Optional[str] = None,
    created_by=None,
) -> Dict[str, Any]:
    from . import models

    if not value:
        raise ValueError("Refusing to store an empty credential value")

    # encrypt() raises SecretsNotConfigured when no master key is present. Let it
    # propagate — the caller must not be able to write a plaintext credential by
    # ignoring an error return.
    ciphertext = secrets_store.encrypt(value)

    row = (
        db.query(models.OrganizationCredential)
        .filter(
            models.OrganizationCredential.credential_type == credential_type,
            models.OrganizationCredential.name == name,
            models.OrganizationCredential.organization_id.is_(None)
            if organization_id is None
            else models.OrganizationCredential.organization_id == organization_id,
        )
        .first()
    )

    if row is None:
        row = models.OrganizationCredential(
            organization_id=organization_id,
            credential_type=credential_type,
            name=name,
            created_by=created_by,
        )
        db.add(row)

    row.encrypted_value = ciphertext
    row.is_encrypted = True
    row.key_fingerprint = secrets_store.master_key_fingerprint()
    row.value_length = len(value)
    row.value_suffix = value[-4:] if len(value) >= 4 else None
    row.privilege_level = privilege_level
    row.scopes = list(scopes or [])
    row.is_active = True
    # A replaced credential has not been verified yet; do not inherit the old verdict.
    row.last_verified_at = None
    row.last_verification_status = "unverified"
    row.last_verification_detail = None
    if description is not None:
        row.description = description
    if client_id is not None:
        row.client_id = client_id
    if tenant_id_value is not None:
        row.tenant_id_value = tenant_id_value

    db.commit()
    db.refresh(row)
    logger.info(
        f"Stored {credential_type}/{name} for organization_id={organization_id} "
        f"(length {row.value_length}, privilege {privilege_level}, "
        f"master key {row.key_fingerprint})"
    )
    return describe(row)


def describe(row) -> Dict[str, Any]:
    """Non-secret description of a stored credential row, safe for API responses."""
    return {
        "id": str(row.id),
        "organization_id": str(row.organization_id) if row.organization_id else None,
        "credential_type": row.credential_type,
        "name": row.name,
        "description": row.description,
        "present": bool(row.encrypted_value),
        "is_encrypted": bool(row.is_encrypted),
        "key_fingerprint": row.key_fingerprint,
        "value_length": row.value_length,
        "value_suffix": row.value_suffix,
        "client_id": row.client_id,
        "tenant_id": _truncate_id(row.tenant_id_value),
        "privilege_level": row.privilege_level,
        "scopes": list(row.scopes or []),
        "known_gaps": list(row.known_gaps or []),
        "expires_at": row.expires_at.isoformat() if row.expires_at else None,
        "last_verified_at": row.last_verified_at.isoformat() if row.last_verified_at else None,
        "last_verification_status": row.last_verification_status,
        "last_verification_detail": row.last_verification_detail,
        "is_active": bool(row.is_active),
    }


def list_credentials(db, organization_id=None, include_global: bool = True) -> List[Dict[str, Any]]:
    from . import models

    q = db.query(models.OrganizationCredential)
    if organization_id is not None:
        if include_global:
            q = q.filter(
                (models.OrganizationCredential.organization_id == organization_id)
                | (models.OrganizationCredential.organization_id.is_(None))
            )
        else:
            q = q.filter(models.OrganizationCredential.organization_id == organization_id)
    return [describe(r) for r in q.order_by(models.OrganizationCredential.credential_type).all()]


def record_gap(db, credential_id, gap: str) -> None:
    """
    Append an observed access gap to a credential.

    Called when a request fails with 403/404 in a way that indicates missing privilege
    rather than missing data, so the limitation is recorded once and reported thereafter
    instead of being rediscovered on every run.
    """
    from . import models

    row = db.query(models.OrganizationCredential).filter(
        models.OrganizationCredential.id == credential_id
    ).first()
    if not row:
        return
    gaps = list(row.known_gaps or [])
    if gap not in gaps:
        gaps.append(gap)
        row.known_gaps = gaps
        db.commit()
        logger.info(f"Recorded access gap on credential {credential_id}: {gap}")


def verify_github_token(token: str, github_org: Optional[str] = None,
                        timeout: int = 15) -> Dict[str, Any]:
    """
    Verify a GitHub PAT and determine what it can actually reach.

    Only ever called on a credential an operator has explicitly submitted for
    verification. It authenticates to github.com, which produces a real audit-log entry
    under the token owner — that is the point, but it is not something to do implicitly
    or to a credential found by a scanner.

    Determines privilege by asking GitHub rather than inferring it:
      - GET /user                                     → identity + X-OAuth-Scopes
      - GET /orgs/{org}/memberships/{login}           → role: admin | member
      - GET /orgs/{org}/actions/runners               → whether runner enumeration works

    Returns status, scopes, privilege_level, and any gaps discovered. Does not include
    the token.
    """
    import requests

    result: Dict[str, Any] = {
        "status": "error",
        "detail": None,
        "login": None,
        "scopes": [],
        "privilege_level": "unknown",
        "gaps": [],
        "token_type": "classic" if token.startswith(("ghp_", "gho_")) else (
            "fine_grained" if token.startswith("github_pat_") else "unknown"
        ),
    }
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }

    try:
        r = requests.get("https://api.github.com/user", headers=headers, timeout=timeout)
    except Exception as exc:
        result["detail"] = f"Request failed: {type(exc).__name__}: {exc}"
        return result

    if r.status_code == 401:
        result["status"] = "unauthorized"
        result["detail"] = "GitHub rejected the token (401). It is invalid or revoked."
        return result
    if r.status_code != 200:
        result["detail"] = f"GET /user returned {r.status_code}"
        return result

    result["status"] = "ok"
    result["login"] = r.json().get("login")
    # Classic PATs report scopes in this header; fine-grained PATs return it empty,
    # so an empty list means "not reported", not "no access".
    scope_header = r.headers.get("X-OAuth-Scopes", "")
    result["scopes"] = [s.strip() for s in scope_header.split(",") if s.strip()]
    if not result["scopes"] and result["token_type"] == "fine_grained":
        result["gaps"].append(
            "fine-grained PAT: GitHub does not report scopes in X-OAuth-Scopes, so "
            "granted permissions cannot be enumerated from the token alone"
        )

    if not github_org or not result["login"]:
        return result

    # Organization role. This is the value that explains missing private repositories.
    try:
        m = requests.get(
            f"https://api.github.com/orgs/{github_org}/memberships/{result['login']}",
            headers=headers, timeout=timeout,
        )
        if m.status_code == 200:
            role = m.json().get("role")
            result["privilege_level"] = "owner" if role == "admin" else "member"
            if result["privilege_level"] == "member":
                result["gaps"].append(
                    f"org role on {github_org} is member, not owner: private repositories "
                    "not explicitly granted to this account are invisible, and their "
                    "absence from results is not evidence of absence"
                )
        elif m.status_code in (403, 404):
            result["privilege_level"] = "outside_collaborator"
            result["gaps"].append(
                f"no org membership visible on {github_org} ({m.status_code}); access is "
                "limited to repositories granted individually"
            )
    except Exception as exc:
        result["gaps"].append(f"org membership check failed: {type(exc).__name__}")

    # Org-level runner enumeration is the specific capability that 403s under member
    # privilege, and it is required for the CI/CD surface in phase 4 of the hunt.
    try:
        runners = requests.get(
            f"https://api.github.com/orgs/{github_org}/actions/runners",
            headers=headers, timeout=timeout,
        )
        if runners.status_code == 200:
            count = runners.json().get("total_count", 0)
            result["runner_enumeration"] = {"ok": True, "total_count": count}
        else:
            result["runner_enumeration"] = {"ok": False, "status": runners.status_code}
            result["gaps"].append(
                f"GET /orgs/{github_org}/actions/runners returned "
                f"{runners.status_code}: self-hosted runner posture cannot be assessed, "
                "so 'no self-hosted runners' must not be reported as a finding"
            )
    except Exception as exc:
        result["gaps"].append(f"runner enumeration check failed: {type(exc).__name__}")

    return result


def record_verification(db, credential_id, status: str, detail: Optional[str] = None,
                        scopes: Optional[List[str]] = None,
                        privilege_level: Optional[str] = None) -> None:
    """Persist the outcome of a credential verification attempt."""
    from . import models

    row = db.query(models.OrganizationCredential).filter(
        models.OrganizationCredential.id == credential_id
    ).first()
    if not row:
        return
    row.last_verification_status = status
    row.last_verification_detail = detail
    row.last_verified_at = datetime.now(timezone.utc).replace(tzinfo=None)
    if scopes is not None:
        row.scopes = list(scopes)
    if privilege_level is not None:
        row.privilege_level = privilege_level
    db.commit()
