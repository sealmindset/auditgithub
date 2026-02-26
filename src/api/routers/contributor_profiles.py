"""
Contributor Profiles API Router

Provides unified identity management for contributors across all repositories.
Designed to integrate with Entra ID for employment status verification.
"""

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, or_, and_, desc
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta
from decimal import Decimal
from loguru import logger
import re
import unicodedata
from difflib import SequenceMatcher

from ..dependencies import get_tenant_db
from .. import models
from ..config import settings
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/contributor-profiles",
    tags=["Contributor Profiles"],
)


# =============================================================================
# PYDANTIC MODELS
# =============================================================================

class ContributorAliasBase(BaseModel):
    alias_type: str = Field(..., description="Alias type: email, github_username, or name")
    alias_value: str = Field(..., description="The alias value (email address, username, or name)")
    is_primary: bool = Field(False, description="Whether this is the primary alias for its type")
    source: Optional[str] = Field(None, description="Source of the alias (manual, auto-detected, etc.)")
    match_confidence: Optional[float] = Field(None, description="Confidence score of the identity match (0.0-1.0)")
    match_reason: Optional[str] = Field(None, description="Reason for the identity match")


class ContributorAliasResponse(ContributorAliasBase):
    id: str = Field(..., description="Unique alias identifier")
    profile_id: str = Field(..., description="Parent contributor profile ID")
    first_seen_at: Optional[datetime] = Field(None, description="When this alias was first seen in commits")
    last_seen_at: Optional[datetime] = Field(None, description="When this alias was last seen in commits")
    created_at: datetime = Field(..., description="When this alias record was created")

    model_config = {"from_attributes": True}


class ContributorProfileBase(BaseModel):
    display_name: str = Field(..., description="Display name of the contributor")
    primary_email: Optional[str] = Field(None, description="Primary email address")
    primary_github_username: Optional[str] = Field(None, description="Primary GitHub username")

    # Entra ID fields
    entra_id_object_id: Optional[str] = Field(None, description="Entra ID object identifier")
    entra_id_upn: Optional[str] = Field(None, description="Entra ID user principal name")
    entra_id_employee_id: Optional[str] = Field(None, description="Entra ID employee identifier")
    entra_id_job_title: Optional[str] = Field(None, description="Job title from Entra ID")
    entra_id_department: Optional[str] = Field(None, description="Department from Entra ID")
    entra_id_manager_upn: Optional[str] = Field(None, description="Manager UPN from Entra ID")

    # Employment
    employment_status: str = Field("unknown", description="Employment status: active, inactive, terminated, contractor, or unknown")
    employment_start_date: Optional[datetime] = Field(None, description="Employment start date")
    employment_end_date: Optional[datetime] = Field(None, description="Employment end date")

    notes: Optional[str] = Field(None, description="Free-text notes about the contributor")


class ContributorProfileCreate(ContributorProfileBase):
    aliases: Optional[List[ContributorAliasBase]] = Field([], description="Initial aliases to associate with the profile")


class ContributorProfileUpdate(BaseModel):
    display_name: Optional[str] = Field(None, description="Updated display name")
    primary_email: Optional[str] = Field(None, description="Updated primary email")
    primary_github_username: Optional[str] = Field(None, description="Updated primary GitHub username")
    entra_id_object_id: Optional[str] = Field(None, description="Updated Entra ID object identifier")
    entra_id_upn: Optional[str] = Field(None, description="Updated Entra ID user principal name")
    entra_id_employee_id: Optional[str] = Field(None, description="Updated Entra ID employee identifier")
    entra_id_job_title: Optional[str] = Field(None, description="Updated job title")
    entra_id_department: Optional[str] = Field(None, description="Updated department")
    entra_id_manager_upn: Optional[str] = Field(None, description="Updated manager UPN")
    employment_status: Optional[str] = Field(None, description="Updated employment status")
    employment_start_date: Optional[datetime] = Field(None, description="Updated employment start date")
    employment_end_date: Optional[datetime] = Field(None, description="Updated employment end date")
    notes: Optional[str] = Field(None, description="Updated notes")
    is_verified: Optional[bool] = Field(None, description="Set verification status")


class ContributorProfileResponse(ContributorProfileBase):
    id: str = Field(..., description="Unique profile identifier")
    total_repos: int = Field(..., description="Total repositories the contributor has committed to")
    total_commits: int = Field(..., description="Total commits across all repositories")
    last_activity_at: Optional[datetime] = Field(None, description="Date of last activity")
    first_activity_at: Optional[datetime] = Field(None, description="Date of first known activity")
    risk_score: int = Field(..., description="Calculated risk score from 0 to 100")
    is_stale: bool = Field(..., description="Whether the contributor is considered stale (no recent activity)")
    has_elevated_access: bool = Field(..., description="Whether the contributor has elevated access")
    files_with_findings: int = Field(..., description="Number of files with security findings")
    critical_files_count: int = Field(..., description="Number of files with critical findings")
    ai_identity_confidence: Optional[float] = Field(None, description="AI confidence in identity resolution (0.0-1.0)")
    ai_summary: Optional[str] = Field(None, description="AI-generated contributor summary")
    is_verified: bool = Field(..., description="Whether the profile identity has been verified")
    verified_at: Optional[datetime] = Field(None, description="When the profile was verified")
    employment_verified_at: Optional[datetime] = Field(None, description="When employment status was last verified")
    created_at: datetime = Field(..., description="Profile creation timestamp")
    updated_at: datetime = Field(..., description="Profile last update timestamp")
    aliases: List[ContributorAliasResponse] = Field([], description="Associated aliases for this profile")

    # Computed fields
    alias_count: int = Field(0, description="Number of aliases associated with this profile")
    repo_names: List[str] = Field([], description="Names of repositories the contributor has committed to")

    model_config = {"from_attributes": True}


class ProfileSummary(BaseModel):
    total_profiles: int = Field(..., description="Total number of contributor profiles")
    verified_profiles: int = Field(..., description="Number of verified profiles")
    unverified_profiles: int = Field(..., description="Number of unverified profiles")
    stale_profiles: int = Field(..., description="Number of stale profiles (no recent activity)")
    active_employees: int = Field(..., description="Number of active employees")
    inactive_employees: int = Field(..., description="Number of inactive employees")
    terminated_employees: int = Field(..., description="Number of terminated employees")
    contractors: int = Field(..., description="Number of contractors")
    unknown_status: int = Field(..., description="Number of profiles with unknown employment status")
    profiles_with_entra_id: int = Field(..., description="Number of profiles linked to Entra ID")
    profiles_needing_review: int = Field(..., description="Profiles that need review (stale, unverified, or unknown status)")


class MergeProfilesRequest(BaseModel):
    source_profile_ids: List[str] = Field(..., description="List of profile IDs to merge (minimum 2)")
    target_display_name: Optional[str] = Field(None, description="Override display name for the merged profile")
    target_primary_email: Optional[str] = Field(None, description="Override primary email for the merged profile")


class BuildProfilesRequest(BaseModel):
    dry_run: bool = Field(True, description="If true, preview changes without creating profiles")
    min_confidence: float = Field(0.85, description="Minimum identity match confidence threshold (0.0-1.0)")


class BuildProfilesResponse(BaseModel):
    profiles_created: int = Field(..., description="Number of profiles created or would be created")
    aliases_linked: int = Field(..., description="Number of aliases linked or would be linked")
    contributors_linked: int = Field(..., description="Number of contributors linked or would be linked")
    profiles: List[Dict[str, Any]] = Field([], description="Preview of profiles (populated during dry run)")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def extract_identity_signals(name: str, email: str, github_username: Optional[str]) -> Dict[str, Any]:
    """Extract identity signals from contributor info for matching."""
    signals = {
        'name': name,
        'email': email,
        'github_username': github_username,
        'name_parts': [],
        'email_local': None,
        'email_domain': None,
        'github_noreply_id': None,
        'is_noreply': False,
    }
    
    if name:
        clean_name = name.strip()
        signals['name_parts'] = [p.lower() for p in clean_name.split() if len(p) > 1]
    
    if email:
        email_lower = email.lower().strip()
        if '@' in email_lower:
            local, domain = email_lower.rsplit('@', 1)
            signals['email_local'] = local
            signals['email_domain'] = domain
            
            if 'noreply.github' in domain:
                signals['is_noreply'] = True
                match = re.match(r'(\d+)\+(.+)', local)
                if match:
                    signals['github_noreply_id'] = match.group(1)
                    signals['github_username'] = match.group(2)
    
    return signals


def normalize_identifier(s: str) -> str:
    """Normalize an identifier by removing dots, hyphens, and underscores."""
    if not s:
        return ""
    return s.lower().replace('.', '').replace('-', '').replace('_', '')


def normalize_unicode(s: str) -> str:
    """Remove Unicode accents and diacritics. E.g., 'Kalač' -> 'Kalac'."""
    if not s:
        return ""
    # Decompose Unicode characters and remove combining marks
    normalized = unicodedata.normalize('NFD', s)
    return ''.join(c for c in normalized if unicodedata.category(c) != 'Mn').lower()


def normalize_github_username(username: str) -> str:
    """Normalize GitHub username by removing corporate suffixes."""
    if not username:
        return ""
    lower = username.lower()
    # Remove corporate suffixes from config
    for suffix in settings.corporate_username_suffixes_list:
        if lower.endswith(suffix):
            lower = lower[:-len(suffix)]
    # Remove numbers at end (GitHub noreply IDs)
    lower = re.sub(r'\d+$', '', lower)
    return normalize_identifier(lower)


def fuzzy_name_match(name1: str, name2: str, threshold: float = 0.85) -> tuple[bool, float]:
    """Check if two names match using fuzzy string matching."""
    if not name1 or not name2:
        return False, 0.0
    
    # Normalize both names
    n1 = normalize_unicode(name1.strip())
    n2 = normalize_unicode(name2.strip())
    
    # Exact match after normalization
    if n1 == n2:
        return True, 1.0
    
    # Use SequenceMatcher for similarity
    ratio = SequenceMatcher(None, n1, n2).ratio()
    return ratio >= threshold, ratio


def calculate_match_confidence(sig1: Dict, sig2: Dict) -> tuple[float, str]:
    """Calculate match confidence between two identity signal sets.
    
    Enhanced to handle:
    - Unicode accents (Kalač vs Kalac)
    - GitHub username suffixes (-sn, -snc)
    - Fuzzy name matching
    - Cross-checking GitHub usernames against name patterns
    """

    # Same email = definite match
    if sig1['email'] and sig2['email']:
        if sig1['email'].lower().strip() == sig2['email'].lower().strip():
            return 1.0, "exact_email_match"

    # Same corporate email local part
    corp_domains = settings.corporate_email_domains_list
    if sig1['email_local'] and sig2['email_local'] and corp_domains:
        if sig1['email_domain'] in corp_domains and sig2['email_domain'] in corp_domains:
            if sig1['email_local'] == sig2['email_local']:
                return 0.99, "same_corporate_email"

    # =========================================================================
    # NEW: Unicode-normalized name comparison (Kalač vs Kalac)
    # =========================================================================
    if sig1['name'] and sig2['name']:
        is_match, ratio = fuzzy_name_match(sig1['name'], sig2['name'], threshold=0.90)
        if is_match:
            # High confidence if names are nearly identical after Unicode normalization
            return 0.97, f"unicode_normalized_name_match (similarity: {ratio:.2f})"

    # =========================================================================
    # NEW: GitHub username with suffix matches email local
    # elza-kalac-sn -> elzakalac matches elza.kalac
    # =========================================================================
    if sig1['github_username'] and sig2['email_local']:
        normalized_gh = normalize_github_username(sig1['github_username'])
        normalized_email = normalize_identifier(sig2['email_local'])
        if normalized_gh and normalized_email and normalized_gh == normalized_email:
            return 0.94, "github_suffix_normalized_matches_email"
    if sig2['github_username'] and sig1['email_local']:
        normalized_gh = normalize_github_username(sig2['github_username'])
        normalized_email = normalize_identifier(sig1['email_local'])
        if normalized_gh and normalized_email and normalized_gh == normalized_email:
            return 0.94, "github_suffix_normalized_matches_email"

    # =========================================================================
    # NEW: GitHub username matches name parts
    # elza-kalac matches "Elza Kalac" or "Elza Kalač"
    # =========================================================================
    if sig1['github_username'] and sig2['name_parts']:
        gh_normalized = normalize_github_username(sig1['github_username'])
        name_normalized = normalize_unicode(''.join(sig2['name_parts']))
        if gh_normalized and name_normalized and gh_normalized == name_normalized:
            return 0.93, "github_matches_name"
    if sig2['github_username'] and sig1['name_parts']:
        gh_normalized = normalize_github_username(sig2['github_username'])
        name_normalized = normalize_unicode(''.join(sig1['name_parts']))
        if gh_normalized and name_normalized and gh_normalized == name_normalized:
            return 0.93, "github_matches_name"

    # GitHub username matches email local (normalize both to handle konrad-dunikowski vs konrad.dunikowski)
    if sig1['github_username'] and sig2['email_local']:
        if normalize_identifier(sig1['github_username']) == normalize_identifier(sig2['email_local']):
            return 0.95, "github_matches_email"
    if sig2['github_username'] and sig1['email_local']:
        if normalize_identifier(sig2['github_username']) == normalize_identifier(sig1['email_local']):
            return 0.95, "github_matches_email"

    # GitHub noreply username matches corporate email local
    if sig1['is_noreply'] and sig1['github_username'] and sig2['email_local']:
        if sig2['email_domain'] in corp_domains:
            if normalize_identifier(sig1['github_username']) == normalize_identifier(sig2['email_local']):
                return 0.96, "noreply_github_matches_corp_email"
    if sig2['is_noreply'] and sig2['github_username'] and sig1['email_local']:
        if sig1['email_domain'] in corp_domains:
            if normalize_identifier(sig2['github_username']) == normalize_identifier(sig1['email_local']):
                return 0.96, "noreply_github_matches_corp_email"
    
    # Name matches email pattern (Unicode normalized)
    if sig1['name_parts'] and sig2['email_local']:
        name_concat = normalize_unicode(''.join(sig1['name_parts']))
        email_local = normalize_identifier(sig2['email_local'])
        if name_concat == email_local:
            return 0.90, "name_matches_email"
    if sig2['name_parts'] and sig1['email_local']:
        name_concat = normalize_unicode(''.join(sig2['name_parts']))
        email_local = normalize_identifier(sig1['email_local'])
        if name_concat == email_local:
            return 0.90, "name_matches_email"
    
    # Same full name (first + last) - Unicode normalized
    if sig1['name_parts'] and sig2['name_parts']:
        if len(sig1['name_parts']) >= 2 and len(sig2['name_parts']) >= 2:
            # Normalize name parts for comparison
            norm1 = [normalize_unicode(p) for p in sig1['name_parts']]
            norm2 = [normalize_unicode(p) for p in sig2['name_parts']]
            if norm1 == norm2:
                common_names = {'john', 'james', 'robert', 'michael', 'david', 'smith', 'johnson', 'williams'}
                if not all(p in common_names for p in norm1):
                    return 0.92, "same_full_name_normalized"
    
    # First initial + last name in email
    if sig1['name_parts'] and sig2['email_local']:
        if len(sig1['name_parts']) >= 2:
            initials = ''.join(p[0] for p in sig1['name_parts'])
            last_name = normalize_unicode(sig1['name_parts'][-1])
            email_local = normalize_identifier(sig2['email_local'])
            if email_local.startswith(initials[0]) and last_name in email_local:
                return 0.88, "initial_lastname_in_email"
    if sig2['name_parts'] and sig1['email_local']:
        if len(sig2['name_parts']) >= 2:
            initials = ''.join(p[0] for p in sig2['name_parts'])
            last_name = normalize_unicode(sig2['name_parts'][-1])
            email_local = normalize_identifier(sig1['email_local'])
            if email_local.startswith(initials[0]) and last_name in email_local:
                return 0.88, "initial_lastname_in_email"
    
    return 0.0, "no_match"


def get_canonical_display_name(names: List[str]) -> str:
    """Pick the best display name from a list."""
    if not names:
        return "Unknown"
    # Prefer full names with spaces over usernames
    return max(names, key=lambda n: (len(n.split()), len(n)))


def get_canonical_email(emails: List[str]) -> Optional[str]:
    """Pick the best email from a list, preferring corporate domain."""
    if not emails:
        return None
    # Prefer corporate domains from config
    corp_domains = settings.corporate_email_domains_list
    for email in emails:
        if email and 'noreply' not in email.lower():
            email_lower = email.lower()
            for domain in corp_domains:
                if domain in email_lower:
                    return email
    # Exclude noreply emails
    non_noreply = [e for e in emails if e and 'noreply' not in e.lower()]
    return non_noreply[0] if non_noreply else emails[0]


# =============================================================================
# API ENDPOINTS
# =============================================================================

@router.get("/summary", response_model=ProfileSummary, dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get contributor profile summary statistics",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}})
def get_profile_summary(db: Session = Depends(get_tenant_db)):
    """
    Get summary statistics for contributor profiles.
    Includes counts by verification status, employment status, and profiles needing review.
    Requires projects:read permission.
    """
    
    total = db.query(models.ContributorProfile).count()
    verified = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.is_verified == True
    ).count()
    stale = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.is_stale == True
    ).count()
    
    # Employment status counts
    status_counts = db.query(
        models.ContributorProfile.employment_status,
        func.count(models.ContributorProfile.id)
    ).group_by(models.ContributorProfile.employment_status).all()
    
    status_map = {s[0]: s[1] for s in status_counts}
    
    with_entra = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.entra_id_object_id.isnot(None)
    ).count()
    
    # Profiles needing review: stale + unverified + unknown status
    needing_review = db.query(models.ContributorProfile).filter(
        or_(
            models.ContributorProfile.is_stale == True,
            models.ContributorProfile.is_verified == False,
            models.ContributorProfile.employment_status == 'unknown'
        )
    ).count()
    
    return ProfileSummary(
        total_profiles=total,
        verified_profiles=verified,
        unverified_profiles=total - verified,
        stale_profiles=stale,
        active_employees=status_map.get('active', 0),
        inactive_employees=status_map.get('inactive', 0),
        terminated_employees=status_map.get('terminated', 0),
        contractors=status_map.get('contractor', 0),
        unknown_status=status_map.get('unknown', 0),
        profiles_with_entra_id=with_entra,
        profiles_needing_review=needing_review
    )


@router.get("/", response_model=List[ContributorProfileResponse], dependencies=[Depends(require_permissions("projects:read"))],
    summary="List contributor profiles",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}})
def list_profiles(
    db: Session = Depends(get_tenant_db),
    skip: int = 0,
    limit: int = Query(default=50, le=200),
    search: Optional[str] = None,
    employment_status: Optional[str] = None,
    is_stale: Optional[bool] = None,
    is_verified: Optional[bool] = None,
    has_entra_id: Optional[bool] = None,
    sort_by: str = Query(default="last_activity_at", enum=["display_name", "last_activity_at", "total_commits", "risk_score"]),
    sort_order: str = Query(default="desc", enum=["asc", "desc"])
):
    """
    List contributor profiles with filtering, searching, and sorting.
    Supports filtering by employment status, staleness, verification, and Entra ID linkage.
    Requires projects:read permission.
    """
    
    query = db.query(models.ContributorProfile)
    
    if search:
        search_term = f"%{search}%"
        query = query.filter(
            or_(
                models.ContributorProfile.display_name.ilike(search_term),
                models.ContributorProfile.primary_email.ilike(search_term),
                models.ContributorProfile.primary_github_username.ilike(search_term),
                models.ContributorProfile.entra_id_upn.ilike(search_term)
            )
        )
    
    if employment_status:
        query = query.filter(models.ContributorProfile.employment_status == employment_status)
    
    if is_stale is not None:
        query = query.filter(models.ContributorProfile.is_stale == is_stale)
    
    if is_verified is not None:
        query = query.filter(models.ContributorProfile.is_verified == is_verified)
    
    if has_entra_id is not None:
        if has_entra_id:
            query = query.filter(models.ContributorProfile.entra_id_object_id.isnot(None))
        else:
            query = query.filter(models.ContributorProfile.entra_id_object_id.is_(None))
    
    # Sorting
    sort_column = getattr(models.ContributorProfile, sort_by)
    if sort_order == "desc":
        query = query.order_by(desc(sort_column))
    else:
        query = query.order_by(sort_column)
    
    profiles = query.offset(skip).limit(limit).all()
    
    # Enrich with aliases and repo names
    results = []
    for profile in profiles:
        # Get linked repo names through contributors
        repo_names = db.query(models.Repository.name).join(
            models.Contributor, models.Contributor.repository_id == models.Repository.id
        ).filter(
            models.Contributor.profile_id == profile.id
        ).distinct().all()
        
        response = ContributorProfileResponse(
            id=str(profile.id),
            display_name=profile.display_name,
            primary_email=profile.primary_email,
            primary_github_username=profile.primary_github_username,
            entra_id_object_id=profile.entra_id_object_id,
            entra_id_upn=profile.entra_id_upn,
            entra_id_employee_id=profile.entra_id_employee_id,
            entra_id_job_title=profile.entra_id_job_title,
            entra_id_department=profile.entra_id_department,
            entra_id_manager_upn=profile.entra_id_manager_upn,
            employment_status=profile.employment_status or 'unknown',
            employment_start_date=profile.employment_start_date,
            employment_end_date=profile.employment_end_date,
            employment_verified_at=profile.employment_verified_at,
            total_repos=profile.total_repos or 0,
            total_commits=profile.total_commits or 0,
            last_activity_at=profile.last_activity_at,
            first_activity_at=profile.first_activity_at,
            risk_score=profile.risk_score or 0,
            is_stale=profile.is_stale or False,
            has_elevated_access=profile.has_elevated_access or False,
            files_with_findings=profile.files_with_findings or 0,
            critical_files_count=profile.critical_files_count or 0,
            ai_identity_confidence=float(profile.ai_identity_confidence) if profile.ai_identity_confidence else None,
            ai_summary=profile.ai_summary,
            is_verified=profile.is_verified or False,
            verified_at=profile.verified_at,
            notes=profile.notes,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
            aliases=[
                ContributorAliasResponse(
                    id=str(a.id),
                    profile_id=str(a.profile_id),
                    alias_type=a.alias_type,
                    alias_value=a.alias_value,
                    is_primary=a.is_primary or False,
                    source=a.source,
                    match_confidence=float(a.match_confidence) if a.match_confidence else None,
                    match_reason=a.match_reason,
                    first_seen_at=a.first_seen_at,
                    last_seen_at=a.last_seen_at,
                    created_at=a.created_at
                ) for a in profile.aliases
            ],
            alias_count=len(profile.aliases),
            repo_names=[r[0] for r in repo_names[:10]]
        )
        results.append(response)
    
    return results


@router.get("/lookup-by-email", response_model=Optional[ContributorProfileResponse], dependencies=[Depends(require_permissions("projects:read"))],
    summary="Look up contributor profile by email",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}})
def lookup_profile_by_email(
    email: str = Query(..., description="Email address to look up"),
    db: Session = Depends(get_tenant_db)
):
    """
    Look up a contributor profile by email address.
    Searches both primary_email and all aliases of type 'email'.
    If multiple profiles are found that should be merged (same display_name),
    aggregates all their aliases into a single response.
    Returns the matching profile with all aliases, or null if not found.
    """
    email_lower = email.lower().strip()
    
    # First check primary_email
    profile = db.query(models.ContributorProfile).filter(
        func.lower(models.ContributorProfile.primary_email) == email_lower
    ).first()
    
    # If not found, check aliases
    if not profile:
        alias = db.query(models.ContributorAlias).filter(
            and_(
                models.ContributorAlias.alias_type == 'email',
                func.lower(models.ContributorAlias.alias_value) == email_lower
            )
        ).first()
        
        if alias:
            profile = db.query(models.ContributorProfile).filter(
                models.ContributorProfile.id == alias.profile_id
            ).first()
    
    if not profile:
        return None
    
    # Find all related profiles (same display_name that should have been merged)
    related_profiles = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.display_name == profile.display_name
    ).all()
    
    # If only one profile, return it normally
    if len(related_profiles) == 1:
        repo_names = db.query(models.Repository.name).join(
            models.Contributor, models.Contributor.repository_id == models.Repository.id
        ).filter(
            models.Contributor.profile_id == profile.id
        ).distinct().all()
        
        return ContributorProfileResponse(
            id=str(profile.id),
            display_name=profile.display_name,
            primary_email=profile.primary_email,
            primary_github_username=profile.primary_github_username,
            entra_id_object_id=profile.entra_id_object_id,
            entra_id_upn=profile.entra_id_upn,
            entra_id_employee_id=profile.entra_id_employee_id,
            entra_id_job_title=profile.entra_id_job_title,
            entra_id_department=profile.entra_id_department,
            entra_id_manager_upn=profile.entra_id_manager_upn,
            employment_status=profile.employment_status or 'unknown',
            employment_start_date=profile.employment_start_date,
            employment_end_date=profile.employment_end_date,
            employment_verified_at=profile.employment_verified_at,
            total_repos=profile.total_repos or 0,
            total_commits=profile.total_commits or 0,
            last_activity_at=profile.last_activity_at,
            first_activity_at=profile.first_activity_at,
            risk_score=profile.risk_score or 0,
            is_stale=profile.is_stale or False,
            has_elevated_access=profile.has_elevated_access or False,
            files_with_findings=profile.files_with_findings or 0,
            critical_files_count=profile.critical_files_count or 0,
            ai_identity_confidence=float(profile.ai_identity_confidence) if profile.ai_identity_confidence else None,
            ai_summary=profile.ai_summary,
            is_verified=profile.is_verified or False,
            verified_at=profile.verified_at,
            notes=profile.notes,
            created_at=profile.created_at,
            updated_at=profile.updated_at,
            aliases=[
                ContributorAliasResponse(
                    id=str(a.id),
                    profile_id=str(a.profile_id),
                    alias_type=a.alias_type,
                    alias_value=a.alias_value,
                    is_primary=a.is_primary or False,
                    source=a.source,
                    match_confidence=float(a.match_confidence) if a.match_confidence else None,
                    match_reason=a.match_reason,
                    first_seen_at=a.first_seen_at,
                    last_seen_at=a.last_seen_at,
                    created_at=a.created_at
                ) for a in profile.aliases
            ],
            alias_count=len(profile.aliases),
            repo_names=[r[0] for r in repo_names]
        )
    
    # Multiple profiles with same display_name - merge them
    # Prefer profile with corporate email as primary
    corp_domains = settings.corporate_email_domains_list
    primary_profile = profile
    for p in related_profiles:
        if p.primary_email:
            email_lower = p.primary_email.lower()
            if any(domain in email_lower for domain in corp_domains):
                primary_profile = p
                break
    
    # Aggregate all aliases from all related profiles
    all_aliases = []
    seen_values = set()
    for p in related_profiles:
        for a in p.aliases:
            key = (a.alias_type, a.alias_value.lower())
            if key not in seen_values:
                seen_values.add(key)
                all_aliases.append(ContributorAliasResponse(
                    id=str(a.id),
                    profile_id=str(a.profile_id),
                    alias_type=a.alias_type,
                    alias_value=a.alias_value,
                    is_primary=a.is_primary or False,
                    source=a.source,
                    match_confidence=float(a.match_confidence) if a.match_confidence else None,
                    match_reason=a.match_reason,
                    first_seen_at=a.first_seen_at,
                    last_seen_at=a.last_seen_at,
                    created_at=a.created_at
                ))
    
    # Aggregate stats
    total_repos = sum(p.total_repos or 0 for p in related_profiles)
    total_commits = sum(p.total_commits or 0 for p in related_profiles)
    files_with_findings = sum(p.files_with_findings or 0 for p in related_profiles)
    critical_files_count = sum(p.critical_files_count or 0 for p in related_profiles)
    
    # Find earliest and latest activity
    first_activity = None
    last_activity = None
    for p in related_profiles:
        if p.first_activity_at:
            if first_activity is None or p.first_activity_at < first_activity:
                first_activity = p.first_activity_at
        if p.last_activity_at:
            if last_activity is None or p.last_activity_at > last_activity:
                last_activity = p.last_activity_at
    
    # Get repo names from all profiles
    profile_ids = [p.id for p in related_profiles]
    repo_names = db.query(models.Repository.name).join(
        models.Contributor, models.Contributor.repository_id == models.Repository.id
    ).filter(
        models.Contributor.profile_id.in_(profile_ids)
    ).distinct().all()
    
    # Pick best github username (prefer non-None)
    github_username = primary_profile.primary_github_username
    if not github_username:
        for p in related_profiles:
            if p.primary_github_username:
                github_username = p.primary_github_username
                break
    
    return ContributorProfileResponse(
        id=str(primary_profile.id),
        display_name=primary_profile.display_name,
        primary_email=primary_profile.primary_email,
        primary_github_username=github_username,
        entra_id_object_id=primary_profile.entra_id_object_id,
        entra_id_upn=primary_profile.entra_id_upn,
        entra_id_employee_id=primary_profile.entra_id_employee_id,
        entra_id_job_title=primary_profile.entra_id_job_title,
        entra_id_department=primary_profile.entra_id_department,
        entra_id_manager_upn=primary_profile.entra_id_manager_upn,
        employment_status=primary_profile.employment_status or 'unknown',
        employment_start_date=primary_profile.employment_start_date,
        employment_end_date=primary_profile.employment_end_date,
        employment_verified_at=primary_profile.employment_verified_at,
        total_repos=total_repos,
        total_commits=total_commits,
        last_activity_at=last_activity,
        first_activity_at=first_activity,
        risk_score=max(p.risk_score or 0 for p in related_profiles),
        is_stale=any(p.is_stale for p in related_profiles),
        has_elevated_access=any(p.has_elevated_access for p in related_profiles),
        files_with_findings=files_with_findings,
        critical_files_count=critical_files_count,
        ai_identity_confidence=float(primary_profile.ai_identity_confidence) if primary_profile.ai_identity_confidence else None,
        ai_summary=primary_profile.ai_summary,
        is_verified=any(p.is_verified for p in related_profiles),
        verified_at=primary_profile.verified_at,
        notes=primary_profile.notes,
        created_at=min(p.created_at for p in related_profiles if p.created_at),
        updated_at=max(p.updated_at for p in related_profiles if p.updated_at),
        aliases=all_aliases,
        alias_count=len(all_aliases),
        repo_names=list(set(r[0] for r in repo_names))
    )


@router.get("/{profile_id}", response_model=ContributorProfileResponse, dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get contributor profile by ID",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}, 404: {"description": "Profile not found"}})
def get_profile(profile_id: str, db: Session = Depends(get_tenant_db)):
    """
    Get a specific contributor profile by ID.
    Returns full profile details including aliases, Entra ID linkage, and activity metrics.
    Requires projects:read permission.
    """
    
    profile = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id == profile_id
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Get linked repo names
    repo_names = db.query(models.Repository.name).join(
        models.Contributor, models.Contributor.repository_id == models.Repository.id
    ).filter(
        models.Contributor.profile_id == profile.id
    ).distinct().all()
    
    return ContributorProfileResponse(
        id=str(profile.id),
        display_name=profile.display_name,
        primary_email=profile.primary_email,
        primary_github_username=profile.primary_github_username,
        entra_id_object_id=profile.entra_id_object_id,
        entra_id_upn=profile.entra_id_upn,
        entra_id_employee_id=profile.entra_id_employee_id,
        entra_id_job_title=profile.entra_id_job_title,
        entra_id_department=profile.entra_id_department,
        entra_id_manager_upn=profile.entra_id_manager_upn,
        employment_status=profile.employment_status or 'unknown',
        employment_start_date=profile.employment_start_date,
        employment_end_date=profile.employment_end_date,
        employment_verified_at=profile.employment_verified_at,
        total_repos=profile.total_repos or 0,
        total_commits=profile.total_commits or 0,
        last_activity_at=profile.last_activity_at,
        first_activity_at=profile.first_activity_at,
        risk_score=profile.risk_score or 0,
        is_stale=profile.is_stale or False,
        has_elevated_access=profile.has_elevated_access or False,
        files_with_findings=profile.files_with_findings or 0,
        critical_files_count=profile.critical_files_count or 0,
        ai_identity_confidence=float(profile.ai_identity_confidence) if profile.ai_identity_confidence else None,
        ai_summary=profile.ai_summary,
        is_verified=profile.is_verified or False,
        verified_at=profile.verified_at,
        notes=profile.notes,
        created_at=profile.created_at,
        updated_at=profile.updated_at,
        aliases=[
            ContributorAliasResponse(
                id=str(a.id),
                profile_id=str(a.profile_id),
                alias_type=a.alias_type,
                alias_value=a.alias_value,
                is_primary=a.is_primary or False,
                source=a.source,
                match_confidence=float(a.match_confidence) if a.match_confidence else None,
                match_reason=a.match_reason,
                first_seen_at=a.first_seen_at,
                last_seen_at=a.last_seen_at,
                created_at=a.created_at
            ) for a in profile.aliases
        ],
        alias_count=len(profile.aliases),
        repo_names=[r[0] for r in repo_names]
    )


@router.post("/", response_model=ContributorProfileResponse, dependencies=[Depends(require_permissions("projects:write"))],
    summary="Create a new contributor profile",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:write"}, 400: {"description": "Profile with given email already exists"}})
def create_profile(profile: ContributorProfileCreate, db: Session = Depends(get_tenant_db)):
    """
    Create a new contributor profile with optional aliases.
    Checks for duplicate primary emails before creation.
    Requires projects:write permission.
    """
    
    # Check for duplicate primary email
    if profile.primary_email:
        existing = db.query(models.ContributorProfile).filter(
            models.ContributorProfile.primary_email == profile.primary_email
        ).first()
        if existing:
            raise HTTPException(
                status_code=400,
                detail=f"Profile with email {profile.primary_email} already exists"
            )
    
    db_profile = models.ContributorProfile(
        display_name=profile.display_name,
        primary_email=profile.primary_email,
        primary_github_username=profile.primary_github_username,
        entra_id_object_id=profile.entra_id_object_id,
        entra_id_upn=profile.entra_id_upn,
        entra_id_employee_id=profile.entra_id_employee_id,
        entra_id_job_title=profile.entra_id_job_title,
        entra_id_department=profile.entra_id_department,
        entra_id_manager_upn=profile.entra_id_manager_upn,
        employment_status=profile.employment_status,
        employment_start_date=profile.employment_start_date,
        employment_end_date=profile.employment_end_date,
        notes=profile.notes
    )
    
    db.add(db_profile)
    db.flush()  # Get the ID
    
    # Add aliases
    for alias in profile.aliases or []:
        db_alias = models.ContributorAlias(
            profile_id=db_profile.id,
            alias_type=alias.alias_type,
            alias_value=alias.alias_value,
            is_primary=alias.is_primary,
            source=alias.source or 'manual',
            match_confidence=alias.match_confidence,
            match_reason=alias.match_reason
        )
        db.add(db_alias)
    
    db.commit()
    db.refresh(db_profile)
    
    return get_profile(str(db_profile.id), db)


@router.patch("/{profile_id}", response_model=ContributorProfileResponse,
    summary="Update a contributor profile",
    responses={401: {"description": "Not authenticated"}, 404: {"description": "Profile not found"}})
def update_profile(
    profile_id: str,
    update: ContributorProfileUpdate,
    db: Session = Depends(get_tenant_db)
):
    """
    Update a contributor profile with partial data.
    Only fields included in the request body will be updated.
    Sets verified_at timestamp automatically when is_verified is set to true.
    """
    
    profile = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id == profile_id
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    update_data = update.model_dump(exclude_unset=True)
    
    for field, value in update_data.items():
        setattr(profile, field, value)
    
    if update.is_verified and not profile.verified_at:
        profile.verified_at = datetime.utcnow()
    
    db.commit()
    db.refresh(profile)
    
    return get_profile(str(profile.id), db)


@router.delete("/{profile_id}",
    summary="Delete a contributor profile",
    responses={401: {"description": "Not authenticated"}, 404: {"description": "Profile not found"}})
def delete_profile(profile_id: str, db: Session = Depends(get_tenant_db)):
    """
    Delete a contributor profile and unlink associated contributors.
    Contributors linked to this profile will have their profile_id set to null.
    """
    
    profile = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id == profile_id
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Unlink contributors first
    db.query(models.Contributor).filter(
        models.Contributor.profile_id == profile_id
    ).update({models.Contributor.profile_id: None})
    
    db.delete(profile)
    db.commit()
    
    return {"status": "deleted", "id": profile_id}


@router.post("/{profile_id}/aliases", response_model=ContributorAliasResponse, dependencies=[Depends(require_permissions("projects:write"))],
    summary="Add an alias to a profile",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:write"}, 400: {"description": "Alias already exists"}, 404: {"description": "Profile not found"}})
def add_alias(
    profile_id: str,
    alias: ContributorAliasBase,
    db: Session = Depends(get_tenant_db)
):
    """
    Add an alias (email, GitHub username, or name) to a contributor profile.
    Checks for duplicate aliases before adding.
    Requires projects:write permission.
    """
    
    profile = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id == profile_id
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    # Check if alias already exists
    existing = db.query(models.ContributorAlias).filter(
        models.ContributorAlias.alias_type == alias.alias_type,
        models.ContributorAlias.alias_value == alias.alias_value
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Alias {alias.alias_value} already exists on profile {existing.profile_id}"
        )
    
    db_alias = models.ContributorAlias(
        profile_id=profile.id,
        alias_type=alias.alias_type,
        alias_value=alias.alias_value,
        is_primary=alias.is_primary,
        source=alias.source or 'manual',
        match_confidence=alias.match_confidence,
        match_reason=alias.match_reason,
        first_seen_at=datetime.utcnow()
    )
    
    db.add(db_alias)
    db.commit()
    db.refresh(db_alias)
    
    return ContributorAliasResponse(
        id=str(db_alias.id),
        profile_id=str(db_alias.profile_id),
        alias_type=db_alias.alias_type,
        alias_value=db_alias.alias_value,
        is_primary=db_alias.is_primary or False,
        source=db_alias.source,
        match_confidence=float(db_alias.match_confidence) if db_alias.match_confidence else None,
        match_reason=db_alias.match_reason,
        first_seen_at=db_alias.first_seen_at,
        last_seen_at=db_alias.last_seen_at,
        created_at=db_alias.created_at
    )


@router.delete("/{profile_id}/aliases/{alias_id}",
    summary="Remove an alias from a profile",
    responses={401: {"description": "Not authenticated"}, 404: {"description": "Alias not found"}})
def remove_alias(profile_id: str, alias_id: str, db: Session = Depends(get_tenant_db)):
    """
    Remove an alias from a contributor profile.
    The alias must belong to the specified profile.
    """
    
    alias = db.query(models.ContributorAlias).filter(
        models.ContributorAlias.id == alias_id,
        models.ContributorAlias.profile_id == profile_id
    ).first()
    
    if not alias:
        raise HTTPException(status_code=404, detail="Alias not found")
    
    db.delete(alias)
    db.commit()
    
    return {"status": "deleted", "alias_id": alias_id}


@router.post("/merge", response_model=ContributorProfileResponse, dependencies=[Depends(require_permissions("projects:write"))],
    summary="Merge multiple profiles into one",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:write"}, 400: {"description": "Need at least 2 profiles to merge"}, 404: {"description": "One or more profiles not found"}})
def merge_profiles(request: MergeProfilesRequest, db: Session = Depends(get_tenant_db)):
    """
    Merge multiple contributor profiles into a single unified profile.
    Aggregates stats, aliases, and contributor links from all source profiles.
    Requires projects:write permission.
    """
    
    if len(request.source_profile_ids) < 2:
        raise HTTPException(status_code=400, detail="Need at least 2 profiles to merge")
    
    # Get all profiles to merge
    profiles = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id.in_(request.source_profile_ids)
    ).all()
    
    if len(profiles) != len(request.source_profile_ids):
        raise HTTPException(status_code=404, detail="One or more profiles not found")
    
    # Collect all data
    all_names = [p.display_name for p in profiles if p.display_name]
    all_emails = [p.primary_email for p in profiles if p.primary_email]
    all_usernames = [p.primary_github_username for p in profiles if p.primary_github_username]
    
    # Pick canonical values
    target_name = request.target_display_name or get_canonical_display_name(all_names)
    target_email = request.target_primary_email or get_canonical_email(all_emails)
    target_username = all_usernames[0] if all_usernames else None
    
    # Use first profile as base, merge others into it
    base_profile = profiles[0]
    base_profile.display_name = target_name
    base_profile.primary_email = target_email
    base_profile.primary_github_username = target_username
    
    # Aggregate stats
    total_repos = sum(p.total_repos or 0 for p in profiles)
    total_commits = sum(p.total_commits or 0 for p in profiles)
    files_with_findings = sum(p.files_with_findings or 0 for p in profiles)
    critical_files = sum(p.critical_files_count or 0 for p in profiles)
    
    # Find earliest/latest activity
    first_activity = min((p.first_activity_at for p in profiles if p.first_activity_at), default=None)
    last_activity = max((p.last_activity_at for p in profiles if p.last_activity_at), default=None)
    
    base_profile.total_repos = total_repos
    base_profile.total_commits = total_commits
    base_profile.files_with_findings = files_with_findings
    base_profile.critical_files_count = critical_files
    base_profile.first_activity_at = first_activity
    base_profile.last_activity_at = last_activity
    
    # Prefer non-null Entra ID values
    for p in profiles[1:]:
        if p.entra_id_object_id and not base_profile.entra_id_object_id:
            base_profile.entra_id_object_id = p.entra_id_object_id
        if p.entra_id_upn and not base_profile.entra_id_upn:
            base_profile.entra_id_upn = p.entra_id_upn
        if p.employment_status != 'unknown' and base_profile.employment_status == 'unknown':
            base_profile.employment_status = p.employment_status
    
    # Move all aliases to base profile
    for p in profiles[1:]:
        for alias in p.aliases:
            alias.profile_id = base_profile.id
        
        # Update contributors to point to base profile
        db.query(models.Contributor).filter(
            models.Contributor.profile_id == p.id
        ).update({models.Contributor.profile_id: base_profile.id})
        
        # Delete the merged profile
        db.delete(p)
    
    db.commit()
    db.refresh(base_profile)
    
    return get_profile(str(base_profile.id), db)


@router.post("/build-from-contributors", response_model=BuildProfilesResponse, dependencies=[Depends(require_permissions("projects:write"))],
    summary="Build profiles from contributor data",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:write"}, 500: {"description": "Profile building error"}})
def build_profiles_from_contributors(
    request: BuildProfilesRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_tenant_db)
):
    """
    Build contributor profiles from existing contributor data using identity deduplication.
    Supports dry_run mode to preview changes before committing.
    Requires projects:write permission.
    """
    
    # Get all contributors
    contributors = db.query(models.Contributor).all()
    
    # Group by identity signals
    identity_groups = []  # List of lists of contributors
    used_ids = set()
    
    for i, c1 in enumerate(contributors):
        if c1.id in used_ids:
            continue
        
        sig1 = extract_identity_signals(c1.name, c1.email, c1.github_username)
        group = [c1]
        used_ids.add(c1.id)
        
        for j, c2 in enumerate(contributors):
            if c2.id in used_ids or j <= i:
                continue
            
            sig2 = extract_identity_signals(c2.name, c2.email, c2.github_username)
            confidence, reason = calculate_match_confidence(sig1, sig2)
            
            if confidence >= request.min_confidence:
                group.append(c2)
                used_ids.add(c2.id)
        
        identity_groups.append(group)
    
    if request.dry_run:
        # Return preview of what would be created
        preview = []
        for group in identity_groups:
            all_names = [c.name for c in group if c.name]
            all_emails = [c.email for c in group if c.email]
            all_usernames = [c.github_username for c in group if c.github_username]
            
            preview.append({
                'display_name': get_canonical_display_name(all_names),
                'primary_email': get_canonical_email(all_emails),
                'all_emails': list(set(all_emails)),
                'all_usernames': list(set(u for u in all_usernames if u)),
                'contributor_count': len(group),
                'total_commits': sum(c.commits or 0 for c in group)
            })
        
        return BuildProfilesResponse(
            profiles_created=len(identity_groups),
            aliases_linked=sum(len(p['all_emails']) + len(p['all_usernames']) for p in preview),
            contributors_linked=len(contributors),
            profiles=preview[:100]  # Limit preview
        )
    
    # Actually create profiles
    profiles_created = 0
    aliases_linked = 0
    contributors_linked = 0
    
    now = datetime.utcnow()
    ninety_days_ago = now - timedelta(days=90)
    
    # Track all aliases globally to avoid duplicates
    used_email_aliases = set()
    used_username_aliases = set()
    used_primary_emails = set()
    
    for group in identity_groups:
        all_names = [c.name for c in group if c.name]
        all_emails = [c.email for c in group if c.email]
        all_usernames = [c.github_username for c in group if c.github_username]
        
        # Get repo names
        repo_ids = set(c.repository_id for c in group)
        
        # Calculate stats
        total_commits = sum(c.commits or 0 for c in group)
        last_commit = max((c.last_commit_at for c in group if c.last_commit_at), default=None)
        first_commit = min((c.last_commit_at for c in group if c.last_commit_at), default=None)
        
        # Dedupe emails for this profile (case-insensitive)
        unique_emails = {}
        for email in all_emails:
            if email:
                key = email.lower().strip()
                if key not in unique_emails:
                    unique_emails[key] = email
        
        # Get the best email, ensuring it's unique as primary
        canonical_email = get_canonical_email(list(unique_emails.values()))
        if canonical_email and canonical_email.lower() in used_primary_emails:
            # Find another unused email for primary
            for email in unique_emails.values():
                if email.lower() not in used_primary_emails:
                    canonical_email = email
                    break
            else:
                canonical_email = None  # No unique email available
        
        if canonical_email:
            used_primary_emails.add(canonical_email.lower())
        
        # Create profile
        profile = models.ContributorProfile(
            display_name=get_canonical_display_name(all_names),
            primary_email=canonical_email,
            primary_github_username=all_usernames[0] if all_usernames else None,
            total_repos=len(repo_ids),
            total_commits=total_commits,
            last_activity_at=last_commit,
            first_activity_at=first_commit,
            is_stale=(last_commit is None or last_commit < ninety_days_ago),
            ai_identity_confidence=0.95 if len(group) > 1 else 1.0
        )
        db.add(profile)
        db.flush()
        profiles_created += 1
        
        # Add email aliases (avoiding duplicates)
        for email_key, email_value in unique_emails.items():
            if email_key not in used_email_aliases:
                used_email_aliases.add(email_key)
                alias = models.ContributorAlias(
                    profile_id=profile.id,
                    alias_type='email',
                    alias_value=email_value,
                    is_primary=(email_value == canonical_email),
                    source='git_log',
                    first_seen_at=first_commit
                )
                db.add(alias)
                aliases_linked += 1
        
        # Add username aliases (avoiding duplicates)
        for username in set(u.lower() for u in all_usernames if u):
            if username not in used_username_aliases:
                used_username_aliases.add(username)
                # Find the original casing
                original = next((u for u in all_usernames if u and u.lower() == username), username)
                alias = models.ContributorAlias(
                    profile_id=profile.id,
                    alias_type='github_username',
                    alias_value=original,
                    is_primary=(original == profile.primary_github_username),
                    source='git_log'
                )
                db.add(alias)
                aliases_linked += 1
        
        # Link contributors to profile
        for c in group:
            c.profile_id = profile.id
            contributors_linked += 1
    
    db.commit()
    
    return BuildProfilesResponse(
        profiles_created=profiles_created,
        aliases_linked=aliases_linked,
        contributors_linked=contributors_linked,
        profiles=[]
    )


@router.post("/refresh-stats", dependencies=[Depends(require_permissions("projects:write"))],
    summary="Refresh aggregated profile statistics",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:write"}})
def refresh_profile_stats(db: Session = Depends(get_tenant_db)):
    """
    Recalculate aggregated statistics for all profiles from linked contributors.
    Updates repo counts, commit totals, activity dates, and staleness indicators.
    Requires projects:write permission.
    """
    
    profiles = db.query(models.ContributorProfile).all()
    now = datetime.utcnow()
    ninety_days_ago = now - timedelta(days=90)
    
    updated = 0
    for profile in profiles:
        # Get linked contributors
        contributors = db.query(models.Contributor).filter(
            models.Contributor.profile_id == profile.id
        ).all()
        
        if not contributors:
            continue
        
        # Recalculate stats
        repo_ids = set(c.repository_id for c in contributors)
        total_commits = sum(c.commits or 0 for c in contributors)
        
        last_commits = [c.last_commit_at for c in contributors if c.last_commit_at]
        last_activity = max(last_commits) if last_commits else None
        first_activity = min(last_commits) if last_commits else None
        
        profile.total_repos = len(repo_ids)
        profile.total_commits = total_commits
        profile.last_activity_at = last_activity
        profile.first_activity_at = first_activity
        profile.is_stale = (last_activity is None or last_activity < ninety_days_ago)
        
        updated += 1
    
    db.commit()
    
    return {"status": "success", "profiles_updated": updated}


# =============================================================================
# Security Leaderboard & Metrics (Phase 4.2)
# =============================================================================

class ContributorSecurityMetrics(BaseModel):
    """Security metrics for a contributor."""
    profile_id: str = Field(..., description="Contributor profile ID")
    display_name: str = Field(..., description="Display name of the contributor")
    primary_email: Optional[str] = Field(None, description="Primary email address")
    findings_introduced: int = Field(..., description="Number of findings introduced by this contributor")
    findings_remediated: int = Field(..., description="Number of findings remediated by this contributor")
    net_security_impact: int = Field(..., description="Net impact: remediated minus introduced")
    avg_time_to_remediate_hours: Optional[float] = Field(None, description="Average time to remediate findings in hours")
    active_findings_count: int = Field(..., description="Number of currently active findings")
    critical_findings_count: int = Field(..., description="Number of critical severity findings")
    repos_contributed: int = Field(..., description="Number of repositories contributed to")


class LeaderboardEntry(BaseModel):
    """An entry in the security leaderboard."""
    rank: int = Field(..., description="Leaderboard position")
    profile_id: str = Field(..., description="Contributor profile ID")
    display_name: str = Field(..., description="Display name of the contributor")
    score: int = Field(..., description="Calculated leaderboard score")
    findings_remediated: int = Field(..., description="Number of findings remediated")
    findings_introduced: int = Field(..., description="Number of findings introduced")
    badge: str = Field(..., description="Badge level: gold, silver, bronze, neutral, or warning")


class LeaderboardResponse(BaseModel):
    """Security leaderboard response."""
    period_days: int = Field(..., description="Analysis period in days")
    top_remediators: List[LeaderboardEntry] = Field(..., description="Top contributors by remediation count")
    most_findings_introduced: List[LeaderboardEntry] = Field(..., description="Contributors who introduced the most findings")
    summary: Dict[str, Any] = Field(..., description="Overall leaderboard summary statistics")


@router.get("/security/leaderboard", response_model=LeaderboardResponse, dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get security contributor leaderboard",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}})
def get_security_leaderboard(
    days: int = Query(90, description="Period to analyze"),
    limit: int = Query(10, le=50),
    db: Session = Depends(get_tenant_db)
):
    """
    Get the security leaderboard showing top remediators and contributors
    who may need additional security training, ranked by remediation activity.
    Requires projects:read permission.
    """
    from datetime import timedelta
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Get all profiles with linked contributors
    profiles = db.query(models.ContributorProfile).all()
    
    metrics_list = []
    
    for profile in profiles:
        # Get contributors linked to this profile
        contributors = db.query(models.Contributor).filter(
            models.Contributor.profile_id == profile.id
        ).all()
        
        if not contributors:
            continue
        
        # Get file paths from commits by this contributor's linked repos
        repo_ids = list(set(c.repository_id for c in contributors))
        
        # Count findings in files last touched by this contributor
        # This is a simplified heuristic - in production would use git blame
        file_paths = db.query(models.FileCommit.file_path).filter(
            models.FileCommit.repository_id.in_(repo_ids),
            models.FileCommit.last_commit_author.in_([c.name for c in contributors])
        ).distinct().all()
        
        file_path_list = [fp[0] for fp in file_paths]
        
        # Findings introduced (open findings in files they touched)
        findings_introduced = db.query(models.Finding).filter(
            models.Finding.status == 'open',
            models.Finding.file_path.in_(file_path_list)
        ).count() if file_path_list else 0
        
        # Findings remediated (resolved findings in files they touched)
        findings_remediated = db.query(models.Finding).filter(
            models.Finding.status == 'resolved',
            models.Finding.resolved_at >= cutoff,
            models.Finding.file_path.in_(file_path_list)
        ).count() if file_path_list else 0
        
        # Active critical findings
        critical = db.query(models.Finding).filter(
            models.Finding.status == 'open',
            models.Finding.severity == 'critical',
            models.Finding.file_path.in_(file_path_list)
        ).count() if file_path_list else 0
        
        metrics_list.append({
            "profile": profile,
            "findings_introduced": findings_introduced,
            "findings_remediated": findings_remediated,
            "net_impact": findings_remediated - findings_introduced,
            "critical": critical,
            "repos": len(repo_ids)
        })
    
    # Build top remediators list
    top_remediators = sorted(metrics_list, key=lambda x: x["findings_remediated"], reverse=True)[:limit]
    top_remediators_entries = []
    for i, m in enumerate(top_remediators):
        if m["findings_remediated"] == 0:
            continue
        badge = "gold" if i < 3 else "silver" if i < 7 else "bronze"
        top_remediators_entries.append(LeaderboardEntry(
            rank=i + 1,
            profile_id=str(m["profile"].id),
            display_name=m["profile"].display_name,
            score=m["findings_remediated"] * 10,
            findings_remediated=m["findings_remediated"],
            findings_introduced=m["findings_introduced"],
            badge=badge
        ))
    
    # Build most findings introduced list (for training focus)
    most_introduced = sorted(metrics_list, key=lambda x: x["findings_introduced"], reverse=True)[:limit]
    most_introduced_entries = []
    for i, m in enumerate(most_introduced):
        if m["findings_introduced"] == 0:
            continue
        badge = "warning" if m["critical"] > 0 else "neutral"
        most_introduced_entries.append(LeaderboardEntry(
            rank=i + 1,
            profile_id=str(m["profile"].id),
            display_name=m["profile"].display_name,
            score=m["findings_introduced"],
            findings_remediated=m["findings_remediated"],
            findings_introduced=m["findings_introduced"],
            badge=badge
        ))
    
    # Summary stats
    total_remediated = sum(m["findings_remediated"] for m in metrics_list)
    total_introduced = sum(m["findings_introduced"] for m in metrics_list)
    
    return LeaderboardResponse(
        period_days=days,
        top_remediators=top_remediators_entries,
        most_findings_introduced=most_introduced_entries,
        summary={
            "total_findings_remediated": total_remediated,
            "total_findings_introduced": total_introduced,
            "net_security_improvement": total_remediated - total_introduced,
            "contributors_analyzed": len([m for m in metrics_list if m["repos"] > 0])
        }
    )


@router.get("/security/metrics/{profile_id}", response_model=ContributorSecurityMetrics, dependencies=[Depends(require_permissions("projects:read"))],
    summary="Get security metrics for a contributor",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires projects:read"}, 400: {"description": "Invalid UUID format"}, 404: {"description": "Profile not found"}})
def get_contributor_security_metrics(
    profile_id: str,
    days: int = Query(90),
    db: Session = Depends(get_tenant_db)
):
    """
    Get detailed security metrics for a specific contributor including findings
    introduced, findings remediated, and average time to remediate.
    Requires projects:read permission.
    """
    import uuid
    from datetime import timedelta
    
    try:
        uuid_obj = uuid.UUID(profile_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid UUID format")
    
    profile = db.query(models.ContributorProfile).filter(
        models.ContributorProfile.id == uuid_obj
    ).first()
    
    if not profile:
        raise HTTPException(status_code=404, detail="Profile not found")
    
    cutoff = datetime.utcnow() - timedelta(days=days)
    
    # Get contributors linked to this profile
    contributors = db.query(models.Contributor).filter(
        models.Contributor.profile_id == profile.id
    ).all()
    
    repo_ids = list(set(c.repository_id for c in contributors))
    
    # Get file paths touched by this contributor
    file_paths = db.query(models.FileCommit.file_path).filter(
        models.FileCommit.repository_id.in_(repo_ids),
        models.FileCommit.last_commit_author.in_([c.name for c in contributors])
    ).distinct().all() if repo_ids else []
    
    file_path_list = [fp[0] for fp in file_paths]
    
    # Calculate metrics
    findings_introduced = db.query(models.Finding).filter(
        models.Finding.status == 'open',
        models.Finding.file_path.in_(file_path_list)
    ).count() if file_path_list else 0
    
    findings_remediated = db.query(models.Finding).filter(
        models.Finding.status == 'resolved',
        models.Finding.resolved_at >= cutoff,
        models.Finding.file_path.in_(file_path_list)
    ).count() if file_path_list else 0
    
    active_findings = db.query(models.Finding).filter(
        models.Finding.status == 'open',
        models.Finding.file_path.in_(file_path_list)
    ).count() if file_path_list else 0
    
    critical_findings = db.query(models.Finding).filter(
        models.Finding.status == 'open',
        models.Finding.severity == 'critical',
        models.Finding.file_path.in_(file_path_list)
    ).count() if file_path_list else 0
    
    # Calculate average remediation time
    resolved_findings = db.query(models.Finding).filter(
        models.Finding.status == 'resolved',
        models.Finding.resolved_at >= cutoff,
        models.Finding.file_path.in_(file_path_list),
        models.Finding.resolved_at.isnot(None)
    ).all() if file_path_list else []
    
    if resolved_findings:
        times = []
        for f in resolved_findings:
            if f.created_at and f.resolved_at:
                delta = (f.resolved_at - f.created_at).total_seconds() / 3600
                times.append(delta)
        avg_time = sum(times) / len(times) if times else None
    else:
        avg_time = None
    
    return ContributorSecurityMetrics(
        profile_id=str(profile.id),
        display_name=profile.display_name,
        primary_email=profile.primary_email,
        findings_introduced=findings_introduced,
        findings_remediated=findings_remediated,
        net_security_impact=findings_remediated - findings_introduced,
        avg_time_to_remediate_hours=round(avg_time, 1) if avg_time else None,
        active_findings_count=active_findings,
        critical_findings_count=critical_findings,
        repos_contributed=len(repo_ids)
    )
