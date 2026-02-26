"""
Attack Surface Visibility API Router.
Provides endpoints for security analysts to assess real-world attack surface risks.
"""
from fastapi import APIRouter, Depends, Query, BackgroundTasks
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, case, desc, asc
from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from pydantic import BaseModel, Field
from enum import Enum
from loguru import logger
import json
import re

from ..dependencies import get_tenant_db
from .. import models
from ..config import settings
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/attack-surface",
    tags=["attack-surface"]
)

# AI Agent singleton for contributor deduplication
_ai_agent = None

def get_ai_agent():
    """Get or create the AI agent singleton."""
    global _ai_agent
    if _ai_agent is None:
        try:
            from ...ai_agent.agent import AIAgent
            _ai_agent = AIAgent(
                openai_api_key=settings.OPENAI_API_KEY,
                anthropic_api_key=settings.ANTHROPIC_API_KEY,
                provider=settings.AI_PROVIDER,
                model=settings.AI_MODEL
            )
        except Exception as e:
            logger.error(f"Failed to initialize AI agent: {e}")
            return None
    return _ai_agent


# =============================================================================
# Pydantic Models
# =============================================================================

class SecretFinding(BaseModel):
    """A hardcoded secret or sensitive data finding."""
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Title of the secret finding")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    scanner_name: str = Field(..., description="Scanner that detected the secret (e.g. trufflehog)")
    repo_name: str = Field(..., description="Repository name where the secret was found")
    repository_id: str = Field(..., description="UUID of the repository")
    file_path: Optional[str] = Field(None, description="File path containing the secret")
    line_start: Optional[int] = Field(None, description="Line number where the secret starts")
    code_snippet: Optional[str] = Field(None, description="Truncated code snippet around the secret")
    secret_type: str = Field(..., description="Type of secret extracted from the title")
    first_seen_at: Optional[datetime] = Field(None, description="When the secret was first detected")
    last_seen_at: Optional[datetime] = Field(None, description="When the secret was last seen")
    file_last_commit_at: Optional[datetime] = Field(None, description="Last commit date for the file")
    file_last_commit_author: Optional[str] = Field(None, description="Author of the last commit to the file")
    is_archived: bool = Field(..., description="Whether the repository is archived")

    model_config = {"from_attributes": True}


class HardcodedAsset(BaseModel):
    """A hardcoded IP, hostname, or URL finding."""
    id: str = Field(..., description="Unique finding identifier")
    title: str = Field(..., description="Title of the hardcoded asset finding")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    scanner_name: str = Field(..., description="Scanner that detected the asset")
    repo_name: str = Field(..., description="Repository name where the asset was found")
    repository_id: str = Field(..., description="UUID of the repository")
    file_path: Optional[str] = Field(None, description="File path containing the hardcoded asset")
    line_start: Optional[int] = Field(None, description="Line number where the asset starts")
    code_snippet: Optional[str] = Field(None, description="Code snippet around the hardcoded asset")
    asset_type: str = Field(..., description="Type of hardcoded asset: ip, hostname, url, or http_link")
    first_seen_at: Optional[datetime] = Field(None, description="When the asset was first detected")

    model_config = {"from_attributes": True}


class SecretsReport(BaseModel):
    """Aggregated secrets/hardcoded assets report."""
    total_secrets: int = Field(..., description="Total number of secret findings")
    total_hardcoded_assets: int = Field(..., description="Total number of hardcoded asset findings")
    secrets_by_type: dict = Field(..., description="Count of secrets grouped by type")
    secrets_by_severity: dict = Field(..., description="Count of secrets grouped by severity")
    secrets_by_repo: List[dict] = Field(..., description="Secret counts per repository")
    top_affected_repos: List[dict] = Field(..., description="Top repositories by secret count")
    recent_secrets: List[SecretFinding] = Field(..., description="Most recently discovered secrets")


class AbandonedRepo(BaseModel):
    """A potentially abandoned repository."""
    id: str = Field(..., description="UUID of the repository")
    name: str = Field(..., description="Repository name")
    url: Optional[str] = Field(None, description="Repository URL")
    description: Optional[str] = Field(None, description="Repository description")
    language: Optional[str] = Field(None, description="Primary programming language")
    pushed_at: Optional[datetime] = Field(None, description="Last push date")
    github_created_at: Optional[datetime] = Field(None, description="GitHub creation date")
    is_archived: bool = Field(..., description="Whether the repository is archived")
    visibility: Optional[str] = Field(None, description="Repository visibility (public, private, internal)")
    days_since_push: Optional[int] = Field(None, description="Number of days since last push")
    abandonment_score: int = Field(..., description="Abandonment risk score from 0 to 100")
    abandonment_reasons: List[str] = Field(..., description="Reasons contributing to the abandonment score")
    open_findings_count: int = Field(..., description="Number of open security findings")
    critical_findings_count: int = Field(..., description="Number of critical severity findings")
    contributor_count: int = Field(..., description="Total number of contributors")
    active_contributors_count: int = Field(..., description="Contributors active in the last year")

    model_config = {"from_attributes": True}


class StaleContributor(BaseModel):
    """A contributor with no recent activity (deduplicated across repos)."""
    id: str = Field(..., description="Unique contributor identifier")
    name: str = Field(..., description="Contributor display name")
    email: Optional[str] = Field(None, description="Primary email address")
    github_username: Optional[str] = Field(None, description="GitHub username")
    total_repos: int = Field(..., description="Number of repos they contributed to")
    repo_names: List[str] = Field(..., description="List of repository names")
    total_commits: int = Field(..., description="Total commits across all repos")
    last_commit_at: Optional[datetime] = Field(None, description="Date of last commit to any repo")
    days_since_last_commit: Optional[int] = Field(None, description="Days since last commit")
    files_with_findings: int = Field(..., description="Number of files with security findings")
    critical_files_count: int = Field(..., description="Number of files with critical findings")
    risk_score: int = Field(..., description="Calculated risk score from 0 to 100")
    merged_identities: int = Field(1, description="Number of identities merged (>1 means duplicates found)")
    all_emails: Optional[List[str]] = Field(None, description="All email addresses if multiple identities merged")

    model_config = {"from_attributes": True}


class PublicExposure(BaseModel):
    """A publicly exposed repository."""
    id: str = Field(..., description="UUID of the repository")
    name: str = Field(..., description="Repository name")
    url: Optional[str] = Field(None, description="Repository URL")
    description: Optional[str] = Field(None, description="Repository description")
    visibility: str = Field(..., description="Repository visibility level")
    is_archived: bool = Field(..., description="Whether the repository is archived")
    pushed_at: Optional[datetime] = Field(None, description="Last push date")
    open_findings_count: int = Field(..., description="Number of open security findings")
    critical_findings_count: int = Field(..., description="Number of critical findings")
    secrets_count: int = Field(..., description="Number of exposed secrets")
    exposure_risk: str = Field(..., description="Overall exposure risk: critical, high, medium, or low")
    risk_factors: List[str] = Field(..., description="List of risk factors contributing to exposure")

    model_config = {"from_attributes": True}


class HighRiskRepo(BaseModel):
    """A high-risk repository based on attack surface analysis."""
    id: str = Field(..., description="UUID of the repository")
    name: str = Field(..., description="Repository name")
    url: Optional[str] = Field(None, description="Repository URL")
    description: Optional[str] = Field(None, description="Repository description")
    visibility: str = Field(..., description="Repository visibility (public, private, internal)")
    is_archived: bool = Field(..., description="Whether the repository is archived")
    is_abandoned: bool = Field(..., description="Whether the repository is considered abandoned")
    last_commit_date: Optional[datetime] = Field(None, description="Date of the last commit")
    days_since_activity: Optional[int] = Field(None, description="Days since last activity")
    open_findings_count: int = Field(..., description="Total open findings count")
    critical_findings_count: int = Field(..., description="Number of critical findings")
    high_findings_count: int = Field(..., description="Number of high severity findings")
    secrets_count: int = Field(..., description="Number of detected secrets")
    risk_score: int = Field(..., description="Calculated risk score from 0 to 100")
    risk_level: str = Field(..., description="Risk level: critical, high, medium, or low")
    risk_factors: List[str] = Field(..., description="List of contributing risk factors")
    primary_language: Optional[str] = Field(None, description="Primary programming language")
    contributors_count: int = Field(..., description="Number of contributors")

    model_config = {"from_attributes": True}


class AttackSurfaceSummary(BaseModel):
    """Overall attack surface summary."""
    total_repos: int = Field(..., description="Total number of repositories")
    public_repos: int = Field(..., description="Number of public repositories")
    archived_repos: int = Field(..., description="Number of archived repositories")
    abandoned_repos: int = Field(..., description="Number of abandoned repositories (no push in 1+ year)")
    total_findings: int = Field(..., description="Total open security findings")
    total_secrets: int = Field(..., description="Total secrets from TruffleHog scans")
    total_hardcoded_assets: int = Field(..., description="Total hardcoded assets from Semgrep scans")
    stale_contributors: int = Field(..., description="Contributors with no recent activity (90+ days)")
    high_risk_repos: int = Field(..., description="Number of repositories classified as high risk")
    active_investigations: int = Field(0, description="Findings currently under triage or incident response")


# =============================================================================
# INCIDENT RESPONSE MODELS
# =============================================================================

class IRFinding(BaseModel):
    """A finding currently under investigation."""
    id: str = Field(..., description="Finding UUID")
    title: str = Field(..., description="Finding title")
    severity: str = Field(..., description="Severity level (critical, high, medium, low)")
    investigation_status: str = Field(..., description="Current investigation status (triage, incident_response)")
    investigation_started_at: Optional[datetime] = Field(None, description="When the investigation was started")
    scanner_name: Optional[str] = Field(None, description="Scanner that detected the finding")
    repo_name: str = Field(..., description="Repository name")
    repository_id: Optional[str] = Field(None, description="UUID of the repository")
    file_path: Optional[str] = Field(None, description="File path of the finding")
    journal_count: int = Field(0, description="Number of journal entries for this investigation")
    last_journal_at: Optional[datetime] = Field(None, description="Timestamp of the last journal entry")

    model_config = {"from_attributes": True}


# =============================================================================
# CONTRIBUTOR IDENTITY DEDUPLICATION HELPERS
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
    
    # Parse name into parts
    if name:
        # Remove common prefixes/suffixes
        clean_name = name.strip()
        signals['name_parts'] = [p.lower() for p in clean_name.split() if len(p) > 1]
    
    # Parse email
    if email:
        email_lower = email.lower().strip()
        if '@' in email_lower:
            local, domain = email_lower.rsplit('@', 1)
            signals['email_local'] = local
            signals['email_domain'] = domain
            
            # Check for GitHub noreply format: 12345678+username@users.noreply.github.com
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

def simple_identity_match(sig1: Dict, sig2: Dict) -> tuple[bool, float, str]:
    """
    Simple rule-based identity matching.
    Returns: (is_match, confidence, reason)
    """
    # Same email (case-insensitive) = definite match
    if sig1['email'] and sig2['email']:
        if sig1['email'].lower().strip() == sig2['email'].lower().strip():
            return True, 1.0, "exact_email_match"

    # Same email local part at corporate domain = very likely match
    corp_domains = settings.corporate_email_domains_list
    if sig1['email_local'] and sig2['email_local'] and corp_domains:
        if sig1['email_domain'] in corp_domains and sig2['email_domain'] in corp_domains:
            if sig1['email_local'] == sig2['email_local']:
                return True, 0.99, "same_corporate_email"

    # GitHub username matches email local part (normalize both to handle konrad-dunikowski vs konrad.dunikowski)
    if sig1['github_username'] and sig2['email_local']:
        if normalize_identifier(sig1['github_username']) == normalize_identifier(sig2['email_local']):
            return True, 0.95, "github_matches_email"
    if sig2['github_username'] and sig1['email_local']:
        if normalize_identifier(sig2['github_username']) == normalize_identifier(sig1['email_local']):
            return True, 0.95, "github_matches_email"

    # GitHub noreply username matches corporate email local
    if sig1['is_noreply'] and sig1['github_username'] and sig2['email_local']:
        if sig2['email_domain'] in corp_domains:
            if normalize_identifier(sig1['github_username']) == normalize_identifier(sig2['email_local']):
                return True, 0.96, "noreply_github_matches_corp_email"
    if sig2['is_noreply'] and sig2['github_username'] and sig1['email_local']:
        if sig1['email_domain'] in corp_domains:
            if normalize_identifier(sig2['github_username']) == normalize_identifier(sig1['email_local']):
                return True, 0.96, "noreply_github_matches_corp_email"
    
    # Name matches email pattern (first.last@domain or firstlast@domain)
    if sig1['name_parts'] and sig2['email_local']:
        name_concat = ''.join(sig1['name_parts'])
        name_dotted = '.'.join(sig1['name_parts'])
        if name_concat == sig2['email_local'] or name_dotted == sig2['email_local']:
            return True, 0.90, "name_matches_email"
    if sig2['name_parts'] and sig1['email_local']:
        name_concat = ''.join(sig2['name_parts'])
        name_dotted = '.'.join(sig2['name_parts'])
        if name_concat == sig1['email_local'] or name_dotted == sig1['email_local']:
            return True, 0.90, "name_matches_email"
    
    # Same name (case-insensitive) with related domains
    if sig1['name_parts'] and sig2['name_parts']:
        if sig1['name_parts'] == sig2['name_parts']:
            # Same name, check domains (include noreply as valid corporate indicator)
            all_corp_domains = corp_domains + ['users.noreply.github.com']
            d1 = sig1['email_domain'] or ''
            d2 = sig2['email_domain'] or ''
            if any(d in d1 for d in all_corp_domains) and any(d in d2 for d in all_corp_domains):
                return True, 0.85, "same_name_corp_domains"
    
    # Same FULL name with first+last = very high confidence for unique names
    # "Isaac Springer" appearing twice is almost certainly same person
    if sig1['name_parts'] and sig2['name_parts']:
        if len(sig1['name_parts']) >= 2 and len(sig2['name_parts']) >= 2:
            if sig1['name_parts'] == sig2['name_parts']:
                # Same full name (first + last) - very likely same person
                # unless it's a super common name like "John Smith"
                common_names = {'john', 'james', 'robert', 'michael', 'david', 'smith', 'johnson', 'williams'}
                if not all(p in common_names for p in sig1['name_parts']):
                    return True, 0.92, "same_full_name"
    
    # Check if email local contains full name parts (e.g., idspringer@onyxhat.com for "Isaac Springer")
    if sig1['name_parts'] and sig2['email_local']:
        # Check if all name initials are in the email
        initials = ''.join(p[0] for p in sig1['name_parts'])
        last_name = sig1['name_parts'][-1] if sig1['name_parts'] else ''
        # Pattern: first initial + last name (e.g., ispringer)
        if sig2['email_local'].startswith(initials[0]) and last_name in sig2['email_local']:
            return True, 0.88, "initial_lastname_in_email"
    if sig2['name_parts'] and sig1['email_local']:
        initials = ''.join(p[0] for p in sig2['name_parts'])
        last_name = sig2['name_parts'][-1] if sig2['name_parts'] else ''
        if sig1['email_local'].startswith(initials[0]) and last_name in sig1['email_local']:
            return True, 0.88, "initial_lastname_in_email"
    
    return False, 0.0, "no_match"

async def ai_identity_match(contributors: List[Dict], agent) -> Dict[str, List[str]]:
    """
    Use AI to identify duplicate contributors with high confidence.
    Returns a mapping of canonical_key -> [list of duplicate keys]
    """
    if not agent or len(contributors) < 2:
        return {}
    
    # Build prompt with contributor info
    # Build corporate domain hint for AI
    corp_domain_hint = ""
    if corp_domains:
        corp_domain_hint = f"Corporate domains: {', '.join(corp_domains)}. "

    prompt = f"""You are an expert at identity resolution. Analyze these contributors and identify which ones are the SAME PERSON with 99%+ confidence.

IMPORTANT RULES:
1. Same email (case-insensitive) = ALWAYS the same person
2. GitHub noreply format "12345+username@users.noreply.github.com" - the username often matches their real name or email
3. {corp_domain_hint}First.Last@corp.com usually matches username "flast" or "firstlast"
4. Be VERY confident - only group people you're 99%+ sure are the same person
5. Consider: name similarity, email patterns, username patterns

CONTRIBUTORS:
"""
    
    for i, c in enumerate(contributors[:50]):  # Limit to 50 for prompt size
        prompt += f"\n{i+1}. Name: \"{c['name']}\" | Email: \"{c['email']}\" | GitHub: \"{c.get('github_username', 'N/A')}\""
    
    prompt += """

OUTPUT FORMAT (JSON only, no explanation):
{
  "groups": [
    {
      "canonical_name": "Full Name",
      "canonical_email": "preferred@email.com",
      "member_indices": [1, 5, 12],
      "confidence": 0.99,
      "reason": "brief explanation"
    }
  ]
}

Only include groups where confidence >= 0.95. If no duplicates found, return {"groups": []}
"""
    
    try:
        # Call the AI provider directly
        response = await agent.provider.client.chat.completions.create(
            model=agent.model,
            messages=[
                {"role": "system", "content": "You are an identity resolution expert. Output only valid JSON."},
                {"role": "user", "content": prompt}
            ],
            response_format={"type": "json_object"},
            max_tokens=2000,
            temperature=0.1
        )
        
        result = json.loads(response.choices[0].message.content)
        return result.get('groups', [])
        
    except Exception as e:
        logger.error(f"AI identity matching failed: {e}")
        return []

def deduplicate_contributors(raw_contributors: List[Dict]) -> List[Dict]:
    """
    Deduplicate contributors using rule-based matching.
    Groups contributors that are likely the same person.
    """
    # Build signals for each contributor
    contributors_with_signals = []
    for c in raw_contributors:
        signals = extract_identity_signals(
            c.get('name', ''),
            c.get('email', ''),
            c.get('github_username')
        )
        contributors_with_signals.append({**c, '_signals': signals})
    
    # Group contributors
    groups = []  # List of merged contributor dicts
    used = set()
    
    for i, c1 in enumerate(contributors_with_signals):
        if i in used:
            continue
        
        # Start a new group with this contributor
        group = [c1]
        used.add(i)
        
        # Find all matches
        for j, c2 in enumerate(contributors_with_signals):
            if j in used or j <= i:
                continue
            
            is_match, confidence, reason = simple_identity_match(
                c1['_signals'], c2['_signals']
            )
            
            if is_match and confidence >= 0.85:
                group.append(c2)
                used.add(j)
                logger.debug(f"Matched contributors: {c1['email']} <-> {c2['email']} ({reason}, {confidence})")
        
        # Merge the group into a single contributor
        merged = merge_contributor_group(group)
        groups.append(merged)
    
    return groups

def merge_contributor_group(group: List[Dict]) -> Dict:
    """Merge a group of duplicate contributors into one."""
    if len(group) == 1:
        result = {k: v for k, v in group[0].items() if not k.startswith('_')}
        return result
    
    # Collect all values
    all_names = [c['name'] for c in group if c.get('name')]
    all_emails = [c['email'] for c in group if c.get('email')]
    all_usernames = [c.get('github_username') for c in group if c.get('github_username')]
    all_repo_names = []
    for c in group:
        all_repo_names.extend(c.get('repo_names', []))
    
    # Pick the best canonical name (prefer full names with spaces)
    canonical_name = max(all_names, key=lambda n: (len(n.split()), len(n))) if all_names else 'Unknown'

    # Pick the best email (prefer corporate domains)
    corp_domains = settings.corporate_email_domains_list
    canonical_email = None
    for email in all_emails:
        if email:
            email_lower = email.lower()
            if any(domain in email_lower for domain in corp_domains):
                canonical_email = email
                break
    if not canonical_email:
        canonical_email = all_emails[0] if all_emails else None
    
    # Use the first github username found
    canonical_username = all_usernames[0] if all_usernames else None
    
    # Sum up commits
    total_commits = sum(c.get('total_commits', 0) for c in group)
    
    # Find most recent commit
    last_commit = None
    for c in group:
        commit_at = c.get('last_commit_at')
        if commit_at:
            if last_commit is None or commit_at > last_commit:
                last_commit = commit_at
    
    # Sum files with findings
    files_with_findings = sum(c.get('files_with_findings', 0) for c in group)
    critical_files = sum(c.get('critical_files_count', 0) for c in group)
    
    return {
        'id': group[0]['id'],
        'name': canonical_name,
        'email': canonical_email,
        'github_username': canonical_username,
        'repo_names': list(set(all_repo_names)),
        'total_commits': total_commits,
        'last_commit_at': last_commit,
        'files_with_findings': files_with_findings,
        'critical_files_count': critical_files,
        'merged_identities': len(group),
        'all_emails': list(set(all_emails)),
    }


# =============================================================================
# 1. HARDCODED SECRETS & ASSETS REPORT
# =============================================================================

@router.get("/secrets", response_model=SecretsReport, dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get hardcoded secrets and sensitive data report",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}, 500: {"description": "Internal server error"}})
def get_secrets_report(
    db: Session = Depends(get_tenant_db),
    severity: Optional[str] = None,
    secret_type: Optional[str] = None,
    repo_name: Optional[str] = None,
    limit: int = Query(default=50, le=500)
):
    """
    Get comprehensive report of hardcoded secrets and sensitive data.
    
    Aggregates findings from TruffleHog (secrets) and Semgrep (hardcoded values).
    """
    # Base query for secrets (TruffleHog)
    secrets_query = db.query(models.Finding).join(
        models.Repository, models.Finding.repository_id == models.Repository.id
    ).outerjoin(
        models.FileCommit,
        and_(
            models.Finding.repository_id == models.FileCommit.repository_id,
            models.Finding.file_path == models.FileCommit.file_path
        )
    ).filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    )
    
    if severity:
        secrets_query = secrets_query.filter(models.Finding.severity == severity)
    if repo_name:
        secrets_query = secrets_query.filter(models.Repository.name.ilike(f'%{repo_name}%'))
    
    secrets = secrets_query.all()
    
    # Count by type (extract from title like "Secret found: AWS")
    secrets_by_type = {}
    for s in secrets:
        secret_type_name = s.title.replace('Secret found: ', '').strip() if s.title else 'Unknown'
        secrets_by_type[secret_type_name] = secrets_by_type.get(secret_type_name, 0) + 1
    
    # Count by severity
    secrets_by_severity = {}
    for s in secrets:
        sev = s.severity or 'unknown'
        secrets_by_severity[sev] = secrets_by_severity.get(sev, 0) + 1
    
    # Count by repo
    repo_counts = {}
    for s in secrets:
        repo = s.repository.name if s.repository else 'Unknown'
        repo_id = str(s.repository.id) if s.repository else None
        if repo not in repo_counts:
            repo_counts[repo] = {'name': repo, 'id': repo_id, 'count': 0, 'critical': 0, 'high': 0}
        repo_counts[repo]['count'] += 1
        if s.severity == 'critical':
            repo_counts[repo]['critical'] += 1
        elif s.severity == 'high':
            repo_counts[repo]['high'] += 1
    
    top_repos = sorted(repo_counts.values(), key=lambda x: (x['critical'], x['high'], x['count']), reverse=True)[:10]
    
    # Hardcoded assets from Semgrep (HTTP links, etc.)
    hardcoded_query = db.query(models.Finding).filter(
        models.Finding.scanner_name == 'semgrep',
        models.Finding.status == 'open',
        or_(
            models.Finding.title.ilike('%http%'),
            models.Finding.title.ilike('%url%'),
            models.Finding.title.ilike('%ip%'),
            models.Finding.title.ilike('%host%')
        )
    )
    hardcoded_assets = hardcoded_query.count()
    
    # Recent secrets with file commit info
    recent_secrets_query = db.query(
        models.Finding,
        models.Repository.name.label('repo_name'),
        models.Repository.is_archived,
        models.FileCommit.last_commit_date,
        models.FileCommit.last_commit_author
    ).join(
        models.Repository, models.Finding.repository_id == models.Repository.id
    ).outerjoin(
        models.FileCommit,
        and_(
            models.Finding.repository_id == models.FileCommit.repository_id,
            models.Finding.file_path == models.FileCommit.file_path
        )
    ).filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).order_by(desc(models.Finding.first_seen_at)).limit(limit)
    
    recent_secrets = []
    for finding, repo_name_val, is_archived, file_commit_date, file_commit_author in recent_secrets_query.all():
        secret_type_name = finding.title.replace('Secret found: ', '').strip() if finding.title else 'Unknown'
        recent_secrets.append(SecretFinding(
            id=str(finding.id),
            title=finding.title,
            severity=finding.severity,
            scanner_name=finding.scanner_name,
            repo_name=repo_name_val,
            repository_id=str(finding.repository_id),
            file_path=finding.file_path,
            line_start=finding.line_start,
            code_snippet=finding.code_snippet[:100] if finding.code_snippet else None,
            secret_type=secret_type_name,
            first_seen_at=finding.first_seen_at,
            last_seen_at=finding.last_seen_at,
            file_last_commit_at=file_commit_date,
            file_last_commit_author=file_commit_author,
            is_archived=is_archived or False
        ))
    
    return SecretsReport(
        total_secrets=len(secrets),
        total_hardcoded_assets=hardcoded_assets,
        secrets_by_type=secrets_by_type,
        secrets_by_severity=secrets_by_severity,
        secrets_by_repo=[{'repo': r['name'], 'id': r['id'], 'count': r['count']} for r in top_repos],
        top_affected_repos=top_repos,
        recent_secrets=recent_secrets
    )


@router.get("/secrets/by-type/{secret_type}", dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get secrets filtered by type",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_secrets_by_type(
    secret_type: str,
    db: Session = Depends(get_tenant_db),
    limit: int = Query(default=100, le=500)
):
    """
    Get all secrets of a specific type (e.g., 'AWS', 'PrivateKey', 'SQLServer').
    Returns findings with file commit metadata and severity ordering.
    Requires findings:read permission.
    """
    findings = db.query(
        models.Finding,
        models.Repository.name.label('repo_name'),
        models.Repository.is_archived,
        models.Repository.visibility,
        models.FileCommit.last_commit_date,
        models.FileCommit.last_commit_author
    ).join(
        models.Repository, models.Finding.repository_id == models.Repository.id
    ).outerjoin(
        models.FileCommit,
        and_(
            models.Finding.repository_id == models.FileCommit.repository_id,
            models.Finding.file_path == models.FileCommit.file_path
        )
    ).filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.title.ilike(f'%{secret_type}%'),
        models.Finding.status == 'open'
    ).order_by(
        desc(case((models.Finding.severity == 'critical', 4),
                  (models.Finding.severity == 'high', 3),
                  (models.Finding.severity == 'medium', 2),
                  else_=1))
    ).limit(limit).all()
    
    results = []
    for finding, repo_name, is_archived, visibility, file_commit_date, file_commit_author in findings:
        results.append({
            "id": str(finding.id),
            "title": finding.title,
            "severity": finding.severity,
            "repo_name": repo_name,
            "repository_id": str(finding.repository_id),
            "file_path": finding.file_path,
            "line_start": finding.line_start,
            "code_snippet": finding.code_snippet[:100] if finding.code_snippet else None,
            "visibility": visibility,
            "is_archived": is_archived,
            "file_last_commit_at": file_commit_date,
            "file_last_commit_author": file_commit_author,
            "first_seen_at": finding.first_seen_at
        })
    
    return {
        "secret_type": secret_type,
        "total": len(results),
        "findings": results
    }


# =============================================================================
# 2. ABANDONED REPOSITORY DETECTION
# =============================================================================

def calculate_abandonment_score(
    days_since_push: Optional[int],
    is_archived: bool,
    active_contributors: int,
    total_contributors: int,
    has_ci: bool = False  # Could be enhanced later
) -> tuple[int, List[str]]:
    """Calculate abandonment risk score (0-100) and reasons."""
    score = 0
    reasons = []
    
    # No push in a long time
    if days_since_push is not None:
        if days_since_push > 1095:  # 3+ years
            score += 40
            reasons.append(f"No commits in {days_since_push // 365} years")
        elif days_since_push > 730:  # 2+ years
            score += 30
            reasons.append(f"No commits in {days_since_push // 365} years")
        elif days_since_push > 365:  # 1+ year
            score += 20
            reasons.append(f"No commits in {days_since_push} days")
        elif days_since_push > 180:
            score += 10
            reasons.append(f"No commits in {days_since_push} days")
    
    # Archived
    if is_archived:
        score += 25
        reasons.append("Repository is archived")
    
    # Single contributor or no active contributors
    if total_contributors == 0:
        score += 15
        reasons.append("No contributors found")
    elif total_contributors == 1:
        score += 15
        reasons.append("Single contributor (bus factor = 1)")
    
    if active_contributors == 0 and total_contributors > 0:
        score += 15
        reasons.append("No active contributors in past year")
    elif active_contributors == 1 and total_contributors > 1:
        score += 10
        reasons.append("Only 1 active contributor")
    
    return min(score, 100), reasons


@router.get("/abandoned", response_model=List[AbandonedRepo], dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get repositories with high abandonment risk",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_abandoned_repos(
    db: Session = Depends(get_tenant_db),
    min_score: int = Query(default=30, ge=0, le=100),
    min_days_inactive: int = Query(default=365),
    include_archived: bool = True,
    has_findings: bool = Query(default=None, description="Filter to repos with findings"),
    limit: int = Query(default=50, le=200)
):
    """
    Get repositories with high abandonment risk scores.
    
    Abandoned repositories are attractive to attackers because:
    - Security issues won't be fixed
    - May have credentials that are still valid
    - Provide reconnaissance about organization
    """
    now = datetime.utcnow()
    cutoff_date = now - timedelta(days=min_days_inactive)
    
    # Get repos with their stats
    repos_query = db.query(
        models.Repository,
        func.count(models.Finding.id).filter(models.Finding.status == 'open').label('open_findings'),
        func.count(models.Finding.id).filter(
            and_(models.Finding.status == 'open', models.Finding.severity == 'critical')
        ).label('critical_findings')
    ).outerjoin(
        models.Finding, models.Repository.id == models.Finding.repository_id
    ).group_by(models.Repository.id)
    
    # Filter by last push date
    repos_query = repos_query.filter(
        or_(
            models.Repository.pushed_at < cutoff_date,
            models.Repository.pushed_at.is_(None)
        )
    )
    
    if not include_archived:
        repos_query = repos_query.filter(models.Repository.is_archived == False)
    
    results = []
    for repo, open_findings, critical_findings in repos_query.all():
        # Get contributor counts
        total_contributors = db.query(models.Contributor).filter(
            models.Contributor.repository_id == repo.id
        ).count()
        
        active_contributors = db.query(models.Contributor).filter(
            models.Contributor.repository_id == repo.id,
            models.Contributor.last_commit_at > (now - timedelta(days=365))
        ).count()
        
        # Calculate days since push
        days_since_push = None
        if repo.pushed_at:
            days_since_push = (now - repo.pushed_at).days
        
        # Calculate abandonment score
        score, reasons = calculate_abandonment_score(
            days_since_push=days_since_push,
            is_archived=repo.is_archived or False,
            active_contributors=active_contributors,
            total_contributors=total_contributors
        )
        
        if score < min_score:
            continue
        
        if has_findings is True and open_findings == 0:
            continue
        if has_findings is False and open_findings > 0:
            continue
        
        results.append(AbandonedRepo(
            id=str(repo.id),
            name=repo.name,
            url=repo.url,
            description=repo.description,
            language=repo.language,
            pushed_at=repo.pushed_at,
            github_created_at=repo.github_created_at,
            is_archived=repo.is_archived or False,
            visibility=repo.visibility,
            days_since_push=days_since_push,
            abandonment_score=score,
            abandonment_reasons=reasons,
            open_findings_count=open_findings or 0,
            critical_findings_count=critical_findings or 0,
            contributor_count=total_contributors,
            active_contributors_count=active_contributors
        ))
    
    # Sort by score descending, then by critical findings
    results.sort(key=lambda x: (x.abandonment_score, x.critical_findings_count), reverse=True)
    
    return results[:limit]


# =============================================================================
# 3. STALE CONTRIBUTOR DETECTION
# =============================================================================

@router.get("/stale-contributors", response_model=List[StaleContributor], dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get inactive contributors across the organization",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_stale_contributors(
    db: Session = Depends(get_tenant_db),
    min_days_inactive: int = Query(default=90, description="Minimum days since last commit to ANY repo"),
    min_commits: int = Query(default=1, description="Minimum total commits to be considered significant"),
    has_findings: bool = Query(default=None, description="Filter to contributors who touched files with findings"),
    limit: int = Query(default=100, le=500)
):
    """
    Get contributors with no recent activity across the entire organization.
    
    This identifies people who haven't committed to ANY repo in the past N days,
    aggregating their activity across all repositories they've contributed to.
    
    Stale contributors are a risk because:
    - May have left the organization but still have access
    - Knowledge of vulnerable code is no longer available
    - Their code may not be maintained
    """
    now = datetime.utcnow()
    cutoff_date = now - timedelta(days=min_days_inactive)
    
    # First, get ALL contributors with their repo info (no date filter yet)
    all_contributors = db.query(
        models.Contributor,
        models.Repository.name.label('repo_name')
    ).join(
        models.Repository, models.Contributor.repository_id == models.Repository.id
    ).filter(
        models.Contributor.commits >= 1  # At least 1 commit
    ).all()
    
    # Aggregate ALL contributors by email first to find their global last_commit_at
    contributor_map = {}  # email -> aggregated data
    
    for contributor, repo_name in all_contributors:
        # Use email as unique key, fall back to name if no email
        key = (contributor.email or contributor.name).lower().strip()
        
        # Calculate files with findings for this contributor
        files_with_findings = 0
        critical_files = 0
        
        if contributor.files_contributed:
            for file_info in contributor.files_contributed:
                if isinstance(file_info, dict):
                    findings_count = file_info.get('findings_count', 0)
                    if findings_count > 0:
                        files_with_findings += 1
                        if file_info.get('severity') == 'critical':
                            critical_files += 1
        
        if key not in contributor_map:
            contributor_map[key] = {
                'id': str(contributor.id),
                'name': contributor.name,
                'email': contributor.email,
                'github_username': contributor.github_username,
                'repo_names': [repo_name],
                'total_commits': contributor.commits or 0,
                'last_commit_at': contributor.last_commit_at,  # Will track the MOST RECENT across all repos
                'files_with_findings': files_with_findings,
                'critical_files_count': critical_files,
            }
        else:
            # Aggregate data
            existing = contributor_map[key]
            if repo_name not in existing['repo_names']:
                existing['repo_names'].append(repo_name)
            existing['total_commits'] += (contributor.commits or 0)
            existing['files_with_findings'] += files_with_findings
            existing['critical_files_count'] += critical_files
            
            # Track the MOST RECENT commit date across ALL repos
            if contributor.last_commit_at:
                if existing['last_commit_at'] is None or contributor.last_commit_at > existing['last_commit_at']:
                    existing['last_commit_at'] = contributor.last_commit_at
            
            # Prefer github_username if found
            if contributor.github_username and not existing['github_username']:
                existing['github_username'] = contributor.github_username
    
    # Convert contributor_map to list and deduplicate identities
    raw_contributors = list(contributor_map.values())
    logger.info(f"Before deduplication: {len(raw_contributors)} unique email/name keys")
    
    deduplicated = deduplicate_contributors(raw_contributors)
    logger.info(f"After deduplication: {len(deduplicated)} unique contributors")
    
    # Now filter to only stale contributors (no commit to ANY repo in past N days)
    results = []
    for data in deduplicated:
        # Skip if they have recent activity (committed to ANY repo recently)
        if data['last_commit_at'] and data['last_commit_at'] >= cutoff_date:
            continue
        
        # Skip if below minimum commits threshold
        if data['total_commits'] < min_commits:
            continue
        
        # Skip if filtering by has_findings
        if has_findings is True and data['files_with_findings'] == 0:
            continue
        if has_findings is False and data['files_with_findings'] > 0:
            continue
        
        # Calculate days since last commit (to ANY repo)
        days_since_commit = None
        if data['last_commit_at']:
            days_since_commit = (now - data['last_commit_at']).days
        
        # Calculate risk score
        risk_score = 0
        # More repos = higher risk (more code knowledge lost)
        risk_score += min(len(data.get('repo_names', [])) * 3, 20)
        # More commits = higher risk (more institutional knowledge)
        risk_score += min(data['total_commits'] // 10, 20)
        
        if days_since_commit:
            if days_since_commit > 365:
                risk_score += 30
            elif days_since_commit > 180:
                risk_score += 20
            elif days_since_commit > 90:
                risk_score += 10
        
        risk_score += min(data['files_with_findings'] * 5, 15)
        risk_score += min(data['critical_files_count'] * 10, 15)
        
        # Include merged identity count if available
        merged_count = data.get('merged_identities', 1)
        all_emails = data.get('all_emails')
        
        results.append(StaleContributor(
            id=data['id'],
            name=data['name'],
            email=data['email'],
            github_username=data.get('github_username'),
            total_repos=len(data.get('repo_names', [])),
            repo_names=sorted(set(data.get('repo_names', [])))[:10],  # Limit to 10 repos for display
            total_commits=data['total_commits'],
            last_commit_at=data['last_commit_at'],
            days_since_last_commit=days_since_commit,
            files_with_findings=data['files_with_findings'],
            critical_files_count=data['critical_files_count'],
            risk_score=min(risk_score, 100),
            merged_identities=merged_count,
            all_emails=all_emails if merged_count > 1 else None
        ))
    
    # Sort by risk score descending, then by days inactive, then by total_repos
    results.sort(key=lambda x: (x.risk_score, x.days_since_last_commit or 0, x.total_repos), reverse=True)
    
    return results[:limit]


# =============================================================================
# 4. PUBLIC EXPOSURE DETECTION
# =============================================================================

@router.get("/public-exposure", response_model=List[PublicExposure], dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get public repositories with exposure risks",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_public_exposures(
    db: Session = Depends(get_tenant_db),
    include_archived: bool = False,
    min_risk: str = Query(default=None, description="Filter by minimum risk level: low, medium, high, critical"),
    limit: int = Query(default=50, le=200)
):
    """
    Get repositories with public exposure risks.
    
    Public repositories are high-risk because:
    - Secrets may be exposed to anyone
    - Attack surface is visible to adversaries
    - Vulnerable code can be studied for exploits
    """
    # Get public repos
    repos_query = db.query(
        models.Repository,
        func.count(models.Finding.id).filter(models.Finding.status == 'open').label('open_findings'),
        func.count(models.Finding.id).filter(
            and_(models.Finding.status == 'open', models.Finding.severity == 'critical')
        ).label('critical_findings'),
        func.count(models.Finding.id).filter(
            and_(models.Finding.status == 'open', models.Finding.scanner_name == 'trufflehog')
        ).label('secrets_count')
    ).outerjoin(
        models.Finding, models.Repository.id == models.Finding.repository_id
    ).filter(
        models.Repository.visibility == 'public'
    ).group_by(models.Repository.id)
    
    if not include_archived:
        repos_query = repos_query.filter(models.Repository.is_archived == False)
    
    results = []
    for repo, open_findings, critical_findings, secrets_count in repos_query.all():
        # Calculate exposure risk
        risk_factors = []
        risk_score = 0
        
        # Public visibility is base risk
        risk_factors.append("Repository is publicly accessible")
        risk_score += 20
        
        # Secrets in public repo = critical
        if secrets_count > 0:
            risk_factors.append(f"{secrets_count} secrets/credentials exposed")
            risk_score += 40
        
        # Critical findings
        if critical_findings > 0:
            risk_factors.append(f"{critical_findings} critical vulnerabilities")
            risk_score += 25
        elif open_findings > 0:
            risk_factors.append(f"{open_findings} open findings")
            risk_score += 15
        
        # Determine risk level
        if risk_score >= 60:
            exposure_risk = 'critical'
        elif risk_score >= 40:
            exposure_risk = 'high'
        elif risk_score >= 25:
            exposure_risk = 'medium'
        else:
            exposure_risk = 'low'
        
        # Filter by minimum risk
        risk_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        if min_risk and risk_order.get(exposure_risk, 0) < risk_order.get(min_risk, 0):
            continue
        
        results.append(PublicExposure(
            id=str(repo.id),
            name=repo.name,
            url=repo.url,
            description=repo.description,
            visibility=repo.visibility or 'public',
            is_archived=repo.is_archived or False,
            pushed_at=repo.pushed_at,
            open_findings_count=open_findings or 0,
            critical_findings_count=critical_findings or 0,
            secrets_count=secrets_count or 0,
            exposure_risk=exposure_risk,
            risk_factors=risk_factors
        ))
    
    # Sort by risk level, then secrets count
    risk_priority = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
    results.sort(key=lambda x: (risk_priority.get(x.exposure_risk, 0), x.secrets_count), reverse=True)
    
    return results[:limit]


# =============================================================================
# HIGH RISK REPOS
# =============================================================================

@router.get("/high-risk-repos", response_model=List[HighRiskRepo], dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get high-risk repositories by attack surface analysis",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_high_risk_repos(
    db: Session = Depends(get_tenant_db),
    limit: int = Query(200, ge=1, le=200),
    offset: int = Query(0, ge=0)
):
    """
    Get high-risk repositories based on attack surface analysis.
    
    High-risk repos are defined as:
    - Public repos with exposed secrets (trufflehog findings)
    - Abandoned/archived repos with critical findings
    - Repos with high risk scores based on multiple factors
    """
    now = datetime.utcnow()
    one_year_ago = now - timedelta(days=365)
    
    # Get repos with secrets from trufflehog scans
    repos_with_secrets = db.query(
        models.Repository.id,
        func.count(models.Finding.id).label('secrets_count')
    ).outerjoin(
        models.Finding,
        and_(
            models.Finding.repository_id == models.Repository.id,
            models.Finding.scanner_name == 'trufflehog'
        )
    ).group_by(models.Repository.id).subquery()
    
    # Get findings counts by severity
    findings_by_severity = db.query(
        models.Finding.repository_id,
        func.count(case((models.Finding.severity == 'critical', 1))).label('critical_count'),
        func.count(case((models.Finding.severity == 'high', 1))).label('high_count'),
        func.count(models.Finding.id).label('total_count')
    ).filter(
        models.Finding.status.in_(['open', 'confirmed'])
    ).group_by(models.Finding.repository_id).subquery()
    
    # Get contributor counts
    contributor_counts = db.query(
        models.Contributor.repository_id,
        func.count(func.distinct(models.Contributor.id)).label('contributors')
    ).group_by(models.Contributor.repository_id).subquery()
    
    # Main query
    query = db.query(
        models.Repository,
        func.coalesce(repos_with_secrets.c.secrets_count, 0).label('secrets_count'),
        func.coalesce(findings_by_severity.c.critical_count, 0).label('critical_count'),
        func.coalesce(findings_by_severity.c.high_count, 0).label('high_count'),
        func.coalesce(findings_by_severity.c.total_count, 0).label('total_count'),
        func.coalesce(contributor_counts.c.contributors, 0).label('contributors_count')
    ).outerjoin(
        repos_with_secrets,
        repos_with_secrets.c.id == models.Repository.id
    ).outerjoin(
        findings_by_severity,
        findings_by_severity.c.repository_id == models.Repository.id
    ).outerjoin(
        contributor_counts,
        contributor_counts.c.repository_id == models.Repository.id
    )
    
    # Filter for high-risk repos:
    # 1. Public repos with secrets
    # 2. Abandoned repos (no activity > 1 year) with critical findings
    # 3. Archived repos with critical findings
    # 4. Any repo with critical findings and secrets
    query = query.filter(
        or_(
            # Public with secrets
            and_(
                models.Repository.visibility == 'public',
                repos_with_secrets.c.secrets_count > 0
            ),
            # Abandoned with critical findings
            and_(
                models.Repository.pushed_at < one_year_ago,
                findings_by_severity.c.critical_count > 0
            ),
            # Archived with critical findings
            and_(
                models.Repository.is_archived == True,
                findings_by_severity.c.critical_count > 0
            ),
            # Any repo with both secrets and critical findings
            and_(
                repos_with_secrets.c.secrets_count > 0,
                findings_by_severity.c.critical_count > 0
            )
        )
    )
    
    results = []
    for row in query.all():
        repo = row[0]
        secrets_count = row[1] or 0
        critical_count = row[2] or 0
        high_count = row[3] or 0
        total_count = row[4] or 0
        contributors = row[5] or 0
        
        # Calculate days since activity
        days_since_activity = None
        if repo.pushed_at:
            days_since_activity = (now - repo.pushed_at).days
        
        is_abandoned = days_since_activity is not None and days_since_activity > 365
        
        # Calculate risk factors
        risk_factors = []
        risk_score = 0
        
        # Public exposure with secrets
        if repo.visibility == 'public' and secrets_count > 0:
            risk_factors.append(f"Public repo with {secrets_count} exposed secret(s)")
            risk_score += 40
        
        # Critical findings
        if critical_count > 0:
            risk_factors.append(f"{critical_count} critical finding(s)")
            risk_score += min(30, critical_count * 10)
        
        # High findings
        if high_count > 0:
            risk_factors.append(f"{high_count} high severity finding(s)")
            risk_score += min(15, high_count * 3)
        
        # Abandoned
        if is_abandoned:
            risk_factors.append(f"Abandoned ({days_since_activity} days since last activity)")
            risk_score += 15
        
        # Archived with issues
        if repo.is_archived and (critical_count > 0 or secrets_count > 0):
            risk_factors.append("Archived with unresolved issues")
            risk_score += 10
        
        # Secrets present
        if secrets_count > 0 and repo.visibility != 'public':
            risk_factors.append(f"{secrets_count} secret(s) detected")
            risk_score += 15
        
        # Cap at 100
        risk_score = min(100, risk_score)
        
        # Determine risk level
        if risk_score >= 70:
            risk_level = 'critical'
        elif risk_score >= 50:
            risk_level = 'high'
        elif risk_score >= 30:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        results.append(HighRiskRepo(
            id=str(repo.id),
            name=repo.name,
            url=repo.url,
            description=repo.description,
            visibility=repo.visibility or 'unknown',
            is_archived=repo.is_archived or False,
            is_abandoned=is_abandoned,
            last_commit_date=repo.pushed_at,
            days_since_activity=days_since_activity,
            open_findings_count=total_count,
            critical_findings_count=critical_count,
            high_findings_count=high_count,
            secrets_count=secrets_count,
            risk_score=risk_score,
            risk_level=risk_level,
            risk_factors=risk_factors,
            primary_language=repo.language,
            contributors_count=contributors
        ))
    
    # Sort by risk score descending
    results.sort(key=lambda x: x.risk_score, reverse=True)
    
    return results[offset:offset + limit]


# =============================================================================
# ATTACK SURFACE SUMMARY
# =============================================================================

@router.get("/summary", response_model=AttackSurfaceSummary, dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get overall attack surface summary",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_attack_surface_summary(db: Session = Depends(get_tenant_db)):
    """
    Get overall attack surface summary for the executive dashboard.
    Aggregates repository counts, findings, secrets, stale contributors, and risk metrics.
    Requires findings:read permission.
    """
    now = datetime.utcnow()
    one_year_ago = now - timedelta(days=365)
    ninety_days_ago = now - timedelta(days=90)
    
    # Total repos
    total_repos = db.query(models.Repository).count()
    
    # Public repos
    public_repos = db.query(models.Repository).filter(
        models.Repository.visibility == 'public'
    ).count()
    
    # Archived repos
    archived_repos = db.query(models.Repository).filter(
        models.Repository.is_archived == True
    ).count()
    
    # Abandoned repos (no push in 1+ year or archived)
    abandoned_repos = db.query(models.Repository).filter(
        or_(
            models.Repository.pushed_at < one_year_ago,
            models.Repository.pushed_at.is_(None),
            models.Repository.is_archived == True
        )
    ).count()
    
    # Total findings
    total_findings = db.query(models.Finding).filter(
        models.Finding.status == 'open'
    ).count()
    
    # Total secrets (TruffleHog)
    total_secrets = db.query(models.Finding).filter(
        models.Finding.scanner_name == 'trufflehog',
        models.Finding.status == 'open'
    ).count()
    
    # Hardcoded assets (Semgrep HTTP/URL findings)
    total_hardcoded = db.query(models.Finding).filter(
        models.Finding.scanner_name == 'semgrep',
        models.Finding.status == 'open',
        or_(
            models.Finding.title.ilike('%http%'),
            models.Finding.title.ilike('%url%')
        )
    ).count()
    
    # Stale contributors (no commits to ANY repo in past 90 days, with deduplication)
    # Use the same logic as the stale-contributors endpoint for accurate count
    all_contributors = db.query(
        models.Contributor,
        models.Repository.name.label('repo_name')
    ).join(
        models.Repository, models.Contributor.repository_id == models.Repository.id
    ).filter(
        models.Contributor.commits >= 1
    ).all()
    
    # Build contributor map (aggregate by email/name)
    contributor_map_summary = {}
    for contributor, repo_name in all_contributors:
        key = (contributor.email or contributor.name).lower().strip()
        if key not in contributor_map_summary:
            contributor_map_summary[key] = {
                'id': str(contributor.id),
                'name': contributor.name,
                'email': contributor.email,
                'github_username': contributor.github_username,
                'repo_names': [repo_name],
                'total_commits': contributor.commits or 0,
                'last_commit_at': contributor.last_commit_at,
                'files_with_findings': 0,
                'critical_files_count': 0,
            }
        else:
            existing = contributor_map_summary[key]
            if repo_name not in existing['repo_names']:
                existing['repo_names'].append(repo_name)
            existing['total_commits'] += (contributor.commits or 0)
            if contributor.last_commit_at:
                if existing['last_commit_at'] is None or contributor.last_commit_at > existing['last_commit_at']:
                    existing['last_commit_at'] = contributor.last_commit_at
    
    # Apply deduplication
    deduplicated_summary = deduplicate_contributors(list(contributor_map_summary.values()))
    
    # Count stale contributors (no commit in 90 days)
    stale_contributors = sum(
        1 for c in deduplicated_summary
        if c['last_commit_at'] is None or c['last_commit_at'] < ninety_days_ago
    )
    
    # High risk repos - use same logic as /high-risk-repos endpoint
    # Get repos with secrets (trufflehog)
    repos_with_secrets_sub = db.query(
        models.Finding.repository_id,
        func.count(models.Finding.id).label('secrets_count')
    ).filter(
        models.Finding.scanner_name == 'trufflehog'
    ).group_by(models.Finding.repository_id).subquery()
    
    # Get repos with critical findings
    repos_with_critical_sub = db.query(
        models.Finding.repository_id,
        func.count(models.Finding.id).label('critical_count')
    ).filter(
        models.Finding.status.in_(['open', 'confirmed']),
        models.Finding.severity == 'critical'
    ).group_by(models.Finding.repository_id).subquery()
    
    # Count high-risk repos matching any of the criteria
    high_risk_repos = db.query(models.Repository).outerjoin(
        repos_with_secrets_sub,
        repos_with_secrets_sub.c.repository_id == models.Repository.id
    ).outerjoin(
        repos_with_critical_sub,
        repos_with_critical_sub.c.repository_id == models.Repository.id
    ).filter(
        or_(
            # Public with secrets
            and_(
                models.Repository.visibility == 'public',
                repos_with_secrets_sub.c.secrets_count > 0
            ),
            # Abandoned with critical findings
            and_(
                models.Repository.pushed_at < one_year_ago,
                repos_with_critical_sub.c.critical_count > 0
            ),
            # Archived with critical findings
            and_(
                models.Repository.is_archived == True,
                repos_with_critical_sub.c.critical_count > 0
            ),
            # Any repo with both secrets and critical findings
            and_(
                repos_with_secrets_sub.c.secrets_count > 0,
                repos_with_critical_sub.c.critical_count > 0
            )
        )
    ).distinct().count()
    
    # Active investigations (triage or incident_response status)
    active_investigations = db.query(models.Finding).filter(
        models.Finding.investigation_status.in_(['triage', 'incident_response'])
    ).count()
    
    return AttackSurfaceSummary(
        total_repos=total_repos,
        public_repos=public_repos,
        archived_repos=archived_repos,
        abandoned_repos=abandoned_repos,
        total_findings=total_findings,
        total_secrets=total_secrets,
        total_hardcoded_assets=total_hardcoded,
        stale_contributors=stale_contributors,
        high_risk_repos=high_risk_repos,
        active_investigations=active_investigations
    )


# =============================================================================
# INCIDENT RESPONSE FINDINGS
# =============================================================================

@router.get("/incident-response", response_model=List[IRFinding], dependencies=[Depends(require_permissions("findings:read"))],
    summary="Get findings under active investigation",
    responses={401: {"description": "Not authenticated"}, 403: {"description": "Insufficient permissions - requires findings:read"}})
def get_ir_findings(
    limit: int = Query(200, description="Maximum number of findings to return"),
    db: Session = Depends(get_tenant_db)
):
    """
    Get all findings currently under investigation (triage or incident_response status).
    Includes journal entry counts and last journal dates for each finding.
    Requires findings:read permission.
    """
    # Query findings with active investigation status
    findings = db.query(models.Finding).join(
        models.Repository, models.Finding.repository_id == models.Repository.id
    ).filter(
        models.Finding.investigation_status.in_(['triage', 'incident_response'])
    ).order_by(
        # Order by status (incident_response first), then by start date
        case(
            (models.Finding.investigation_status == 'incident_response', 1),
            (models.Finding.investigation_status == 'triage', 2),
            else_=3
        ),
        models.Finding.investigation_started_at.desc()
    ).limit(limit).all()
    
    # Get journal counts for each finding
    finding_ids = [f.id for f in findings]
    journal_counts = {}
    last_journal_dates = {}
    
    if finding_ids:
        # Get count and last entry date per finding
        journal_stats = db.query(
            models.JournalEntry.finding_id,
            func.count(models.JournalEntry.id).label('count'),
            func.max(models.JournalEntry.created_at).label('last_at')
        ).filter(
            models.JournalEntry.finding_id.in_(finding_ids)
        ).group_by(models.JournalEntry.finding_id).all()
        
        for stat in journal_stats:
            journal_counts[stat.finding_id] = stat.count
            last_journal_dates[stat.finding_id] = stat.last_at
    
    return [IRFinding(
        id=str(f.finding_uuid),
        title=f.title,
        severity=f.severity,
        investigation_status=f.investigation_status,
        investigation_started_at=f.investigation_started_at,
        scanner_name=f.scanner_name,
        repo_name=f.repository.name if f.repository else "Unknown",
        repository_id=str(f.repository.id) if f.repository else None,
        file_path=f.file_path,
        journal_count=journal_counts.get(f.id, 0),
        last_journal_at=last_journal_dates.get(f.id)
    ) for f in findings]
