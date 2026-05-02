"""
WAF (Web Application Firewall) API Router

Serves WAF findings (static Terraform analysis + live AWS audit) to the frontend UI.
Provides dashboard summary, paginated findings, drift detection, and AI-powered
analysis for WAF rule remediation.
"""

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from sqlalchemy import func, case, and_
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from datetime import datetime
from uuid import UUID
import logging

from ..dependencies import get_tenant_db
from .. import models
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# WAF severity model — domain-specific severity that maps to traditional levels
# ---------------------------------------------------------------------------

WAF_SEVERITY_MAP: Dict[str, Dict[str, str]] = {
    "active_risk": {
        "label": "Active Risk",
        "color": "#dc2626",
        "icon": "shield-alert",
        "description": "Live misconfiguration, exploitable now",
        "traditional": "critical",
    },
    "code_risk": {
        "label": "Code Risk",
        "color": "#ea580c",
        "icon": "code",
        "description": "Deployable misconfiguration in Terraform",
        "traditional": "high",
    },
    "drift_risk": {
        "label": "Drift Risk",
        "color": "#d97706",
        "icon": "git-compare",
        "description": "Code and live AWS config diverge",
        "traditional": "medium",
    },
    "informational": {
        "label": "Informational",
        "color": "#2563eb",
        "icon": "info",
        "description": "Best practice recommendation",
        "traditional": "low",
    },
}

WAF_SCANNER_NAMES = ["waf-static", "waf-auditor"]

# ---------------------------------------------------------------------------
# Pydantic response models
# ---------------------------------------------------------------------------


class SeverityMeta(BaseModel):
    """WAF-specific severity metadata for frontend display."""
    label: str = Field(..., description="Human-readable severity label")
    color: str = Field(..., description="Hex color code for UI rendering")
    icon: str = Field(..., description="Icon name (Lucide icon set)")
    description: str = Field(..., description="One-line explanation of this severity")
    traditional: str = Field(..., description="Mapped traditional severity (critical/high/medium/low)")


class WAFSummaryResponse(BaseModel):
    """Dashboard-level WAF summary statistics."""
    total_findings: int = Field(..., description="Total number of WAF findings")
    by_severity: Dict[str, int] = Field(
        ..., description="Finding count keyed by WAF severity (active_risk, code_risk, drift_risk, informational)"
    )
    by_source: Dict[str, int] = Field(
        ..., description="Finding count keyed by source (static, live, drift)"
    )
    by_rule_type: Dict[str, int] = Field(
        ..., description="Finding count keyed by WAF rule type (permanent_block, rate_limit, mode, etc.)"
    )
    web_acls_analyzed: int = Field(..., description="Number of distinct WebACLs analyzed")
    has_static_scan: bool = Field(..., description="Whether at least one static scan exists")
    has_live_audit: bool = Field(..., description="Whether at least one live audit exists")
    last_static_scan: Optional[datetime] = Field(None, description="Timestamp of most recent static scan")
    last_live_audit: Optional[datetime] = Field(None, description="Timestamp of most recent live audit")


class WAFFindingResponse(BaseModel):
    """Single WAF finding with enriched metadata."""
    id: str = Field(..., description="Finding UUID")
    severity: str = Field(..., description="WAF severity key (active_risk, code_risk, drift_risk, informational)")
    severity_meta: SeverityMeta = Field(..., description="Display metadata for the severity level")
    source: str = Field(..., description="Finding source: static, live, or drift")
    rule_type: Optional[str] = Field(None, description="WAF rule type (permanent_block, rate_limit, mode, etc.)")
    title: str = Field(..., description="Finding title")
    description: Optional[str] = Field(None, description="Detailed finding description")
    web_acl_name: Optional[str] = Field(None, description="Name of the WebACL this finding relates to")
    rule_name: Optional[str] = Field(None, description="Name of the specific WAF rule")
    file_path: Optional[str] = Field(None, description="Terraform file path (static findings)")
    line_start: Optional[int] = Field(None, description="Start line in the file")
    line_end: Optional[int] = Field(None, description="End line in the file")
    code_snippet: Optional[str] = Field(None, description="Relevant code snippet")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation text")
    remediation_terraform: Optional[str] = Field(None, description="Suggested Terraform remediation code")
    status: str = Field(..., description="Finding status (open, resolved, etc.)")
    created_at: datetime = Field(..., description="When the finding was created")


class PaginatedWAFFindingsResponse(BaseModel):
    """Paginated list of WAF findings."""
    findings: List[WAFFindingResponse] = Field(..., description="Page of WAF findings")
    total: int = Field(..., description="Total findings matching the filters")
    page: int = Field(..., description="Current page number (1-based)")
    per_page: int = Field(..., description="Items per page")


class WAFFindingDetailResponse(WAFFindingResponse):
    """Full WAF finding detail including raw risk_factors."""
    risk_factors: Optional[Dict[str, Any]] = Field(
        None, description="Raw risk_factors JSONB data with all WAF metadata"
    )
    ai_remediation_text: Optional[str] = Field(None, description="AI-generated remediation guidance")
    ai_remediation_diff: Optional[str] = Field(None, description="AI-generated code diff")
    scanner_name: str = Field(..., description="Scanner that produced this finding (waf-static or waf-auditor)")
    finding_type: Optional[str] = Field(None, description="Finding type classification")
    cwe_id: Optional[str] = Field(None, description="CWE identifier if applicable")


class DriftItem(BaseModel):
    """A single attribute that differs between code and live."""
    rule_name: str = Field(..., description="WAF rule name where drift was detected")
    attribute: str = Field(..., description="Attribute that differs (e.g., action, priority)")
    code_value: Optional[str] = Field(None, description="Value in Terraform code")
    live_value: Optional[str] = Field(None, description="Value in live AWS configuration")
    severity: str = Field("drift_risk", description="Severity classification for this drift")
    description: str = Field(..., description="Human-readable drift description")


class WebACLDrift(BaseModel):
    """Drift analysis for a single WebACL."""
    name: str = Field(..., description="WebACL name")
    in_code: bool = Field(..., description="Whether this WebACL exists in Terraform code")
    in_live: bool = Field(..., description="Whether this WebACL exists in live AWS")
    drift_items: List[DriftItem] = Field(default_factory=list, description="Specific drift items found")
    code_only_rules: List[str] = Field(default_factory=list, description="Rules only in code, not live")
    live_only_rules: List[str] = Field(default_factory=list, description="Rules only in live, not code")


class DriftResponse(BaseModel):
    """Drift comparison between static Terraform and live AWS WAF configuration."""
    web_acls: List[WebACLDrift] = Field(default_factory=list, description="Per-WebACL drift analysis")
    has_live_audit: bool = Field(..., description="Whether live audit data is available for comparison")


class AskAIRequest(BaseModel):
    """Request body for the AI analysis endpoint."""
    finding_id: str = Field(..., description="UUID of the finding to analyze")
    question: Optional[str] = Field(None, description="Optional custom question to ask about the finding")


class AskAIResponse(BaseModel):
    """AI-generated analysis of a WAF finding."""
    analysis: str = Field(..., description="Markdown-formatted AI explanation")
    remediation_code: Optional[str] = Field(None, description="Suggested Terraform remediation code block")
    confidence: float = Field(..., description="AI confidence score (0.0-1.0)")


class RuleReplacementRequest(BaseModel):
    """Request body for the AI rule replacement endpoint."""
    finding_id: str = Field(..., description="UUID of the finding to generate replacement for")


class RuleReplacementResponse(BaseModel):
    """AI-generated adaptive rule replacement."""
    original_code: str = Field(..., description="Original Terraform HCL code")
    replacement_code: str = Field(..., description="Suggested replacement HCL code")
    explanation: str = Field(..., description="Markdown explanation of changes made")
    changes_summary: List[str] = Field(
        ..., description="Bullet-point summary of each change (e.g., 'Added rate-based threshold of 500/5min')"
    )


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/projects/{project_id}/waf",
    tags=["waf"],
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _get_waf_findings_query(db: Session, project_id: str):
    """Base query for WAF findings scoped to a project (repository)."""
    return db.query(models.Finding).filter(
        models.Finding.repository_id == project_id,
        models.Finding.scanner_name.in_(WAF_SCANNER_NAMES),
    )


def _extract_risk_factor(finding: models.Finding, key: str, default=None):
    """Safely extract a value from the risk_factors JSONB column."""
    rf = finding.risk_factors
    if rf and isinstance(rf, dict):
        return rf.get(key, default)
    return default


def _waf_severity(finding: models.Finding) -> str:
    """Determine the WAF severity for a finding.

    Checks risk_factors['waf_severity'] first, then falls back to mapping
    the traditional severity column to the WAF severity domain.
    """
    waf_sev = _extract_risk_factor(finding, "waf_severity")
    if waf_sev and waf_sev in WAF_SEVERITY_MAP:
        return waf_sev

    # Fallback: map traditional severity to WAF severity
    traditional_map = {
        "critical": "active_risk",
        "high": "code_risk",
        "medium": "drift_risk",
        "low": "informational",
        "info": "informational",
    }
    return traditional_map.get((finding.severity or "").lower(), "informational")


def _finding_source(finding: models.Finding) -> str:
    """Determine the source (static/live/drift) for a finding."""
    source = _extract_risk_factor(finding, "source")
    if source:
        return source
    # Infer from scanner_name
    if finding.scanner_name == "waf-static":
        return "static"
    elif finding.scanner_name == "waf-auditor":
        return "live"
    return "unknown"


def _severity_meta(waf_sev: str) -> SeverityMeta:
    """Get SeverityMeta for a WAF severity key, defaulting to informational."""
    meta = WAF_SEVERITY_MAP.get(waf_sev, WAF_SEVERITY_MAP["informational"])
    return SeverityMeta(**meta)


def _serialize_finding(finding: models.Finding) -> WAFFindingResponse:
    """Convert a Finding ORM instance into a WAFFindingResponse."""
    waf_sev = _waf_severity(finding)
    return WAFFindingResponse(
        id=str(finding.id),
        severity=waf_sev,
        severity_meta=_severity_meta(waf_sev),
        source=_finding_source(finding),
        rule_type=_extract_risk_factor(finding, "rule_type"),
        title=finding.title,
        description=finding.description,
        web_acl_name=_extract_risk_factor(finding, "web_acl_name"),
        rule_name=_extract_risk_factor(finding, "rule_name"),
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
        recommendation=finding.ai_remediation_text,
        remediation_terraform=_extract_risk_factor(finding, "remediation_terraform"),
        status=finding.status or "open",
        created_at=finding.created_at or datetime.utcnow(),
    )


def _get_llm_provider():
    """Get the LLM provider, returning None if not configured."""
    try:
        from src.services.llm_provider import get_llm_provider
        return get_llm_provider()
    except Exception as e:
        logger.warning(f"LLM provider not available: {e}")
        return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get(
    "/summary",
    response_model=WAFSummaryResponse,
    summary="WAF dashboard summary",
    description="Returns aggregate WAF statistics for the project dashboard.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def get_waf_summary(
    project_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> WAFSummaryResponse:
    """Return WAF dashboard summary for a project."""
    findings = _get_waf_findings_query(db, project_id).all()

    # Aggregate counts
    by_severity: Dict[str, int] = {k: 0 for k in WAF_SEVERITY_MAP}
    by_source: Dict[str, int] = {}
    by_rule_type: Dict[str, int] = {}
    web_acl_names: set = set()
    has_static = False
    has_live = False
    last_static: Optional[datetime] = None
    last_live: Optional[datetime] = None

    for f in findings:
        waf_sev = _waf_severity(f)
        by_severity[waf_sev] = by_severity.get(waf_sev, 0) + 1

        source = _finding_source(f)
        by_source[source] = by_source.get(source, 0) + 1

        rt = _extract_risk_factor(f, "rule_type")
        if rt:
            by_rule_type[rt] = by_rule_type.get(rt, 0) + 1

        acl = _extract_risk_factor(f, "web_acl_name")
        if acl:
            web_acl_names.add(acl)

        if f.scanner_name == "waf-static":
            has_static = True
            if f.created_at and (last_static is None or f.created_at > last_static):
                last_static = f.created_at
        elif f.scanner_name == "waf-auditor":
            has_live = True
            if f.created_at and (last_live is None or f.created_at > last_live):
                last_live = f.created_at

    return WAFSummaryResponse(
        total_findings=len(findings),
        by_severity=by_severity,
        by_source=by_source,
        by_rule_type=by_rule_type,
        web_acls_analyzed=len(web_acl_names),
        has_static_scan=has_static,
        has_live_audit=has_live,
        last_static_scan=last_static,
        last_live_audit=last_live,
    )


@router.get(
    "/findings",
    response_model=PaginatedWAFFindingsResponse,
    summary="List WAF findings",
    description="Returns a paginated, filterable list of WAF findings.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def list_waf_findings(
    project_id: str,
    severity: Optional[str] = Query(None, description="Filter by WAF severity (active_risk, code_risk, drift_risk, informational)"),
    source: Optional[str] = Query(None, description="Filter by source (static, live, drift)"),
    rule_type: Optional[str] = Query(None, description="Filter by WAF rule type"),
    web_acl: Optional[str] = Query(None, description="Filter by WebACL name"),
    page: int = Query(1, ge=1, description="Page number (1-based)"),
    per_page: int = Query(20, ge=1, le=100, description="Items per page (max 100)"),
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> PaginatedWAFFindingsResponse:
    """Return paginated WAF findings with optional filters."""
    # Fetch all WAF findings for filtering (JSONB filtering done in Python
    # for portability; could be pushed into SQL for large datasets).
    query = _get_waf_findings_query(db, project_id)

    # Pre-filter by scanner if source is known
    if source == "static":
        query = query.filter(models.Finding.scanner_name == "waf-static")
    elif source == "live":
        query = query.filter(models.Finding.scanner_name == "waf-auditor")

    all_findings = query.order_by(models.Finding.created_at.desc()).all()

    # Apply JSONB-level filters in Python
    filtered = []
    for f in all_findings:
        if severity and _waf_severity(f) != severity:
            continue
        if source == "drift" and _finding_source(f) != "drift":
            continue
        if rule_type and _extract_risk_factor(f, "rule_type") != rule_type:
            continue
        if web_acl and _extract_risk_factor(f, "web_acl_name") != web_acl:
            continue
        filtered.append(f)

    total = len(filtered)
    start = (page - 1) * per_page
    page_items = filtered[start : start + per_page]

    return PaginatedWAFFindingsResponse(
        findings=[_serialize_finding(f) for f in page_items],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get(
    "/findings/{finding_id}",
    response_model=WAFFindingDetailResponse,
    summary="WAF finding detail",
    description="Returns full detail for a single WAF finding including raw risk_factors.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Finding not found"},
    },
)
async def get_waf_finding(
    project_id: str,
    finding_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> WAFFindingDetailResponse:
    """Return full detail for a WAF finding."""
    finding = (
        _get_waf_findings_query(db, project_id)
        .filter(models.Finding.id == finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="WAF finding not found")

    waf_sev = _waf_severity(finding)
    return WAFFindingDetailResponse(
        id=str(finding.id),
        severity=waf_sev,
        severity_meta=_severity_meta(waf_sev),
        source=_finding_source(finding),
        rule_type=_extract_risk_factor(finding, "rule_type"),
        title=finding.title,
        description=finding.description,
        web_acl_name=_extract_risk_factor(finding, "web_acl_name"),
        rule_name=_extract_risk_factor(finding, "rule_name"),
        file_path=finding.file_path,
        line_start=finding.line_start,
        line_end=finding.line_end,
        code_snippet=finding.code_snippet,
        recommendation=finding.ai_remediation_text,
        remediation_terraform=_extract_risk_factor(finding, "remediation_terraform"),
        status=finding.status or "open",
        created_at=finding.created_at or datetime.utcnow(),
        risk_factors=finding.risk_factors,
        ai_remediation_text=finding.ai_remediation_text,
        ai_remediation_diff=finding.ai_remediation_diff,
        scanner_name=finding.scanner_name,
        finding_type=finding.finding_type,
        cwe_id=finding.cwe_id,
    )


@router.get(
    "/drift",
    response_model=DriftResponse,
    summary="WAF drift analysis",
    description="Cross-references static Terraform and live AWS findings to detect configuration drift.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
    },
)
async def get_waf_drift(
    project_id: str,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> DriftResponse:
    """Return drift comparison between static and live WAF configurations."""
    all_findings = _get_waf_findings_query(db, project_id).all()

    # Separate findings by scanner
    static_findings = [f for f in all_findings if f.scanner_name == "waf-static"]
    live_findings = [f for f in all_findings if f.scanner_name == "waf-auditor"]

    has_live = len(live_findings) > 0

    if not has_live:
        # Build response from static data only, indicating no live audit
        static_acls: Dict[str, List[str]] = {}
        for f in static_findings:
            acl = _extract_risk_factor(f, "web_acl_name") or "unknown"
            rule = _extract_risk_factor(f, "rule_name")
            if acl not in static_acls:
                static_acls[acl] = []
            if rule and rule not in static_acls[acl]:
                static_acls[acl].append(rule)

        web_acls = [
            WebACLDrift(
                name=name,
                in_code=True,
                in_live=False,
                drift_items=[],
                code_only_rules=rules,
                live_only_rules=[],
            )
            for name, rules in static_acls.items()
        ]
        return DriftResponse(web_acls=web_acls, has_live_audit=False)

    # Build per-ACL rule maps
    # Structure: {acl_name: {rule_name: finding}}
    static_by_acl: Dict[str, Dict[str, models.Finding]] = {}
    live_by_acl: Dict[str, Dict[str, models.Finding]] = {}

    for f in static_findings:
        acl = _extract_risk_factor(f, "web_acl_name") or "unknown"
        rule = _extract_risk_factor(f, "rule_name") or f.title
        static_by_acl.setdefault(acl, {})[rule] = f

    for f in live_findings:
        acl = _extract_risk_factor(f, "web_acl_name") or "unknown"
        rule = _extract_risk_factor(f, "rule_name") or f.title
        live_by_acl.setdefault(acl, {})[rule] = f

    all_acl_names = set(static_by_acl.keys()) | set(live_by_acl.keys())

    web_acls = []
    for acl_name in sorted(all_acl_names):
        code_rules = static_by_acl.get(acl_name, {})
        live_rules = live_by_acl.get(acl_name, {})

        in_code = acl_name in static_by_acl
        in_live = acl_name in live_by_acl

        code_only = sorted(set(code_rules.keys()) - set(live_rules.keys()))
        live_only = sorted(set(live_rules.keys()) - set(code_rules.keys()))

        # Find drift on rules present in both
        drift_items = []
        shared_rules = set(code_rules.keys()) & set(live_rules.keys())
        for rule_name in sorted(shared_rules):
            code_f = code_rules[rule_name]
            live_f = live_rules[rule_name]
            code_rf = code_f.risk_factors or {}
            live_rf = live_f.risk_factors or {}

            # Compare known attributes stored in risk_factors
            drift_attrs = _compare_risk_factors(code_rf, live_rf, rule_name)
            drift_items.extend(drift_attrs)

        # Also include explicit drift findings from the scanner
        for f in all_findings:
            if _finding_source(f) == "drift":
                f_acl = _extract_risk_factor(f, "web_acl_name") or "unknown"
                if f_acl == acl_name:
                    drift_items.append(
                        DriftItem(
                            rule_name=_extract_risk_factor(f, "rule_name") or f.title,
                            attribute=_extract_risk_factor(f, "drift_attribute") or "configuration",
                            code_value=_extract_risk_factor(f, "code_value"),
                            live_value=_extract_risk_factor(f, "live_value"),
                            severity="drift_risk",
                            description=f.description or "Configuration drift detected",
                        )
                    )

        web_acls.append(
            WebACLDrift(
                name=acl_name,
                in_code=in_code,
                in_live=in_live,
                drift_items=drift_items,
                code_only_rules=code_only,
                live_only_rules=live_only,
            )
        )

    return DriftResponse(web_acls=web_acls, has_live_audit=True)


def _compare_risk_factors(
    code_rf: Dict[str, Any],
    live_rf: Dict[str, Any],
    rule_name: str,
) -> List[DriftItem]:
    """Compare risk_factors dicts to detect drift on comparable attributes."""
    drift_items = []
    # Attributes that are meaningful to compare between code and live
    comparable_keys = ["action", "priority", "rate_limit", "ip_set", "scope", "metric_name"]

    for key in comparable_keys:
        code_val = code_rf.get(key)
        live_val = live_rf.get(key)
        if code_val is not None and live_val is not None:
            if str(code_val) != str(live_val):
                drift_items.append(
                    DriftItem(
                        rule_name=rule_name,
                        attribute=key,
                        code_value=str(code_val),
                        live_value=str(live_val),
                        severity="drift_risk",
                        description=f"Rule {key} differs between code and live",
                    )
                )

    return drift_items


@router.post(
    "/ask-ai",
    response_model=AskAIResponse,
    summary="AI analysis of a WAF finding",
    description="Uses AI to explain a WAF finding, assess security impact, and suggest remediation.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Finding not found"},
        503: {"description": "AI service not available"},
    },
)
async def ask_ai(
    project_id: str,
    body: AskAIRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> AskAIResponse:
    """AI-powered analysis of a WAF finding."""
    # Load the finding
    finding = (
        _get_waf_findings_query(db, project_id)
        .filter(models.Finding.id == body.finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="WAF finding not found")

    llm = _get_llm_provider()
    if llm is None:
        raise HTTPException(
            status_code=503,
            detail="AI service is not configured. Set AI_PROVIDER and required API keys.",
        )

    # Apply safety pipeline
    from src.services.ai_safety.sanitize import sanitize_prompt_input
    from src.services.ai_safety.validate import validate_agent_output

    waf_sev = _waf_severity(finding)
    sev_meta = WAF_SEVERITY_MAP.get(waf_sev, WAF_SEVERITY_MAP["informational"])

    # Build security-focused prompt
    context_parts = [
        f"## WAF Finding Analysis Request",
        f"**Title:** {finding.title}",
        f"**Severity:** {sev_meta['label']} ({waf_sev}) - {sev_meta['description']}",
        f"**Source:** {_finding_source(finding)}",
        f"**Scanner:** {finding.scanner_name}",
    ]

    if finding.description:
        context_parts.append(f"**Description:** {finding.description}")

    rule_name = _extract_risk_factor(finding, "rule_name")
    web_acl_name = _extract_risk_factor(finding, "web_acl_name")
    rule_type = _extract_risk_factor(finding, "rule_type")

    if web_acl_name:
        context_parts.append(f"**WebACL:** {web_acl_name}")
    if rule_name:
        context_parts.append(f"**Rule Name:** {rule_name}")
    if rule_type:
        context_parts.append(f"**Rule Type:** {rule_type}")
    if finding.file_path:
        context_parts.append(f"**File:** {finding.file_path}:{finding.line_start or '?'}")
    if finding.code_snippet:
        context_parts.append(f"\n**Code Snippet:**\n```hcl\n{finding.code_snippet}\n```")

    # Include existing remediation if present
    remediation_tf = _extract_risk_factor(finding, "remediation_terraform")
    if remediation_tf:
        context_parts.append(f"\n**Existing Remediation Suggestion:**\n```hcl\n{remediation_tf}\n```")

    context_str = "\n".join(context_parts)

    user_prompt = f"""{context_str}

## Instructions
Please provide:
1. **Explanation** - What this WAF rule does and why this finding was flagged
2. **Security Impact** - What an attacker could exploit if this is not fixed
3. **Remediation Steps** - Step-by-step instructions to fix this finding
4. **Suggested Terraform Code** - Complete, production-ready Terraform code to remediate this finding

Format your response in Markdown."""

    if body.question:
        sanitized_question = sanitize_prompt_input(body.question)
        user_prompt += f"\n\n## Additional Question\n{sanitized_question}"

    system_prompt = (
        "You are an expert AWS WAF security engineer specializing in WAFv2 Terraform configurations. "
        "You analyze WAF findings and provide actionable, production-ready remediation guidance. "
        "Always explain the security implications clearly and provide complete Terraform code blocks. "
        "When suggesting Terraform code, use aws_wafv2_* resources and follow AWS best practices."
    )

    try:
        result = llm.create_message(
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
            max_tokens=4096,
            temperature=0.3,
        )

        content = result["content"]

        # Validate AI output
        validation = validate_agent_output(content)
        content = validation["sanitized_text"]
        if not validation["valid"]:
            logger.warning(f"AI output validation issues: {validation['issues']}")

        # Extract Terraform code block if present
        remediation_code = _extract_terraform_block(content)

        return AskAIResponse(
            analysis=content,
            remediation_code=remediation_code,
            confidence=0.85 if finding.code_snippet else 0.70,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI analysis failed: {e}", exc_info=True)
        from src.services.ai_safety.errors import sanitize_ai_error
        safe_error = sanitize_ai_error(e)
        raise HTTPException(status_code=503, detail=safe_error["message"])


@router.post(
    "/ask-ai/rule-replacement",
    response_model=RuleReplacementResponse,
    summary="AI-generated WAF rule replacement",
    description="Generates adaptive rule replacement Terraform code with graduated response patterns.",
    dependencies=[Depends(require_permissions("findings:read"))],
    responses={
        401: {"description": "Not authenticated"},
        403: {"description": "Insufficient permissions"},
        404: {"description": "Finding not found"},
        503: {"description": "AI service not available"},
    },
)
async def ask_ai_rule_replacement(
    project_id: str,
    body: RuleReplacementRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
) -> RuleReplacementResponse:
    """Generate an adaptive WAF rule replacement with graduated response."""
    # Load the finding
    finding = (
        _get_waf_findings_query(db, project_id)
        .filter(models.Finding.id == body.finding_id)
        .first()
    )
    if not finding:
        raise HTTPException(status_code=404, detail="WAF finding not found")

    llm = _get_llm_provider()
    if llm is None:
        raise HTTPException(
            status_code=503,
            detail="AI service is not configured. Set AI_PROVIDER and required API keys.",
        )

    from src.services.ai_safety.validate import validate_agent_output

    original_code = finding.code_snippet or _extract_risk_factor(finding, "remediation_terraform") or ""
    waf_sev = _waf_severity(finding)
    sev_meta = WAF_SEVERITY_MAP.get(waf_sev, WAF_SEVERITY_MAP["informational"])
    rule_name = _extract_risk_factor(finding, "rule_name") or "unknown-rule"
    web_acl_name = _extract_risk_factor(finding, "web_acl_name") or "unknown-acl"
    rule_type = _extract_risk_factor(finding, "rule_type") or "unknown"

    user_prompt = f"""## WAF Rule Replacement Request

**Finding Title:** {finding.title}
**Severity:** {sev_meta['label']} ({waf_sev})
**WebACL:** {web_acl_name}
**Rule Name:** {rule_name}
**Rule Type:** {rule_type}
**Description:** {finding.description or 'N/A'}

### Current Terraform Code
```hcl
{original_code}
```

## Instructions
1. **Explain what is wrong** with the current rule (e.g., permanent block on single criteria, no graduated response)
2. **Generate a complete replacement** Terraform resource block that includes:
   - `rate_based_statement` with appropriate threshold (e.g., 500 requests / 5 minutes)
   - Graduated response pattern (count -> rate-limit -> block)
   - Proper CloudWatch metric and logging configuration
   - Inline HCL comments explaining each change
3. **List each change** you made as a bullet point

### Response Format
Return your response in exactly this format:

EXPLANATION_START
<your markdown explanation>
EXPLANATION_END

REPLACEMENT_CODE_START
<complete Terraform HCL>
REPLACEMENT_CODE_END

CHANGES_START
- Change 1
- Change 2
- Change 3
CHANGES_END"""

    system_prompt = (
        "You are an expert AWS WAF security engineer. You specialize in converting static, "
        "permanent-block WAF rules into adaptive, graduated-response rules using AWS WAFv2 "
        "rate_based_statement and managed rule groups. Always output complete, valid Terraform "
        "HCL that can be applied directly. Include inline comments in the HCL explaining each section."
    )

    try:
        result = llm.create_message(
            messages=[{"role": "user", "content": user_prompt}],
            system=system_prompt,
            max_tokens=4096,
            temperature=0.3,
        )

        content = result["content"]

        # Validate AI output
        validation = validate_agent_output(content)
        content = validation["sanitized_text"]
        if not validation["valid"]:
            logger.warning(f"AI output validation issues: {validation['issues']}")

        # Parse structured response
        explanation = _extract_section(content, "EXPLANATION_START", "EXPLANATION_END")
        replacement_code = _extract_section(content, "REPLACEMENT_CODE_START", "REPLACEMENT_CODE_END")
        changes_raw = _extract_section(content, "CHANGES_START", "CHANGES_END")

        # Fallback: if structured parsing fails, use the whole response
        if not explanation:
            explanation = content
        if not replacement_code:
            replacement_code = _extract_terraform_block(content) or "# AI could not generate replacement code"

        changes_summary = []
        if changes_raw:
            for line in changes_raw.strip().splitlines():
                line = line.strip()
                if line.startswith("- "):
                    changes_summary.append(line[2:])
                elif line:
                    changes_summary.append(line)

        if not changes_summary:
            changes_summary = ["See explanation for details"]

        return RuleReplacementResponse(
            original_code=original_code or "# No original code available",
            replacement_code=replacement_code,
            explanation=explanation,
            changes_summary=changes_summary,
        )

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"AI rule replacement failed: {e}", exc_info=True)
        from src.services.ai_safety.errors import sanitize_ai_error
        safe_error = sanitize_ai_error(e)
        raise HTTPException(status_code=503, detail=safe_error["message"])


# ---------------------------------------------------------------------------
# Text extraction helpers
# ---------------------------------------------------------------------------


def _extract_terraform_block(text: str) -> Optional[str]:
    """Extract the first ```hcl or ```terraform fenced code block from text."""
    import re
    pattern = r"```(?:hcl|terraform)\s*\n(.*?)```"
    match = re.search(pattern, text, re.DOTALL)
    if match:
        return match.group(1).strip()
    return None


def _extract_section(text: str, start_marker: str, end_marker: str) -> Optional[str]:
    """Extract text between two markers."""
    try:
        start_idx = text.index(start_marker) + len(start_marker)
        end_idx = text.index(end_marker, start_idx)
        return text[start_idx:end_idx].strip()
    except ValueError:
        return None
