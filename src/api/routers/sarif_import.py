from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import and_
from typing import Optional, Dict
from loguru import logger
from pydantic import BaseModel, Field
from datetime import datetime
import uuid
import re

from ..dependencies import get_tenant_db
from ..database import get_current_org_id
from .. import models
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions

router = APIRouter(
    prefix="/findings",
    tags=["findings"],
)

# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class SarifImportRequest(BaseModel):
    sarif: dict = Field(..., description="Raw SARIF 2.1.0 JSON object")
    repository_name: str = Field(..., description="Target repository name (used to look up repository_id)")
    default_severity: str = Field(default="medium", description="Fallback severity when SARIF level is missing")


class SarifImportResponse(BaseModel):
    scan_run_id: str = Field(..., description="UUID of the created ScanRun")
    findings_imported: int = Field(..., description="Total new findings created")
    findings_deduplicated: int = Field(default=0, description="Findings skipped due to deduplication")
    findings_by_severity: Dict[str, int] = Field(default_factory=dict, description="Breakdown by severity")
    tool_name: str = Field(..., description="Tool name extracted from SARIF metadata")
    runs_processed: int = Field(..., description="Number of SARIF runs processed")


# ---------------------------------------------------------------------------
# SARIF severity mapping
# ---------------------------------------------------------------------------

def _map_severity(level: Optional[str], rule_tags: list, default: str) -> str:
    """Map SARIF level + rule tags to AGH severity."""
    if level == "error":
        # Promote to critical if rule tags indicate it
        for tag in rule_tags:
            if "security/critical" in tag.lower() or "critical" == tag.lower():
                return "critical"
        return "high"
    if level == "warning":
        return "medium"
    if level == "note":
        return "low"
    return default


def _extract_cwe(tags: list) -> Optional[str]:
    """Extract CWE ID from SARIF rule tags."""
    for tag in tags:
        # Match patterns like "CWE-79", "external/cwe/cwe-79"
        m = re.search(r'[Cc][Ww][Ee]-?(\d+)', tag)
        if m:
            return f"CWE-{m.group(1)}"
    return None


def _extract_cve(tags: list) -> Optional[str]:
    """Extract CVE ID from SARIF rule tags."""
    for tag in tags:
        m = re.search(r'(CVE-\d{4}-\d+)', tag, re.IGNORECASE)
        if m:
            return m.group(1).upper()
    return None


def _strip_file_prefix(uri: str) -> str:
    """Strip file:// prefix from artifact URIs."""
    if uri.startswith("file://"):
        return uri[7:]
    return uri


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@router.post(
    "/import/sarif",
    dependencies=[Depends(require_permissions("findings:write"))],
    response_model=SarifImportResponse,
    summary="Import findings from a SARIF file",
    description="Accepts a SARIF 2.1.0 JSON payload and imports findings into AGH. "
                "Supports any SARIF-producing tool (MegaLinter, CodeQL, Semgrep, etc.).",
    responses={
        404: {"description": "Repository not found"},
        400: {"description": "Invalid SARIF payload"},
        403: {"description": "Insufficient permissions — requires findings:write"},
    },
)
def import_sarif(
    request: SarifImportRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    org_id = get_current_org_id()

    # --- Validate SARIF structure ---
    runs = request.sarif.get("runs")
    if not runs or not isinstance(runs, list):
        raise HTTPException(status_code=400, detail="Invalid SARIF: missing or empty 'runs' array")

    # --- Look up repository ---
    repo_filter = [models.Repository.name == request.repository_name]
    if org_id:
        repo_filter.append(models.Repository.organization_id == org_id)

    repo = db.query(models.Repository).filter(and_(*repo_filter)).first()
    if not repo:
        raise HTTPException(
            status_code=404,
            detail=f"Repository '{request.repository_name}' not found in this organization",
        )

    # --- Extract tool name from first run ---
    first_tool = runs[0].get("tool", {}).get("driver", {}).get("name", "unknown")

    # --- Create ScanRun ---
    scan_run = models.ScanRun(
        organization_id=org_id or repo.organization_id,
        repository_id=repo.id,
        scan_type="sarif-import",
        status="completed",
        triggered_by="api",
        trigger_reference=first_tool,
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=0,
        findings_count=0,
        new_findings_count=0,
        scan_config={
            "sarif_version": request.sarif.get("version", "2.1.0"),
            "tool": first_tool,
            "runs": len(runs),
        },
    )
    db.add(scan_run)
    db.flush()  # get scan_run.id

    # --- Process SARIF runs ---
    total_imported = 0
    total_deduped = 0
    severity_counts: Dict[str, int] = {}

    for run in runs:
        driver = run.get("tool", {}).get("driver", {})
        tool_name = driver.get("name", "unknown")

        # Build rule lookup
        rules_list = driver.get("rules", [])
        rules_map = {r.get("id"): r for r in rules_list if r.get("id")}

        for result in run.get("results", []):
            rule_id = result.get("ruleId", "")
            rule = rules_map.get(rule_id, {})
            rule_props = rule.get("properties", {})
            rule_tags = rule_props.get("tags", [])

            # --- Severity ---
            sarif_level = result.get("level")
            severity = _map_severity(sarif_level, rule_tags, request.default_severity)

            # --- Location ---
            locations = result.get("locations", [])
            phys = locations[0].get("physicalLocation", {}) if locations else {}
            file_path = _strip_file_prefix(phys.get("artifactLocation", {}).get("uri", "N/A"))
            region = phys.get("region", {})
            line_start = region.get("startLine", 0)
            line_end = region.get("endLine", line_start)
            snippet = region.get("snippet", {}).get("text", "")

            # --- Metadata ---
            cwe_id = _extract_cwe(rule_tags)
            cve_id = _extract_cve(rule_tags)

            # --- Title & description ---
            title = (
                result.get("message", {}).get("text")
                or rule.get("shortDescription", {}).get("text")
                or f"{tool_name}: {rule_id}"
            )
            description = (
                rule.get("fullDescription", {}).get("text")
                or rule.get("help", {}).get("text")
                or ""
            )

            # --- Deduplication: same scanner, file, line, title, open ---
            existing = db.query(models.Finding).filter(
                and_(
                    models.Finding.repository_id == repo.id,
                    models.Finding.scanner_name == tool_name,
                    models.Finding.file_path == file_path,
                    models.Finding.line_start == line_start,
                    models.Finding.title == title,
                    models.Finding.status == "open",
                )
            ).first()

            if existing:
                existing.last_seen_at = datetime.utcnow()
                total_deduped += 1
                continue

            # --- Create Finding ---
            finding = models.Finding(
                organization_id=org_id or repo.organization_id,
                repository_id=repo.id,
                scan_run_id=scan_run.id,
                scanner_name=tool_name,
                finding_type="sast",
                severity=severity,
                title=title,
                description=description,
                file_path=file_path,
                line_start=line_start,
                line_end=line_end,
                code_snippet=snippet or f"Rule: {rule_id}",
                cwe_id=cwe_id,
                cve_id=cve_id,
                status="open",
                first_seen_at=datetime.utcnow(),
                last_seen_at=datetime.utcnow(),
            )
            db.add(finding)
            total_imported += 1
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

    # --- Finalize ScanRun counts ---
    scan_run.findings_count = total_imported
    scan_run.new_findings_count = total_imported

    db.commit()

    logger.info(
        f"SARIF import complete: tool={first_tool}, repo={request.repository_name}, "
        f"imported={total_imported}, deduped={total_deduped}"
    )

    return SarifImportResponse(
        scan_run_id=str(scan_run.id),
        findings_imported=total_imported,
        findings_deduplicated=total_deduped,
        findings_by_severity=severity_counts,
        tool_name=first_tool,
        runs_processed=len(runs),
    )
