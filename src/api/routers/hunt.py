"""
Threat-hunting endpoints.

Each hunt tool is exposed directly, so an analyst can run one surface at a time without
going through the LLM planner. That matters for two reasons: the planner's tool choice is
not always what an analyst wants, and a hunt step that produces a legally or
operationally significant zero should be reproducible by hand.

Permissions:
    hunt:read      the source registry — static metadata, no external calls
    hunt:execute   everything that queries a registry, GitHub, or Microsoft Graph

Every response carries a `coverage` block. Callers must not treat an empty result set as
a negative finding without reading it.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from src.rbac.dependencies import require_permissions

from ..dependencies import get_tenant_db
from ...ai_agent.tools import hunt_tools

router = APIRouter(prefix="/hunt", tags=["hunt"])


# =============================================================================
# Request models
# =============================================================================

class RegistryTruthRequest(BaseModel):
    packages: List[str] = Field(..., description="Package names to resolve")
    window_start: str = Field(..., description="ISO-8601 start of the suspected window")
    window_end: str = Field(..., description="ISO-8601 end of the suspected window")
    ecosystem: str = Field("npm", description="npm, pypi, crates, or rubygems")
    force_refresh: bool = Field(
        False,
        description="Bypass the intel cache. Use when the incident is live and the "
                    "registry state is still changing."
    )


class ArbitrateRequest(BaseModel):
    claims: List[Dict[str, Any]] = Field(
        ...,
        description="Claims to arbitrate. Each: {claim_type, subject, value, assertions: "
                    "[{source_id, stance, value, detail}]}"
    )
    malicious_specs: Optional[List[str]] = Field(
        None,
        description="Registry-derived malicious name@version set, used as the tier-0 "
                    "oracle. Omitting it means vendor consensus goes unchallenged."
    )
    ground_truth_url: Optional[str] = Field(None, description="Citation for the oracle")


class ExposureRequest(BaseModel):
    specs: List[str] = Field(..., description="Exact name@version specs")
    organization_id: Optional[str] = Field(None, description="Restrict to one organization")


class CiActivityRequest(BaseModel):
    window_start: str
    window_end: str
    repository_names: Optional[List[str]] = None
    organization_id: Optional[str] = None


class DeadDropRequest(BaseModel):
    markers: List[str] = Field(
        ...,
        description="Marker strings, e.g. 'Shai-Hulud: Here We Go Again.'"
    )
    created_after: Optional[str] = Field(
        None,
        description="Also list repositories created after this ISO-8601 time regardless "
                    "of marker — a renamed dead drop keeps its creation timestamp."
    )
    organization_id: Optional[str] = None


class EndpointExecutionRequest(BaseModel):
    indicators: List[str] = Field(..., description="Strings to search command lines for")
    hours: int = Field(168, ge=1, le=720, description="Lookback. Retention is 30 days.")
    table: str = Field("DeviceProcessEvents", description="Advanced hunting table")


class AlertsRequest(BaseModel):
    days: int = Field(7, ge=1, le=90)
    severities: Optional[List[str]] = None
    title_contains: Optional[str] = Field(
        None, description="Matched client-side; alerts_v2 cannot $filter on title."
    )


class HuntQueryRequest(BaseModel):
    query: str = Field(..., description="KQL advanced hunting query")
    strict_lint: bool = Field(
        True,
        description="Reject queries containing known traps. Disable only if you have "
                    "verified the lint is wrong, and say why in your notes."
    )


# =============================================================================
# Read-only metadata
# =============================================================================

@router.get(
    "/sources",
    dependencies=[Depends(require_permissions("hunt:read"))],
    summary="List threat-intel sources with URLs and evidentiary tier",
)
async def list_sources(ecosystem: Optional[str] = None, max_tier: int = 3):
    """
    The source registry: real URLs, not vendor names, so a claim can be followed back.

    Tier 0 sources are registries and authoritative feeds and settle disputes outright.
    Tiers 1-3 are vendor and press reporting, used to widen hunt scope and never to
    establish a fact. Sources proven to contradict themselves are listed as disqualified
    with the reason.
    """
    return hunt_tools.hunt_intel_sources(ecosystem=ecosystem, max_tier=max_tier)


@router.get(
    "/tools",
    dependencies=[Depends(require_permissions("hunt:read"))],
    summary="List the hunt tools available to the analyst agent",
)
async def list_tools():
    """The tool catalog the zero-day planner is given, with signatures."""
    from ...ai_agent import zda_prompt

    return {
        "tools": zda_prompt.tool_specs(),
        "requiring_hunt_execute": sorted(zda_prompt.HUNT_TOOL_NAMES),
    }


@router.get(
    "/access",
    dependencies=[Depends(require_permissions("hunt:read"))],
    summary="What the stored credentials can and cannot see",
)
async def access_coverage(db: Session = Depends(get_tenant_db)):
    """
    Per-organization credential provenance, recorded privilege, and blind spots.

    Read this before believing any hunt result. Organizations resolving to a member-level
    token cannot enumerate org runners and cannot see private repositories not explicitly
    granted, so their absence from any result set is not evidence of absence.
    """
    return hunt_tools.hunt_access_coverage(db)


# =============================================================================
# Ground truth and arbitration
# =============================================================================

@router.post(
    "/registry-truth",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Derive the authoritative malicious version set from the package registry",
)
async def registry_truth(request: RegistryTruthRequest):
    """
    Ask the registry which versions were genuinely malicious.

    A version is attacker-published if it was published inside the window AND has since
    been unpublished. Both conditions, from the registry's own record. Derive the attack
    window from the returned publish timestamps rather than from advisory prose — vendor
    summaries of a window have been materially wrong on this estate.
    """
    result = hunt_tools.hunt_registry_truth(
        packages=request.packages,
        window_start=request.window_start,
        window_end=request.window_end,
        ecosystem=request.ecosystem,
        force_refresh=request.force_refresh,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post(
    "/arbitrate",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Reconcile conflicting source claims against ground truth",
)
async def arbitrate(request: ArbitrateRequest):
    """
    Resolve competing claims into a hunt scope and a verdict set.

    Returns two lists of deliberately different size. `hunt_scope` is the union of
    everything any source asserted — query all of it, since omission is not denial.
    `verdict_set` is what survived arbitration — report only that. Disagreements come
    back with the contradicted source named.
    """
    return hunt_tools.hunt_arbitrate(
        claims=request.claims,
        malicious_specs=request.malicious_specs,
        ground_truth_url=request.ground_truth_url,
    )


# =============================================================================
# Estate exposure
# =============================================================================

@router.post(
    "/exposure",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Repositories declaring specific name@version specs",
)
async def exposure(request: ExposureRequest, db: Session = Depends(get_tenant_db)):
    """
    Exact-version dependency exposure, with floating ranges flagged separately.

    Code search is deliberately not used: GitHub does not index files over 384 KB and the
    lockfiles in this estate are 415-950 KB, so a code search would return a confident
    and wrong zero.
    """
    return hunt_tools.hunt_dependency_exposure(
        db, specs=request.specs, organization_id=request.organization_id
    )


@router.post(
    "/ci-activity",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Workflow runs and deployments overlapping an attack window",
)
async def ci_activity(request: CiActivityRequest, db: Session = Depends(get_tenant_db)):
    """
    The mechanism by which a declared dependency becomes an executed payload.

    Check `coverage.never_collected` in the response before drawing any conclusion: if
    the underlying tables were never ingested, a zero here is structural and rules
    nothing out.
    """
    result = hunt_tools.hunt_ci_activity(
        db,
        window_start=request.window_start,
        window_end=request.window_end,
        repository_names=request.repository_names,
        organization_id=request.organization_id,
    )
    if result.get("error"):
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@router.post(
    "/dead-drops",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Sweep the repository inventory for exfiltration dead-drop markers",
)
async def dead_drops(request: DeadDropRequest, db: Session = Depends(get_tenant_db)):
    """
    Worm-class supply-chain malware exfiltrates into a repository it creates under the
    victim's account, with a recognizable description. The inventory is therefore itself
    a detector.

    Note the scope limit in the response: dead drops created under a user namespace sit
    outside every scanned organization and this sweep cannot see them.
    """
    return hunt_tools.hunt_dead_drop_repos(
        db,
        markers=request.markers,
        organization_id=request.organization_id,
        created_after=request.created_after,
    )


# =============================================================================
# Endpoint and identity telemetry
# =============================================================================

@router.get(
    "/coverage-control",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Prove endpoint telemetry exists before interpreting any zero",
)
async def coverage_control(hours: int = 24, db: Session = Depends(get_tenant_db)):
    """
    Rule 0.1: a zero result is a finding only if a control shows the query could have
    returned something. Run this first. If `telemetry_present` is false, the pipeline is
    the finding and every other Defender result in the hunt is uninterpretable.
    """
    return hunt_tools.hunt_coverage_control(db, hours=hours)


@router.post(
    "/endpoint-execution",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Search Defender XDR process telemetry for indicators",
)
async def endpoint_execution(request: EndpointExecutionRequest,
                             db: Session = Depends(get_tenant_db)):
    """
    Process-execution evidence, with the telemetry control attached to the result.

    Two limits are always reported and both change conclusions: advanced hunting retains
    30 days, so a zero bounds only that window; and containers on macOS hosts are
    invisible to the endpoint agent, so an in-container process leaves only the host-side
    docker invocation.
    """
    result = hunt_tools.hunt_endpoint_execution(
        db, indicators=request.indicators, hours=request.hours, table=request.table
    )
    if result.get("error") and not result.get("rows"):
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@router.post(
    "/alerts",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Unified alerts across a window, paginated correctly",
)
async def alerts(request: AlertsRequest, db: Session = Depends(get_tenant_db)):
    """
    alerts_v2 silently caps a page at 100 rows and returns no continuation link, so a
    single call looks like a complete answer. This assembles the window by subdivision;
    on a recent 7-day window the true count was 514 against a naive 100.
    """
    result = hunt_tools.hunt_alerts(
        db, days=request.days, severities=request.severities,
        title_contains=request.title_contains,
    )
    if result.get("error"):
        raise HTTPException(status_code=502, detail=result["error"])
    return result


@router.post(
    "/query",
    dependencies=[Depends(require_permissions("hunt:execute"))],
    summary="Run a raw KQL advanced hunting query",
)
async def raw_query(request: HuntQueryRequest, db: Session = Depends(get_tenant_db)):
    """
    Run an arbitrary advanced hunting query.

    The query is linted first and rejected if it contains a known trap — `$table`,
    `order by ... asc | take N`, a UserAgent reference against AADSpnSignInEventsBeta.
    Those do not error at the API; they return plausible, wrong output, so pre-call is
    the only point at which they can be caught. KQL control commands and `externaldata`
    are refused outright: the Graph client is read-only by construction.
    """
    from ..integrations.msgraph import GraphClient, GraphError, KqlLintError

    try:
        client = GraphClient.from_db(db)
        result = client.run_hunting_query(request.query, strict_lint=request.strict_lint)
    except KqlLintError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except GraphError as exc:
        logger.warning(f"Hunting query failed: {exc}")
        raise HTTPException(status_code=502, detail=str(exc))

    return result.to_dict()
