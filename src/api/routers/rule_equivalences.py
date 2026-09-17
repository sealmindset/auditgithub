"""Review queue for cross-scanner rule merges.

Filing groups findings by ``(scanner_name, rule_id)``, which files two issues
when two scanners report one defect under their own rule names. An AI pass
proposes which rule pairs are really one defect; these endpoints are where a
person approves or rejects those proposals.

Nothing here files anything, and nothing here reaches AuditBoard. A proposal
with no review decision changes nothing at all -- ``load_equivalence_map``
reads only ``approved`` + ``equivalent`` rows -- so the effect of approving a
pair is limited to how a *future* filing groups findings.

``POST /propose`` is the only endpoint that spends money: it calls the
configured AI provider once per candidate pair. It is capped per request and
never runs itself.
"""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from loguru import logger
from pydantic import BaseModel, Field
from sqlalchemy import or_
from sqlalchemy.orm import Session

from .. import models
from ..database import get_current_org_id
from ..dependencies import get_tenant_db
from ..services import rule_equivalence as svc
from src.auth.dependencies import get_current_user
from src.auth.models import User
from src.rbac.dependencies import require_permissions

router = APIRouter(prefix="/rule-equivalences", tags=["rule-equivalences"])


# Reads use findings:read and decisions use findings:write, rather than a new
# permission. A merge decision changes how findings are grouped and nothing
# else, so it is the same authority; inventing a permission nobody is seeded
# with would lock every existing role out of the queue.
READ = Depends(require_permissions("findings:read"))
WRITE = Depends(require_permissions("findings:write"))


class RuleSideModel(BaseModel):
    """One rule in a pair."""

    scanner_name: str = Field(description="Scanner that emits this rule")
    rule_id: str = Field(description="Scanner's own rule identifier")
    key: str = Field(description="scanner::rule, the identity used for grouping")


class CandidateModel(BaseModel):
    """A pair the AI has not been asked about yet."""

    pair_key: str = Field(description="Canonical key for the pair, stable in either order")
    rule_a: RuleSideModel
    rule_b: RuleSideModel
    shared_repos: int = Field(description="Repositories where both rules hit the same normalized path")
    shared_locations: int = Field(description="Distinct (repository, path) places where both hit")
    sample_paths: List[str] = Field(default_factory=list, description="A few of those paths")


class EquivalenceModel(BaseModel):
    """A recorded proposal and its review state."""

    id: str
    rule_a: RuleSideModel
    rule_b: RuleSideModel
    pair_key: str
    verdict: str = Field(description="'equivalent' or 'distinct', as proposed")
    confidence: Optional[float] = Field(default=None, description="Model's stated confidence, 0.0-1.0")
    model: Optional[str] = Field(default=None, description="Model that produced the verdict")
    rationale: Optional[str] = Field(default=None, description="Why the model said so")
    evidence: Optional[Dict[str, Any]] = Field(default=None, description="What the model was shown")
    review_decision: Optional[str] = Field(
        default=None,
        description="'approved', 'rejected', or null for unreviewed. Only approved+equivalent changes grouping.",
    )
    reviewed_by: Optional[str] = None
    review_note: Optional[str] = None
    affects_grouping: bool = Field(
        description="Whether this row currently merges the two rules for filing"
    )


class ProposeRequest(BaseModel):
    """Ask the AI about candidate pairs."""

    limit: int = Field(
        default=10,
        ge=1,
        le=100,
        description="How many pairs to ask about. Each is one AI call.",
    )
    min_locations: int = Field(
        default=1,
        ge=1,
        description="Only ask about pairs co-located in at least this many places",
    )
    all_severities: bool = Field(
        default=False,
        description=(
            "Include pairs outside the Critical/High/Medium filing floor. "
            "Those pairs cannot be filed as a group, so they are excluded by default."
        ),
    )
    concurrency: int = Field(
        default=4, ge=1, le=8, description="Parallel AI calls. Shared deployment; kept low."
    )


class ProposeResponse(BaseModel):
    asked: int = Field(description="Pairs put to the model")
    equivalent: int = Field(description="Proposed as one defect, pending review")
    distinct: int = Field(description="Proposed as separate")
    downgraded: int = Field(
        description="Answered 'equivalent' below the confidence floor, recorded as 'distinct'"
    )
    no_answer: int = Field(
        description="Failed, timed out or unparseable. Nothing recorded; scanners stay separate."
    )
    model: Optional[str] = Field(default=None, description="Model asked")
    candidates_remaining: int = Field(description="Blocked pairs still undecided after this run")


class ReviewRequest(BaseModel):
    decision: str = Field(description="'approved' or 'rejected'")
    note: Optional[str] = Field(default=None, description="Why, for the audit trail")


class StatsResponse(BaseModel):
    total: int
    pending: int
    pending_equivalent: int
    approved_equivalent: int
    approved_distinct: int
    rejected: int
    candidates_total: int = Field(description="Blocked pairs at the filing severity floor")
    candidates_all_severities: int = Field(description="Blocked pairs ignoring the severity floor")
    candidates_undecided: int = Field(description="Blocked pairs with no row yet")
    min_confidence: float = Field(description="Floor below which 'equivalent' is downgraded")


def _side(scanner: str, rule: str) -> RuleSideModel:
    identity = svc.Identity(scanner_name=scanner, rule_id=rule)
    return RuleSideModel(scanner_name=scanner, rule_id=rule, key=identity.key)


def _row_model(row: models.RuleEquivalence) -> EquivalenceModel:
    return EquivalenceModel(
        id=str(row.id),
        rule_a=_side(row.scanner_a, row.rule_a),
        rule_b=_side(row.scanner_b, row.rule_b),
        pair_key=svc.pair_key(
            svc.Identity(row.scanner_a, row.rule_a),
            svc.Identity(row.scanner_b, row.rule_b),
        ),
        verdict=row.verdict,
        confidence=float(row.confidence) if row.confidence is not None else None,
        model=row.model,
        rationale=row.rationale,
        evidence=row.evidence,
        review_decision=row.review_decision,
        reviewed_by=row.reviewed_by,
        review_note=row.review_note,
        affects_grouping=(
            row.review_decision == svc.REVIEW_APPROVED
            and row.verdict == svc.VERDICT_EQUIVALENT
        ),
    )


@router.get(
    "",
    dependencies=[READ],
    response_model=List[EquivalenceModel],
    summary="List rule-merge proposals",
    description=(
        "Proposals and their review state. Default `status=pending` is the "
        "review queue; pending rows do not affect grouping."
    ),
)
def list_equivalences(
    status: str = Query(
        default="pending",
        description="pending | approved | rejected | all",
    ),
    verdict: Optional[str] = Query(default=None, description="equivalent | distinct"),
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_tenant_db),
):
    org_id = get_current_org_id()
    query = db.query(models.RuleEquivalence)
    if org_id:
        query = query.filter(
            or_(
                models.RuleEquivalence.organization_id == org_id,
                models.RuleEquivalence.organization_id.is_(None),
            )
        )

    if status == "pending":
        query = query.filter(models.RuleEquivalence.review_decision.is_(None))
    elif status in svc.REVIEW_DECISIONS:
        query = query.filter(models.RuleEquivalence.review_decision == status)
    elif status != "all":
        raise HTTPException(
            status_code=400,
            detail="status must be one of: pending, approved, rejected, all",
        )

    if verdict:
        if verdict not in svc.VERDICTS:
            raise HTTPException(
                status_code=400,
                detail=f"verdict must be one of: {', '.join(svc.VERDICTS)}",
            )
        query = query.filter(models.RuleEquivalence.verdict == verdict)

    # Highest-confidence merges first: those are the ones worth a reviewer's
    # attention, and the ones that change the most findings if approved.
    rows = (
        query.order_by(
            models.RuleEquivalence.verdict.asc(),
            models.RuleEquivalence.confidence.desc().nullslast(),
        )
        .limit(limit)
        .all()
    )
    return [_row_model(r) for r in rows]


@router.get(
    "/stats",
    dependencies=[READ],
    response_model=StatsResponse,
    summary="Queue depth and candidate coverage",
    description=(
        "How much of the blocked candidate space has been asked about, and how "
        "much is waiting on a person. `candidates_undecided` is the work left."
    ),
)
def equivalence_stats(db: Session = Depends(get_tenant_db)):
    org_id = get_current_org_id()
    stats = svc.review_stats(db, org_id)
    return StatsResponse(
        **stats,
        candidates_total=svc.count_candidate_pairs(db, org_id),
        candidates_all_severities=svc.count_candidate_pairs(db, org_id, severities=[]),
        candidates_undecided=len(
            svc.find_candidate_pairs(db, org_id, limit=10_000, skip_decided=True)
        ),
        min_confidence=svc.MIN_CONFIDENCE,
    )


@router.get(
    "/candidates",
    dependencies=[READ],
    response_model=List[CandidateModel],
    summary="Rule pairs not yet asked about",
    description=(
        "Cross-scanner rule pairs that co-occur on the same normalized path in "
        "the same repository, with no proposal recorded. Read-only: listing a "
        "candidate calls no AI provider."
    ),
)
def list_candidates(
    limit: int = Query(default=25, ge=1, le=200),
    min_locations: int = Query(default=1, ge=1),
    all_severities: bool = Query(default=False),
    db: Session = Depends(get_tenant_db),
):
    org_id = get_current_org_id()
    candidates = svc.find_candidate_pairs(
        db,
        org_id,
        limit=limit,
        min_locations=min_locations,
        severities=[] if all_severities else None,
    )
    return [
        CandidateModel(
            pair_key=c.key,
            rule_a=_side(c.identity_a.scanner_name, c.identity_a.rule_id),
            rule_b=_side(c.identity_b.scanner_name, c.identity_b.rule_id),
            shared_repos=c.shared_repos,
            shared_locations=c.shared_locations,
            sample_paths=c.sample_paths,
        )
        for c in candidates
    ]


@router.post(
    "/propose",
    dependencies=[WRITE],
    response_model=ProposeResponse,
    summary="Ask the AI about candidate pairs",
    description=(
        "One AI call per candidate, capped by `limit`. Writes unreviewed "
        "proposals only — nothing is merged and nothing is filed. Pairs that "
        "fail or answer unusably are left as candidates so a later run retries."
    ),
)
async def propose_equivalences(
    request: ProposeRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    org_id = get_current_org_id()

    # Imported here, not at module scope: the ai router builds its agent at
    # import time from settings, and importing it eagerly would tie this
    # router's import to the AI provider being configured.
    from .ai import ai_agent

    if ai_agent is None or not hasattr(ai_agent.provider, "execute_prompt"):
        raise HTTPException(
            status_code=503,
            detail=(
                "No AI provider is configured, so rule pairs cannot be proposed. "
                "Merges can still be recorded by hand through the review queue."
            ),
        )

    candidates = svc.find_candidate_pairs(
        db,
        org_id,
        limit=request.limit,
        min_locations=request.min_locations,
        severities=[] if request.all_severities else None,
    )
    if not candidates:
        return ProposeResponse(
            asked=0,
            equivalent=0,
            distinct=0,
            downgraded=0,
            no_answer=0,
            model=getattr(ai_agent, "model", None),
            candidates_remaining=0,
        )

    logger.info(
        "Asking {} about {} rule pairs (requested by {})",
        getattr(ai_agent, "model", "the configured provider"),
        len(candidates),
        getattr(current_user, "email", None) or getattr(current_user, "username", "?"),
    )

    results = await svc.ask_provider_batch(
        ai_agent.provider, candidates, concurrency=request.concurrency
    )
    counts = svc.record_proposals(
        db, results, model=getattr(ai_agent, "model", None), org_id=org_id
    )
    db.commit()

    remaining = len(
        svc.find_candidate_pairs(
            db,
            org_id,
            limit=10_000,
            skip_decided=True,
            severities=[] if request.all_severities else None,
        )
    )
    return ProposeResponse(
        asked=len(candidates),
        equivalent=counts["equivalent"],
        distinct=counts["distinct"],
        downgraded=counts["downgraded"],
        no_answer=counts["no_answer"],
        model=getattr(ai_agent, "model", None),
        candidates_remaining=remaining,
    )


@router.post(
    "/{equivalence_id}/review",
    dependencies=[WRITE],
    response_model=EquivalenceModel,
    summary="Approve or reject a proposal",
    description=(
        "Approving an `equivalent` proposal is what makes two scanners' rules "
        "file as one defect from then on. Approving a `distinct` proposal "
        "records that they are separate and stops the pair being asked again. "
        "Already-filed issues are not changed: AuditBoard descriptions cannot "
        "be edited after create."
    ),
)
def review_equivalence(
    equivalence_id: str,
    request: ReviewRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    row = (
        db.query(models.RuleEquivalence)
        .filter(models.RuleEquivalence.id == equivalence_id)
        .first()
    )
    if row is None:
        raise HTTPException(status_code=404, detail="Proposal not found")

    reviewer = (
        getattr(current_user, "email", None)
        or getattr(current_user, "username", None)
        or "unknown"
    )
    try:
        svc.apply_review(db, row, request.decision, reviewer, request.note)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    db.commit()
    db.refresh(row)
    logger.info(
        "Rule pair {} {} by {}",
        svc.pair_key(
            svc.Identity(row.scanner_a, row.rule_a),
            svc.Identity(row.scanner_b, row.rule_b),
        ),
        row.review_decision,
        reviewer,
    )
    return _row_model(row)


class ManualMergeRequest(BaseModel):
    """Record a merge a person found themselves, with no AI involved."""

    scanner_a: str
    rule_a: str
    scanner_b: str
    rule_b: str
    verdict: str = Field(default=svc.VERDICT_EQUIVALENT, description="equivalent | distinct")
    note: Optional[str] = Field(default=None, description="Why, for the audit trail")


@router.post(
    "",
    dependencies=[WRITE],
    response_model=EquivalenceModel,
    summary="Record a merge decision by hand",
    description=(
        "For pairs the blocking query never proposes — two rules that never "
        "share a file path but are the same advisory — and for use when no AI "
        "provider is configured. Recorded as approved, attributed to the caller."
    ),
)
def create_manual_equivalence(
    request: ManualMergeRequest,
    db: Session = Depends(get_tenant_db),
    current_user: User = Depends(get_current_user),
):
    if request.verdict not in svc.VERDICTS:
        raise HTTPException(
            status_code=400, detail=f"verdict must be one of: {', '.join(svc.VERDICTS)}"
        )
    identity_a = svc.Identity(request.scanner_a.strip(), request.rule_a.strip())
    identity_b = svc.Identity(request.scanner_b.strip(), request.rule_b.strip())
    if not all([identity_a.scanner_name, identity_a.rule_id, identity_b.scanner_name, identity_b.rule_id]):
        raise HTTPException(status_code=400, detail="Both scanner and rule are required on each side")
    if identity_a == identity_b:
        raise HTTPException(status_code=400, detail="A rule cannot be merged with itself")

    org_id = get_current_org_id()
    candidate = svc.CandidatePair(
        identity_a=identity_a,
        identity_b=identity_b,
        shared_repos=0,
        shared_locations=0,
    )
    reviewer = (
        getattr(current_user, "email", None)
        or getattr(current_user, "username", None)
        or "unknown"
    )
    row = svc.record_proposal(
        db,
        candidate,
        svc.Proposal(
            verdict=request.verdict,
            confidence=None,
            rationale=request.note or f"Recorded by hand by {reviewer}",
        ),
        model=None,
        org_id=org_id,
    )
    # Say so in the evidence. The default evidence describes the blocking
    # query, which did not run here, and a stored claim about how a decision
    # was reached has to be true or it is worse than absent.
    row.evidence = {
        "source": "manual",
        "recorded_by": reviewer,
        "note": request.note,
        "blocking": "none - entered by hand, not proposed by the blocking query",
    }
    # A hand-entered decision is already reviewed: the person entering it is
    # the reviewer. Leaving it pending would mean waiting for approval of
    # something that was already a decision.
    if not row.review_decision:
        svc.apply_review(db, row, svc.REVIEW_APPROVED, reviewer, request.note)
    db.commit()
    db.refresh(row)
    return _row_model(row)
