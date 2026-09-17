"""Decide when two scanners' rules describe one defect.

Filing groups findings by ``(scanner_name, rule_id)``. That is right within a
scanner and wrong across scanners: grype's ``GHSA-M7JM-9GC2-MPF2`` and
trivy-fs's ``CVE-2024-21538`` can be the same advisory in the same file, and
they file as two issues. ``cve_id`` is populated on 0% of findings in this
instance and ``ghsa_id`` only on grype, so the identifiers that would settle it
by string comparison are not there.

So it is asked. An AI pass proposes ``equivalent`` or ``distinct`` for a rule
pair, a person approves or rejects, and only approved rows change grouping
(``load_equivalence_map`` in ``finding_groups``). Four properties matter, in
this order:

*   **Unreviewed has no effect.** AuditBoard issues cannot be deleted and their
    descriptions cannot be edited after create, so a wrong merge permanently
    claims an issue covers a finding it does not describe. A missed merge files
    a duplicate, which a person can see and close. The cheap error is chosen.
*   **Failure keeps scanners separate.** A timeout, an unparseable answer, a
    confidence below the floor: all record ``distinct`` at most, never a merge.
*   **Verdicts are cached at the rule pair.** The question is about two rules,
    not two findings, so 11,517 findings of one defect cost one call. The
    unique constraint on the pair is the cache.
*   **Pairs are blocked before they are asked about.** Only rules that actually
    co-occur on the same normalized path in the same repository are plausible
    candidates, against a cross product in the millions. Measured 2026-09-16:
    **834** such pairs across all severities, **478** of them within the
    Critical/High/Medium floor that group filing is limited to. The severity
    floor is the default, because a pair that can never be filed as a group is
    a call spent on nothing; ``severities=[]`` asks about all 834.

Nothing here writes to AuditBoard, and nothing here files anything. The most it
does is change which findings a future filing would group together, and only
after a human says so.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlalchemy import String, bindparam, func, or_, text
from sqlalchemy.dialects.postgresql import ARRAY
from sqlalchemy.orm import Session

from .. import models
from ..config import settings
from .finding_groups import Identity, normalize_path

logger = logging.getLogger(__name__)


#: Verdicts the AI may return. Anything else is treated as no answer.
VERDICT_EQUIVALENT = "equivalent"
VERDICT_DISTINCT = "distinct"
VERDICTS = (VERDICT_EQUIVALENT, VERDICT_DISTINCT)

#: Review decisions a person may record.
REVIEW_APPROVED = "approved"
REVIEW_REJECTED = "rejected"
REVIEW_DECISIONS = (REVIEW_APPROVED, REVIEW_REJECTED)

#: Below this, an ``equivalent`` proposal is downgraded to ``distinct`` before
#: it is ever shown. Rob Vance's decision, 2026-09-16: keep scanners separate
#: when the model is not sure. A low-confidence merge waved through by a tired
#: reviewer is the failure this guards against.
MIN_CONFIDENCE = 0.80

#: How many sample findings are shown per rule. Enough to see what the rule is
#: about; few enough that one pair is one small prompt.
SAMPLES_PER_RULE = 3


# ---------------------------------------------------------------------------
# Canonical pair ordering
# ---------------------------------------------------------------------------


def canonical_pair(left: Identity, right: Identity) -> Tuple[Identity, Identity]:
    """The pair in stored order, so it cannot be recorded twice reversed.

    Without this, asking about (grype, trivy) and later (trivy, grype) writes
    two rows that can hold opposite verdicts, and which one wins depends on
    query order.
    """
    return (left, right) if left <= right else (right, left)


def pair_key(left: Identity, right: Identity) -> str:
    """Display and de-duplication key for a pair, in canonical order."""
    first, second = canonical_pair(left, right)
    return f"{first.key} <-> {second.key}"


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------


@dataclass
class RuleSample:
    """One finding shown to the model as an example of what a rule reports.

    ``code_snippet`` is deliberately absent. A snippet is not needed to decide
    whether two rules describe the same defect, and for the secret-scanner
    family the snippet is the credential (see ``issue_redaction``).
    """

    title: Optional[str]
    description: Optional[str]
    severity: Optional[str]
    file_path: Optional[str]

    def as_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "description": _clip(self.description, 400),
            "severity": self.severity,
            "file_path": self.file_path,
        }


@dataclass
class CandidatePair:
    """Two rules that co-occur closely enough to be worth asking about."""

    identity_a: Identity
    identity_b: Identity
    #: Distinct repositories where both rules hit the same normalized path.
    shared_repos: int
    #: Distinct (repository, normalized path) places where both hit.
    shared_locations: int
    #: A few of those paths, so a reviewer can see the overlap is real.
    sample_paths: List[str] = field(default_factory=list)
    samples_a: List[RuleSample] = field(default_factory=list)
    samples_b: List[RuleSample] = field(default_factory=list)

    @property
    def key(self) -> str:
        return pair_key(self.identity_a, self.identity_b)

    def evidence(self) -> Dict[str, Any]:
        """What the verdict was based on, stored beside it.

        Kept because a verdict with no record of its inputs cannot be
        re-examined when a model is replaced, and both are then worthless.
        """
        return {
            "shared_repos": self.shared_repos,
            "shared_locations": self.shared_locations,
            "sample_paths": self.sample_paths,
            "samples_a": [s.as_dict() for s in self.samples_a],
            "samples_b": [s.as_dict() for s in self.samples_b],
            "blocking": "same repository, same normalized path, different scanner",
        }


def _clip(value: Optional[str], limit: int) -> Optional[str]:
    if not value:
        return value
    text_value = " ".join(value.split())
    return text_value if len(text_value) <= limit else text_value[: limit - 1] + "…"


#: Normalizes a path in SQL the same way ``normalize_path`` does in Python.
#: Only the scan-directory prefix is stripped: both sides of the join are in
#: the same repository, so stripping the repository name would change both
#: paths identically and cannot change whether they match.
_SQL_NORMALIZED_PATH = "regexp_replace(f.file_path, '^/tmp/repo_scan_[^/]+/', '')"

_CANDIDATE_SQL = text(
    f"""
    WITH scoped AS (
        SELECT DISTINCT
               f.repository_id,
               {_SQL_NORMALIZED_PATH} AS norm_path,
               f.scanner_name,
               f.rule_id
        FROM findings f
        WHERE f.scanner_name IS NOT NULL
          AND f.rule_id IS NOT NULL
          AND f.file_path IS NOT NULL
          AND f.repository_id IS NOT NULL
          AND (:org_id IS NULL OR f.organization_id = CAST(:org_id AS uuid))
          AND (
                NOT :exclude_non_actionable
                OR f.excluded_from_actionable IS NOT TRUE
              )
          -- An empty severity list means every severity, so the count here
          -- and the count a caller asks for cannot come apart.
          AND (
                CARDINALITY(:severities) = 0
                OR LOWER(f.severity) = ANY(:severities)
              )
    )
    SELECT a.scanner_name AS scanner_a,
           a.rule_id      AS rule_a,
           b.scanner_name AS scanner_b,
           b.rule_id      AS rule_b,
           COUNT(DISTINCT a.repository_id) AS shared_repos,
           COUNT(*)                        AS shared_locations,
           (ARRAY_AGG(DISTINCT a.norm_path))[1:3] AS sample_paths
    FROM scoped a
    JOIN scoped b
      ON a.repository_id = b.repository_id
     AND a.norm_path = b.norm_path
     -- Strictly less than: cross-scanner only, and it fixes the stored order.
     -- Two rules of one scanner are that scanner's own taxonomy; merging them
     -- would hide a distinction its authors drew on purpose.
     AND a.scanner_name < b.scanner_name
    GROUP BY 1, 2, 3, 4
    HAVING COUNT(*) >= :min_locations
    ORDER BY COUNT(*) DESC, 1, 2, 3, 4
    LIMIT :limit
    """
).bindparams(bindparam("severities", type_=ARRAY(String)))


def default_severities() -> List[str]:
    """The filing severity floor, which is what candidates default to.

    Read from ``FILING_SEVERITIES`` rather than hard-coded, so the population
    asked about and the population that can be filed as a group stay the same
    list.
    """
    return list(settings.filing_severities_list)


def _candidate_params(
    org_id: Optional[str],
    severities: Optional[Sequence[str]],
    min_locations: int,
    limit: int,
) -> Dict[str, Any]:
    if severities is None:
        severities = default_severities()
    return {
        "org_id": org_id,
        "exclude_non_actionable": bool(settings.FILING_EXCLUDE_NON_ACTIONABLE),
        "severities": [s.strip().lower() for s in severities if s and s.strip()],
        "min_locations": max(1, min_locations),
        "limit": limit,
    }


def count_candidate_pairs(
    db: Session,
    org_id: Optional[str] = None,
    severities: Optional[Sequence[str]] = None,
    min_locations: int = 1,
) -> int:
    """How many blocked pairs exist, asked or not. The denominator."""
    rows = db.execute(
        _CANDIDATE_SQL,
        _candidate_params(org_id, severities, min_locations, 1_000_000),
    ).fetchall()
    return len(rows)


def find_candidate_pairs(
    db: Session,
    org_id: Optional[str] = None,
    limit: int = 50,
    min_locations: int = 1,
    skip_decided: bool = True,
    severities: Optional[Sequence[str]] = None,
) -> List[CandidatePair]:
    """Rule pairs worth asking about, most co-located first.

    ``skip_decided`` drops pairs that already have a row, which is what makes
    the verdict cache a cache: a second run costs only the pairs that appeared
    since the first.
    """
    rows = db.execute(
        _CANDIDATE_SQL,
        _candidate_params(
            org_id,
            severities,
            min_locations,
            # Over-fetch, because already-decided pairs are filtered in Python
            # and would otherwise eat the limit.
            max(limit * 4, limit) if skip_decided else limit,
        ),
    ).fetchall()

    decided = _decided_keys(db, org_id) if skip_decided else set()

    candidates: List[CandidatePair] = []
    for row in rows:
        identity_a = Identity(scanner_name=row.scanner_a, rule_id=row.rule_a)
        identity_b = Identity(scanner_name=row.scanner_b, rule_id=row.rule_b)
        key = pair_key(identity_a, identity_b)
        if key in decided:
            continue
        candidates.append(
            CandidatePair(
                identity_a=identity_a,
                identity_b=identity_b,
                shared_repos=int(row.shared_repos or 0),
                shared_locations=int(row.shared_locations or 0),
                sample_paths=[p for p in (row.sample_paths or []) if p][:3],
            )
        )
        if len(candidates) >= limit:
            break

    for candidate in candidates:
        candidate.samples_a = _samples_for(db, candidate.identity_a, org_id)
        candidate.samples_b = _samples_for(db, candidate.identity_b, org_id)
    return candidates


def _decided_keys(db: Session, org_id: Optional[str]) -> set:
    """Pairs already recorded, by canonical key.

    Every row counts, whatever its verdict or review state. A pending proposal
    is not asked again -- that would spend a call to overwrite an answer a
    reviewer may be part-way through reading.
    """
    query = db.query(
        models.RuleEquivalence.scanner_a,
        models.RuleEquivalence.rule_a,
        models.RuleEquivalence.scanner_b,
        models.RuleEquivalence.rule_b,
    )
    if org_id:
        query = query.filter(
            or_(
                models.RuleEquivalence.organization_id == org_id,
                models.RuleEquivalence.organization_id.is_(None),
            )
        )
    return {
        pair_key(Identity(r[0], r[1]), Identity(r[2], r[3])) for r in query.all()
    }


def _samples_for(
    db: Session, identity: Identity, org_id: Optional[str]
) -> List[RuleSample]:
    query = db.query(
        models.Finding.title,
        models.Finding.description,
        models.Finding.severity,
        models.Finding.file_path,
    ).filter(
        models.Finding.scanner_name == identity.scanner_name,
        models.Finding.rule_id == identity.rule_id,
    )
    if org_id:
        query = query.filter(models.Finding.organization_id == org_id)
    rows = query.limit(SAMPLES_PER_RULE).all()
    return [
        RuleSample(
            title=r[0],
            description=r[1],
            severity=r[2],
            file_path=normalize_path(r[3]),
        )
        for r in rows
    ]


# ---------------------------------------------------------------------------
# The question
# ---------------------------------------------------------------------------


PROMPT_TEMPLATE = """\
You are deciding whether two security scanners reported the SAME defect under \
different rule identifiers, for a GRC issue register.

Answer with JSON only, no prose around it:
{{"verdict": "equivalent" | "distinct", "confidence": 0.0-1.0, "rationale": "one or two sentences"}}

Say "equivalent" only if a remediation engineer fixing one would necessarily \
fix the other, because it is one underlying defect. Say "distinct" if they are \
different defects, different components, or different classes of problem, even \
when they appear in the same file.

Bias toward "distinct". Merging two different defects into one issue makes a \
GRC register claim an issue covers something it does not describe, and it \
cannot be undone. Reporting a duplicate is recoverable.

RULE A
  scanner: {scanner_a}
  rule id: {rule_a}
  examples:
{samples_a}

RULE B
  scanner: {scanner_b}
  rule id: {rule_b}
  examples:
{samples_b}

OVERLAP
  Both rules report findings at the same file path in {shared_repos} \
repository/repositories, at {shared_locations} distinct place(s).
  Example paths: {sample_paths}

Co-location is why you are being asked; it is not evidence of equivalence. Two \
unrelated defects in the same package-lock.json co-locate perfectly.
"""


def build_prompt(candidate: CandidatePair) -> str:
    """The question put to the model for one pair.

    Pure: takes a candidate, returns text. It makes no call and touches no
    database, so what is asked can be tested without a provider.
    """
    first, second = canonical_pair(candidate.identity_a, candidate.identity_b)
    samples = {
        first: candidate.samples_a
        if first == candidate.identity_a
        else candidate.samples_b,
        second: candidate.samples_b
        if second == candidate.identity_b
        else candidate.samples_a,
    }
    return PROMPT_TEMPLATE.format(
        scanner_a=first.scanner_name,
        rule_a=first.rule_id,
        samples_a=_render_samples(samples[first]),
        scanner_b=second.scanner_name,
        rule_b=second.rule_id,
        samples_b=_render_samples(samples[second]),
        shared_repos=candidate.shared_repos,
        shared_locations=candidate.shared_locations,
        sample_paths=", ".join(candidate.sample_paths) or "(none recorded)",
    )


def _render_samples(samples: Sequence[RuleSample]) -> str:
    if not samples:
        return "    (no examples available)"
    lines = []
    for sample in samples:
        lines.append(f"    - title: {sample.title or '(none)'}")
        lines.append(f"      severity: {sample.severity or 'unknown'}")
        lines.append(f"      path: {sample.file_path or '(none)'}")
        if sample.description:
            lines.append(f"      detail: {_clip(sample.description, 400)}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The answer
# ---------------------------------------------------------------------------


@dataclass
class Proposal:
    """A parsed verdict, already downgraded if it did not clear the floor."""

    verdict: str
    confidence: Optional[float]
    rationale: Optional[str]
    #: Set when the answer was changed on the way in, so the reason a merge did
    #: not happen is visible to the reviewer rather than inferred from a number.
    downgraded_from: Optional[str] = None


_JSON_BLOCK = re.compile(r"\{.*\}", re.DOTALL)


def parse_verdict(raw: Optional[str], min_confidence: float = MIN_CONFIDENCE) -> Optional[Proposal]:
    """Read a model's answer, or return None if it did not give one.

    None means "no answer", and the caller records nothing: the pair stays a
    candidate and the scanners stay separate. An unparseable reply is never
    read as a merge, and never as a rejection either -- a rejection is a claim
    too, and one nobody made here.

    An ``equivalent`` verdict below ``min_confidence`` is returned as
    ``distinct`` with ``downgraded_from`` set. The proposal is still recorded,
    because knowing the model was unsure about a pair is worth more than
    silence, and a reviewer can still approve the pair by hand.
    """
    if not raw or not raw.strip():
        return None

    block = _JSON_BLOCK.search(raw)
    if not block:
        return None
    try:
        parsed = json.loads(block.group(0))
    except (ValueError, TypeError):
        return None
    if not isinstance(parsed, dict):
        return None

    verdict = str(parsed.get("verdict", "")).strip().lower()
    if verdict not in VERDICTS:
        return None

    confidence: Optional[float]
    try:
        confidence = float(parsed.get("confidence"))
    except (TypeError, ValueError):
        confidence = None
    if confidence is not None:
        confidence = max(0.0, min(1.0, confidence))

    rationale = parsed.get("rationale")
    rationale = _clip(str(rationale), 1000) if rationale else None

    # A verdict with no confidence is treated as unsure, not as certain.
    if verdict == VERDICT_EQUIVALENT and (
        confidence is None or confidence < min_confidence
    ):
        return Proposal(
            verdict=VERDICT_DISTINCT,
            confidence=confidence,
            rationale=rationale,
            downgraded_from=VERDICT_EQUIVALENT,
        )

    return Proposal(verdict=verdict, confidence=confidence, rationale=rationale)


# ---------------------------------------------------------------------------
# Asking
# ---------------------------------------------------------------------------


async def ask_provider(
    provider,
    candidate: CandidatePair,
    timeout_seconds: float = 90.0,
) -> Optional[Proposal]:
    """Put one pair to a model. Returns None on any failure.

    Every failure mode collapses to the same answer -- no answer -- because
    every one of them has the same correct consequence: the pair is not
    merged, and it stays a candidate so a later run can ask again. A timeout
    is not a verdict.

    ``provider`` is only required to have ``execute_prompt``, which every
    provider in ``src/ai_agent/providers`` implements, so this works whatever
    ``AI_PROVIDER`` is set to and can be tested with a stub.
    """
    prompt = build_prompt(candidate)
    try:
        raw = await asyncio.wait_for(
            provider.execute_prompt(prompt), timeout=timeout_seconds
        )
    except asyncio.TimeoutError:
        logger.warning(
            "Rule-equivalence call timed out after %ss for %s; pair stays separate",
            timeout_seconds,
            candidate.key,
        )
        return None
    except Exception as exc:  # noqa: BLE001 - provider errors are all one case
        logger.warning(
            "Rule-equivalence call failed for %s (%s); pair stays separate",
            candidate.key,
            type(exc).__name__,
        )
        return None

    proposal = parse_verdict(raw if isinstance(raw, str) else str(raw or ""))
    if proposal is None:
        logger.warning(
            "Unparseable rule-equivalence answer for %s; pair stays separate",
            candidate.key,
        )
    return proposal


async def ask_provider_batch(
    provider,
    candidates: Sequence[CandidatePair],
    concurrency: int = 4,
    timeout_seconds: float = 90.0,
) -> List[Tuple[CandidatePair, Optional[Proposal]]]:
    """Ask about several pairs, bounded.

    Bounded because this runs against a shared Azure Foundry deployment that
    the rest of the app also calls; an unbounded fan-out over 478 pairs would
    rate-limit the triage and architecture features at the same time.

    Results come back in the order the candidates were given, not the order
    they finished, so a run is reproducible when read back.
    """
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def one(candidate: CandidatePair):
        async with semaphore:
            return candidate, await ask_provider(provider, candidate, timeout_seconds)

    return list(await asyncio.gather(*(one(c) for c in candidates)))


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def record_proposal(
    db: Session,
    candidate: CandidatePair,
    proposal: Proposal,
    model: Optional[str],
    org_id: Optional[str] = None,
) -> models.RuleEquivalence:
    """Store a proposal in canonical order, unreviewed.

    ``review_decision`` is left null on purpose. Until a person sets it the row
    changes nothing about grouping, which is the whole safety property.
    """
    first, second = canonical_pair(candidate.identity_a, candidate.identity_b)
    evidence = candidate.evidence()
    if proposal.downgraded_from:
        evidence["downgraded_from"] = proposal.downgraded_from
        evidence["min_confidence"] = MIN_CONFIDENCE

    existing = (
        db.query(models.RuleEquivalence)
        .filter(
            models.RuleEquivalence.scanner_a == first.scanner_name,
            models.RuleEquivalence.rule_a == first.rule_id,
            models.RuleEquivalence.scanner_b == second.scanner_name,
            models.RuleEquivalence.rule_b == second.rule_id,
        )
        .first()
    )
    if existing is not None:
        # A reviewed row is left exactly as the reviewer left it. Re-proposing
        # over a human decision would silently reverse it.
        if existing.review_decision:
            return existing
        existing.verdict = proposal.verdict
        existing.confidence = proposal.confidence
        existing.model = model
        existing.rationale = proposal.rationale
        existing.evidence = evidence
        return existing

    row = models.RuleEquivalence(
        organization_id=org_id,
        scanner_a=first.scanner_name,
        rule_a=first.rule_id,
        scanner_b=second.scanner_name,
        rule_b=second.rule_id,
        verdict=proposal.verdict,
        confidence=proposal.confidence,
        model=model,
        rationale=proposal.rationale,
        evidence=evidence,
    )
    db.add(row)
    return row


def record_proposals(
    db: Session,
    results: Iterable[Tuple[CandidatePair, Optional[Proposal]]],
    model: Optional[str],
    org_id: Optional[str] = None,
) -> Dict[str, int]:
    """Store a batch and report what happened, including what was not stored."""
    counts = {"equivalent": 0, "distinct": 0, "downgraded": 0, "no_answer": 0}
    for candidate, proposal in results:
        if proposal is None:
            counts["no_answer"] += 1
            logger.warning(
                "No usable verdict for rule pair %s; scanners stay separate",
                candidate.key,
            )
            continue
        record_proposal(db, candidate, proposal, model, org_id)
        counts[proposal.verdict] += 1
        if proposal.downgraded_from:
            counts["downgraded"] += 1
    return counts


def apply_review(
    db: Session,
    row: models.RuleEquivalence,
    decision: str,
    reviewer: Optional[str],
    note: Optional[str] = None,
) -> models.RuleEquivalence:
    """Record a human decision on a proposal.

    Approving a ``distinct`` row is allowed and means "yes, these really are
    separate" -- it is a decision worth keeping, and it stops the pair coming
    back. Only ``approved`` + ``equivalent`` changes grouping.
    """
    if decision not in REVIEW_DECISIONS:
        raise ValueError(
            f"decision must be one of: {', '.join(REVIEW_DECISIONS)}"
        )
    row.review_decision = decision
    row.reviewed_by = reviewer
    # Database clock, not this container's: reviewed_at is compared against
    # proposed_at, and two clocks would make a review look earlier than the
    # proposal it decided.
    row.reviewed_at = func.now()
    row.review_note = note
    return row


def review_stats(db: Session, org_id: Optional[str] = None) -> Dict[str, int]:
    """Queue depth, so the escalation is visible without reading every row."""
    query = db.query(models.RuleEquivalence)
    if org_id:
        query = query.filter(
            or_(
                models.RuleEquivalence.organization_id == org_id,
                models.RuleEquivalence.organization_id.is_(None),
            )
        )
    rows = query.with_entities(
        models.RuleEquivalence.verdict,
        models.RuleEquivalence.review_decision,
    ).all()

    stats = {
        "total": len(rows),
        "pending": 0,
        "pending_equivalent": 0,
        "approved_equivalent": 0,
        "approved_distinct": 0,
        "rejected": 0,
    }
    for verdict, decision in rows:
        if not decision:
            stats["pending"] += 1
            if verdict == VERDICT_EQUIVALENT:
                stats["pending_equivalent"] += 1
        elif decision == REVIEW_REJECTED:
            stats["rejected"] += 1
        elif verdict == VERDICT_EQUIVALENT:
            stats["approved_equivalent"] += 1
        else:
            stats["approved_distinct"] += 1
    return stats
