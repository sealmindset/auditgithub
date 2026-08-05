"""
Cross-source arbitration.

Implements docs/playbooks/supply-chain-hunt-ttp.md section 1.2: normalize each claim,
tabulate which sources assert / deny / omit it, classify the result, and escalate
disagreements to tier-0 ground truth.

Two behaviours are deliberate and load-bearing:

1. Omission is not denial. A source that never mentions a package has not cleared it.
   Collapsing those two states is how a real finding gets dropped.
2. Hunt the union, report the arbitrated set. Querying for an unverified indicator is
   cheap; a false negative is not. So everything claimed goes into the hunt scope,
   while only tier-0-confirmed claims reach the verdict.
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional

from .sources import SOURCES, Tier

logger = logging.getLogger(__name__)


class Stance(str, Enum):
    ASSERT = "assert"
    DENY = "deny"
    OMIT = "omit"


class Resolution(str, Enum):
    CONSENSUS = "consensus"                # all asserting sources agree, no denials
    DISAGREEMENT = "disagreement"          # sources conflict; tier 0 decides
    SINGLE_SOURCE = "single_source"        # one source only; unverified
    UNSUPPORTED = "unsupported"            # no source addressed it at all
    GROUND_TRUTH_ONLY = "ground_truth_only"  # registry established it; no vendor said so


class ClaimType(str, Enum):
    MALICIOUS_VERSION = "malicious_version"
    AFFECTED_PACKAGE = "affected_package"
    TIMESTAMP = "timestamp"
    IOC_HASH = "ioc_hash"
    IOC_FILENAME = "ioc_filename"
    IOC_NETWORK = "ioc_network"
    IOC_MARKER = "ioc_marker"          # e.g. dead-drop repo description strings
    PERSISTENCE = "persistence"
    SCOPE_COUNT = "scope_count"
    MITIGATION = "mitigation"
    SAFE_VERSION = "safe_version"


@dataclass
class Assertion:
    """One source's position on one claim."""

    source_id: str
    stance: Stance
    value: Optional[Any] = None   # the source's own value, when it differs
    detail: str = ""

    @property
    def tier(self) -> Tier:
        source = SOURCES.get(self.source_id)
        return source.tier if source else Tier.PRESS


@dataclass
class Claim:
    """A normalized, comparable assertion about the incident."""

    claim_type: ClaimType
    subject: str                  # e.g. "keyv" or "first_malicious_publish"
    value: Optional[Any] = None   # e.g. "6.0.0" or an ISO timestamp
    assertions: List[Assertion] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.claim_type.value}:{self.subject}:{self.value}"

    def add(self, source_id: str, stance: Stance, value: Any = None, detail: str = "") -> "Claim":
        self.assertions.append(Assertion(source_id, stance, value, detail))
        return self


@dataclass
class ArbitrationResult:
    claim: Claim
    resolution: Resolution
    accepted: bool
    accepted_value: Optional[Any]
    ground_truth_value: Optional[Any] = None
    ground_truth_url: Optional[str] = None
    asserting: List[str] = field(default_factory=list)
    denying: List[str] = field(default_factory=list)
    omitting: List[str] = field(default_factory=list)
    conflicting_values: Dict[str, Any] = field(default_factory=dict)
    # Sources proven wrong by tier 0. Recorded so the next run starts calibrated.
    incorrect_sources: List[str] = field(default_factory=list)
    rationale: str = ""
    in_hunt_scope: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "claim_type": self.claim.claim_type.value,
            "subject": self.claim.subject,
            "claimed_value": self.claim.value,
            "resolution": self.resolution.value,
            "accepted": self.accepted,
            "accepted_value": self.accepted_value,
            "ground_truth_value": self.ground_truth_value,
            "ground_truth_url": self.ground_truth_url,
            "asserting": self.asserting,
            "denying": self.denying,
            "omitting": self.omitting,
            "conflicting_values": self.conflicting_values,
            "incorrect_sources": self.incorrect_sources,
            "rationale": self.rationale,
            "in_hunt_scope": self.in_hunt_scope,
        }


def arbitrate(
    claim: Claim,
    ground_truth: Optional[Callable[[Claim], Dict[str, Any]]] = None,
) -> ArbitrationResult:
    """
    Resolve a single claim.

    ground_truth is an optional callable returning
        {"resolved": bool, "value": Any, "url": str, "detail": str}
    It is consulted whenever sources disagree, and opportunistically otherwise so a
    consensus can still be contradicted by the registry.
    """
    asserting = [a for a in claim.assertions if a.stance == Stance.ASSERT]
    denying = [a for a in claim.assertions if a.stance == Stance.DENY]
    omitting = [a for a in claim.assertions if a.stance == Stance.OMIT]

    conflicting: Dict[str, Any] = {
        a.source_id: a.value for a in asserting
        if a.value is not None and a.value != claim.value
    }

    has_conflict = bool(denying) or bool(conflicting)

    gt: Dict[str, Any] = {}
    if ground_truth and (has_conflict or asserting):
        try:
            gt = ground_truth(claim) or {}
        except Exception as exc:
            logger.warning(f"Ground-truth lookup failed for {claim.key}: {exc}")
            gt = {}

    gt_resolved = bool(gt.get("resolved"))
    gt_value = gt.get("value")
    gt_url = gt.get("url")

    # --- classify -----------------------------------------------------------
    if not asserting and not denying:
        resolution = Resolution.GROUND_TRUTH_ONLY if gt_resolved else Resolution.UNSUPPORTED
    elif has_conflict:
        resolution = Resolution.DISAGREEMENT
    elif len(asserting) == 1:
        resolution = Resolution.SINGLE_SOURCE
    else:
        resolution = Resolution.CONSENSUS

    # --- resolve ------------------------------------------------------------
    incorrect: List[str] = []
    rationale = ""

    if gt_resolved:
        # Tier 0 decides, unconditionally. This is the whole point of the tiering.
        accepted = bool(gt_value) if isinstance(gt_value, bool) else gt_value is not None
        accepted_value = gt_value

        for a in denying:
            if accepted:
                incorrect.append(a.source_id)
        for a in asserting:
            if not accepted:
                incorrect.append(a.source_id)
            elif a.value is not None and gt_value is not None and a.value != gt_value:
                incorrect.append(a.source_id)

        if incorrect:
            rationale = (
                f"Escalated to tier-0 ground truth, which resolved to {gt_value!r}. "
                f"Contradicted by: {', '.join(sorted(set(incorrect)))}. "
                f"{gt.get('detail', '')}".strip()
            )
        else:
            rationale = (
                f"Confirmed against tier-0 ground truth ({gt_value!r}). {gt.get('detail', '')}"
            ).strip()

    elif resolution == Resolution.CONSENSUS:
        accepted = True
        accepted_value = claim.value
        rationale = (
            f"Consensus across {len(asserting)} sources with no denials, but not verified "
            "against tier 0 — no registry oracle applies to this claim type."
        )

    elif resolution == Resolution.SINGLE_SOURCE:
        accepted = False
        accepted_value = claim.value
        rationale = (
            f"Asserted only by {asserting[0].source_id} and unverified. Included in hunt scope "
            "because querying is cheap, but must not be reported as established."
        )

    elif resolution == Resolution.DISAGREEMENT:
        accepted = False
        accepted_value = None
        rationale = (
            "Sources conflict and tier-0 ground truth could not resolve it. Report as "
            "unresolved; do not average or pick a favourite vendor."
        )

    else:  # UNSUPPORTED
        accepted = False
        accepted_value = None
        rationale = "No source addressed this claim."

    return ArbitrationResult(
        claim=claim,
        resolution=resolution,
        accepted=accepted,
        accepted_value=accepted_value,
        ground_truth_value=gt_value,
        ground_truth_url=gt_url,
        asserting=[a.source_id for a in asserting],
        denying=[a.source_id for a in denying],
        omitting=[a.source_id for a in omitting],
        conflicting_values=conflicting,
        incorrect_sources=sorted(set(incorrect)),
        rationale=rationale,
        # Everything claimed by anyone gets hunted, accepted or not.
        in_hunt_scope=bool(asserting) or accepted,
    )


def arbitrate_all(
    claims: List[Claim],
    ground_truth: Optional[Callable[[Claim], Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Arbitrate a set of claims and summarize.

    Returns both the per-claim results and the two lists a hunt actually consumes:
    hunt_scope (query for all of these) and verdict_set (report only these).
    """
    results = [arbitrate(claim, ground_truth) for claim in claims]

    by_resolution: Dict[str, int] = {}
    for r in results:
        by_resolution[r.resolution.value] = by_resolution.get(r.resolution.value, 0) + 1

    scorecard: Dict[str, Dict[str, int]] = {}
    for r in results:
        for source_id in r.incorrect_sources:
            scorecard.setdefault(source_id, {"incorrect": 0, "correct": 0})["incorrect"] += 1
        for source_id in r.asserting:
            if r.accepted and source_id not in r.incorrect_sources:
                scorecard.setdefault(source_id, {"incorrect": 0, "correct": 0})["correct"] += 1

    disagreements = [r.to_dict() for r in results if r.resolution == Resolution.DISAGREEMENT
                     or r.incorrect_sources]

    return {
        "results": [r.to_dict() for r in results],
        "by_resolution": by_resolution,
        "hunt_scope": [r.claim.key for r in results if r.in_hunt_scope],
        "verdict_set": [r.claim.key for r in results if r.accepted],
        "unverified": [r.claim.key for r in results if not r.accepted and r.in_hunt_scope],
        "disagreements": disagreements,
        "source_scorecard": scorecard,
        "source_urls": {
            source_id: SOURCES[source_id].url
            for r in results for source_id in (r.asserting + r.denying)
            if source_id in SOURCES
        },
    }
