"""
Estimate effort for a remediation action.

Rob's instruction was "refer but don't define": the report may say what makes a
piece of work large, and roughly how large, but it must not assert an hour
count it cannot support. So this module does two separate things and keeps them
separate.

**Drivers are measured.** Every value in `EffortDrivers` is counted from the
database or computed from version strings. A driver is a fact and is reported
as one.

**The band is estimated.** S/M/L/XL comes from the drivers by the scoring
function below. It is a judgement with the weights written down, and it is
labelled as an estimate everywhere it renders. It is never multiplied out into
hours, days, or cost, because the measurement that would justify that
conversion — how long past remediations of each band actually took — does not
exist in this system.

Effort is per remediation *action*, never per finding. Upgrading lodash once
fixes forty findings; forty separate estimates would overstate the work by a
factor of forty. Actions roll up to a report total by summing bands per
category, not by summing findings.

See docs/specs/REPORT_GENERATOR_WIZARD_SPEC.md §5.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from src.api.constants.remediation import (
    ROLE_FOR_CATEGORY,
    EffortBand,
    EffortRole,
    RemediationCategory,
)


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

_SEMVER_RE = re.compile(
    r"^[^\d]*(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\.(?P<patch>\d+))?"
)


def _parse_version(value: Optional[str]) -> Optional[tuple[int, int, int]]:
    """Best-effort numeric prefix of a version string. None when unparseable."""
    if not value:
        return None
    match = _SEMVER_RE.match(value.strip())
    if not match:
        return None
    return (
        int(match.group("major")),
        int(match.group("minor") or 0),
        int(match.group("patch") or 0),
    )


def is_major_upgrade(current: Optional[str], fixed: Optional[str]) -> Optional[bool]:
    """
    Whether the jump crosses a major version.

    Returns None — not False — when either version is missing or unparseable.
    The three states matter: a known-minor upgrade is cheap, a known-major
    upgrade is expensive, and an unknown one is a risk that should be visible
    rather than silently scored as cheap.
    """
    left = _parse_version(current)
    right = _parse_version(fixed)
    if left is None or right is None:
        return None
    return right[0] > left[0]


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------


@dataclass
class EffortDrivers:
    """
    What makes this action big or small. Every field is counted, not guessed.

    `unknowns` accumulates the name of each driver that could not be measured.
    It is rendered alongside the band so a reader can see how much of the
    estimate rests on absent data, rather than being handed a band that looks
    equally well-founded either way.
    """

    findings_count: int = 0
    files_count: int = 0
    repos_count: int = 1
    # None = could not be determined. See is_major_upgrade.
    crosses_major_version: Optional[bool] = None
    is_transitive: Optional[bool] = None
    environments: tuple[str, ...] = ()
    roles: tuple[EffortRole, ...] = ()
    unknowns: list[str] = field(default_factory=list)

    @property
    def touches_production(self) -> bool:
        return any(env.lower() in ("prod", "production") for env in self.environments)


def drivers_for_action(
    *,
    category: RemediationCategory,
    findings_count: int,
    distinct_file_paths: int,
    distinct_repos: int,
    current_version: Optional[str] = None,
    fixed_version: Optional[str] = None,
    is_transitive: Optional[bool] = None,
    environments: tuple[str, ...] = (),
) -> EffortDrivers:
    """Assemble the measured drivers, recording what could not be measured."""
    primary, supporting = ROLE_FOR_CATEGORY[category]
    unknowns: list[str] = []

    crosses_major: Optional[bool] = None
    if category in (
        RemediationCategory.UPGRADE_DEPENDENCY,
        RemediationCategory.REMOVE_DEPENDENCY,
    ):
        crosses_major = is_major_upgrade(current_version, fixed_version)
        if crosses_major is None:
            # This is the common case in this estate: fixed_version is not
            # recorded at ingest, so breaking-change risk is unmeasured.
            unknowns.append("whether the upgrade crosses a major version")
        if is_transitive is None:
            unknowns.append("whether the dependency is direct or transitive")

    if not environments:
        unknowns.append("which environments run this code")

    if distinct_file_paths == 0 and category in (
        RemediationCategory.CODE_CHANGE,
        RemediationCategory.CONFIGURE,
    ):
        unknowns.append("how many files the change touches")

    return EffortDrivers(
        findings_count=findings_count,
        files_count=distinct_file_paths,
        repos_count=distinct_repos,
        crosses_major_version=crosses_major,
        is_transitive=is_transitive,
        environments=environments,
        roles=(primary,) + supporting,
        unknowns=unknowns,
    )


# ---------------------------------------------------------------------------
# Band
# ---------------------------------------------------------------------------
#
# The weights. Written as data so they can be argued with in one place, and so
# a report can print the arithmetic behind any band it shows.
#
# The scale is deliberately coarse. A finer one would imply a precision the
# inputs do not have.

_SCORE_THRESHOLDS: tuple[tuple[int, EffortBand], ...] = (
    (3, EffortBand.S),
    (6, EffortBand.M),
    (10, EffortBand.L),
)


@dataclass(frozen=True)
class EffortEstimate:
    """A band, the score behind it, and the reasons that produced the score."""

    band: EffortBand
    score: int
    reasons: tuple[str, ...]
    unknowns: tuple[str, ...]

    @property
    def is_well_founded(self) -> bool:
        """False when any driver could not be measured. Renders next to the band."""
        return not self.unknowns


def estimate(category: RemediationCategory, drivers: EffortDrivers) -> EffortEstimate:
    """
    Score the drivers into a band.

    The returned reasons are the report's justification. A band with no reasons
    is a band nobody can challenge, which is the same as a band nobody should
    believe.
    """
    score = 0
    reasons: list[str] = []

    # Breadth. One finding in one file is small however severe it is; severity
    # drives priority, not effort, and conflating the two is how "critical"
    # comes to mean "hard".
    if drivers.findings_count >= 100:
        score += 3
        reasons.append(f"{drivers.findings_count} findings in this action")
    elif drivers.findings_count >= 10:
        score += 2
        reasons.append(f"{drivers.findings_count} findings in this action")
    elif drivers.findings_count > 1:
        score += 1
        reasons.append(f"{drivers.findings_count} findings in this action")

    if drivers.files_count >= 50:
        score += 3
        reasons.append(f"{drivers.files_count} files affected")
    elif drivers.files_count >= 10:
        score += 2
        reasons.append(f"{drivers.files_count} files affected")
    elif drivers.files_count > 1:
        score += 1
        reasons.append(f"{drivers.files_count} files affected")

    if drivers.repos_count > 1:
        score += 2
        reasons.append(
            f"{drivers.repos_count} repositories, each needing its own review and release"
        )

    # Breaking change.
    if drivers.crosses_major_version is True:
        score += 3
        reasons.append("upgrade crosses a major version, so the API may change")
    elif drivers.crosses_major_version is None and category in (
        RemediationCategory.UPGRADE_DEPENDENCY,
        RemediationCategory.REMOVE_DEPENDENCY,
    ):
        # Unknown is scored as a cost, not as zero. Treating missing data as
        # "no problem" is what makes an estimate optimistic by construction.
        score += 1
        reasons.append("target version unknown, so breaking-change risk is unassessed")

    if drivers.is_transitive is True:
        score += 2
        reasons.append("dependency is transitive, so the fix goes through an intermediate package")

    # Coordination.
    if len(drivers.roles) > 1:
        score += 1
        reasons.append(
            "needs " + " and ".join(role.value for role in drivers.roles)
        )

    if drivers.touches_production:
        score += 1
        reasons.append("code runs in production, so the change needs a release window")

    # Category floors. Some work is never small regardless of how few findings
    # it covers: rotating a live credential is a coordinated outage-risking
    # operation whether it appears once or once hundred times.
    if category == RemediationCategory.ROTATE_SECRET:
        score = max(score, 4)
        reasons.append("secret rotation is coordinated work regardless of finding count")
    elif category == RemediationCategory.REMOVE_DEPENDENCY:
        score = max(score, 6)
        reasons.append("replacing a dependency requires selecting and integrating an alternative")

    band = EffortBand.XL
    for threshold, candidate in _SCORE_THRESHOLDS:
        if score <= threshold:
            band = candidate
            break

    return EffortEstimate(
        band=band,
        score=score,
        reasons=tuple(reasons),
        unknowns=tuple(drivers.unknowns),
    )


def band_label(estimate_: EffortEstimate) -> str:
    """
    How a band renders in a report.

    Always carries the word "estimated", and says so when the inputs were
    incomplete. A bare "L" in a table reads as a measurement.
    """
    text = f"estimated {estimate_.band.value}"
    if not estimate_.is_well_founded:
        text += f" (incomplete inputs: {len(estimate_.unknowns)})"
    return text
