"""How findings become one GRC issue. The filing principle, in one place.

Decided by Rob Vance on 2026-09-16 and recorded here because it governs what
leaves this system: an AuditBoard issue cannot be deleted and its description
cannot be edited after create, so a grouping mistake is permanent in someone
else's system of record.

The principle
-------------

One issue per **defect per project**, listing every place inside that project
where the defect was found. Not one issue per finding, and not one issue per
file path.

Why not per finding: the same defect repeats. ``grype`` reported 11,517
findings against ``/package-lock.json`` alone. Filing those individually would
bury the register.

Why not per file path — which is what this app did until now: the old key was
``(scanner_name, file_path)``, and every npm project on earth has a
``package-lock.json``. That key merged 11,517 findings across 100+ unrelated
projects and 1,287 different CVEs into a single "group" that described none of
them, while splitting one CVE across every project it touched. It was wrong in
both directions at once.

The key is therefore the defect's identity and the project it lives in.

Tiers
-----

``SPECIFIC``  one finding. Kept for reporting a single instance deliberately.
``PROJECT``   one defect in one project, every location listed. The default.
``ORG``       one defect across all projects, projects and their locations
              listed. Used when the defect is too widespread to be any one
              team's to own.

The escalation from PROJECT to ORG is by volume, at
``settings.FILING_PROJECT_ESCALATION_THRESHOLD`` projects (10). Measured
2026-09-16 over the critical tier: of 268 distinct critical defects, 125 touch
a single project, 94 touch two or three, 34 touch four to ten, and 15 touch
more than ten — and those 15 account for 25,274 findings. So the threshold
leaves 253 defects owned by the team that can fix them and stops the other 15
from filing a hundred records each.

Identity
--------

``(scanner_name, rule_id)``. ``rule_id`` is populated on 100% of findings from
all ten scanners in this instance, which no other candidate column is:
``cve_id`` is empty everywhere, ``ghsa_id`` only on grype.

Two scanners reporting the same defect are one defect, but only when a human
has approved that claim. See :func:`canonical_identity` — the AI proposes,
the reviewer decides, and an unreviewed pair stays separate. Guessing the
merge would hide a finding inside an issue that does not describe it, and
that error cannot be corrected later.

Paths
-----

75% of findings in this instance (573,526 of 767,974) carry a per-scan
``/tmp/repo_scan_<hash>/<repo>/`` prefix. It is scan scaffolding, not part of
the defect's location: it changes on every scan, so anything keyed on or
printed from the raw path silently stops matching after a rescan and shows a
reader a directory that no longer exists. :func:`normalize_path` removes it.
Verified against all 573,526 affected rows — the segment following the hash is
the repository name in every case.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Iterable, List, Optional, Sequence, Set, Tuple

# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

#: Ascending. Index is the comparison, so "highest wins" is a max().
SEVERITY_ORDER: Tuple[str, ...] = ("info", "low", "medium", "high", "critical")

_SEVERITY_RANK: Dict[str, int] = {name: i for i, name in enumerate(SEVERITY_ORDER)}


def severity_rank(severity: Optional[str]) -> int:
    """Rank for comparison. Unknown severities sort lowest, never highest.

    An unrecognised value must not win a max() and promote a group to
    critical on the strength of a typo.
    """
    return _SEVERITY_RANK.get((severity or "").strip().lower(), -1)


def highest_severity(severities: Iterable[Optional[str]]) -> Optional[str]:
    """The most severe of several ratings.

    Used when scanners that a reviewer merged disagree: the group carries the
    worst rating any contributing scanner gave it, and the issue body still
    names each scanner's own rating so the disagreement stays visible.
    Under-rating a defect in a GRC register is the more expensive error.
    """
    best: Optional[str] = None
    best_rank = -1
    for value in severities:
        rank = severity_rank(value)
        if rank > best_rank:
            best_rank = rank
            best = (value or "").strip().lower() or None
    return best


# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

#: The scan working directory. ``<repo>`` is captured only to be discarded —
#: it is verified to be the repository name, so keeping it would print the
#: project twice in a location list that is already scoped to one project.
_SCAN_PREFIX = re.compile(r"^/tmp/repo_scan_[^/]+/")


def normalize_path(file_path: Optional[str], repo_name: Optional[str] = None) -> Optional[str]:
    """Repo-relative path, free of per-scan scaffolding.

    ``repo_name`` is used only to strip the repository directory that the
    scanner cloned into. It is optional because 25% of findings have clean
    paths already, and because a caller that does not know the repository
    should still get the ``/tmp`` prefix removed.

    Returns None only for a missing path. An empty result after stripping is
    returned as the original value rather than an empty string, so a location
    list never contains a blank line.
    """
    if not file_path:
        return None

    path = file_path.strip()
    if not path:
        return None

    # Whether the prefix was there is tested explicitly, not inferred from
    # re.sub returning a different object — it is not documented to.
    in_scan_dir = bool(_SCAN_PREFIX.match(path))
    stripped = _SCAN_PREFIX.sub("", path) if in_scan_dir else path
    if in_scan_dir and repo_name:
        # Only inside a scan directory is the leading segment known to be the
        # repository. A clean path may legitimately begin with a directory
        # that happens to share the repository's name.
        prefix = f"{repo_name}/"
        if stripped.startswith(prefix):
            stripped = stripped[len(prefix):]

    stripped = stripped.lstrip("/")
    return stripped or path


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------


@dataclass(frozen=True, order=True)
class Identity:
    """What makes two findings the same defect.

    Ordered so a set of identities has a deterministic minimum, which is how
    a merged group picks its canonical member without needing a stored
    preference.
    """

    scanner_name: str
    rule_id: str

    @property
    def key(self) -> str:
        """Stable string form, for a group key or a label."""
        return f"{self.scanner_name}::{self.rule_id}"

    def __str__(self) -> str:  # pragma: no cover - display only
        return self.key


def identity_of(finding) -> Optional[Identity]:
    """Identity of a finding, or None when it cannot be grouped.

    A finding with no ``rule_id`` has no defect identity, so it can only be
    filed as SPECIFIC. None of the 767,974 findings in this instance are in
    that state, but a new scanner could be, and a silent fallback to grouping
    by title would merge unrelated defects.
    """
    scanner = (getattr(finding, "scanner_name", None) or "").strip()
    rule = (getattr(finding, "rule_id", None) or "").strip()
    if not scanner or not rule:
        return None
    return Identity(scanner_name=scanner, rule_id=rule)


class EquivalenceMap:
    """Approved cross-scanner merges, as a union-find over identities.

    Holds only pairs a human approved. An AI proposal that nobody has looked
    at is absent from this map, which is what makes "unreviewed stays
    separate" the default rather than a code path someone has to remember.

    The canonical member of a merged set is its lexicographic minimum. That
    keeps the group key stable no matter which member a filer happened to have
    open, and needs no extra stored state to stay consistent.
    """

    def __init__(self, approved_pairs: Iterable[Tuple[Identity, Identity]] = ()) -> None:
        self._parent: Dict[Identity, Identity] = {}
        for left, right in approved_pairs:
            self.union(left, right)

    def _find(self, item: Identity) -> Identity:
        root = self._parent.get(item, item)
        if root == item:
            return item
        resolved = self._find(root)
        self._parent[item] = resolved
        return resolved

    def union(self, left: Identity, right: Identity) -> None:
        a, b = self._find(left), self._find(right)
        if a == b:
            return
        # Smaller identity becomes the root, so canonical() is the set minimum.
        low, high = sorted((a, b))
        self._parent[high] = low

    def canonical(self, item: Identity) -> Identity:
        """Identity this one files under. Itself, when nothing is merged to it."""
        return self._find(item)

    def members(self, item: Identity) -> List[Identity]:
        """Every identity that files under the same canonical identity.

        Includes ``item``. Sorted, so an issue body lists contributing
        scanners in the same order every time it is generated.
        """
        root = self.canonical(item)
        found = {root} | {i for i in self._parent if self._find(i) == root}
        found.add(item)
        return sorted(found)

    def is_merged(self, item: Identity) -> bool:
        return len(self.members(item)) > 1

    def __len__(self) -> int:
        return len(self._parent)


def canonical_identity(
    finding, equivalence: Optional[EquivalenceMap] = None
) -> Optional[Identity]:
    """Identity a finding files under, after approved cross-scanner merges.

    With no map, or an unreviewed rule, this is the finding's own identity.
    """
    identity = identity_of(finding)
    if identity is None or equivalence is None:
        return identity
    return equivalence.canonical(identity)


# ---------------------------------------------------------------------------
# Tiers
# ---------------------------------------------------------------------------


class GroupTier(str, Enum):
    """Scope an issue speaks at. The wire value is the string."""

    SPECIFIC = "specific"
    PROJECT = "project"
    ORG = "org"

    #: A set of findings someone ticked by hand. Unlike every other tier this
    #: one is not a rule, so it cannot be derived from a finding — the
    #: membership is written to ``auditboard_issue_findings`` at filing time and
    #: read back from there. It is therefore absent from
    #: :data:`FILEABLE_TIERS`, which answers "what may the per-finding endpoint
    #: file at?"; selections are filed through their own endpoint, which is
    #: given the member list explicitly.
    SELECTION = "selection"

    #: The pre-2026-09-16 key, ``(scanner_name, file_path)``. Retained only so
    #: issues filed before the principle changed keep matching their findings;
    #: nothing new is filed at this tier. Removing it would make four already
    #: filed issues look unfiled and invite duplicates.
    LEGACY_GLOBAL = "global"


#: Tiers a caller may ask to file at. LEGACY_GLOBAL is readable, not writable.
FILEABLE_TIERS: Tuple[GroupTier, ...] = (
    GroupTier.SPECIFIC,
    GroupTier.PROJECT,
    GroupTier.ORG,
)


def recommended_tier(project_count: int, threshold: int) -> GroupTier:
    """PROJECT, until a defect is too widespread for one team to own.

    ``project_count`` is measured, not estimated. A defect in a single project
    is still PROJECT rather than SPECIFIC: the issue should speak for every
    location in that project, which is the whole point of the change.
    """
    if project_count > max(1, threshold):
        return GroupTier.ORG
    return GroupTier.PROJECT


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------


@dataclass
class Location:
    """One place a defect was found, as a reader can act on it."""

    path: str
    #: Occurrences at this path. A file can hold the same defect many times.
    count: int = 1
    #: Lowest line number seen, when any scanner reported one. Line 0 is what
    #: several scanners emit for "file-level", and is not shown.
    line: Optional[int] = None

    def render(self) -> str:
        parts = [self.path]
        if self.line:
            parts.append(f":{self.line}")
        if self.count > 1:
            parts.append(f" ({self.count} occurrences)")
        return "".join(parts)


@dataclass
class ProjectLocations:
    """Every location of one defect inside one project."""

    repo_name: str
    locations: List[Location] = field(default_factory=list)
    #: Findings behind those locations, which exceeds len(locations) whenever
    #: a file holds the defect more than once.
    finding_count: int = 0

    @property
    def location_count(self) -> int:
        return len(self.locations)


def collect_locations(
    rows: Sequence[Tuple[Optional[str], Optional[str], Optional[str], int]],
) -> List[ProjectLocations]:
    """Group ``(repo_name, file_path, line_start, count)`` rows into projects.

    Takes pre-aggregated rows rather than finding objects: the largest group
    in this instance is 11,517 findings, and loading those to count paths
    would be work the database has already done.

    Paths are normalized here, which can merge rows the SQL treated as
    distinct — two scans of the same file under different temp directories.
    Their counts are summed rather than one overwriting the other.
    """
    by_repo: Dict[str, Dict[str, Location]] = {}
    totals: Dict[str, int] = {}

    for repo_name, file_path, line_start, count in rows:
        repo = (repo_name or "unknown project").strip() or "unknown project"
        path = normalize_path(file_path, repo)
        if not path:
            continue

        # Scanners store line_start as text, and several use "0" for
        # file-level. Anything non-numeric is dropped rather than guessed.
        line: Optional[int] = None
        try:
            parsed = int(str(line_start).strip())
            line = parsed if parsed > 0 else None
        except (TypeError, ValueError):
            line = None

        bucket = by_repo.setdefault(repo, {})
        totals[repo] = totals.get(repo, 0) + int(count or 0)

        existing = bucket.get(path)
        if existing is None:
            bucket[path] = Location(path=path, count=int(count or 0), line=line)
            continue

        existing.count += int(count or 0)
        if line is not None and (existing.line is None or line < existing.line):
            existing.line = line

    projects: List[ProjectLocations] = []
    for repo, paths in by_repo.items():
        projects.append(
            ProjectLocations(
                repo_name=repo,
                locations=sorted(paths.values(), key=lambda loc: loc.path),
                finding_count=totals.get(repo, 0),
            )
        )
    # Worst first: the project with the most work to do leads the issue.
    projects.sort(key=lambda p: (-p.finding_count, p.repo_name))
    return projects


def render_locations(
    projects: Sequence[ProjectLocations],
    tier: GroupTier,
    max_locations: int,
) -> str:
    """The location section of an issue body.

    Capped, because the cap is load-bearing: the largest group in this
    instance resolves to 1,005 distinct paths, which would push the rest of
    the issue past AuditBoard's description limit. Only 8 of 10,367 groups
    exceed 100 paths, so the cap almost never fires — and when it does, the
    line says how many were omitted rather than trailing off, so a reader
    knows to come back here for the full list.
    """
    if not projects:
        return "Locations\nNone recorded."

    lines: List[str] = []
    remaining = max(1, max_locations)
    omitted = 0

    for project in projects:
        # ORG and SELECTION both span projects, so both need the project named
        # above its paths. Without it a reader gets a flat list of file paths
        # with no way to tell which repository each one is in — and for a
        # selection that is the common case, because the whole reason to tick
        # rows by hand is to gather findings that no single rule groups.
        if tier in (GroupTier.ORG, GroupTier.SELECTION):
            lines.append(
                f"{project.repo_name} — {project.finding_count} finding(s) "
                f"in {project.location_count} location(s)"
            )
            indent = "  - "
        else:
            indent = "- "

        for location in project.locations:
            if remaining <= 0:
                omitted += 1
                continue
            lines.append(f"{indent}{location.render()}")
            remaining -= 1

    heading = "Locations in this project" if tier == GroupTier.PROJECT else "Locations"
    if omitted:
        lines.append(
            f"… and {omitted} further location(s) not listed. "
            "The full list is in AuditGitHub."
        )
    return f"{heading}\n" + "\n".join(lines)


# ---------------------------------------------------------------------------
# Queries
#
# The pure functions above decide the rules; these read the database to apply
# them. Kept in one module so a caller cannot pick up the key without the
# population it implies, which is how the old duplicated grouping drifted.
# ---------------------------------------------------------------------------

from sqlalchemy import and_, false, func, or_, select, tuple_  # noqa: E402  (grouped with its users)
from sqlalchemy.orm import Session  # noqa: E402

from .. import models  # noqa: E402
from ..config import settings  # noqa: E402


def load_equivalence_map(db: Session, org_id: Optional[str] = None) -> EquivalenceMap:
    """Approved cross-scanner merges for this organization.

    Only ``approved`` + ``equivalent`` rows are read. Pending proposals and
    rejections are deliberately invisible here: an unreviewed pair must behave
    exactly as if the AI had never run.
    """
    query = db.query(models.RuleEquivalence).filter(
        models.RuleEquivalence.review_decision == "approved",
        models.RuleEquivalence.verdict == "equivalent",
    )
    if org_id:
        query = query.filter(
            or_(
                models.RuleEquivalence.organization_id == org_id,
                models.RuleEquivalence.organization_id.is_(None),
            )
        )

    pairs: List[Tuple[Identity, Identity]] = []
    for row in query.all():
        pairs.append(
            (
                Identity(scanner_name=row.scanner_a, rule_id=row.rule_a),
                Identity(scanner_name=row.scanner_b, rule_id=row.rule_b),
            )
        )
    return EquivalenceMap(pairs)


def _identity_filter(identities: Sequence[Identity]):
    """SQL for "any of these (scanner, rule) pairs".

    A row-value IN is used rather than an OR chain so the planner can use the
    composite index, and so a group merged across four scanners does not build
    a four-clause disjunction per query.
    """
    return tuple_(models.Finding.scanner_name, models.Finding.rule_id).in_(
        [(i.scanner_name, i.rule_id) for i in identities]
    )


def _base_population_query(db: Session, identities: Sequence[Identity], org_id: Optional[str]):
    query = db.query(models.Finding).filter(_identity_filter(identities))
    if org_id:
        query = query.filter(models.Finding.organization_id == org_id)
    if settings.FILING_EXCLUDE_NON_ACTIONABLE:
        # Findings this app already ruled out of the work list do not become
        # GRC work. 546,977 of 767,974 findings carry an exclusion reason.
        query = query.filter(
            or_(
                models.Finding.excluded_from_actionable.is_(False),
                models.Finding.excluded_from_actionable.is_(None),
            )
        )
    return query


@dataclass
class GroupPopulation:
    """Everything an issue at a given tier speaks for, measured not estimated."""

    tier: GroupTier
    identity: Identity
    #: Every identity filing under this one, including itself. Longer than one
    #: only where a reviewer approved a cross-scanner merge.
    members: List[Identity]
    finding_count: int
    project_count: int
    projects: List[ProjectLocations]
    #: Highest severity among the findings in scope.
    severity: Optional[str]
    #: (scanner, severity, count), so an issue can show where scanners
    #: disagreed rather than silently resolving it.
    severity_breakdown: List[Tuple[str, str, int]]
    org_scoped: bool
    #: True when the measured spread exceeded the escalation threshold, so a
    #: caller filing at PROJECT tier can be told the defect is wider.
    exceeds_threshold: bool

    @property
    def location_count(self) -> int:
        return sum(p.location_count for p in self.projects)

    @property
    def repo_names(self) -> List[str]:
        return [p.repo_name for p in self.projects]


def measure_group(
    db: Session,
    finding,
    tier: GroupTier,
    equivalence: Optional[EquivalenceMap] = None,
    org_id: Optional[str] = None,
) -> Optional[GroupPopulation]:
    """Measure the population an issue at ``tier`` would cover.

    Read-only. Returns None when the finding has no defect identity, which is
    the caller's signal that only SPECIFIC filing is available.

    ``project_count`` is always measured across the whole organization even
    when ``tier`` is PROJECT, because it is what decides whether the defect
    should have been escalated — a figure taken inside one project could never
    exceed one.
    """
    identity = identity_of(finding)
    if identity is None:
        return None

    equivalence = equivalence or EquivalenceMap()
    canonical = equivalence.canonical(identity)
    members = equivalence.members(identity)

    spread_query = _base_population_query(db, members, org_id)
    project_count = (
        spread_query.with_entities(
            func.count(func.distinct(models.Finding.repository_id))
        ).scalar()
        or 0
    )

    scoped = spread_query
    if tier == GroupTier.PROJECT:
        scoped = scoped.filter(models.Finding.repository_id == finding.repository_id)
    elif tier == GroupTier.SPECIFIC:
        scoped = scoped.filter(models.Finding.id == finding.id)

    finding_count = scoped.with_entities(func.count(models.Finding.id)).scalar() or 0

    location_rows = (
        scoped.join(models.Repository, models.Finding.repository_id == models.Repository.id)
        .with_entities(
            models.Repository.name,
            models.Finding.file_path,
            models.Finding.line_start,
            func.count(models.Finding.id),
        )
        .group_by(models.Repository.name, models.Finding.file_path, models.Finding.line_start)
        .all()
    )
    projects = collect_locations([tuple(row) for row in location_rows])

    breakdown_rows = (
        scoped.with_entities(
            models.Finding.scanner_name,
            models.Finding.severity,
            func.count(models.Finding.id),
        )
        .group_by(models.Finding.scanner_name, models.Finding.severity)
        .all()
    )
    breakdown = sorted(
        ((r[0] or "unknown", r[1] or "unknown", int(r[2])) for r in breakdown_rows),
        key=lambda r: (-severity_rank(r[1]), r[0]),
    )

    return GroupPopulation(
        tier=tier,
        identity=canonical,
        members=members,
        finding_count=finding_count,
        project_count=project_count,
        projects=projects,
        severity=highest_severity(r[1] for r in breakdown) or finding.severity,
        severity_breakdown=breakdown,
        org_scoped=bool(org_id),
        exceeds_threshold=project_count > max(1, settings.FILING_PROJECT_ESCALATION_THRESHOLD),
    )


def _scoped_population_query(
    db: Session,
    finding,
    tier: GroupTier,
    members: Sequence[Identity],
    org_id: Optional[str],
):
    """The rows at ``tier``, filtered the same way ``measure_group`` filters.

    Shared so a second question about the same group cannot be asked of a
    different population than the one the issue was measured from.
    """
    query = _base_population_query(db, members, org_id)
    if tier == GroupTier.PROJECT:
        query = query.filter(models.Finding.repository_id == finding.repository_id)
    elif tier == GroupTier.SPECIFIC:
        query = query.filter(models.Finding.id == finding.id)
    return query


@dataclass
class SelectionPopulation:
    """What an issue filed from ticked rows would cover.

    Deliberately not a :class:`GroupPopulation`. That class has one ``identity``
    because every tier it describes *is* one defect; a selection can hold as
    many defects as the person ticked, and collapsing them to a single identity
    would let the issue claim a key it does not have.
    """

    #: Findings that exist and were resolved from the submitted ids.
    finding_count: int
    project_count: int
    projects: List[ProjectLocations]
    #: Every distinct defect in the selection, ordered for a stable rendering.
    identities: List[Identity]
    severity: Optional[str]
    severity_breakdown: List[Tuple[str, str, int]]
    #: Ids submitted that matched no finding. Reported rather than ignored:
    #: filing a permanent record for a set smaller than the one the filer
    #: believed they picked is the failure this whole flow exists to avoid.
    missing_ids: List[str]
    #: Selected findings the filing policy would refuse on their own, with the
    #: reason. Not removed here -- the caller decides whether to refuse the
    #: whole selection or file the rest, and needs to see them either way.
    ineligible: List[Tuple[str, str]]

    @property
    def location_count(self) -> int:
        return sum(p.location_count for p in self.projects)

    @property
    def repo_names(self) -> List[str]:
        return [p.repo_name for p in self.projects]


def measure_selection(
    db: Session,
    finding_ids: Sequence[str],
    org_id: Optional[str] = None,
) -> SelectionPopulation:
    """Measure exactly the findings whose ids were submitted. Read-only.

    No identity is derived and no group is expanded: a selection covers what was
    ticked and nothing else. Sibling findings of the same defect are *not*
    pulled in, because the person looking at the table chose these rows, and
    silently widening a permanent record beyond the choice is the same defect as
    the file-path grouping this replaced.
    """
    ids = [str(i) for i in finding_ids]
    unique_ids = list(dict.fromkeys(ids))
    if not unique_ids:
        return SelectionPopulation(
            finding_count=0,
            project_count=0,
            projects=[],
            identities=[],
            severity=None,
            severity_breakdown=[],
            missing_ids=[],
            ineligible=[],
        )

    query = db.query(models.Finding).filter(models.Finding.id.in_(unique_ids))
    if org_id:
        query = query.filter(models.Finding.organization_id == org_id)

    rows = query.all()
    found_ids = {str(r.id) for r in rows}
    missing = [i for i in unique_ids if i not in found_ids]

    ineligible: List[Tuple[str, str]] = []
    for row in rows:
        ok, reason = is_filing_eligible(row)
        if not ok:
            ineligible.append((str(row.id), reason or "not eligible"))

    location_rows = (
        query.join(models.Repository, models.Finding.repository_id == models.Repository.id)
        .with_entities(
            models.Repository.name,
            models.Finding.file_path,
            models.Finding.line_start,
            func.count(models.Finding.id),
        )
        .group_by(models.Repository.name, models.Finding.file_path, models.Finding.line_start)
        .all()
    )
    projects = collect_locations([tuple(r) for r in location_rows])

    breakdown_rows = (
        query.with_entities(
            models.Finding.scanner_name,
            models.Finding.severity,
            func.count(models.Finding.id),
        )
        .group_by(models.Finding.scanner_name, models.Finding.severity)
        .all()
    )
    breakdown = sorted(
        ((r[0] or "unknown", r[1] or "unknown", int(r[2])) for r in breakdown_rows),
        key=lambda r: (-severity_rank(r[1]), r[0]),
    )

    identities = sorted(
        {i for i in (identity_of(r) for r in rows) if i is not None},
        key=lambda i: (i.scanner_name, i.rule_id),
    )

    project_count = len({r.repository_id for r in rows if r.repository_id is not None})

    return SelectionPopulation(
        finding_count=len(rows),
        project_count=project_count,
        projects=projects,
        identities=identities,
        # Highest severity among the members, which is Rob's decision 8 applied
        # to a set rather than to a merge: understating severity in a permanent
        # register entry is the more expensive mistake.
        severity=highest_severity(r[1] for r in breakdown),
        severity_breakdown=breakdown,
        missing_ids=missing,
        ineligible=ineligible,
    )


def earliest_identified_date(
    db: Session,
    finding,
    population: GroupPopulation,
    org_id: Optional[str] = None,
):
    """Oldest first-seen date in the group, as a ``date``, or None.

    The identified date of a grouped issue is when the *defect* was first seen,
    not when the finding the filer happened to click was first seen. Using the
    clicked finding would date a two-year-old defect to whichever project was
    scanned most recently, which is the figure an auditor asks for.

    AuditBoard refuses to set ``identified_date`` after create, so this is the
    only chance to get it right.
    """
    scoped = _scoped_population_query(db, finding, population.tier, population.members, org_id)
    first_seen_col = getattr(models.Finding, "first_seen_at", None)
    candidates = []
    if first_seen_col is not None:
        candidates.append(scoped.with_entities(func.min(first_seen_col)).scalar())
    candidates.append(scoped.with_entities(func.min(models.Finding.created_at)).scalar())

    found = [c for c in candidates if c is not None]
    if not found:
        return None
    earliest = min(found)
    return earliest.date() if hasattr(earliest, "date") else earliest


def filing_match_condition(finding, members: Optional[Sequence[Identity]] = None):
    """SQL for "some existing issue already covers this finding".

    One place, because this question was answered separately at eight call
    sites before 2026-09-16 and the answers had drifted apart. Every tier has
    to be handled here, including the retired one:

    *   ``specific`` — matched by ``finding_id`` elsewhere, not here.
    *   ``project`` — same defect identity, same project.
    *   ``org`` — same defect identity, any project.
    *   ``global`` — the retired key of scanner plus file path. Still matched
        so issues filed before the change keep covering their findings;
        nothing new is written at this tier.

    ``members`` lets an approved cross-scanner merge count: an issue filed on
    one member's rule covers findings reported under any of them. Pass the
    output of :meth:`EquivalenceMap.members`; omit it and only the finding's
    own rule matches.
    """
    identities = list(members) if members else []
    if not identities:
        own = identity_of(finding)
        identities = [own] if own else []

    clauses = []

    # A hand-picked selection covers exactly the findings written down for it,
    # and nothing about this finding's identity can imply membership. Keyed on
    # the finding's own id, so it works even for a finding with no rule_id.
    finding_id = getattr(finding, "id", None)
    if finding_id is not None:
        clauses.append(
            and_(
                models.AuditBoardIssue.scope == GroupTier.SELECTION.value,
                models.AuditBoardIssue.id.in_(
                    select(models.AuditBoardIssueFinding.auditboard_issue_id).where(
                        models.AuditBoardIssueFinding.finding_id == finding_id
                    )
                ),
            )
        )

    if finding.scanner_name and finding.file_path:
        clauses.append(
            and_(
                models.AuditBoardIssue.scope == GroupTier.LEGACY_GLOBAL.value,
                models.AuditBoardIssue.scanner_name == finding.scanner_name,
                models.AuditBoardIssue.file_path == finding.file_path,
            )
        )

    if identities:
        identity_match = tuple_(
            models.AuditBoardIssue.scanner_name, models.AuditBoardIssue.rule_id
        ).in_([(i.scanner_name, i.rule_id) for i in identities])

        if finding.repository_id is not None:
            clauses.append(
                and_(
                    models.AuditBoardIssue.scope == GroupTier.PROJECT.value,
                    models.AuditBoardIssue.repository_id == finding.repository_id,
                    identity_match,
                )
            )
        clauses.append(
            and_(
                models.AuditBoardIssue.scope == GroupTier.ORG.value,
                identity_match,
            )
        )

    if not clauses:
        # No key at all. False rather than a bare identity match, because an
        # empty condition would return every filing in the table.
        return false()
    return or_(*clauses)


def findings_covered_condition(issue_row, equivalence: Optional[EquivalenceMap] = None):
    """SQL for "the findings this filed issue speaks for".

    The inverse of :func:`filing_match_condition`, and needed for a different
    question: before deleting findings, whether anything is left behind the
    issue. An issue whose last finding is deleted is an open GRC record with no
    evidence under it, and only a person with AuditBoard rights can close it.

    Keyed off the tier the issue was actually filed at, not off the current
    default — a ``global`` row filed before 2026-09-16 still covers what it
    covered then.
    """
    scope = (getattr(issue_row, "scope", None) or GroupTier.SPECIFIC.value).lower()

    if scope == GroupTier.SPECIFIC.value:
        return models.Finding.id == issue_row.finding_id

    if scope == GroupTier.SELECTION.value:
        # The membership was written at filing time; there is no rule to
        # re-derive it from. A selection row with no members covers nothing,
        # which is the safe answer: it cannot suppress a delete warning.
        return models.Finding.id.in_(
            select(models.AuditBoardIssueFinding.finding_id).where(
                models.AuditBoardIssueFinding.auditboard_issue_id == issue_row.id
            )
        )

    if scope == GroupTier.LEGACY_GLOBAL.value:
        if not issue_row.scanner_name or not issue_row.file_path:
            return false()
        return and_(
            models.Finding.scanner_name == issue_row.scanner_name,
            models.Finding.file_path == issue_row.file_path,
        )

    if not issue_row.scanner_name or not issue_row.rule_id:
        # A project- or org-tier row with no rule cannot have been written by
        # the filing endpoint. Treated as covering nothing rather than
        # everything, so a bad row cannot suppress a delete warning.
        return false()

    own = Identity(scanner_name=issue_row.scanner_name, rule_id=issue_row.rule_id)
    members = (equivalence or EquivalenceMap()).members(own)
    identity_match = _identity_filter(members)

    if scope == GroupTier.PROJECT.value:
        if issue_row.repository_id is None:
            return false()
        return and_(identity_match, models.Finding.repository_id == issue_row.repository_id)

    return identity_match


def is_filing_eligible(finding) -> Tuple[bool, Optional[str]]:
    """Whether a finding may be filed at all, and why not when it may not.

    The severity floor and the exclusion list are policy, so they are checked
    here rather than in a route, and the reason is returned as text a dialog
    can show — a disabled button with no stated cause gets worked around.
    """
    if settings.FILING_EXCLUDE_NON_ACTIONABLE and getattr(
        finding, "excluded_from_actionable", False
    ):
        reason = getattr(finding, "exclusion_reason", None) or "it is excluded from the work list"
        return False, f"This finding is not actionable: {reason}"

    allowed = settings.filing_severities_list
    severity = (getattr(finding, "severity", None) or "").strip().lower()
    if allowed and severity not in allowed:
        return False, (
            f"Severity '{severity or 'unknown'}' is below the filing floor "
            f"({', '.join(allowed)})"
        )
    return True, None
