"""
Group findings into remediation actions.

The unit a person acts on is not a finding. Forty lodash findings across nine
repositories are one decision — upgrade lodash — and reporting them as forty
items of work misrepresents both the effort and what closing them buys.

Grouping is by `action_key`: a deterministic string derived only from stored
fields. Determinism is the point. The same corpus produces the same keys on
every run, which is what lets a second AuditBoard push recognise the issue it
created last time instead of filing a duplicate.

Scope is per-organization. An action spans that organization's repositories;
`repos_count` then carries the breadth into the effort estimate, because a
change landing in nine repositories needs nine reviews and nine releases even
when the diff is identical.

Where grouping is honest about its limits, it says so rather than grouping
anyway — see `rotate_secret` below.

See docs/specs/REPORT_GENERATOR_WIZARD_SPEC.md §4.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterable, Optional

from src.api.constants.remediation import (
    REMEDIATION_TEXT,
    ROLE_FOR_CATEGORY,
    RemediationCategory,
    remediation_text,
)
from src.services.effort import EffortEstimate, drivers_for_action, estimate

# Ephemeral scan paths. Roughly three quarters of the file_path values in this
# estate look like /tmp/repo_scan_8f3a/src/index.js — the checkout directory of
# a scan run that no longer exists. Counting those as distinct files would make
# files_count change between two scans of identical code, so the prefix is
# stripped before counting and before display.
_EPHEMERAL_PATH_RE = re.compile(r"^/(?:tmp|var/folders)/[^/]*repo[_-]?scan[^/]*/")


def normalize_file_path(path: Optional[str]) -> Optional[str]:
    """
    Strip a scan-checkout prefix so a path is repo-relative.

    Returns None for a path that is empty. Returns the input unchanged when it
    carries no recognised prefix, because a path we do not understand is
    reported as-is rather than mangled into something that looks authoritative.
    """
    if not path:
        return None
    stripped = _EPHEMERAL_PATH_RE.sub("", path.strip())
    return stripped.lstrip("/") or None


def _slug(value: Optional[str], fallback: str = "unknown") -> str:
    """Key-safe fragment. Keeps the value readable; a key is read by humans too."""
    if not value:
        return fallback
    cleaned = re.sub(r"\s+", "-", value.strip().lower())
    cleaned = re.sub(r"[^a-z0-9._:/-]", "", cleaned)
    return cleaned[:120] or fallback


@dataclass
class FindingRow:
    """The fields grouping reads. A plain record so this is testable without a database."""

    id: str
    repository_id: Optional[str]
    category: RemediationCategory
    severity: Optional[str] = None
    scanner_name: Optional[str] = None
    rule_id: Optional[str] = None
    cve_id: Optional[str] = None
    ghsa_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None
    fixed_version: Optional[str] = None
    file_path: Optional[str] = None
    ecosystem: Optional[str] = None


def action_key_for(finding: FindingRow) -> str:
    """
    The deterministic grouping key.

    Every branch falls back to (scanner, rule_id) rather than to the finding's
    own id. Falling back to the id would produce one action per finding, which
    is the failure this module exists to prevent — and it would do it silently,
    looking like a large amount of work rather than a missing field.
    """
    category = finding.category
    scanner = _slug(finding.scanner_name, "unknown-scanner")
    rule = _slug(finding.rule_id, "unknown-rule")

    if category is RemediationCategory.UPGRADE_DEPENDENCY:
        if finding.package_name:
            target = _slug(finding.fixed_version, "no-fixed-version")
            return f"upgrade:{_slug(finding.ecosystem, 'unknown-ecosystem')}:{_slug(finding.package_name)}:{target}"
        # No package name recorded. The advisory identifier is the next most
        # specific thing that still groups duplicates of the same problem.
        advisory = finding.cve_id or finding.ghsa_id
        if advisory:
            return f"upgrade:advisory:{_slug(advisory)}"
        return f"upgrade:{scanner}:{rule}"

    if category is RemediationCategory.REMOVE_DEPENDENCY:
        if finding.package_name:
            return f"remove:{_slug(finding.ecosystem, 'unknown-ecosystem')}:{_slug(finding.package_name)}"
        return f"remove:{scanner}:{rule}"

    if category is RemediationCategory.PATCH:
        advisory = finding.cve_id or finding.ghsa_id
        if advisory:
            return f"patch:{_slug(advisory)}"
        return f"patch:{scanner}:{rule}"

    if category is RemediationCategory.ROTATE_SECRET:
        # Secrets do not group the way dependencies do. Two findings of the same
        # detector type are two different credentials unless we can show the
        # values match, and no value or hash is stored. Grouping them into one
        # action would produce a single "rotate the AWS key" item covering
        # several distinct keys, of which someone rotates one and closes all.
        #
        # So the key includes the repository and the normalised path: the
        # narrowest grouping the stored data supports. Two findings collapse
        # only when they are the same detector at the same location, which is a
        # re-scan of the same secret rather than two secrets.
        location = _slug(normalize_file_path(finding.file_path), "unknown-location")
        return f"rotate:{rule}:{_slug(finding.repository_id, 'unknown-repo')}:{location}"

    if category is RemediationCategory.CONFIGURE:
        return f"configure:{scanner}:{rule}"

    if category is RemediationCategory.CODE_CHANGE:
        return f"code:{scanner}:{rule}"

    if category is RemediationCategory.ACCESS_CONTROL:
        return f"access:{scanner}:{rule}"

    if category is RemediationCategory.INFRA_CONTROL:
        return f"infra:{scanner}:{rule}"

    if category is RemediationCategory.COMPENSATING_CONTROL:
        return f"detect:{scanner}:{rule}"

    if category is RemediationCategory.ACCEPT_RISK:
        return f"accept:{scanner}:{rule}"

    if category is RemediationCategory.FALSE_POSITIVE:
        return f"suppress:{scanner}:{rule}"

    raise ValueError(f"no action key shape for category {category!r}")


@dataclass
class GroupedAction:
    """One action, its findings, its measured drivers and its estimated band."""

    action_key: str
    category: RemediationCategory
    title: str
    remediation_text: str
    finding_ids: list[str] = field(default_factory=list)
    repository_ids: set[str] = field(default_factory=set)
    file_paths: set[str] = field(default_factory=set)
    severity_counts: dict[str, int] = field(default_factory=dict)
    package_name: Optional[str] = None
    package_ecosystem: Optional[str] = None
    current_version: Optional[str] = None
    fixed_version: Optional[str] = None
    effort: Optional[EffortEstimate] = None

    @property
    def findings_count(self) -> int:
        return len(self.finding_ids)


def _title_for(finding: FindingRow, key: str) -> str:
    """A title a person can act on, without inventing detail the row does not hold."""
    display = REMEDIATION_TEXT[finding.category]["display"]
    if finding.package_name:
        target = f" to {finding.fixed_version}" if finding.fixed_version else ""
        return f"{display}: {finding.package_name}{target}"
    if finding.rule_id:
        return f"{display}: {finding.rule_id}"
    return f"{display}: {key}"


def group_findings(
    findings: Iterable[FindingRow],
    *,
    environments: tuple[str, ...] = (),
) -> list[GroupedAction]:
    """
    Group, count the drivers, and estimate each action.

    `environments` is the set of environments the source repositories are known
    to run in, resolved by the caller from RepoDeploymentMap. Passing an empty
    tuple is correct when deployment is unresolved; the effort model records
    that as an unknown rather than assuming the code is not in production.
    """
    buckets: dict[str, GroupedAction] = {}
    first_row: dict[str, FindingRow] = {}
    severity_tally: dict[str, defaultdict[str, int]] = {}

    for finding in findings:
        key = action_key_for(finding)

        if key not in buckets:
            first_row[key] = finding
            severity_tally[key] = defaultdict(int)
            buckets[key] = GroupedAction(
                action_key=key,
                category=finding.category,
                title=_title_for(finding, key),
                remediation_text="",
                package_name=finding.package_name,
                package_ecosystem=finding.ecosystem,
                current_version=finding.package_version,
                fixed_version=finding.fixed_version,
            )

        action = buckets[key]
        action.finding_ids.append(finding.id)
        if finding.repository_id:
            action.repository_ids.add(finding.repository_id)
        normalized = normalize_file_path(finding.file_path)
        if normalized:
            action.file_paths.add(normalized)
        severity_tally[key][(finding.severity or "unknown").lower()] += 1

    for key, action in buckets.items():
        action.severity_counts = dict(severity_tally[key])
        row = first_row[key]

        drivers = drivers_for_action(
            category=action.category,
            findings_count=action.findings_count,
            distinct_file_paths=len(action.file_paths),
            distinct_repos=len(action.repository_ids),
            current_version=action.current_version,
            fixed_version=action.fixed_version,
            environments=environments,
        )
        action.effort = estimate(action.category, drivers)

        action.remediation_text = remediation_text(
            action.category,
            package=action.package_name,
            current_version=action.current_version,
            fixed_version=action.fixed_version,
            reference=row.cve_id or row.ghsa_id,
            rule=row.rule_id,
            setting=row.rule_id,
            location=next(iter(sorted(action.file_paths)), None),
            secret_type=row.rule_id,
            scope=next(iter(sorted(action.file_paths)), None),
            breaking_note=_breaking_note(action),
        )

    # Largest first: the report leads with the action that closes the most.
    return sorted(buckets.values(), key=lambda a: a.findings_count, reverse=True)


def _breaking_note(action: GroupedAction) -> str:
    """The second line of an upgrade's remediation text."""
    if not action.fixed_version:
        return (
            "No fixed version was recorded for this dependency, so whether an upgrade "
            "exists — and whether it breaks the API — has not been established."
        )
    if action.effort and any("major version" in reason for reason in action.effort.reasons):
        return "This crosses a major version; the API may change and callers may need edits."
    return "This is within the same major version and is not expected to change the API."


def primary_role_for(action: GroupedAction) -> tuple[str, list[str]]:
    """Who does it. Derived from category — the derivation lives in one place."""
    primary, supporting = ROLE_FOR_CATEGORY[action.category]
    return primary.value, [role.value for role in supporting]
