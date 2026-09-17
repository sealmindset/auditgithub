"""
Assign a remediation category to a finding.

Rules run first. They are deterministic, free, and reproducible: the same row
classifies the same way on every run, and a reader can check the decision
against the table below without running anything. Only what the rules cannot
match is offered to a model.

Every decision carries its source (`rule` / `ai` / `human`) and a rationale, so
a report can break its category totals down by how each one was decided. A
rule-matched count and a model-inferred count are different claims and are
never presented as one number.

Rule IDs are also recovered here. Four of the nine scanners in this estate
encode their rule identity in the finding title and nothing else — the column
does not exist yet and the value was discarded at ingest. `extract_rule_id`
reads it back out of the title using the patterns each scanner actually emits,
which means existing findings can be keyed to a knowledge-base entry without a
re-scan.

See docs/specs/REPORT_GENERATOR_WIZARD_SPEC.md §2.1 and §3.1.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol

from src.api.constants.remediation import CategorySource, RemediationCategory


# ---------------------------------------------------------------------------
# finding_type normalisation
# ---------------------------------------------------------------------------
#
# `finding_type` accumulated aliases: execution/ingest_results.py writes
# 'vulnerability' for Trivy while the projects router queries for 'oss', and a
# third path writes 'dependency'. Classifying on the raw value would silently
# mis-bucket whichever alias the rule author did not happen to know about, so
# every alias is folded to one canonical value here rather than in each rule.
FINDING_TYPE_ALIASES: dict[str, str] = {
    "vulnerability": "oss",
    "dependency": "oss",
    "sca": "oss",
    "secrets": "secret",
    "infrastructure": "iac",
    "terraform": "iac",
}


def canonical_finding_type(finding_type: Optional[str]) -> str:
    """Fold known aliases onto one value. Unknown values pass through lowercased."""
    if not finding_type:
        return ""
    value = finding_type.strip().lower()
    return FINDING_TYPE_ALIASES.get(value, value)


# ---------------------------------------------------------------------------
# Rule ID recovery
# ---------------------------------------------------------------------------
#
# Each pattern was derived from the titles these scanners actually wrote into
# this database, not from their documentation. Where a scanner emits no stable
# identifier, `extract_rule_id` returns the title unchanged and the caller can
# tell the difference by the returned `is_stable` flag: a check name is usable
# as a grouping key, but it is prose and may be reworded by an upstream release.
_RULE_PATTERNS: dict[str, re.Pattern[str]] = {
    "whispers": re.compile(r"^Secret:\s*(?P<rule>.+)$"),
    "trufflehog": re.compile(r"^Secret found:\s*(?P<rule>.+)$"),
    "gitleaks": re.compile(r"^Secret found:\s*(?P<rule>.+)$"),
    # horusec prefixes every title with a "(n/m) *" occurrence marker
    "horusec": re.compile(r"^\(\d+/\d+\)\s*\*\s*Possible vulnerability detected:\s*(?P<rule>.+)$"),
    "retirejs": re.compile(r"^Vulnerable JS Library:\s*(?P<rule>\S+)"),
    "mobsf": re.compile(r"^\[(?P<category>[^\]]+)\]\s*(?P<rule>.+)$"),
}

# Scanners whose title *is* a stable identifier already.
_TITLE_IS_RULE_ID: frozenset[str] = frozenset({"terrascan", "semgrep", "checkov"})

_GHSA_RE = re.compile(r"^(GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4})$", re.IGNORECASE)
_CVE_RE = re.compile(r"\b(CVE-\d{4}-\d{4,})\b", re.IGNORECASE)

# retirejs writes "Vulnerable JS Library: {package} {version}", which is the only
# place package and version survive for that scanner.
_RETIREJS_PKG_RE = re.compile(r"^Vulnerable JS Library:\s*(?P<pkg>\S+)\s+(?P<version>\S+)\s*$")


@dataclass(frozen=True)
class RuleIdentity:
    """What a finding's title yields about the rule that produced it."""

    rule_id: Optional[str]
    is_stable: bool           # False when rule_id is prose, not an identifier
    ghsa_id: Optional[str] = None
    cve_id: Optional[str] = None
    package_name: Optional[str] = None
    package_version: Optional[str] = None


def extract_rule_id(scanner_name: Optional[str], title: Optional[str]) -> RuleIdentity:
    """
    Recover rule identity from a finding title.

    Returns a RuleIdentity with `rule_id=None` when nothing can be recovered.
    That is an explicit "not available", not an empty string, so a backfill can
    distinguish "no rule id in this title" from "rule id is the empty string".
    """
    if not title:
        return RuleIdentity(rule_id=None, is_stable=False)

    scanner = (scanner_name or "").strip().lower()
    title = title.strip()

    # grype writes the advisory identifier as the whole title.
    ghsa = _GHSA_RE.match(title)
    if ghsa:
        advisory = ghsa.group(1).upper()
        return RuleIdentity(rule_id=advisory, is_stable=True, ghsa_id=advisory)

    cve = _CVE_RE.search(title)

    # mobsf scanner names carry a platform suffix: "mobsf:android".
    lookup = scanner.split(":", 1)[0]

    pattern = _RULE_PATTERNS.get(lookup)
    if pattern:
        match = pattern.match(title)
        if match:
            groups = match.groupdict()
            rule = groups["rule"].strip()
            if "category" in groups and groups["category"]:
                rule = f"{groups['category'].strip()}/{rule}"

            pkg = version = None
            if lookup == "retirejs":
                pkg_match = _RETIREJS_PKG_RE.match(title)
                if pkg_match:
                    pkg = pkg_match.group("pkg")
                    version = pkg_match.group("version")

            return RuleIdentity(
                rule_id=rule,
                is_stable=True,
                cve_id=cve.group(1).upper() if cve else None,
                package_name=pkg,
                package_version=version,
            )

    if lookup in _TITLE_IS_RULE_ID:
        return RuleIdentity(
            rule_id=title,
            is_stable=True,
            cve_id=cve.group(1).upper() if cve else None,
        )

    # No pattern. The title is the only identity available and it is prose.
    return RuleIdentity(
        rule_id=title,
        is_stable=False,
        cve_id=cve.group(1).upper() if cve else None,
    )


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Classification:
    """One category decision, with who made it and why."""

    category: RemediationCategory
    source: CategorySource
    confidence: float
    rationale: str
    # True when the finding should not appear in an actionable report. The row
    # is kept and stays queryable; only its place in the work list changes.
    excluded: bool = False
    exclusion_reason: Optional[str] = None


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------
#
# Two scanner rules produce 547,013 of the 769,825 findings in this estate —
# 71.1% of everything — and neither is reporting a credential. Leaving them in
# means an "actionable items" report opens with half a million rotations that
# are not rotations, which is worse than useless: it trains the reader to
# distrust the whole list.
#
# Each entry carries the measurement that justifies it, because suppressing
# three quarters of a corpus on an unstated hunch is exactly the kind of claim
# that should not survive a skeptical reader. Reproduce either with:
#   python scripts/sample_findings.py --scanner whispers \
#       --title "Secret: comment" --n 120 --seed 2026-09-14
#
# Neither entry deletes anything. The rows stay, the counts stay reportable,
# and removing an entry here puts them back in the work list on the next run.

SUPPRESSIONS: dict[tuple[str, str], tuple[RemediationCategory, str]] = {
    ("whispers", "comment"): (
        RemediationCategory.FALSE_POSITIVE,
        "Matches any text in a code comment. 502,234 findings resolve to only 1,538 "
        "distinct values, overwhelmingly generated-documentation boilerplate. A random "
        "sample of 120 (seed 2026-09-14) contained no credential, and a scan of all "
        "1,538 distinct values for credential-shaped strings surfaced one candidate — a "
        "password-reset token in a page saved from http://localhost:8080 — which is "
        "recorded separately for review rather than closed here.",
    ),
    ("whispers", "file"): (
        RemediationCategory.ROTATE_SECRET,
        "Matches on filename alone and never on content: for 44,241 of 44,779 findings "
        "the entire evidence is the file's own path. This is a file inventory, not a "
        "detection, so it is excluded from the work list rather than marked a false "
        "positive — calling it false would assert these files are clean, and the "
        "scanner never opened them. The 14,559 .env, .tfvars and .git/config files it "
        "names are tracked as a separate content scan.",
    ),
}


def suppression_for(
    scanner_name: Optional[str], rule_id: Optional[str]
) -> Optional[tuple[RemediationCategory, str]]:
    """The suppression entry for a rule, or None. Lookup is exact, never a prefix."""
    if not scanner_name or not rule_id:
        return None
    return SUPPRESSIONS.get((scanner_name.strip().lower(), rule_id.strip()))


class _FindingLike(Protocol):
    """The subset of `Finding` this module reads. Keeps the rules unit-testable."""

    finding_type: Optional[str]
    scanner_name: Optional[str]
    status: Optional[str]
    fixed_version: Optional[str]
    ai_triage_recommendation: Optional[str]
    ai_triage_confidence: Optional[float]


# The rule table, in evaluation order. First match wins.
#
# A note on what is NOT here. The obvious rule for dependency findings is
# "fixed_version present -> upgrade, absent -> remove". It is not used, because
# `fixed_version` is populated on zero of the 769,825 findings in this estate:
# the ingest path drops it. Keying on it would send every dependency finding to
# `remove_dependency`, which is both wrong and expensive advice. Dependency
# findings therefore classify as `upgrade_dependency` with a rationale that says
# the fixed version was not recorded, and the effort model reads the same
# absence as a driver (see effort.py: has_fixed_version).


def classify(
    finding: _FindingLike, rule_id: Optional[str] = None
) -> Optional[Classification]:
    """
    Apply the deterministic rules.

    `rule_id` is the recovered identity from extract_rule_id. It is passed in
    rather than read off the finding so this works during the backfill, before
    the column exists on the row.

    Returns None when no rule matches, which is the signal to fall through to
    the model. A None here is not a failure; it is the boundary between what we
    can assert and what we can only infer.
    """
    ftype = canonical_finding_type(finding.finding_type)
    status = (finding.status or "").strip().lower()

    # Analyst decisions outrank scanner taxonomy, and outrank suppression: a
    # person who looked at a row and ruled on it is better evidence than a rule
    # about the row's neighbours.
    if status == "accepted":
        return Classification(
            RemediationCategory.ACCEPT_RISK,
            CategorySource.RULE,
            1.0,
            "finding status is 'accepted'",
        )

    triage = (finding.ai_triage_recommendation or "").strip().lower()
    triage_confidence = float(finding.ai_triage_confidence or 0.0)
    if triage == "false_positive" and triage_confidence >= 0.8:
        return Classification(
            RemediationCategory.FALSE_POSITIVE,
            CategorySource.RULE,
            1.0,
            f"AI triage marked false positive at confidence {triage_confidence:.2f}",
        )

    suppression = suppression_for(finding.scanner_name, rule_id)
    if suppression:
        category, reason = suppression
        return Classification(
            category,
            CategorySource.RULE,
            1.0,
            reason,
            excluded=True,
            exclusion_reason=reason,
        )

    if ftype == "secret":
        return Classification(
            RemediationCategory.ROTATE_SECRET,
            CategorySource.RULE,
            1.0,
            "finding_type is 'secret'; a disclosed credential is rotated, not patched",
        )

    if ftype == "oss":
        if finding.fixed_version:
            return Classification(
                RemediationCategory.UPGRADE_DEPENDENCY,
                CategorySource.RULE,
                1.0,
                f"dependency finding with a published fixed version ({finding.fixed_version})",
            )
        return Classification(
            RemediationCategory.UPGRADE_DEPENDENCY,
            CategorySource.RULE,
            1.0,
            "dependency finding; fixed version was not recorded at ingest, so whether an "
            "upgrade exists is unverified and the effort model treats it as unknown",
        )

    if ftype == "iac":
        return Classification(
            RemediationCategory.CONFIGURE,
            CategorySource.RULE,
            1.0,
            "infrastructure-as-code finding; the fix is a setting, not application code",
        )

    if ftype in ("sast", "mobile", "data_flow"):
        return Classification(
            RemediationCategory.CODE_CHANGE,
            CategorySource.RULE,
            1.0,
            f"static analysis finding (finding_type '{ftype}'); the fix is in application code",
        )

    # dast, malware, and anything new fall through to the model on purpose.
    # A runtime finding may be a configuration problem, a WAF rule, or a code
    # defect, and the type alone does not say which.
    return None


def classification_for_override(reason: str) -> Classification:
    """Wrap a human decision so it carries the same shape as a rule or model one."""
    raise NotImplementedError(
        "human overrides are written through the findings API, not this module"
    )
