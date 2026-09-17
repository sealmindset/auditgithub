"""
Derive the knowledge base key for a finding.

This is the join between 222,844 findings and a few thousand knowledge base
entries, so it has one hard requirement: the same finding must produce the same
key on every run, forever. Everything downstream -- KB lookup, report rendering,
the AuditBoard push -- inherits its stability from here.

Measured against the live corpus on 2026-09-14: all 222,844 actionable findings
resolve to a key, giving 2,639 distinct keys. 1,158 are advisories and 1,481 are
scanner rules. There are no orphans and no singletons.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional, Protocol

from src.api.constants.kb import KBKeyType

# Advisory identifiers are case-insensitive upstream but must be case-stable
# here, or the same advisory produces two KB entries. Lowercased in the key,
# preserved in upper case in the parsed field.
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)

# Not a CWE. Horusec's ingest wrote its engine name into findings.cwe_id on
# 59,699 rows; across all 769,825 findings the column holds exactly two values,
# this string and empty. Anything matching this is discarded rather than keyed
# on, because 'cwe:horusecengine' would be a knowledge base entry about nothing
# that 59,699 findings would then point at.
_CWE_ID_REJECT = frozenset({"horusecengine"})


class _FindingLike(Protocol):
    scanner_name: Optional[str]
    rule_id: Optional[str]
    ghsa_id: Optional[str]
    cve_id: Optional[str]
    cwe_id: Optional[str]


@dataclass(frozen=True)
class KBKey:
    """A knowledge base key and the evidence for choosing it."""

    key: str
    key_type: KBKeyType
    # The identifier in its canonical upstream form, for display and for the
    # enrichment fetch. `key` is lowercased for equality; this is not.
    identifier: str
    # True when the key is built from prose that an upstream release may reword
    # -- see rule_id_is_stable on findings. A KB entry on an unstable key is
    # still correct today and may silently orphan on a scanner upgrade.
    is_stable: bool = True


def normalize_cwe(raw: Optional[str]) -> Optional[str]:
    """Return a canonical `CWE-nnn`, or None if the value is not a CWE.

    Accepts `79`, `cwe-79`, `CWE-79`. Rejects the Horusec engine string and
    anything else that does not parse, rather than passing it through: a
    knowledge base keyed on a scanner's internal name is worse than one with a
    gap, because the gap is visible.
    """
    if not raw:
        return None
    value = str(raw).strip()
    if not value or value.lower() in _CWE_ID_REJECT:
        return None
    if value.isdigit():
        value = f"CWE-{value}"
    if not _CWE_RE.match(value):
        return None
    return value.upper()


def normalize_ghsa(raw: Optional[str]) -> Optional[str]:
    if raw and _GHSA_RE.match(raw.strip()):
        return raw.strip().upper()
    return None


def normalize_cve(raw: Optional[str]) -> Optional[str]:
    if raw and _CVE_RE.match(raw.strip()):
        return raw.strip().upper()
    return None


def kb_key_for(finding: _FindingLike) -> Optional[KBKey]:
    """Derive the knowledge base key. First match wins.

    Precedence: ghsa -> cve -> rule -> cwe.

    `ghsa` leads because grype -- the dependency scanner in use here -- reports
    GitHub advisories and `cve_id` is NULL on every finding in this estate. A
    precedence starting at `cve` falls through to `rule` on every dependency
    finding, which is how one advisory becomes several KB entries.

    `cwe` sits last and, in this estate, never fires: see _CWE_ID_REJECT.

    Returns None when nothing identifies the finding. That is a real state and
    the caller must handle it -- it is not defaulted to the finding's own id,
    because a KB entry per finding is not a knowledge base.
    """
    ghsa = normalize_ghsa(getattr(finding, "ghsa_id", None))
    if ghsa:
        return KBKey(f"ghsa:{ghsa.lower()}", KBKeyType.GHSA, ghsa)

    cve = normalize_cve(getattr(finding, "cve_id", None))
    if cve:
        return KBKey(f"cve:{cve.lower()}", KBKeyType.CVE, cve)

    scanner = (getattr(finding, "scanner_name", None) or "").strip()
    rule_id = (getattr(finding, "rule_id", None) or "").strip()
    if scanner and rule_id:
        # Not lowercased. Scanner rule IDs are case-sensitive upstream
        # (`CKV_AWS_18`, `python.lang.security...`), and folding case would
        # merge two rules that a scanner considers distinct.
        is_stable = getattr(finding, "rule_id_is_stable", None)
        return KBKey(
            f"rule:{scanner}/{rule_id}",
            KBKeyType.RULE,
            f"{scanner}/{rule_id}",
            is_stable=True if is_stable is None else bool(is_stable),
        )

    cwe = normalize_cwe(getattr(finding, "cwe_id", None))
    if cwe:
        return KBKey(f"cwe:{cwe.lower()}", KBKeyType.CWE, cwe)

    return None
