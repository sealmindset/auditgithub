"""
Populate knowledge base entries for advisory keys from GitHub's advisory API.

This is a **fetch, not an inference**. Everything it writes came from a public
advisory and is cited back to the URL it came from, so `source` is `import` and
`ai_confidence` stays NULL. Nothing here is generated.

It exists because the local data is missing fields the report needs and the
advisory has them:

| Field            | In `findings`                    | In the advisory |
|------------------|----------------------------------|-----------------|
| `cve_id`         | NULL on all 769,825 rows         | present         |
| `cwe_id`         | `HorusecEngine` or empty         | a real CWE list |
| `fixed_version`  | empty on all 769,825 rows        | per-package     |
| EPSS             | not collected                    | present         |

The `fixed_version` recovery is the consequential one. Its absence is why §2.1's
original rule would have routed every dependency finding to `remove_dependency`,
and why every dependency effort estimate currently carries an unmeasured driver.
Recovering it for the 1,158 advisory keys narrows that gap with fetched fact.

Constraints this obeys, from the standing rules of this workstream:

- Passive and free only. This reads a public advisory endpoint. It sends nothing
  to any host discovered by scanning, and needs no paid source.
- TLS verification is whatever `SSL_VERIFY` says, via the existing threat-intel
  cache. No `verify=False` is introduced here.
- Responses are cached on disk, so a re-run costs no requests and the fetched
  values are reproducible when the network is unavailable.
- A failed fetch produces an explicit failure, never a partially-filled entry
  that reads like a complete one.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

from src.api.constants.kb import (
    KBKeyType,
    KBSource,
    TargetAssetType,
)
from src.services.kb_key import normalize_cve, normalize_cwe, normalize_ghsa
from src.services.markdown_excerpt import excerpt_markdown
from src.threat_intel.cache import cached_fetch

# Advisory descriptions are Markdown and occasionally very long. 6,000 characters
# holds the whole of almost all of them; the excerpt names what it dropped when
# it does not.
_SUMMARY_BUDGET = 6000

logger = logging.getLogger(__name__)

_ADVISORY_URL = "https://api.github.com/advisories/{ghsa}"

# Advisories are amended (severity revised, packages added), but not often.
# A week keeps the data current without making a KB rebuild a network event.
_TTL_SECONDS = 7 * 24 * 3600


def _headers() -> dict[str, str]:
    """Advisory reads are public, but the anonymous quota is 60 requests an hour
    and this estate has 1,158 advisories to fetch. With the token already in the
    environment the quota is 5,000, so a full pass is one run rather than a day.

    The token is only ever sent to api.github.com, and only to read published
    advisories -- no repository, org or private data is touched by this path.
    """
    headers = {"Accept": "application/vnd.github+json",
               "X-GitHub-Api-Version": "2022-11-28"}
    token = (os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN") or "").strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


@dataclass
class AdvisoryFacts:
    """What an advisory told us, and where it came from.

    `ok` False means the fetch failed. The caller must not treat the empty
    fields as 'the advisory has no CWE' -- those are different claims, which is
    why `error` and `ok` are separate from the data.
    """

    ghsa_id: str
    ok: bool
    source_url: str
    fetched_from: str = "none"          # "live" | "cache" | "none"
    error: Optional[str] = None

    cve_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    published_at: Optional[str] = None
    withdrawn_at: Optional[str] = None

    cwes: list[dict[str, str]] = field(default_factory=list)
    references: list[dict[str, str]] = field(default_factory=list)
    # [{ecosystem, package, vulnerable_range, first_patched_version}]
    affected: list[dict[str, Optional[str]]] = field(default_factory=list)

    epss_score: Optional[float] = None
    epss_percentile: Optional[float] = None

    @property
    def cwe_ids(self) -> list[str]:
        return [c["id"] for c in self.cwes]

    @property
    def is_withdrawn(self) -> bool:
        """A withdrawn advisory is not a finding. Rendering one as live work
        sends an engineer to fix something upstream has retracted."""
        return bool(self.withdrawn_at)

    def first_patched_for(self, package: Optional[str]) -> Optional[str]:
        """The fixed version for one package, or None.

        None is returned both when the package is unknown to the advisory and
        when the advisory records no fix. The caller distinguishes those with
        `affected`; collapsing them here would let 'no fix exists' be reported
        as 'we did not look'.
        """
        if not package:
            return None
        target = package.strip().lower()
        for entry in self.affected:
            if (entry.get("package") or "").lower() == target:
                return entry.get("first_patched_version")
        return None


def _parse(ghsa_id: str, payload: dict[str, Any], url: str, origin: str) -> AdvisoryFacts:
    facts = AdvisoryFacts(ghsa_id=ghsa_id, ok=True, source_url=url, fetched_from=origin)

    facts.cve_id = normalize_cve(payload.get("cve_id"))
    facts.summary = payload.get("summary")
    facts.description = payload.get("description")
    facts.severity = (payload.get("severity") or "").lower() or None
    facts.published_at = payload.get("published_at")
    facts.withdrawn_at = payload.get("withdrawn_at")

    for entry in payload.get("cwes") or []:
        cwe = normalize_cwe(entry.get("cwe_id"))
        if cwe:
            facts.cwes.append({"id": cwe, "name": entry.get("name") or ""})

    for ref in payload.get("references") or []:
        if isinstance(ref, str):
            facts.references.append({"type": "advisory", "url": ref})

    for vuln in payload.get("vulnerabilities") or []:
        pkg = (vuln.get("package") or {})
        facts.affected.append({
            "ecosystem": pkg.get("ecosystem"),
            "package": pkg.get("name"),
            "vulnerable_range": vuln.get("vulnerable_version_range"),
            "first_patched_version": vuln.get("first_patched_version"),
        })

    # GitHub serves EPSS inline. Taking it here avoids a second source with a
    # second refresh cadence disagreeing with this one inside one report.
    epss = payload.get("epss") or {}
    if isinstance(epss, dict):
        facts.epss_score = epss.get("percentage")
        facts.epss_percentile = epss.get("percentile")

    return facts


def fetch_advisory(ghsa_id: str, *, force_refresh: bool = False) -> AdvisoryFacts:
    """Fetch one advisory. Cached; safe to call per KB entry in a loop."""
    normalized = normalize_ghsa(ghsa_id)
    url = _ADVISORY_URL.format(ghsa=normalized or ghsa_id)

    if not normalized:
        return AdvisoryFacts(
            ghsa_id=str(ghsa_id), ok=False, source_url=url,
            error=f"not a GHSA identifier: {ghsa_id!r}",
        )

    result = cached_fetch(
        key=f"ghsa_{normalized.lower()}",
        url=url,
        ttl=_TTL_SECONDS,
        force_refresh=force_refresh,
        headers=_headers(),
        allow_404=True,
    )

    if not result.get("ok"):
        return AdvisoryFacts(
            ghsa_id=normalized, ok=False, source_url=url,
            error=result.get("error") or "fetch failed",
        )

    payload = result.get("data")
    if not isinstance(payload, dict) or not payload.get("ghsa_id"):
        # A 404 with allow_404 lands here: the advisory genuinely is not
        # published under that id. Reported as a failure with a reason rather
        # than as an empty-but-successful entry.
        return AdvisoryFacts(
            ghsa_id=normalized, ok=False, source_url=url,
            fetched_from=result.get("source", "none"),
            error="advisory not found",
        )

    return _parse(normalized, payload, url, result.get("source", "none"))


def kb_fields_from_advisory(facts: AdvisoryFacts) -> dict[str, Any]:
    """Shape advisory facts into `finding_knowledge_base` columns.

    Returns only what the advisory actually stated. Blast radius, mitigation
    options and the CAPEC/ATT&CK chain are deliberately absent: the first two
    are authored (§3.3, §3.5) and the third is derived from committed MITRE data
    (§3.4). Mixing a fetched fact and a generated one into a single write is how
    `source` stops meaning anything.
    """
    if not facts.ok:
        raise ValueError(f"cannot build KB fields from a failed fetch: {facts.error}")

    reference_ids: list[dict[str, str]] = [
        {"type": "ghsa", "id": facts.ghsa_id,
         "url": f"https://github.com/advisories/{facts.ghsa_id}"}
    ]
    if facts.cve_id:
        reference_ids.append({
            "type": "cve", "id": facts.cve_id,
            "url": f"https://nvd.nist.gov/vuln/detail/{facts.cve_id}",
        })
    for cwe in facts.cwes:
        number = cwe["id"].split("-", 1)[1]
        reference_ids.append({
            "type": "cwe", "id": cwe["id"],
            "url": f"https://cwe.mitre.org/data/definitions/{number}.html",
        })
    reference_ids.extend(facts.references)

    ecosystems = sorted({e["ecosystem"] for e in facts.affected if e.get("ecosystem")})
    packages = sorted({e["package"] for e in facts.affected if e.get("package")})

    return {
        "kb_key": f"ghsa:{facts.ghsa_id.lower()}",
        "key_type": KBKeyType.GHSA.value,
        "cve_id": facts.cve_id,
        "cwe_id": facts.cwe_ids[0] if facts.cwes else None,
        "title": facts.summary or facts.ghsa_id,
        # The advisory's own prose. Fetched, not written, so it is citable and
        # carries `source: import` honestly. Bounded, because advisories run to
        # tens of thousands of characters and the excerpt states what it cut
        # rather than trailing off. Where the advisory has no description the
        # field stays None: an entry with no authored summary should read as
        # unauthored, not as a one-line title dressed up as an explanation.
        "summary": (
            excerpt_markdown(facts.description, _SUMMARY_BUDGET).text or None
            if facts.description else None
        ),
        "reference_ids": reference_ids,
        "target_asset_type": TargetAssetType.DEPENDENCY.value,
        "target_asset_detail": (
            f"{', '.join(packages)} ({', '.join(ecosystems)})" if packages
            else "unknown — the advisory names no affected package"
        ),
        "exploitability": {
            "epss_score": facts.epss_score,
            "epss_percentile": facts.epss_percentile,
            # Not asserted. KEV membership and public-exploit existence are
            # separate sources; leaving these None keeps 'we did not check'
            # distinct from 'we checked and it is not listed'.
            "kev_listed": None,
            "has_public_exploit": None,
            "source": facts.source_url,
            "observed_at": facts.published_at,
        },
        "upstream_severity": facts.severity,
        "is_withdrawn": facts.is_withdrawn,
        "affected_packages": facts.affected,
        "source": KBSource.IMPORT.value,
        "ai_confidence": None,
        "source_url": facts.source_url,
    }
