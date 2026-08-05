"""
Threat-intel acquisition and cross-source arbitration.

Implements Phase 1 of docs/playbooks/supply-chain-hunt-ttp.md: reconcile vendor
advisories against registry ground truth before hunting the estate.

    from src.threat_intel import RegistryOracle, Claim, ClaimType, Stance, arbitrate_all
"""

from .arbitration import (
    Assertion,
    Claim,
    ClaimType,
    Resolution,
    Stance,
    arbitrate,
    arbitrate_all,
)
from .cache import cache_age_seconds, cache_dir, cached_fetch, refresh_all
from .registry_oracle import RegistryOracle
from .sources import (
    DISQUALIFIED,
    SOURCES,
    Source,
    SourceKind,
    Tier,
    advisory_urls,
    get_source,
    registry_for_ecosystem,
    sources_by_tier,
)

__all__ = [
    "Assertion",
    "Claim",
    "ClaimType",
    "Resolution",
    "Stance",
    "arbitrate",
    "arbitrate_all",
    "cache_age_seconds",
    "cache_dir",
    "cached_fetch",
    "refresh_all",
    "RegistryOracle",
    "DISQUALIFIED",
    "SOURCES",
    "Source",
    "SourceKind",
    "Tier",
    "advisory_urls",
    "get_source",
    "registry_for_ecosystem",
    "sources_by_tier",
]
