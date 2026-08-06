"""
Threat-intel source registry.

Sources are tiered by evidentiary weight. Tier 0 is ground truth and decides
disagreements; tiers 1-3 generate hypotheses only.

See docs/playbooks/supply-chain-hunt-ttp.md section 1 for the arbitration doctrine
this registry implements.
"""

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, List, Optional


class Tier(IntEnum):
    """Evidentiary weight. Lower wins arbitration."""

    GROUND_TRUTH = 0   # package registries, OSV, GHSA, KEV — machine-queryable, authoritative
    PRIMARY = 1        # vendor research required for cross-comparison
    CORROBORATING = 2  # vendor research used to break tier-1 ties
    PRESS = 3          # timeline context only, never IoCs


class SourceKind(IntEnum):
    """How a source is consumed."""

    REGISTRY_API = 0   # queryable per-package, returns structured version data
    FEED = 1           # bulk downloadable dataset
    ADVISORY = 2       # human-readable narrative; claims extracted by analyst or LLM


@dataclass(frozen=True)
class Source:
    """A single threat-intel source."""

    id: str
    name: str
    tier: Tier
    kind: SourceKind
    url: str
    description: str = ""
    # Ecosystems this source is authoritative for (registry APIs only).
    ecosystems: tuple = field(default_factory=tuple)
    # Recorded when a source has been wrong, so future runs start calibrated.
    calibration_notes: str = ""
    enabled: bool = True

    @property
    def is_authoritative(self) -> bool:
        return self.tier == Tier.GROUND_TRUTH


# =============================================================================
# Tier 0 — ground truth
# =============================================================================
# The malicious-version oracle. A name@version is malicious only if it was
# published inside the attack window AND subsequently unpublished. Both conditions.

_TIER0: List[Source] = [
    Source(
        id="npm",
        name="npm registry",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.REGISTRY_API,
        url="https://registry.npmjs.org/{package}",
        ecosystems=("npm",),
        description=(
            "Packument. The 'time' map holds publish timestamps for every version ever "
            "released; the 'versions' map holds only what is currently published. A version "
            "present in 'time' but absent from 'versions' has been unpublished."
        ),
    ),
    Source(
        id="pypi",
        name="PyPI JSON API",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.REGISTRY_API,
        url="https://pypi.org/pypi/{package}/json",
        ecosystems=("pypi",),
        description="'releases' map; an empty or missing release list indicates withdrawal.",
    ),
    Source(
        id="crates",
        name="crates.io",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.REGISTRY_API,
        url="https://crates.io/api/v1/crates/{package}",
        ecosystems=("cargo", "crates"),
        description="Per-version 'yanked' flag is the withdrawal signal.",
    ),
    Source(
        id="rubygems",
        name="RubyGems",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.REGISTRY_API,
        url="https://rubygems.org/api/v1/versions/{package}.json",
        ecosystems=("rubygems", "gem"),
    ),
    Source(
        id="osv",
        name="OSV",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.REGISTRY_API,
        url="https://api.osv.dev/v1/query",
        ecosystems=("npm", "pypi", "cargo", "rubygems", "maven", "nuget", "go"),
        description="Cross-ecosystem affected-range data, machine readable.",
    ),
    Source(
        id="ghsa",
        name="GitHub Advisory Database",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.ADVISORY,
        url="https://github.com/advisories",
        description="GHSA IDs and affected ranges. Also reachable via the GraphQL securityAdvisories connection.",
    ),
    Source(
        id="kev",
        name="CISA Known Exploited Vulnerabilities",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.FEED,
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        description="Known-exploited status. Already cached by this platform at .cache/kev.json.",
    ),
    Source(
        id="epss",
        name="EPSS",
        tier=Tier.GROUND_TRUTH,
        kind=SourceKind.FEED,
        url="https://epss.cyentia.com/epss_scores-current.csv.gz",
        description="Exploitation probability. Already cached at .cache/epss.json.",
    ),
]

# =============================================================================
# Tier 1 — primary vendor research (the required comparison set)
# =============================================================================

_TIER1: List[Source] = [
    Source(
        id="chainguard",
        name="Chainguard",
        tier=Tier.PRIMARY,
        kind=SourceKind.ADVISORY,
        url=(
            "https://www.chainguard.dev/unchained/"
            "the-keyv-and-cacheable-npm-supply-chain-attack-inside-the-mini-shai-hulud-campaign"
        ),
        description="Campaign narrative, provenance analysis, safe restore versions.",
        calibration_notes=(
            "2026-08-04 Mini Shai-Hulud: stated ecto was unaffected. The npm registry shows "
            "ecto@5.0.1 published 10:28:01Z inside the window and subsequently unpublished. "
            "Chainguard was wrong; had this been trusted, ecto would have been excluded from the "
            "hunt set. Verify Chainguard scope claims against tier 0."
        ),
    ),
    Source(
        id="socket",
        name="Socket — analysis",
        tier=Tier.PRIMARY,
        kind=SourceKind.ADVISORY,
        url=(
            "https://socket.dev/blog/"
            "popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain"
        ),
        description="Version-accurate affected list, semver reachability analysis, IoC hashes.",
        calibration_notes=(
            "2026-08-04 Mini Shai-Hulud: accurate on versions (file-entry-cache@11.1.6), "
            "conservative on scope. An early-snapshot artifact circulating 11.1.7 was refuted by "
            "the registry — that version never existed. Socket's own blog states 11.1.6."
        ),
    ),
    Source(
        id="socket_campaign",
        name="Socket — live campaign tracker",
        tier=Tier.PRIMARY,
        kind=SourceKind.ADVISORY,
        url="https://socket.dev/supply-chain-attacks/keyv-and-cacheable-compromise",
        description="Updated continuously during a live incident. Re-fetch rather than trusting a cached snapshot.",
    ),
    Source(
        id="phoenix",
        name="Phoenix Security",
        tier=Tier.PRIMARY,
        kind=SourceKind.ADVISORY,
        url="https://phoenix.security/mini-shai-hulud-keyv-cacheable-npm-supply-chain-worm/",
        description=(
            "Detection-philosophy source rather than an enumerative one. Central argument: "
            "CVE-based and signature-based controls have no detection surface for this attack "
            "class, and a lifecycle-script delta rule would have caught every Shai-Hulud wave. "
            "Also documents staged rotation runbooks that sequence watcher-removal before token "
            "rotation."
        ),
    ),
    Source(
        id="elastic",
        name="Elastic Security Labs",
        tier=Tier.PRIMARY,
        kind=SourceKind.ADVISORY,
        url="https://www.elastic.co/security-labs/shai-hulud-chaindrop-npm-supply-chain",
        description=(
            "Reverse-engineering source: names the worm CHAINDROP, decomposes it into dropper, "
            "payload and a 711 KB collector, and documents the obfuscation (control-flow "
            "flattening, Base91). Uniquely contributes the C2 domain awqhnjewqjkl.icu, the "
            "collector's 300+ credential patterns including AI tooling (Anthropic, Claude, "
            "Codex, Cursor) and Alibaba plus instance-metadata endpoints, the AES-256-GCM + RSA "
            "exfil shape, and the detail that propagation writes hooks to up to 50 branches per "
            "accessible repository — so inspecting only the default branch reads a compromised "
            "repository as clean. Local claims are held in "
            "github_conf/ioc/chaindrop_elastic_2026_08.json."
        ),
        calibration_notes=(
            "Names five root packages and does not enumerate the 400+ propagated ones, so it "
            "neither confirms nor refutes any specific version. Its silence on an indicator is "
            "not a denial of it."
        ),
    ),
]

# =============================================================================
# Tier 2 — corroborating vendor research
# =============================================================================

_TIER2: List[Source] = [
    Source(
        id="wiz",
        name="Wiz",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url="https://www.wiz.io/blog/keyv-and-cacheable-npm-supply-chain-attack",
        description=(
            "Ethereum-smart-contract C2 resolution; IDE persistence via Claude Code hooks and "
            "VS Code tasks.json; environment prevalence data."
        ),
    ),
    Source(
        id="aikido",
        name="Aikido Security",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url="https://www.aikido.dev/blog/keyv-and-friends-compromised-in-npm-supply-chain-attack",
        description="Two-file payload shape (setup.mjs + Math_Symbol.js) and dynamic C2 fallback.",
    ),
    Source(
        id="safedep",
        name="SafeDep",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url="https://safedep.io/keyv-npm-supply-chain-compromise/",
        description="Largest confirmed footprint: 2,234 poisoned versions across 444 package names.",
    ),
    Source(
        id="jfrog",
        name="JFrog Security Research",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url="https://research.jfrog.com/post/shai-hulud-is-back-august/",
        description=(
            "428 packages / 1700+ versions. Uniquely reports that npm >= 12 does not run "
            "preinstall lifecycle hooks by default — a material mitigating factor worth "
            "verifying per builder."
        ),
    ),
    Source(
        id="snyk",
        name="Snyk",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url=(
            "https://snyk.io/blog/"
            "inside-keyv-npm-compromise-preinstall-malware-trusted-provenance-ide-hooks/"
        ),
        description="Exploit-maturity rating and trusted-provenance analysis.",
    ),
    Source(
        id="cloudsmith",
        name="Cloudsmith",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url=(
            "https://cloudsmith.com/blog/"
            "keyv-and-cacheable-npm-packages-compromised-in-active-supply-chain-attack"
        ),
        description="Registry-operator view; ~444 packages / ~2,236 malicious versions.",
    ),
    Source(
        id="kodem",
        name="Kodem",
        tier=Tier.CORROBORATING,
        kind=SourceKind.ADVISORY,
        url=(
            "https://www.kodemsecurity.com/resources/"
            "keyv-supply-chain-attack-shai-hulud-npm-worm-affected-versions-iocs-and-first-hour-response-runbook"
        ),
        description="Consolidated IoC list plus a first-hour response runbook.",
    ),
]

# =============================================================================
# Tier 3 — press, timeline context only
# =============================================================================

_TIER3: List[Source] = [
    Source(
        id="thehackernews",
        name="The Hacker News",
        tier=Tier.PRESS,
        kind=SourceKind.ADVISORY,
        url="https://thehackernews.com/2026/08/keyv-linked-npm-worm-poisons-hundreds.html",
    ),
    Source(
        id="scmedia",
        name="SC Media",
        tier=Tier.PRESS,
        kind=SourceKind.ADVISORY,
        url="https://www.scworld.com/news/keyv-cacheable-npm-supply-chain-attack-hits-400-plus-packages",
    ),
]

# =============================================================================
# Disqualified sources
# =============================================================================
# Kept explicitly rather than silently omitted, so the reason survives.

DISQUALIFIED: Dict[str, str] = {
    "gbhackers": (
        "https://gbhackers.com/shai-hulud-supply-chain-attack-compromises-keyv/ — dated the "
        "compromise 2023 while citing a source that says 2026. A source that contradicts its own "
        "citation is disqualified, not averaged in."
    ),
}


SOURCES: Dict[str, Source] = {
    s.id: s for s in (_TIER0 + _TIER1 + _TIER2 + _TIER3)
}


def get_source(source_id: str) -> Optional[Source]:
    return SOURCES.get(source_id)


def sources_by_tier(tier: Tier, enabled_only: bool = True) -> List[Source]:
    return [
        s for s in SOURCES.values()
        if s.tier == tier and (s.enabled or not enabled_only)
    ]


def registry_for_ecosystem(ecosystem: str) -> Optional[Source]:
    """Return the tier-0 registry API that is authoritative for an ecosystem."""
    eco = (ecosystem or "").lower()
    for source in _TIER0:
        if source.kind == SourceKind.REGISTRY_API and eco in source.ecosystems:
            return source
    return None


def advisory_urls(include_press: bool = False) -> List[Dict[str, str]]:
    """
    Flat list of advisory sources with URLs, for embedding in a report.

    Reports must cite the URL, not just the vendor name.
    """
    max_tier = Tier.PRESS if include_press else Tier.CORROBORATING
    return [
        {
            "id": s.id,
            "name": s.name,
            "tier": f"tier{int(s.tier)}",
            "url": s.url,
            "description": s.description,
            "calibration_notes": s.calibration_notes,
        }
        for s in sorted(SOURCES.values(), key=lambda x: (x.tier, x.id))
        if s.kind == SourceKind.ADVISORY and s.tier <= max_tier and s.enabled
    ]
