"""
Finding Knowledge Base vocabulary.

One entry per unique finding *signature*, not per occurrence. 222,844 actionable
findings in this estate resolve to 2,639 distinct signatures, and the ten largest
cover half of them — so the KB is a few hundred entries that matter, not a
parallel copy of the findings table.

Everything here is a closed set. The model selects from these values and may not
invent one; where no value applies, the absence is recorded explicitly rather
than approximated by the nearest available option.
"""

from enum import Enum


class KBKeyType(str, Enum):
    """Which identifier a knowledge base entry is keyed on.

    Ordered by the precedence in `src/services/kb_key.py`. The order is not
    cosmetic: an advisory describes one vulnerability across every scanner that
    reports it, while a scanner rule describes one detector's view of possibly
    many vulnerabilities. Keying on the rule when an advisory exists splits one
    vulnerability into as many entries as there are scanners.
    """

    GHSA = "ghsa"
    CVE = "cve"
    RULE = "rule"
    CWE = "cwe"


class ImpactClass(str, Enum):
    """What an attacker gains. Exploitation impact, not regulatory impact.

    Deliberately not a severity: severity is the scanner's ordering of findings,
    this is the shape of the consequence. A `dos` and an `rce` can both be
    'high' and are not the same conversation.
    """

    RCE = "rce"
    DATA_EXPOSURE = "data_exposure"
    AUTH_BYPASS = "auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    DOS = "dos"
    SUPPLY_CHAIN = "supply_chain"
    INFORMATION_DISCLOSURE = "information_disclosure"


class TargetAssetType(str, Enum):
    """What the finding is *against*."""

    DEPENDENCY = "dependency"
    SOURCE_FILE = "source_file"
    IAC_RESOURCE = "iac_resource"
    SECRET = "secret"
    API_ENDPOINT = "api_endpoint"
    CONTAINER_IMAGE = "container_image"
    MOBILE_APP = "mobile_app"


class MappingSource(str, Enum):
    """How a CWE -> CAPEC -> ATT&CK mapping was obtained.

    NONE is a first-class outcome and by far the most common one in this estate.
    A report that prints "no published mapping" is making a smaller claim than
    one that prints a plausible technique ID, and the smaller claim is the true
    one. The model is never asked to supply a technique ID.
    """

    CWE_CAPEC_ATTACK = "cwe_capec_attack"  # derived from committed MITRE data files
    CURATED = "curated"                    # a human wrote it and signed for it
    NONE = "none"                          # no published mapping exists


class KBStatus(str, Enum):
    """Only APPROVED entries render into a report."""

    DRAFT = "draft"
    APPROVED = "approved"
    DEPRECATED = "deprecated"


class KBSource(str, Enum):
    """Who authored the entry. Kept distinct so a reader can tell a fetched
    fact from a generated one -- the same reason findings carry category_source.

    UNAUTHORED exists because a placeholder is not an author. The first build of
    this table wrote 1,481 stub rows -- "Knowledge base entry not yet authored"
    -- and labelled them `ai`, which is the exact confusion this enum is for:
    nothing generated them, and a later reader counting `ai` entries would have
    counted 1,481 model outputs that never existed. A row is `ai` only once a
    model has actually written its content.
    """

    AI = "ai"
    HUMAN = "human"
    IMPORT = "import"           # deterministic fetch from an upstream advisory
    UNAUTHORED = "unauthored"   # key exists, content does not; nobody wrote it
