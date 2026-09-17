"""
Tests for knowledge base key derivation and advisory enrichment.

No database and no network: `fetch_advisory` is exercised through a stubbed
cache so the parsing is tested without making the suite depend on GitHub being
reachable.

The assertions that matter most are the refusals: not keying on a scanner's
internal name that happens to sit in a CWE column, not folding two case-distinct
scanner rules together, and not turning a failed fetch into an entry that reads
like a successful one.
"""

import pytest

from src.api.constants.kb import (
    ImpactClass,
    KBKeyType,
    KBSource,
    KBStatus,
    MappingSource,
)
from src.services import ghsa_enrichment
from src.services.ghsa_enrichment import (
    AdvisoryFacts,
    fetch_advisory,
    kb_fields_from_advisory,
)
from src.services.kb_key import kb_key_for, normalize_cwe


class _F:
    """Minimal stand-in for the ORM row."""

    def __init__(self, **kw):
        self.scanner_name = kw.get("scanner_name")
        self.rule_id = kw.get("rule_id")
        self.rule_id_is_stable = kw.get("rule_id_is_stable")
        self.ghsa_id = kw.get("ghsa_id")
        self.cve_id = kw.get("cve_id")
        self.cwe_id = kw.get("cwe_id")


# ---------------------------------------------------------------------------
# Key derivation
# ---------------------------------------------------------------------------


def test_advisory_outranks_scanner_rule():
    """grype reports advisories. Keying on its rule instead would create one KB
    entry per scanner for a single vulnerability."""
    key = kb_key_for(_F(ghsa_id="GHSA-4v7x-pqxf-cx7m",
                        scanner_name="grype", rule_id="something"))
    assert key.key == "ghsa:ghsa-4v7x-pqxf-cx7m"
    assert key.key_type is KBKeyType.GHSA
    assert key.identifier == "GHSA-4V7X-PQXF-CX7M"


def test_advisory_key_is_case_stable():
    """Upstream writes GHSAs both ways. Two cases must not be two entries."""
    lower = kb_key_for(_F(ghsa_id="ghsa-4v7x-pqxf-cx7m"))
    upper = kb_key_for(_F(ghsa_id="GHSA-4V7X-PQXF-CX7M"))
    assert lower.key == upper.key


def test_rule_key_preserves_case():
    """`CKV_AWS_18` and `ckv_aws_18` are not the same rule to Checkov, so they
    are not the same entry here."""
    key = kb_key_for(_F(scanner_name="checkov", rule_id="CKV_AWS_18"))
    assert key.key == "rule:checkov/CKV_AWS_18"
    assert key.key_type is KBKeyType.RULE


def test_unstable_rule_id_is_flagged_on_the_key():
    """trivy-fs keys on a check sentence. Still usable, but a KB entry built on
    it can orphan when upstream rewords the check."""
    key = kb_key_for(_F(scanner_name="trivy-fs", rule_id_is_stable=False,
                        rule_id="Storage account should have infrastructure encryption enabled"))
    assert key.is_stable is False
    assert kb_key_for(_F(scanner_name="checkov", rule_id="CKV_AWS_18")).is_stable is True


def test_horusec_engine_string_is_never_keyed_on():
    """findings.cwe_id holds exactly two values across all 769,825 rows: empty,
    and the literal 'HorusecEngine'. Keying on it would produce one KB entry
    about nothing, pointed at by 59,699 findings."""
    assert normalize_cwe("HorusecEngine") is None
    assert kb_key_for(_F(cwe_id="HorusecEngine")) is None


def test_cwe_normalises_but_only_when_it_is_a_cwe():
    assert normalize_cwe("79") == "CWE-79"
    assert normalize_cwe("cwe-79") == "CWE-79"
    assert normalize_cwe("CWE-79") == "CWE-79"
    assert normalize_cwe("") is None
    assert normalize_cwe(None) is None
    assert normalize_cwe("not-a-cwe") is None


def test_unidentifiable_finding_returns_none_not_a_per_finding_key():
    """A KB with one entry per finding is not a knowledge base. The caller must
    handle the gap rather than have it papered over with the finding id."""
    assert kb_key_for(_F()) is None
    assert kb_key_for(_F(scanner_name="grype")) is None   # rule_id missing


def test_precedence_order_is_ghsa_then_cve_then_rule():
    both = _F(ghsa_id="GHSA-4v7x-pqxf-cx7m", cve_id="CVE-2021-23337",
              scanner_name="grype", rule_id="r")
    assert kb_key_for(both).key_type is KBKeyType.GHSA
    no_ghsa = _F(cve_id="CVE-2021-23337", scanner_name="grype", rule_id="r")
    assert kb_key_for(no_ghsa).key_type is KBKeyType.CVE
    no_advisory = _F(scanner_name="grype", rule_id="r")
    assert kb_key_for(no_advisory).key_type is KBKeyType.RULE


# ---------------------------------------------------------------------------
# Advisory enrichment
# ---------------------------------------------------------------------------

# Trimmed from the live response for GHSA-W5HQ-G745-H8PQ, the advisory with the
# most findings in this estate (643).
_LIVE_PAYLOAD = {
    "ghsa_id": "GHSA-w5hq-g745-h8pq",
    "cve_id": "CVE-2026-41907",
    "summary": "uuid: Missing buffer bounds check in v3/v5/v6 when buf is provided",
    "description": "A bounds check is missing...",
    "severity": "medium",
    "published_at": "2026-08-01T00:00:00Z",
    "withdrawn_at": None,
    "cwes": [
        {"cwe_id": "CWE-787", "name": "Out-of-bounds Write"},
        {"cwe_id": "CWE-1285", "name": "Improper Validation of Specified Index"},
    ],
    "references": ["https://github.com/uuidjs/uuid/commit/abc"],
    "epss": {"percentage": 0.0035, "percentile": 0.27568},
    "vulnerabilities": [
        {"package": {"ecosystem": "npm", "name": "uuid"},
         "vulnerable_version_range": "< 11.1.1", "first_patched_version": "11.1.1"},
        {"package": {"ecosystem": "npm", "name": "uuid"},
         "vulnerable_version_range": ">= 12.0.0, < 12.0.1", "first_patched_version": "12.0.1"},
    ],
}


@pytest.fixture
def stub_cache(monkeypatch):
    """Replace the network with a canned response."""
    calls = []

    def _fake(**kwargs):
        calls.append(kwargs)
        return {"ok": True, "data": _LIVE_PAYLOAD, "source": "cache",
                "url": kwargs["url"], "error": None}

    monkeypatch.setattr(ghsa_enrichment, "cached_fetch", _fake)
    return calls


def test_advisory_supplies_the_cwe_the_database_lacks(stub_cache):
    """The whole reason this module exists: no finding in this estate carries a
    real CWE, and the CWE -> CAPEC -> ATT&CK chain has no other input."""
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.ok
    assert facts.cwe_ids == ["CWE-787", "CWE-1285"]


def test_advisory_supplies_fixed_version_per_package(stub_cache):
    """fixed_version is empty on all 769,825 rows. This is where it comes back."""
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.first_patched_for("uuid") == "11.1.1"
    assert facts.first_patched_for("UUID") == "11.1.1"      # case-insensitive
    assert facts.first_patched_for("lodash") is None        # not in this advisory
    assert facts.first_patched_for(None) is None


def test_advisory_supplies_the_missing_cve(stub_cache):
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.cve_id == "CVE-2026-41907"


def test_bad_identifier_fails_without_a_request(monkeypatch):
    """A malformed id must not become a URL fetch."""
    def _boom(**kwargs):
        raise AssertionError("no request should be made for a malformed id")
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch", _boom)

    facts = fetch_advisory("not-an-advisory")
    assert facts.ok is False
    assert "not a GHSA identifier" in facts.error


def test_failed_fetch_cannot_become_a_knowledge_base_entry(monkeypatch):
    """The failure mode this guards against: a network error silently producing
    an entry with no CWE and no fix, indistinguishable from an advisory that
    genuinely has neither."""
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch",
                        lambda **kw: {"ok": False, "data": None, "source": "none",
                                      "url": kw["url"], "error": "connection reset"})
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.ok is False
    assert facts.error == "connection reset"
    with pytest.raises(ValueError):
        kb_fields_from_advisory(facts)


def test_missing_advisory_is_a_failure_not_an_empty_entry(monkeypatch):
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch",
                        lambda **kw: {"ok": True, "data": None, "source": "live",
                                      "url": kw["url"], "error": None})
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.ok is False
    assert facts.error == "advisory not found"


def test_withdrawn_advisory_is_visible(monkeypatch):
    """An engineer sent to fix a retracted advisory has been sent to do nothing."""
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch",
                        lambda **kw: {"ok": True, "source": "cache", "url": kw["url"],
                                      "error": None,
                                      "data": {**_LIVE_PAYLOAD,
                                               "withdrawn_at": "2026-08-09T00:00:00Z"}})
    facts = fetch_advisory("GHSA-w5hq-g745-h8pq")
    assert facts.is_withdrawn is True
    assert kb_fields_from_advisory(facts)["is_withdrawn"] is True


def test_kb_fields_are_marked_imported_not_generated(stub_cache):
    """A fetched fact and a model-written paragraph must never share a source
    value, or `source` stops distinguishing anything."""
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    assert fields["source"] == KBSource.IMPORT.value
    assert fields["ai_confidence"] is None
    assert fields["source_url"].endswith("GHSA-W5HQ-G745-H8PQ")


def test_kb_fields_carry_citable_references(stub_cache):
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    types = [r["type"] for r in fields["reference_ids"]]
    assert "ghsa" in types and "cve" in types and "cwe" in types
    assert all(r.get("url") for r in fields["reference_ids"])


def test_enrichment_does_not_author_blast_radius_or_mitigations(stub_cache):
    """The advisory does not state these, so the import must not invent them.
    They are authored (§3.3, §3.5) and arrive by a different path."""
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    assert "blast_radius" not in fields
    assert "mitigation_options" not in fields
    assert "ttp" not in fields


def test_unchecked_exploitability_signals_stay_none(stub_cache):
    """'We did not check' and 'we checked and it is not listed' are different
    claims. KEV membership is not in this response, so it stays None."""
    ex = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))["exploitability"]
    assert ex["kev_listed"] is None
    assert ex["has_public_exploit"] is None
    assert ex["epss_score"] == 0.0035
    assert ex["source"].startswith("https://api.github.com/advisories/")


# ---------------------------------------------------------------------------
# Vocabulary
# ---------------------------------------------------------------------------


def test_mapping_source_none_is_a_real_value():
    """No finding in this estate carries a usable CWE, so `none` is the default
    outcome of the TTP mapping, not an error path."""
    assert MappingSource.NONE.value == "none"


def test_only_approved_entries_can_render():
    assert {s.value for s in KBStatus} == {"draft", "approved", "deprecated"}


def test_impact_class_is_exploitation_not_severity():
    values = {i.value for i in ImpactClass}
    assert "rce" in values and "supply_chain" in values
    assert "high" not in values and "critical" not in values


def test_an_unauthored_entry_claims_no_author():
    """The first build wrote 1,481 placeholder rows labelled `ai`. Nothing
    generated them, so anyone counting `ai` entries was counting model outputs
    that never happened. A key with no content is `unauthored`."""
    assert KBSource.UNAUTHORED.value == "unauthored"
    assert {s.value for s in KBSource} == {"ai", "human", "import", "unauthored"}


def test_advisory_description_is_imported_as_the_summary(stub_cache):
    """The advisory's own prose is a fetched fact, so importing it is what makes
    `source: import` true of the whole row rather than just its metadata."""
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    assert fields["summary"] == "A bounds check is missing..."
    assert fields["source"] == KBSource.IMPORT.value


def test_an_advisory_with_no_description_yields_no_summary(monkeypatch):
    """Falling back to the title would dress a one-line headline up as an
    explanation, and the entry would stop looking like it needs authoring."""
    payload = {**_LIVE_PAYLOAD, "description": None}
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch",
                        lambda **kw: {"ok": True, "data": payload, "source": "cache",
                                      "url": kw["url"], "error": None})
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    assert fields["summary"] is None


def test_a_very_long_advisory_description_is_bounded_and_says_so(monkeypatch):
    """Advisories run to tens of thousands of characters. The summary column is
    not a transcript, and a silent cut is the defect §1.2 already fixed once."""
    payload = {**_LIVE_PAYLOAD,
               "description": "## Impact\n" + ("Long advisory prose. " * 2000)}
    monkeypatch.setattr(ghsa_enrichment, "cached_fetch",
                        lambda **kw: {"ok": True, "data": payload, "source": "cache",
                                      "url": kw["url"], "error": None})
    fields = kb_fields_from_advisory(fetch_advisory("GHSA-w5hq-g745-h8pq"))
    assert len(fields["summary"]) < len(payload["description"])
    assert "truncated" in fields["summary"] or "omitted" in fields["summary"]
