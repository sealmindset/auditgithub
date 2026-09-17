"""
Tests for the remediation taxonomy, classifier, grouping and effort model.

These run without a database. Every input is a plain record, which is why the
grouping and effort modules take dataclasses rather than ORM rows.

The tests that matter most here are the ones asserting what the code refuses to
do: not inventing an hour count, not silently producing one action per finding
when a field is missing, not scoring unknown data as zero cost, and not
grouping two separate credentials into one rotation.
"""

import pytest

from src.api.constants.remediation import (
    NON_REMOVING_CATEGORIES,
    REMEDIATION_TEXT,
    ROLE_FOR_CATEGORY,
    CategorySource,
    EffortBand,
    RemediationCategory,
    remediation_text,
)
from src.services import effort as effort_mod
from src.services.remediation_classifier import (
    SUPPRESSIONS,
    canonical_finding_type,
    classify,
    extract_rule_id,
    suppression_for,
)
from src.services.remediation_grouping import (
    FindingRow,
    action_key_for,
    group_findings,
    normalize_file_path,
)


# ---------------------------------------------------------------------------
# Taxonomy
# ---------------------------------------------------------------------------


def test_every_category_has_text_and_a_role():
    """A category with no rendering or no owner cannot appear in a report."""
    for category in RemediationCategory:
        assert category in REMEDIATION_TEXT, f"{category} has no remediation text"
        assert REMEDIATION_TEXT[category]["display"]
        assert category in ROLE_FOR_CATEGORY, f"{category} has no role derivation"


def test_remediation_text_is_two_lines():
    """Line one is the action, line two the caveat. A one-line instruction is how
    a breaking upgrade gets filed as routine work."""
    for category, entry in REMEDIATION_TEXT.items():
        assert entry["text"].count("\n") == 1, f"{category} text is not two lines"


def test_missing_placeholder_renders_as_a_named_unknown():
    """A blank reads as 'nothing to do here'. An unknown must say what would fix it."""
    rendered = remediation_text(RemediationCategory.UPGRADE_DEPENDENCY)
    assert "unknown — no package recorded on this finding" in rendered
    assert "unknown — no fixed_version recorded on this finding" in rendered


def test_non_removing_categories_are_marked():
    """Summing these into 'findings resolved' overstates what the work bought."""
    assert RemediationCategory.INFRA_CONTROL in NON_REMOVING_CATEGORIES
    assert RemediationCategory.COMPENSATING_CONTROL in NON_REMOVING_CATEGORIES
    assert RemediationCategory.ACCEPT_RISK in NON_REMOVING_CATEGORIES
    assert RemediationCategory.UPGRADE_DEPENDENCY not in NON_REMOVING_CATEGORIES


# ---------------------------------------------------------------------------
# Rule identity recovery
# ---------------------------------------------------------------------------
#
# Every title below was taken from the live corpus, not from scanner docs.

@pytest.mark.parametrize(
    "scanner,title,expected",
    [
        ("whispers", "Secret: comment", "comment"),
        ("trufflehog", "Secret found: AzureDevopsPersonalAccessToken",
         "AzureDevopsPersonalAccessToken"),
        ("horusec", "(1/1) * Possible vulnerability detected: Hard-coded password",
         "Hard-coded password"),
        ("terrascan", "reme_checkStorageContainerAccess", "reme_checkStorageContainerAccess"),
        ("retirejs", "Vulnerable JS Library: DOMPurify 2.4.0", "DOMPurify"),
        ("mobsf:android", "[Weak Cryptography] Weak Crypto", "Weak Cryptography/Weak Crypto"),
    ],
)
def test_rule_id_recovered_from_live_titles(scanner, title, expected):
    identity = extract_rule_id(scanner, title)
    assert identity.rule_id == expected
    assert identity.is_stable is True


def test_grype_title_is_a_github_advisory_not_a_cve():
    """cve_id is NULL on every finding in this estate; grype reports GHSAs."""
    identity = extract_rule_id("grype", "GHSA-4v7x-pqxf-cx7m")
    assert identity.ghsa_id == "GHSA-4V7X-PQXF-CX7M"
    assert identity.cve_id is None


def test_retirejs_title_carries_package_and_version():
    """The only place package and version survive for this scanner."""
    identity = extract_rule_id("retirejs", "Vulnerable JS Library: DOMPurify 2.4.0")
    assert identity.package_name == "DOMPurify"
    assert identity.package_version == "2.4.0"


def test_prose_title_is_returned_but_flagged_unstable():
    """trivy-fs emits a check name in prose. Usable as a key, but upstream may reword it."""
    identity = extract_rule_id(
        "trivy-fs", "Storage account should have infrastructure encryption enabled"
    )
    assert identity.rule_id == "Storage account should have infrastructure encryption enabled"
    assert identity.is_stable is False


def test_empty_title_yields_none_not_empty_string():
    """A backfill must tell 'no rule id here' from 'the rule id is empty'."""
    assert extract_rule_id("whispers", None).rule_id is None
    assert extract_rule_id("whispers", "").rule_id is None


# ---------------------------------------------------------------------------
# Classification
# ---------------------------------------------------------------------------


class _Finding:
    """Minimal stand-in for the ORM row."""

    def __init__(self, **kwargs):
        self.finding_type = kwargs.get("finding_type")
        self.scanner_name = kwargs.get("scanner_name")
        self.scanner_name = kwargs.get("scanner_name")
        self.status = kwargs.get("status")
        self.fixed_version = kwargs.get("fixed_version")
        self.ai_triage_recommendation = kwargs.get("ai_triage_recommendation")
        self.ai_triage_confidence = kwargs.get("ai_triage_confidence")


def test_finding_type_aliases_fold_to_one_value():
    """Trivy writes 'vulnerability' where the API queries 'oss'. Both are dependencies."""
    assert canonical_finding_type("vulnerability") == "oss"
    assert canonical_finding_type("dependency") == "oss"
    assert canonical_finding_type("OSS") == "oss"
    # Unknown types pass through so a new scanner is visible, not silently rebucketed.
    assert canonical_finding_type("dast") == "dast"


def test_dependency_without_fixed_version_still_classifies_as_upgrade():
    """fixed_version is empty on all 769,825 findings in this estate. A rule keyed on
    it would send every dependency finding to remove_dependency — wrong, and the most
    expensive advice available."""
    result = classify(_Finding(finding_type="oss"))
    assert result.category is RemediationCategory.UPGRADE_DEPENDENCY
    assert "fixed version was not recorded" in result.rationale


def test_accepted_status_outranks_scanner_taxonomy():
    result = classify(_Finding(finding_type="oss", status="accepted"))
    assert result.category is RemediationCategory.ACCEPT_RISK


def test_low_confidence_false_positive_triage_is_not_honoured():
    """A model that is unsure must not close a finding by itself."""
    result = classify(
        _Finding(finding_type="sast",
                 ai_triage_recommendation="false_positive",
                 ai_triage_confidence=0.4)
    )
    assert result.category is RemediationCategory.CODE_CHANGE


def test_unmatched_type_returns_none_to_signal_the_model():
    """dast is genuinely ambiguous — config, WAF rule, or code defect. The type alone
    does not say which, so the rules decline rather than guess."""
    assert classify(_Finding(finding_type="dast")) is None


def test_every_rule_decision_is_sourced_and_reasoned():
    for ftype in ("secret", "oss", "iac", "sast"):
        result = classify(_Finding(finding_type=ftype))
        assert result.source is CategorySource.RULE
        assert result.confidence == 1.0
        assert result.rationale


# ---------------------------------------------------------------------------
# Suppression
# ---------------------------------------------------------------------------


def test_comment_rule_is_excluded_as_a_false_positive():
    """502,234 findings, 1,538 distinct values, 0 credentials in a 120-row sample."""
    result = classify(_Finding(finding_type="secret", scanner_name="whispers"),
                      rule_id="comment")
    assert result.category is RemediationCategory.FALSE_POSITIVE
    assert result.excluded is True


def test_file_rule_is_excluded_but_not_called_a_false_positive():
    """The rule matches on filename and never opens the file. Calling it a false
    positive would assert those 44,779 files are clean, which nothing here shows."""
    result = classify(_Finding(finding_type="secret", scanner_name="whispers"),
                      rule_id="file")
    assert result.category is not RemediationCategory.FALSE_POSITIVE
    assert result.excluded is True


def test_every_suppression_states_its_basis_in_numbers():
    """Suppressing three quarters of a corpus on an unstated hunch is the kind of
    claim that should not survive a skeptical reader."""
    for (scanner, rule), (_, reason) in SUPPRESSIONS.items():
        assert any(ch.isdigit() for ch in reason), f"{scanner}:{rule} cites no measurement"
        assert len(reason) > 120, f"{scanner}:{rule} reason is too thin to check"


def test_other_whispers_rules_are_untouched():
    """Suppression is exact-match. A neighbouring rule keeps its finding."""
    result = classify(_Finding(finding_type="secret", scanner_name="whispers"),
                      rule_id="aws_account")
    assert result.category is RemediationCategory.ROTATE_SECRET
    assert result.excluded is False


def test_suppression_does_not_override_an_analyst_decision():
    """A person who looked at the row beats a rule about the row's neighbours."""
    result = classify(
        _Finding(finding_type="secret", scanner_name="whispers", status="accepted"),
        rule_id="comment",
    )
    assert result.category is RemediationCategory.ACCEPT_RISK
    assert result.excluded is False


def test_suppression_lookup_is_exact_not_a_prefix():
    assert suppression_for("whispers", "comment") is not None
    assert suppression_for("whispers", "comment_key") is None
    assert suppression_for("trufflehog", "comment") is None
    assert suppression_for(None, "comment") is None


# ---------------------------------------------------------------------------
# Path normalisation
# ---------------------------------------------------------------------------


def test_ephemeral_scan_paths_are_made_repo_relative():
    """About three quarters of file_path values point at a checkout directory that no
    longer exists. Unnormalised, files_count changes between two scans of identical code."""
    assert normalize_file_path("/tmp/repo_scan_8f3a/src/index.js") == "src/index.js"
    assert normalize_file_path("/tmp/repo_scan-91/a/b.tf") == "a/b.tf"


def test_unrecognised_path_is_returned_unchanged():
    """A path we do not understand is reported as-is, not mangled into something that
    looks authoritative."""
    assert normalize_file_path("src/main/java/App.java") == "src/main/java/App.java"
    assert normalize_file_path(None) is None


# ---------------------------------------------------------------------------
# Grouping
# ---------------------------------------------------------------------------


def _dep(idx, repo="r1", pkg="lodash", fixed="4.17.21", path=None):
    return FindingRow(
        id=f"f{idx}",
        repository_id=repo,
        category=RemediationCategory.UPGRADE_DEPENDENCY,
        severity="high",
        scanner_name="grype",
        rule_id="GHSA-4v7x-pqxf-cx7m",
        package_name=pkg,
        package_version="4.17.11",
        fixed_version=fixed,
        ecosystem="npm",
        file_path=path or f"/tmp/repo_scan_1/pkg{idx}/package.json",
    )


def test_one_upgrade_covers_many_findings():
    """The whole reason this module exists."""
    actions = group_findings([_dep(i, repo=f"r{i % 3}") for i in range(40)])
    assert len(actions) == 1
    action = actions[0]
    assert action.findings_count == 40
    assert action.action_key == "upgrade:npm:lodash:4.17.21"
    assert len(action.repository_ids) == 3


def test_missing_package_name_does_not_fall_back_to_one_action_per_finding():
    """Falling back to the finding id would look like a large amount of work rather
    than a missing field."""
    rows = [
        FindingRow(
            id=f"f{i}",
            repository_id="r1",
            category=RemediationCategory.UPGRADE_DEPENDENCY,
            scanner_name="grype",
            rule_id="GHSA-4v7x-pqxf-cx7m",
            ghsa_id="GHSA-4V7X-PQXF-CX7M",
        )
        for i in range(12)
    ]
    actions = group_findings(rows)
    assert len(actions) == 1
    assert actions[0].action_key == "upgrade:advisory:ghsa-4v7x-pqxf-cx7m"


def test_two_secrets_of_the_same_type_are_two_rotations():
    """No secret value or hash is stored, so two findings of one detector are two
    different credentials. Grouping them means someone rotates one key and closes both."""
    rows = [
        FindingRow(id="f1", repository_id="r1",
                   category=RemediationCategory.ROTATE_SECRET,
                   scanner_name="trufflehog", rule_id="AWSAccessKey",
                   file_path="/tmp/repo_scan_1/app/config.yml"),
        FindingRow(id="f2", repository_id="r1",
                   category=RemediationCategory.ROTATE_SECRET,
                   scanner_name="trufflehog", rule_id="AWSAccessKey",
                   file_path="/tmp/repo_scan_1/infra/main.tf"),
    ]
    actions = group_findings(rows)
    assert len(actions) == 2


def test_same_secret_at_the_same_location_collapses():
    """Two scans of one credential are one rotation, not two."""
    rows = [
        FindingRow(id="f1", repository_id="r1",
                   category=RemediationCategory.ROTATE_SECRET,
                   scanner_name="trufflehog", rule_id="AWSAccessKey",
                   file_path="/tmp/repo_scan_1/app/config.yml"),
        FindingRow(id="f2", repository_id="r1",
                   category=RemediationCategory.ROTATE_SECRET,
                   scanner_name="trufflehog", rule_id="AWSAccessKey",
                   # different scan directory, same file
                   file_path="/tmp/repo_scan_99/app/config.yml"),
    ]
    actions = group_findings(rows)
    assert len(actions) == 1
    assert actions[0].findings_count == 2


def test_action_key_is_stable_across_runs():
    """Idempotency of the AuditBoard push rests entirely on this."""
    row = _dep(1)
    assert action_key_for(row) == action_key_for(_dep(1))


def test_every_category_produces_a_key():
    for category in RemediationCategory:
        row = FindingRow(id="f", repository_id="r", category=category,
                         scanner_name="s", rule_id="R1")
        assert action_key_for(row)


def test_actions_are_ordered_by_what_they_close():
    rows = [_dep(i) for i in range(5)]
    rows += [
        FindingRow(id="s1", repository_id="r1", category=RemediationCategory.CONFIGURE,
                   scanner_name="checkov", rule_id="CKV_AWS_18")
    ]
    actions = group_findings(rows)
    assert actions[0].findings_count == 5


# ---------------------------------------------------------------------------
# Effort
# ---------------------------------------------------------------------------


def test_band_is_never_expressed_in_hours():
    """Rob's instruction was 'refer but don't define'. The measurement that would
    justify an hour count — how long past remediations took — is not collected."""
    source = (effort_mod.__doc__ or "") + str(vars(effort_mod).keys())
    assert not hasattr(effort_mod, "HOURS_PER_BAND")
    for band in EffortBand:
        assert band.value in ("S", "M", "L", "XL")


def test_unknown_target_version_is_scored_as_cost_not_as_zero():
    """Treating missing data as 'no problem' makes an estimate optimistic by
    construction."""
    known = effort_mod.estimate(
        RemediationCategory.UPGRADE_DEPENDENCY,
        effort_mod.drivers_for_action(
            category=RemediationCategory.UPGRADE_DEPENDENCY,
            findings_count=1, distinct_file_paths=1, distinct_repos=1,
            current_version="4.17.11", fixed_version="4.17.21",
            is_transitive=False, environments=("dev",),
        ),
    )
    unknown = effort_mod.estimate(
        RemediationCategory.UPGRADE_DEPENDENCY,
        effort_mod.drivers_for_action(
            category=RemediationCategory.UPGRADE_DEPENDENCY,
            findings_count=1, distinct_file_paths=1, distinct_repos=1,
            is_transitive=False, environments=("dev",),
        ),
    )
    assert unknown.score > known.score
    assert unknown.is_well_founded is False
    assert known.is_well_founded is True


def test_major_version_jump_costs_more_than_a_patch_jump():
    assert effort_mod.is_major_upgrade("4.17.11", "5.0.0") is True
    assert effort_mod.is_major_upgrade("4.17.11", "4.17.21") is False
    # Three states, not two: unknown is not False.
    assert effort_mod.is_major_upgrade(None, "5.0.0") is None
    assert effort_mod.is_major_upgrade("4.17.11", "latest") is None


def test_secret_rotation_has_a_floor_regardless_of_count():
    """One exposed credential is still a coordinated, outage-risking operation."""
    est = effort_mod.estimate(
        RemediationCategory.ROTATE_SECRET,
        effort_mod.drivers_for_action(
            category=RemediationCategory.ROTATE_SECRET,
            findings_count=1, distinct_file_paths=1, distinct_repos=1,
            environments=("prod",),
        ),
    )
    assert est.band in (EffortBand.M, EffortBand.L, EffortBand.XL)


def test_every_band_carries_its_reasons():
    """A band with no reasons is one nobody can challenge, which is the same as one
    nobody should believe."""
    est = effort_mod.estimate(
        RemediationCategory.UPGRADE_DEPENDENCY,
        effort_mod.drivers_for_action(
            category=RemediationCategory.UPGRADE_DEPENDENCY,
            findings_count=200, distinct_file_paths=80, distinct_repos=9,
            current_version="4.17.11", fixed_version="5.0.0",
            environments=("prod",),
        ),
    )
    assert est.band is EffortBand.XL
    assert len(est.reasons) >= 4


def test_band_label_says_estimated_and_flags_incomplete_inputs():
    est = effort_mod.estimate(
        RemediationCategory.UPGRADE_DEPENDENCY,
        effort_mod.drivers_for_action(
            category=RemediationCategory.UPGRADE_DEPENDENCY,
            findings_count=1, distinct_file_paths=1, distinct_repos=1,
        ),
    )
    label = effort_mod.band_label(est)
    assert label.startswith("estimated ")
    assert "incomplete inputs" in label


def test_severity_does_not_drive_effort():
    """Severity drives priority. Conflating the two is how 'critical' comes to mean
    'hard', and how a one-line config fix gets budgeted like a rewrite."""
    low = group_findings([
        FindingRow(id="f1", repository_id="r1", category=RemediationCategory.CONFIGURE,
                   severity="low", scanner_name="checkov", rule_id="CKV_AWS_18")
    ])
    critical = group_findings([
        FindingRow(id="f1", repository_id="r1", category=RemediationCategory.CONFIGURE,
                   severity="critical", scanner_name="checkov", rule_id="CKV_AWS_18")
    ])
    assert low[0].effort.band is critical[0].effort.band
