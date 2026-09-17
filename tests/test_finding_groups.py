"""
Tests for the defect-grouping rule behind AuditBoard filings.

The rule is stated in `src/api/services/finding_groups.py`: an issue is filed
against a *defect*, identified by `(scanner_name, rule_id)`, and it lists every
location of that defect inside the project it is filed for. Before this, filing
grouped on `(scanner_name, file_path)`, which put 11,517 findings from 1,287
unrelated advisories behind one key because they all sat in a file called
`package-lock.json`, and split a single advisory across each of the 100+
projects it touched.

Everything here is a pure function over its arguments -- no database, no
network, no AuditBoard. The query layer is exercised separately against real
data; these pin the decisions that a database cannot check:

*   a per-scan temp prefix never reaches an issue body, because a path under
    `/tmp/repo_scan_<id>/` stops resolving the moment the scan is gone;
*   the canonical identity of a merged group does not depend on which member
    the filer happened to have open, or the same defect files twice;
*   an unrecognized severity never wins a `max()`, so a typo cannot promote an
    issue to critical;
*   the location list is capped and *says* it was capped, because a truncated
    list that looks complete is worse than a count with no list.
"""

import pytest

from src.api.services.finding_groups import (
    EquivalenceMap,
    GroupTier,
    Identity,
    Location,
    ProjectLocations,
    collect_locations,
    highest_severity,
    identity_of,
    normalize_path,
    recommended_tier,
    render_locations,
    severity_rank,
)


class _Finding:
    """Just the attributes the pure functions read."""

    def __init__(self, scanner_name=None, rule_id=None, severity=None):
        self.scanner_name = scanner_name
        self.rule_id = rule_id
        self.severity = severity


# ---------------------------------------------------------------------------
# Severity
# ---------------------------------------------------------------------------

def test_severity_rank_orders_ascending():
    assert severity_rank("info") < severity_rank("low") < severity_rank("medium")
    assert severity_rank("medium") < severity_rank("high") < severity_rank("critical")


def test_unknown_severity_ranks_below_everything():
    """A typo must not outrank a real severity in a max()."""
    assert severity_rank("kritical") < severity_rank("info")
    assert severity_rank(None) < severity_rank("info")


def test_highest_severity_wins():
    assert highest_severity(["low", "critical", "medium"]) == "critical"


def test_highest_severity_ignores_unknown_values():
    assert highest_severity(["kritical", "low"]) == "low"


def test_highest_severity_of_nothing_is_none():
    assert highest_severity([]) is None
    assert highest_severity([None, ""]) is None


def test_severity_is_case_insensitive():
    assert highest_severity(["CRITICAL", "low"]) == "critical"


# ---------------------------------------------------------------------------
# Path normalization
#
# 573,526 of 767,974 findings carry a path under a per-scan temp directory.
# ---------------------------------------------------------------------------

def test_scan_prefix_is_stripped():
    assert (
        normalize_path("/tmp/repo_scan_abc123/InvisionTwo/app/google-services.json")
        == "InvisionTwo/app/google-services.json"
    )


def test_repo_name_is_stripped_when_it_leads_the_path():
    """The project is named by the section heading, so repeating it is noise."""
    assert (
        normalize_path(
            "/tmp/repo_scan_abc123/InvisionTwo/app/google-services.json",
            repo_name="InvisionTwo",
        )
        == "app/google-services.json"
    )


def test_repo_name_is_not_stripped_outside_a_scan_directory():
    """A path that is already repo-relative is left alone."""
    assert (
        normalize_path("InvisionTwo/app/build.gradle", repo_name="InvisionTwo")
        == "InvisionTwo/app/build.gradle"
    )


def test_repo_name_matching_a_directory_deeper_in_is_left_alone():
    assert (
        normalize_path("/tmp/repo_scan_x/Outer/app/app.json", repo_name="app")
        == "Outer/app/app.json"
    )


def test_a_path_that_is_only_a_scan_prefix_is_kept_as_is():
    """Never return an empty path: an issue body with no location is unactionable."""
    raw = "/tmp/repo_scan_abc123/"
    assert normalize_path(raw) == raw


def test_blank_paths_survive_as_none():
    assert normalize_path(None) is None
    assert normalize_path("") is None


# ---------------------------------------------------------------------------
# Identity
# ---------------------------------------------------------------------------

def test_identity_key_is_scanner_and_rule():
    assert Identity("grype", "GHSA-M7JM-9GC2-MPF2").key == "grype::GHSA-M7JM-9GC2-MPF2"


def test_identity_requires_both_halves():
    """No rule means no defect identity, which means specific filing only."""
    assert identity_of(_Finding(scanner_name="grype", rule_id=None)) is None
    assert identity_of(_Finding(scanner_name="grype", rule_id="  ")) is None
    assert identity_of(_Finding(scanner_name=None, rule_id="CVE-2024-1")) is None


def test_identity_is_read_off_the_finding():
    found = identity_of(_Finding(scanner_name="whispers", rule_id="current_key"))
    assert found == Identity("whispers", "current_key")


# ---------------------------------------------------------------------------
# Equivalence
#
# Only reviewer-approved pairs reach this map. An unreviewed proposal is inert
# by design: AuditBoard issues cannot be deleted and their descriptions cannot
# be edited after create, so a wrong merge permanently claims an issue covers a
# finding it does not describe.
# ---------------------------------------------------------------------------

def test_an_unmerged_identity_is_its_own_canonical_form():
    empty = EquivalenceMap()
    identity = Identity("grype", "CVE-2024-1")
    assert empty.canonical(identity) == identity
    assert empty.members(identity) == [identity]
    assert not empty.is_merged(identity)


def test_merged_identities_share_one_canonical_key():
    a, b = Identity("grype", "CVE-2024-1"), Identity("trivy", "CVE-2024-1")
    merged = EquivalenceMap([(a, b)])
    assert merged.canonical(a) == merged.canonical(b)
    assert merged.is_merged(a)


def test_canonical_form_does_not_depend_on_which_member_was_opened():
    """Otherwise the same defect files twice, once per scanner."""
    a, b = Identity("grype", "CVE-2024-1"), Identity("trivy", "CVE-2024-1")
    from_a = EquivalenceMap([(a, b)])
    from_b = EquivalenceMap([(b, a)])
    assert from_a.canonical(a) == from_b.canonical(b)


def test_merges_are_transitive():
    a = Identity("grype", "CVE-2024-1")
    b = Identity("trivy", "CVE-2024-1")
    c = Identity("osv", "GHSA-xxxx")
    merged = EquivalenceMap([(a, b), (b, c)])
    assert merged.members(a) == merged.members(c)
    assert len(merged.members(a)) == 3


def test_members_are_returned_in_a_stable_order():
    a = Identity("trivy", "CVE-2024-1")
    b = Identity("grype", "CVE-2024-1")
    merged = EquivalenceMap([(a, b)])
    assert merged.members(a) == merged.members(b)
    assert merged.members(a) == sorted(merged.members(a))


# ---------------------------------------------------------------------------
# Volume rule
#
# Rob Vance's decision, 2026-09-16: escalate above 10 projects.
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("projects", [0, 1, 5, 10])
def test_at_or_below_the_threshold_stays_with_the_project(projects):
    assert recommended_tier(projects, 10) is GroupTier.PROJECT


@pytest.mark.parametrize("projects", [11, 14, 100])
def test_above_the_threshold_escalates_to_the_organization(projects):
    assert recommended_tier(projects, 10) is GroupTier.ORG


def test_the_retired_global_tier_is_not_fileable():
    from src.api.services.finding_groups import FILEABLE_TIERS

    assert GroupTier.LEGACY_GLOBAL not in FILEABLE_TIERS
    assert set(FILEABLE_TIERS) == {GroupTier.SPECIFIC, GroupTier.PROJECT, GroupTier.ORG}


# ---------------------------------------------------------------------------
# Locations
# ---------------------------------------------------------------------------

def test_locations_are_grouped_by_project_and_counted():
    projects = collect_locations([
        ("InvisionTwo", "/tmp/repo_scan_a/InvisionTwo/app/a.json", 32, 20),
        ("InvisionTwo", "/tmp/repo_scan_a/InvisionTwo/app/b.json", 23, 10),
        ("Other", "/tmp/repo_scan_a/Other/c.json", 1, 5),
    ])
    assert [p.repo_name for p in projects] == ["InvisionTwo", "Other"]
    assert projects[0].finding_count == 30
    assert projects[0].location_count == 2


def test_the_worst_project_is_listed_first():
    projects = collect_locations([
        ("Quiet", "/tmp/repo_scan_a/Quiet/a.json", 1, 2),
        ("Loud", "/tmp/repo_scan_a/Loud/a.json", 1, 99),
    ])
    assert [p.repo_name for p in projects] == ["Loud", "Quiet"]


def test_counts_are_summed_when_normalization_merges_two_paths():
    """Two scans of the same file under different temp directories are one place."""
    projects = collect_locations([
        ("App", "/tmp/repo_scan_first/App/a.json", 7, 3),
        ("App", "/tmp/repo_scan_second/App/a.json", 7, 4),
    ])
    assert projects[0].location_count == 1
    assert projects[0].locations[0].count == 7
    assert projects[0].finding_count == 7


def test_a_file_level_finding_renders_without_a_line_number():
    assert Location(path="package-lock.json", count=6, line=0).render() == (
        "package-lock.json (6 occurrences)"
    )


def test_a_line_level_finding_renders_with_its_line():
    assert Location(path="app/a.json", count=1, line=32).render() == "app/a.json:32"


def test_a_single_occurrence_carries_no_count():
    """One finding at one place needs no tally; "(1 occurrence)" is just noise."""
    assert Location(path="package-lock.json", count=1, line=0).render() == (
        "package-lock.json"
    )
    assert Location(path="package-lock.json", count=2, line=0).render() == (
        "package-lock.json (2 occurrences)"
    )


def test_project_tier_does_not_repeat_the_project_name():
    rendered = render_locations(
        collect_locations([("App", "/tmp/repo_scan_a/App/a.json", 3, 2)]),
        GroupTier.PROJECT,
        max_locations=100,
    )
    assert "Locations in this project" in rendered
    assert "- a.json:3 (2 occurrences)" in rendered


def test_org_tier_names_every_project():
    rendered = render_locations(
        collect_locations([
            ("Alpha", "/tmp/repo_scan_a/Alpha/a.json", 0, 2),
            ("Beta", "/tmp/repo_scan_a/Beta/b.json", 0, 1),
        ]),
        GroupTier.ORG,
        max_locations=100,
    )
    assert "Alpha" in rendered and "Beta" in rendered


def test_a_capped_list_says_how_many_it_left_out():
    """A truncated list that looks complete is worse than a count with no list."""
    rows = [("App", f"/tmp/repo_scan_a/App/file{i}.json", 0, 1) for i in range(10)]
    rendered = render_locations(collect_locations(rows), GroupTier.PROJECT, max_locations=3)
    assert rendered.count("\n- ") == 3
    assert "7 further location" in rendered


def test_no_locations_is_stated_rather_than_left_blank():
    rendered = render_locations([], GroupTier.PROJECT, max_locations=100)
    assert rendered.strip() != ""
    assert "None" in rendered or "none" in rendered


def test_project_location_count_counts_places_not_findings():
    project = ProjectLocations(
        repo_name="App",
        locations=[Location(path="a.json", count=50, line=1)],
        finding_count=50,
    )
    assert project.location_count == 1
    assert project.finding_count == 50
