"""
Tests for filing an AuditBoard issue from a hand-picked selection of findings.

Every other scope this app files at is a *rule*. `specific`, `project` and
`org` each name a population the server can re-derive from the issue row alone:
ask whether a finding shares a defect identity with the issue and, for
`project`, whether it is in the same repository. Nothing has to be remembered,
and a finding first seen tomorrow falls under an issue filed today.

A selection is not a rule. Someone ticked rows in the findings table, and only
those rows are covered. That difference is the whole subject of this file, and
it has consequences a database cannot check for us:

*   **Membership must be written down.** With no stored member list, "is this
    finding already filed?" has no answer for a selection: the AuditBoard
    column would stay blank forever and the same findings would be filed twice.
    AuditBoard issues cannot be deleted, so a duplicate is permanent.
*   **A selection must never be widened into a rule.** Writing the reference
    finding's `rule_id` onto a selection-scope issue row would make that issue
    match every other finding of that rule — precisely the population the filer
    chose *not* to file. These tests pin that the coverage query for a
    selection reads the membership table and does not touch `rule_id`.
*   **The body has to name the projects.** A selection spans repositories by
    construction, so a flat list of file paths would leave a reader unable to
    tell which repository any location is in.

Pure functions and compiled SQL expressions only -- no database, no network, no
AuditBoard. The queries are compiled against the PostgreSQL dialect because
that is the only dialect this application runs on; the SQLite-backed fixtures
elsewhere cannot render `UUID` or `JSONB`.
"""

import pytest
from sqlalchemy.dialects import postgresql

from src.api.services.finding_groups import (
    FILEABLE_TIERS,
    GroupTier,
    Identity,
    Location,
    ProjectLocations,
    SelectionPopulation,
    filing_match_condition,
    findings_covered_condition,
    render_locations,
)


def _sql(expression) -> str:
    """Compile an expression to PostgreSQL text with its literals inlined."""
    return str(
        expression.compile(
            dialect=postgresql.dialect(),
            compile_kwargs={"literal_binds": True},
        )
    )


class _Finding:
    """Just the attributes the functions under test read."""

    def __init__(self, **kwargs):
        self.id = kwargs.get("id")
        self.scanner_name = kwargs.get("scanner_name")
        self.rule_id = kwargs.get("rule_id")
        self.file_path = kwargs.get("file_path")
        self.repository_id = kwargs.get("repository_id")
        self.severity = kwargs.get("severity")


class _IssueRow:
    """Just the attributes ``findings_covered_condition`` reads."""

    def __init__(self, **kwargs):
        self.scope = kwargs.get("scope")
        self.id = kwargs.get("id")
        self.finding_id = kwargs.get("finding_id")
        self.scanner_name = kwargs.get("scanner_name")
        self.rule_id = kwargs.get("rule_id")
        self.file_path = kwargs.get("file_path")
        self.repository_id = kwargs.get("repository_id")


# ---------------------------------------------------------------------------
# The tier itself
# ---------------------------------------------------------------------------


def test_selection_is_a_real_tier_with_a_stable_value():
    # Persisted to auditboard_issues.scope and read back by the coverage
    # query, so renaming it silently unfiles every selection issue.
    assert GroupTier.SELECTION.value == "selection"


def test_selection_is_not_something_the_per_finding_endpoint_can_file_at():
    # The per-finding endpoint derives its population from a rule. Offering it
    # 'selection' would mean deriving a member list from one finding, which is
    # a contradiction: selections are filed through their own endpoint with the
    # members passed in explicitly.
    assert GroupTier.SELECTION not in FILEABLE_TIERS


def test_the_retired_global_tier_is_still_excluded_too():
    # Guards against a future edit that rebuilds FILEABLE_TIERS from the enum
    # and readmits both the legacy tier and the selection tier by accident.
    assert GroupTier.LEGACY_GLOBAL not in FILEABLE_TIERS
    assert set(FILEABLE_TIERS) == {
        GroupTier.SPECIFIC,
        GroupTier.PROJECT,
        GroupTier.ORG,
    }


# ---------------------------------------------------------------------------
# "Is this finding already filed?"
# ---------------------------------------------------------------------------


def test_a_finding_matches_a_selection_issue_through_the_membership_table():
    condition = filing_match_condition(
        _Finding(
            id="11111111-1111-1111-1111-111111111111",
            scanner_name="grype",
            rule_id="CVE-2021-1234",
        )
    )
    sql = _sql(condition)
    # The membership table, not a rule comparison: this is the only way a
    # selection issue can be recognized as covering a finding.
    assert "auditboard_issue_findings" in sql
    assert "'selection'" in sql


def test_a_finding_with_no_id_asks_no_selection_question():
    # A finding object assembled from a partial row has no id to look up, and
    # a membership query with a null id would match nothing while looking like
    # it asked. Cheaper and clearer to omit the clause.
    sql = _sql(filing_match_condition(_Finding(scanner_name="grype", rule_id="CVE-1")))
    assert "auditboard_issue_findings" not in sql


def test_the_selection_clause_does_not_replace_the_rule_clauses():
    # A finding can be covered both by a selection issue and by an org-tier
    # issue for its defect. Reporting only one would let a duplicate be filed.
    sql = _sql(
        filing_match_condition(
            _Finding(
                id="11111111-1111-1111-1111-111111111111",
                scanner_name="grype",
                rule_id="CVE-2021-1234",
            )
        )
    )
    assert "auditboard_issue_findings" in sql
    assert "CVE-2021-1234" in sql


# ---------------------------------------------------------------------------
# "Which findings does this issue cover?"
# ---------------------------------------------------------------------------


def test_a_selection_issue_covers_exactly_its_recorded_members():
    row = _IssueRow(
        scope="selection",
        id="22222222-2222-2222-2222-222222222222",
        scanner_name="grype",
        rule_id="CVE-2021-1234",
    )
    sql = _sql(findings_covered_condition(row))
    assert "auditboard_issue_findings" in sql
    assert "22222222-2222-2222-2222-222222222222" in sql


def test_a_selection_issue_never_covers_findings_by_rule():
    """The defect this test exists for.

    If the coverage query for a selection fell through to the rule branch, an
    issue filed for five hand-picked findings would report itself as covering
    every finding of those rules -- thousands, in this estate. The delete
    dry-run would then say an issue still has evidence behind it when it does
    not, and the findings table would mark unfiled findings as filed.
    """
    row = _IssueRow(
        scope="selection",
        id="22222222-2222-2222-2222-222222222222",
        scanner_name="grype",
        rule_id="CVE-2021-1234",
    )
    sql = _sql(findings_covered_condition(row))
    assert "CVE-2021-1234" not in sql
    assert "grype" not in sql


def test_an_org_issue_still_covers_by_rule():
    # The control for the test above: the rule branch has to keep working, or
    # the assertion there would pass for the wrong reason.
    row = _IssueRow(
        scope="org",
        id="33333333-3333-3333-3333-333333333333",
        scanner_name="grype",
        rule_id="CVE-2021-1234",
    )
    sql = _sql(findings_covered_condition(row))
    assert "CVE-2021-1234" in sql
    assert "auditboard_issue_findings" not in sql


# ---------------------------------------------------------------------------
# What the measurement reports
# ---------------------------------------------------------------------------


def _population(**overrides) -> SelectionPopulation:
    defaults = dict(
        finding_count=0,
        project_count=0,
        projects=[],
        identities=[],
        severity=None,
        severity_breakdown=[],
        missing_ids=[],
        ineligible=[],
    )
    defaults.update(overrides)
    return SelectionPopulation(**defaults)


def test_location_count_counts_places_not_findings():
    population = _population(
        finding_count=9,
        project_count=2,
        projects=[
            ProjectLocations(
                repo_name="alpha",
                locations=[
                    Location(path="a.py", count=5, line=3),
                    Location(path="b.py", count=1, line=None),
                ],
                finding_count=6,
            ),
            ProjectLocations(
                repo_name="beta",
                locations=[Location(path="c.py", count=3, line=9)],
                finding_count=3,
            ),
        ],
    )
    # Nine findings, three places. The issue body lists places, so a body
    # claiming nine locations would be wrong about its own contents.
    assert population.location_count == 3
    assert population.repo_names == ["alpha", "beta"]


def test_an_empty_selection_measures_to_nothing_rather_than_raising():
    population = _population()
    assert population.finding_count == 0
    assert population.location_count == 0
    assert population.repo_names == []


def test_missing_and_ineligible_ids_are_carried_rather_than_dropped():
    # Both are reported so a caller can refuse. Dropping them silently is how
    # a permanent record gets filed for a smaller set than the filer saw.
    population = _population(
        finding_count=2,
        missing_ids=["deadbeef-0000-0000-0000-000000000000"],
        ineligible=[("abc", "severity below the filing floor")],
    )
    assert population.missing_ids == ["deadbeef-0000-0000-0000-000000000000"]
    assert population.ineligible == [("abc", "severity below the filing floor")]


# ---------------------------------------------------------------------------
# The location list in the body
# ---------------------------------------------------------------------------


@pytest.fixture
def two_projects():
    return [
        ProjectLocations(
            repo_name="payments-api",
            locations=[
                Location(path="src/auth.py", count=2, line=14),
                Location(path="src/db.py", count=1, line=None),
            ],
            finding_count=3,
        ),
        ProjectLocations(
            repo_name="mobile-app",
            locations=[Location(path="app/login.kt", count=1, line=88)],
            finding_count=1,
        ),
    ]


def test_a_selection_names_the_project_above_its_paths(two_projects):
    """A selection spans repositories, so the paths need an owner.

    Without the project line a reader sees `src/auth.py:14` with no way to tell
    which of two repositories it is in -- and for a hand-picked selection that
    is the normal case, because the reason to tick rows individually is to
    gather findings no single rule groups.
    """
    body = render_locations(two_projects, GroupTier.SELECTION, 100)
    assert "payments-api — 3 finding(s) in 2 location(s)" in body
    assert "mobile-app — 1 finding(s) in 1 location(s)" in body
    assert "  - src/auth.py:14" in body


def test_a_project_tier_body_still_omits_the_project_name(two_projects):
    # The control: at PROJECT tier the repository is in the issue's own
    # context, so repeating it on every line is noise.
    body = render_locations(two_projects[:1], GroupTier.PROJECT, 100)
    assert "payments-api —" not in body
    assert "- src/auth.py:14" in body


def test_a_capped_selection_list_says_how_many_it_left_out(two_projects):
    # A truncated list that looks complete is worse than a count with no list,
    # and an AuditBoard description cannot be edited after it is created.
    body = render_locations(two_projects, GroupTier.SELECTION, 1)
    assert "and 2 further location(s) not listed" in body


# ---------------------------------------------------------------------------
# Identity reporting
# ---------------------------------------------------------------------------


def test_a_selection_reports_every_defect_in_it_not_one():
    """A selection has no single identity, and must not be given one.

    `GroupPopulation` carries one `identity` because every tier it describes is
    one defect. Collapsing a selection's defects to one would let the issue
    claim a key it does not have, and that key would then match other findings.
    """
    population = _population(
        finding_count=3,
        identities=[
            Identity(scanner_name="grype", rule_id="CVE-2021-1234"),
            Identity(scanner_name="horusec", rule_id="Hard-coded password"),
        ],
    )
    assert [i.key for i in population.identities] == [
        "grype::CVE-2021-1234",
        "horusec::Hard-coded password",
    ]
    assert not hasattr(population, "identity")
