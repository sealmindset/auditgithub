"""
Tests that the `organizations` table holds the columns the multi-org code reads.

Nothing checked this, and the table had drifted to 10 columns against the 30
declared in migrations/002_organizations.sql. Neither 002 nor 006 (which
re-adds the same columns idempotently) had run against this database, and
there is no migration-tracking table here to have recorded that.

execution/ai_org_agent.py reads and writes the missing columns, so the
consequences were specific rather than theoretical:

  * `scan_repos.py --list-orgs` failed with
    'column "schema_version" does not exist'.
  * The organization scan endpoint returned 500 and launched no scanner --
    mark_scan_started() writes scan_status and scan_progress.
  * Every agent startup logged a schema-sync warning for the same reason,
    which made the warning look like normal noise.

get_organization() was the exception: it degrades to NULL for absent fields
instead of raising, which is why single-org work kept succeeding and hid the
rest. So a test that only exercised one organization would have stayed green
through all of it -- hence the checks below run against information_schema
directly, and against the agent's own SQL.

Run inside the container, against the real database:

    docker exec auditgh_api python -m pytest tests/test_organization_schema.py -q

Read-only apart from list_organizations(), which only selects. The fix is
migrations/025_organization_scan_columns.sql; until it is applied these fail.
"""

import re
from pathlib import Path

import pytest
from sqlalchemy import text

from src.api.database import engine


AGENT_SOURCE = Path(__file__).resolve().parents[1] / "execution" / "ai_org_agent.py"


# Columns ai_org_agent.py reads or writes on `organizations`. Kept explicit so
# the failure message names what is missing, rather than only that a query
# broke.
REQUIRED_COLUMNS = {
    # identity, present before the drift
    "id", "api_id", "name", "display_name", "github_org", "database_name",
    "is_active", "is_default", "created_at", "updated_at",
    # schema synchronization
    "schema_version", "schema_version_name", "schema_sync_status",
    "last_schema_sync", "schema_sync_error",
    # scan tracking
    "last_scan_at", "scan_status", "scan_progress", "total_scans",
    "total_repos", "total_findings",
}


@pytest.fixture(scope="module")
def organization_columns():
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT column_name, data_type, column_default, is_nullable "
            "FROM information_schema.columns "
            "WHERE table_name = 'organizations'"
        )).all()
    return {row[0]: {"type": row[1], "default": row[2], "nullable": row[3]}
            for row in rows}


def test_every_column_the_agent_uses_exists(organization_columns):
    missing = sorted(REQUIRED_COLUMNS - set(organization_columns))
    assert missing == [], (
        f"organizations is missing {len(missing)} column(s): {missing}. "
        "Apply migrations/025_organization_scan_columns.sql"
    )


def test_counter_columns_default_to_zero_not_null(organization_columns):
    """finish_scan() does `total_scans = total_scans + 1`. NULL + 1 is NULL,
    so a missing default silently stops the counter instead of failing."""
    for column in ("total_scans", "total_repos", "total_findings", "scan_progress"):
        assert column in organization_columns, f"{column} absent"
        default = organization_columns[column]["default"]
        assert default is not None and "0" in default, (
            f"{column} has default {default!r}; the increment in finish_scan() "
            "yields NULL without one"
        )


def test_no_organization_row_has_a_null_counter():
    """Rows written before the defaults existed would still carry NULL."""
    with engine.connect() as connection:
        nulls = connection.execute(text(
            "SELECT name FROM organizations "
            "WHERE total_scans IS NULL OR scan_progress IS NULL "
            "OR scan_status IS NULL"
        )).all()
    assert nulls == [], f"rows with NULL scan counters: {[r[0] for r in nulls]}"


def test_scan_status_is_wide_enough_for_every_value_written(organization_columns):
    """'cancelled' is 9 characters and is written by the stop endpoint."""
    with engine.connect() as connection:
        length = connection.execute(text(
            "SELECT character_maximum_length FROM information_schema.columns "
            "WHERE table_name='organizations' AND column_name='scan_status'"
        )).scalar()
    assert length is None or length >= len("cancelled")


# --------------------------------------------------------------------------- #
# The agent's own SQL, against the table
# --------------------------------------------------------------------------- #

def test_the_columns_the_agent_writes_are_all_declared_required():
    """Two-sided guard. The list above is hand-maintained, so this reads the
    agent's UPDATE statements and fails if one writes a column the list does
    not cover -- which would otherwise let a new column reach production
    untested, exactly as these did."""
    source = AGENT_SOURCE.read_text()
    written = set()
    # Scoped to UPDATE organizations specifically: the agent also writes
    # organization_credentials and organization_audit_log, whose columns have
    # nothing to do with this table.
    for match in re.finditer(
        r"UPDATE\s+organizations\s+SET\s+(.+?)(?=\bWHERE\b)",
        source, re.DOTALL | re.IGNORECASE,
    ):
        for assignment in match.group(1).split(","):
            name = assignment.split("=")[0].strip()
            if re.fullmatch(r"[a-z_][a-z0-9_]*", name):
                written.add(name)

    assert written, "no UPDATE organizations statements found; has the agent changed?"
    unknown = sorted(written - REQUIRED_COLUMNS)
    assert unknown == [], (
        f"ai_org_agent.py writes {unknown}, which this test does not require "
        "to exist. Add them to REQUIRED_COLUMNS and to a migration."
    )


@pytest.mark.asyncio
async def test_list_organizations_succeeds():
    """The `--list-orgs` failure, at its source. This selects 17 columns; the
    drifted table had 10, so it raised UndefinedColumn."""
    import sys

    sys.path.insert(0, str(AGENT_SOURCE.parent))
    from execution.ai_org_agent import AIOrganizationAgent

    agent = AIOrganizationAgent()
    await agent.initialize()
    orgs = await agent.list_organizations()
    assert isinstance(orgs, list)
    for org in orgs:
        assert org.name


@pytest.mark.asyncio
async def test_get_organization_reads_the_scan_columns_too():
    """get_organization() selected ten columns and let the dataclass default
    the rest, so it returned scan_status None and total_repos 0 for a row
    holding 'idle' and real counts. Nothing raised -- which is why the column
    drift stayed invisible while single-org work kept succeeding.

    GET /organizations/{org}/scan/status reads this. The endpoint could not
    report a scan at all, and passed None to reconcile_stale(), which is what
    decides whether a scan the API lost track of gets cleared.

    Takes the name from the table rather than from list_organizations(), so
    this still runs when list_organizations() is the thing that is broken."""
    import sys

    with engine.connect() as connection:
        row = connection.execute(text(
            "SELECT name, scan_status, total_repos, total_findings "
            "FROM organizations ORDER BY name LIMIT 1"
        )).one_or_none()
    if row is None:
        pytest.skip("no organizations registered in this database")
    name, scan_status, total_repos, total_findings = row

    sys.path.insert(0, str(AGENT_SOURCE.parent))
    from execution.ai_org_agent import AIOrganizationAgent

    agent = AIOrganizationAgent()
    await agent.initialize()
    org = await agent.get_organization(name)

    assert org is not None
    assert org.name == name
    assert org.scan_status == scan_status
    assert org.total_repos == (total_repos or 0)
    assert org.total_findings == (total_findings or 0)


@pytest.mark.asyncio
async def test_get_organization_agrees_with_list_organizations():
    """Same row, two code paths, one answer. The paths had different SELECT
    lists, so they disagreed about a row neither of them failed to read."""
    import sys

    sys.path.insert(0, str(AGENT_SOURCE.parent))
    from execution.ai_org_agent import AIOrganizationAgent

    agent = AIOrganizationAgent()
    await agent.initialize()
    listed = await agent.list_organizations()
    if not listed:
        pytest.skip("no organizations registered in this database")

    for from_list in listed:
        fetched = await agent.get_organization(from_list.name)
        assert fetched is not None
        assert fetched.to_dict() == from_list.to_dict(), (
            f"get_organization({from_list.name!r}) and list_organizations() "
            "describe the same row differently"
        )


def test_the_organization_queries_share_one_column_list():
    """They diverged once: list_organizations() selected all seventeen,
    get_organization() and get_default_organization() the short ten. A test
    on any one of them alone cannot see that."""
    source = AGENT_SOURCE.read_text()
    assert source.count("SELECT {ORGANIZATION_COLUMNS}") == 3, (
        "an organizations query is spelling out its own column list again; "
        "all three should select ORGANIZATION_COLUMNS"
    )
