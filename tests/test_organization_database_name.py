"""
Tests for how `organizations.database_name` is written, validated and used.

The observed failure: `scan_repos.py --list-orgs` reported the `sleepnumber`
organization as `Schema: error`, and the stored error was

    zero-length delimited identifier
    LINE 1: CREATE DATABASE ""

The row's database_name is NULL. _row_to_org() coerces NULL to '' so the
dataclass field stays a str, and the empty string was then interpolated into
DDL five frames later:

    initialize() -> sync_all_schemas() -> sync_schema('sleepnumber')
        -> _apply_master_schema('') -> _apply_schema_via_psycopg2('')
        -> _ensure_database_exists('') -> CREATE DATABASE ""

Nothing on that path checked the value, so the report named neither the
organization nor the column. The error text then stayed on the row
indefinitely, because only a *failed* sync wrote schema_sync_error and no
later run ever cleared it -- so one bad row read as a permanent schema
failure.

Two further consequences of the same unset value, neither of which announced
itself:

  * get_database_url() built 'postgresql://user:pass@host:5432/' -- a valid
    libpq URL that connects to the database named after the user. Scan
    results would have been written to 'postgres'.
  * check_schema_drift() hashed the empty string (pg_dump fails, and the
    fallback hashes the name) and reported drift against master: a difference
    between two schemas, one of which does not exist.

And the name itself was written two different ways -- create_organization()
used 'auditgithub_{name}', _auto_register_orgs_from_env() used
'auditgh_{name}' -- so an organization's database name depended on which
path registered it.

Run inside the container, against the real database:

    docker exec auditgh_api python -m pytest tests/test_organization_database_name.py -q

The sync tests insert one organization row and delete it again; everything
else is read-only or pure.
"""

import uuid
from pathlib import Path

import pytest
from sqlalchemy import text

from src.api.database import engine
from execution.ai_org_agent import (
    AIOrganizationAgent,
    DATABASE_NAME_PREFIX,
    default_database_name,
    validate_database_name,
)


AGENT_SOURCE = Path(__file__).resolve().parents[1] / "execution" / "ai_org_agent.py"


# --------------------------------------------------------------------------- #
# validate_database_name
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("value", [None, "", "   ", "\t\n"])
def test_blank_database_name_is_refused_before_it_reaches_ddl(value):
    with pytest.raises(ValueError) as excinfo:
        validate_database_name(value, context="ctx")
    message = str(excinfo.value)
    # The message has to name the column and the fix, because the operator
    # reading it is looking at a row, not at this stack.
    assert "database_name" in message
    assert DATABASE_NAME_PREFIX in message
    assert "ctx" in message


@pytest.mark.parametrize("value", [
    "bad name",          # space
    "1abc",              # leading digit
    "abc-def",           # hyphen
    'evil"; DROP DATABASE security_portal; --',
    "a" * 64,            # over NAMEDATALEN - 1
])
def test_unusable_identifiers_are_refused(value):
    """These names are interpolated into CREATE DATABASE, which takes an
    identifier and so cannot be parameterized. Validation is the control."""
    with pytest.raises(ValueError):
        validate_database_name(value, context="ctx")


@pytest.mark.parametrize("value", [
    "auditgithub_sleepnumberinc",
    "security_portal",
    "_leading_underscore",
    "MixedCase99",
    "a" * 63,            # exactly NAMEDATALEN - 1
])
def test_usable_identifiers_are_accepted(value):
    assert validate_database_name(value, context="ctx") == value


def test_surrounding_whitespace_is_stripped_not_rejected():
    assert validate_database_name("  auditgithub_x  ", context="ctx") == "auditgithub_x"


# --------------------------------------------------------------------------- #
# One naming convention
# --------------------------------------------------------------------------- #

def test_default_database_name_is_lowercased_and_prefixed():
    assert default_database_name("  SleepNumber ") == f"{DATABASE_NAME_PREFIX}sleepnumber"


def test_both_registration_paths_use_the_shared_helper():
    """Source-level guard. The two paths disagreed ('auditgithub_' vs
    'auditgh_'), which is the kind of divergence a unit test on either one
    alone cannot see."""
    source = AGENT_SOURCE.read_text()
    assert 'f"auditgh_{' not in source, (
        "the auditgh_ prefix is back; both registration paths should call "
        "default_database_name()"
    )
    assert 'f"auditgithub_{' not in source, (
        "database name built inline again rather than via default_database_name()"
    )
    assert source.count("default_database_name(") >= 3  # def + two call sites


def test_existing_rows_match_the_convention():
    """The two organizations with databases were written as auditgithub_*, so
    the helper has to keep producing that and not silently re-point them."""
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT name, database_name FROM organizations "
            "WHERE database_name IS NOT NULL AND database_name <> ''"
        )).all()
    for name, database_name in rows:
        assert database_name == default_database_name(name), (
            f"{name} has database_name {database_name!r}, which "
            f"default_database_name() would not produce"
        )


def test_no_row_holds_an_empty_string_database_name():
    """NULL means 'uses the master database' and every consumer now handles
    it. An empty string means the same thing to a human and something
    different to `IS NOT NULL`, so it would slip past the checks above."""
    with engine.connect() as connection:
        empty = connection.execute(text(
            "SELECT name FROM organizations WHERE database_name = ''"
        )).all()
    assert empty == [], (
        f"rows with an empty-string database_name: {[r[0] for r in empty]}. "
        "Set NULL instead, or a real name."
    )


def test_every_stored_database_name_is_a_usable_identifier():
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT name, database_name FROM organizations "
            "WHERE database_name IS NOT NULL AND database_name <> ''"
        )).all()
    for name, database_name in rows:
        validate_database_name(database_name, context=f"organization {name}")


# --------------------------------------------------------------------------- #
# The DDL entry points
# --------------------------------------------------------------------------- #

@pytest.fixture
def no_connections(monkeypatch):
    """Fails the test if a database connection is opened. The guard has to
    reject before connecting, not after -- the original bug reached Postgres
    and came back as a parse error."""
    import execution.ai_org_agent as agent_module

    def refuse(*args, **kwargs):
        raise AssertionError("connected to the database despite a blank name")

    monkeypatch.setattr(agent_module.psycopg2, "connect", refuse)


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "   ", None])
async def test_create_database_refuses_a_blank_name(blank, no_connections):
    agent = AIOrganizationAgent()
    with pytest.raises(ValueError, match="database_name"):
        await agent._create_database(blank)


@pytest.mark.asyncio
@pytest.mark.parametrize("blank", ["", "   ", None])
async def test_ensure_database_exists_refuses_a_blank_name(blank, no_connections):
    """This is the frame that ran CREATE DATABASE "" in the observed failure."""
    agent = AIOrganizationAgent()
    with pytest.raises(ValueError, match="database_name"):
        await agent._ensure_database_exists(blank)


# --------------------------------------------------------------------------- #
# Sync, against a real row
# --------------------------------------------------------------------------- #

@pytest.fixture
def org_without_database_name():
    """An organizations row with database_name NULL, deleted afterwards."""
    name = f"pytest_no_db_name_{uuid.uuid4().hex[:8]}"
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO organizations (id, name, github_org, is_active, is_default) "
            "VALUES (:id, :name, :name, true, false)"
        ), {"id": str(uuid.uuid4()), "name": name})
    try:
        yield name
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM organizations WHERE name = :name"),
                {"name": name},
            )


def _row(name, column):
    with engine.connect() as connection:
        return connection.execute(
            text(f"SELECT {column} FROM organizations WHERE name = :name"),
            {"name": name},
        ).scalar()


@pytest.mark.asyncio
async def test_sync_skips_an_organization_with_no_database_name(org_without_database_name):
    """The multi-tenant case. A deployment that does give each organization a
    database still has to cope with a row that names none -- otherwise this is
    only tested by the mode that skips everything anyway."""
    agent = AIOrganizationAgent()
    agent.multi_tenant = True
    result = await agent.sync_schema(org_without_database_name)
    assert result["status"] == "skipped"
    assert "database_name" in result["reason"]


@pytest.mark.asyncio
async def test_sync_skips_everything_in_single_database_mode(org_without_database_name):
    """MULTI_TENANT_ENABLED false: there are no per-organization schemas to
    keep in step, and attempting it created empty databases nothing reads."""
    agent = AIOrganizationAgent()
    agent.multi_tenant = False
    result = await agent.sync_schema(org_without_database_name)
    assert result["status"] == "skipped"
    assert "MULTI_TENANT_ENABLED" in result["reason"]


@pytest.mark.asyncio
async def test_a_skipped_sync_clears_a_stale_error(org_without_database_name):
    """The `sleepnumber` row carried 'zero-length delimited identifier' long
    after anything was still attempting that DDL, because only failures wrote
    the column."""
    with engine.begin() as connection:
        connection.execute(text(
            "UPDATE organizations SET schema_sync_status = 'error', "
            "schema_sync_error = 'stale text from an earlier run' "
            "WHERE name = :name"
        ), {"name": org_without_database_name})

    agent = AIOrganizationAgent()
    await agent.sync_schema(org_without_database_name)

    assert _row(org_without_database_name, "schema_sync_status") == "skipped"
    assert _row(org_without_database_name, "schema_sync_error") is None


@pytest.mark.asyncio
async def test_sync_all_counts_skipped_apart_from_errors(org_without_database_name):
    """Startup reported '2 synced, 1 errors' for a configuration that has
    nothing to sync, which is indistinguishable from a real failure."""
    agent = AIOrganizationAgent()
    results = await agent.sync_all_schemas()
    assert results["skipped"] >= 1
    detail = next(d for d in results["details"]
                  if d["organization"] == org_without_database_name)
    assert detail["status"] == "skipped"


@pytest.mark.asyncio
async def test_drift_check_reports_skipped_rather_than_drift(org_without_database_name):
    agent = AIOrganizationAgent()
    reports = await agent.check_schema_drift()
    report = next(r for r in reports
                  if r["organization"] == org_without_database_name)
    assert report["status"] == "skipped"
    assert report["is_synced"] is None


@pytest.mark.asyncio
async def test_database_url_falls_back_to_master_rather_than_a_bare_slash(
    org_without_database_name,
):
    """'postgresql://user:pass@host:5432/' connects to the database named
    after the user, so this failed by writing somewhere else rather than by
    raising."""
    agent = AIOrganizationAgent()
    url = await agent.get_database_url(org_without_database_name)
    assert not url.endswith("/")
    assert url == agent.master_db_url


# --------------------------------------------------------------------------- #
# Where a scan's results go
# --------------------------------------------------------------------------- #
#
# scan_repos.py --target <org> rebinds SessionLocal to whatever
# select_organization() puts in DATABASE_URL, and --target is what the
# organization scan button runs (src/services/scan_runner.py). So this
# decision is where an organization scan writes its findings.
#
# It used to be made from the row alone. On this host that sent scans of
# sleepnumberinc to auditgithub_sleepnumberinc -- a database with no
# `repositories` table -- while the UI read 2,540 repositories and 767,895
# findings from the master.

def _org(database_name):
    from datetime import datetime

    from execution.ai_org_agent import Organization

    now = datetime(2026, 1, 1)
    return Organization(
        id="00000000-0000-0000-0000-000000000000",
        api_id=1,
        name="acme",
        display_name="Acme",
        github_org="acme",
        database_name=database_name,
        is_active=True,
        is_default=False,
        created_at=now,
        updated_at=now,
    )


@pytest.mark.parametrize("database_name", [
    "auditgithub_acme",   # a row that names a database
    None,                 # a row that does not
    "",
])
def test_single_database_mode_scans_into_the_master(database_name):
    """MULTI_TENANT_ENABLED false: the row's database_name is not an
    instruction, because there is only one database holding data."""
    agent = AIOrganizationAgent()
    agent.multi_tenant = False
    assert agent._scan_database_name(_org(database_name)) == agent.master_db_name


def test_multi_tenant_mode_scans_into_the_organization_database():
    agent = AIOrganizationAgent()
    agent.multi_tenant = True
    assert agent._scan_database_name(_org("auditgithub_acme")) == "auditgithub_acme"


@pytest.mark.parametrize("database_name", [None, "", "   "])
def test_multi_tenant_mode_still_falls_back_when_the_row_names_nothing(database_name):
    """Both conditions, not either: multi-tenancy does not conjure a database
    for a row that names none."""
    agent = AIOrganizationAgent()
    agent.multi_tenant = True
    assert agent._scan_database_name(_org(database_name)) == agent.master_db_name


def test_the_deployment_flag_is_read_from_the_same_variable_as_the_api():
    """src/api/database.py, src/api/dependencies.py and
    src/rbac/dependencies.py all key off MULTI_TENANT_ENABLED. The agent
    ignoring it is what put the scanner and the UI in different databases."""
    import os

    expected = os.environ.get("MULTI_TENANT_ENABLED", "false").lower() == "true"
    assert AIOrganizationAgent().multi_tenant is expected


def test_new_organizations_do_not_claim_a_database_in_single_database_mode():
    """create_database defaulted to True, so registering an organization
    created a database nothing would read and recorded its name on the row --
    which the scan path then treated as where results belong."""
    source = AGENT_SOURCE.read_text()
    assert "create_database: Optional[bool] = None" in source, (
        "create_database should default to the deployment's mode, not to True"
    )
    assert "create_database = self.multi_tenant" in source
