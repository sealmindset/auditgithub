"""
Tests for schema fingerprinting and schema application in ai_org_agent.py.

Three failures stacked here, each one hiding the next. All three reported
success.

1. The fingerprint was a hash of the database name.

   _get_schema_hash() shelled out to pg_dump. The api image contains neither
   pg_dump nor psql, so every call raised FileNotFoundError and took the
   fallback arm: sha256(database_name). The stored schema_version for
   sleepnumberinc was byte-for-byte sha256(b'auditgithub_sleepnumberinc').

   A database's name never equals the master's name, so master_hash was never
   equal to org_hash, so sync_schema() concluded drift and re-applied the
   whole schema on every agent startup -- indefinitely. And since the hash of
   a name cannot change when a schema changes, the column documented as
   'SHA-256 hash of current schema DDL for drift detection' could not detect
   drift either.

2. The applier skipped every CREATE TABLE.

   Statements were split on ';', which leaves each fragment carrying the
   comment lines above it:

       -- 1. Users & Authentication
       CREATE TABLE IF NOT EXISTS users (...)

   The filter was `if stmt and not stmt.startswith('--')`. Every table in
   scripts/setup/schema.sql is preceded by a numbered comment, so all nine
   CREATE TABLE statements were discarded as comments. Seven comment-free
   fragments ran, five of them indexes on the tables that had just been
   skipped -- hence 'relation "findings" does not exist' in the logs.

3. 'synced' was written whether or not any of that worked.

   Per-statement failures were printed as warnings, the applier returned
   normally, and sync_schema() wrote schema_sync_status='synced'. On this
   host both organizations recorded 'synced' while holding one table and zero
   tables against the master's 66.

Run inside the container, against the real database:

    docker exec auditgh_api python -m pytest tests/test_organization_schema_sync.py -q

Read-only against existing databases: no test here creates, drops or applies
a schema to anything. The one test that needs an organizations row inserts
and deletes it.
"""

import hashlib
import uuid

import pytest
from sqlalchemy import text

from src.api.database import engine
from execution.ai_org_agent import (
    AIOrganizationAgent,
    split_sql_statements,
)


MASTER_DB = "security_portal"
ABSENT_DB = "auditgithub_this_database_does_not_exist"


@pytest.fixture
def agent():
    return AIOrganizationAgent()


# --------------------------------------------------------------------------- #
# 1. The fingerprint
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_the_fingerprint_is_not_a_hash_of_the_name(agent):
    """The exact observed value. sleepnumberinc's stored schema_version was
    sha256 of its own database name."""
    digest = await agent._get_schema_hash(MASTER_DB)
    assert digest != hashlib.sha256(MASTER_DB.encode()).hexdigest()
    assert digest != hashlib.sha256(b'').hexdigest()


@pytest.mark.asyncio
async def test_the_fingerprint_reflects_the_schema(agent):
    """Two databases with different schemas must fingerprint differently, and
    the master -- 66 tables -- must not fingerprint as empty."""
    master = await agent._get_schema_hash(MASTER_DB)
    with engine.connect() as connection:
        others = connection.execute(text(
            "SELECT datname FROM pg_database WHERE datname LIKE 'auditgithub_%'"
        )).scalars().all()
    if not others:
        pytest.skip("no second database on this host to compare against")

    for other in others:
        assert await agent._get_schema_hash(other) != master


@pytest.mark.asyncio
async def test_the_fingerprint_is_stable(agent):
    """Ordering is fixed in SQL rather than left to the planner, so repeated
    calls have to agree -- otherwise every check reports drift."""
    first = await agent._get_schema_hash(MASTER_DB)
    second = await agent._get_schema_hash(MASTER_DB)
    assert first == second


@pytest.mark.asyncio
async def test_an_absent_database_fingerprints_as_none_not_as_a_value(agent):
    """Returning sha256(b'') for a missing database is what let the old code
    compare master against nothing and call the difference drift."""
    assert await agent._get_schema_hash(ABSENT_DB) is None


@pytest.mark.asyncio
async def test_the_public_accessor_refuses_to_invent_a_hash(agent):
    with pytest.raises(ValueError, match="does not exist"):
        await agent.get_schema_hash(ABSENT_DB)


@pytest.mark.asyncio
async def test_no_stored_schema_version_is_a_hash_of_its_own_name():
    """Regression over the live rows. Any row still holding the old value is
    carrying a fingerprint that cannot detect drift."""
    with engine.connect() as connection:
        rows = connection.execute(text(
            "SELECT name, database_name, schema_version FROM organizations "
            "WHERE schema_version IS NOT NULL AND schema_version <> ''"
        )).all()
    for name, database_name, stored in rows:
        assert stored != hashlib.sha256((database_name or '').encode()).hexdigest(), (
            f"{name}.schema_version is sha256 of its database name, not of a "
            "schema"
        )


# --------------------------------------------------------------------------- #
# 2. The applier
# --------------------------------------------------------------------------- #

def test_a_statement_preceded_by_a_comment_is_not_discarded():
    sql = """
-- 1. Users & Authentication
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY
);
"""
    statements = split_sql_statements(sql)
    assert len(statements) == 1
    assert statements[0].startswith("CREATE TABLE")


def test_comment_only_text_produces_no_statement():
    assert split_sql_statements("-- just a header\n\n-- and another\n") == []


def test_inline_comments_inside_a_statement_survive():
    """`is_internal BOOLEAN DEFAULT true,  -- vs public` is real content in
    schema.sql; stripping comments wholesale would corrupt the column list."""
    sql = "CREATE TABLE t (\n  a BOOLEAN DEFAULT true,  -- vs public\n  b INT\n);"
    statements = split_sql_statements(sql)
    assert len(statements) == 1
    assert "b INT" in statements[0]


def test_dollar_quoted_bodies_are_refused_rather_than_cut_in_half():
    """Splitting on ';' would truncate a function body. The current schema
    file has none, so this guard fails loudly if that changes instead of
    applying half a function."""
    sql = "CREATE FUNCTION f() RETURNS void AS $$ BEGIN PERFORM 1; END; $$ LANGUAGE plpgsql;"
    with pytest.raises(ValueError, match=r"\$\$"):
        split_sql_statements(sql)


def test_every_table_in_the_real_schema_file_is_kept():
    """The measurement that identified the bug: 17 fragments, 10 of them
    discarded as comments, including all nine CREATE TABLE statements."""
    from pathlib import Path

    schema_file = (Path(__file__).resolve().parents[1]
                   / "scripts" / "setup" / "schema.sql")
    sql = schema_file.read_text()
    statements = split_sql_statements(sql)

    declared = sql.count("CREATE TABLE")
    kept = sum(1 for s in statements if s.upper().startswith("CREATE TABLE"))
    assert kept == declared, (
        f"{declared} CREATE TABLE statements in the file, {kept} kept by the "
        "splitter"
    )

    # The old filter, for the record.
    old_filter_kept = sum(
        1 for f in (s.strip() for s in sql.split(';'))
        if f and not f.startswith('--') and f.upper().startswith("CREATE TABLE")
    )
    assert old_filter_kept == 0, (
        "the old comment filter is expected to have kept zero tables; if this "
        "changes, the schema file has changed shape"
    )


# --------------------------------------------------------------------------- #
# 3. The status write
# --------------------------------------------------------------------------- #

@pytest.fixture
def org_pointing_at_a_real_but_different_database():
    """An organizations row whose database_name is an existing database that
    is not the master, so a sync against it cannot legitimately report
    'synced'."""
    with engine.connect() as connection:
        target = connection.execute(text(
            "SELECT datname FROM pg_database WHERE datname LIKE 'auditgithub_%' "
            "ORDER BY datname LIMIT 1"
        )).scalar()
    if not target:
        pytest.skip("no non-master database on this host")

    name = f"pytest_sync_{uuid.uuid4().hex[:8]}"
    with engine.begin() as connection:
        connection.execute(text(
            "INSERT INTO organizations "
            "(id, name, github_org, database_name, is_active, is_default) "
            "VALUES (:id, :name, :name, :db, true, false)"
        ), {"id": str(uuid.uuid4()), "name": name, "db": target})
    try:
        yield name
    finally:
        with engine.begin() as connection:
            connection.execute(
                text("DELETE FROM organizations WHERE name = :name"),
                {"name": name},
            )


@pytest.mark.asyncio
async def test_sync_does_not_report_synced_when_the_apply_changed_nothing(
    org_pointing_at_a_real_but_different_database, monkeypatch
):
    """With the apply stubbed out, the target database is unchanged and still
    differs from master. The old code wrote 'synced' here, which is how two
    near-empty databases came to be recorded as synchronized.

    The stub is what keeps this test read-only: nothing is applied to the
    database the row points at.
    """
    name = org_pointing_at_a_real_but_different_database
    agent = AIOrganizationAgent()
    # This host runs single-database mode, where sync is skipped entirely.
    # The verification below is about what sync does when it does run.
    agent.multi_tenant = True

    applied = []

    async def fake_apply(database_name):
        applied.append(database_name)

    monkeypatch.setattr(agent, "_apply_master_schema", fake_apply)

    with pytest.raises(RuntimeError, match="did not reproduce the master schema"):
        await agent.sync_schema(name)

    assert applied, "sync_schema should have attempted the apply"

    with engine.connect() as connection:
        status, error = connection.execute(text(
            "SELECT schema_sync_status, schema_sync_error FROM organizations "
            "WHERE name = :name"
        ), {"name": name}).one()

    assert status == "error"
    assert "master schema" in error
