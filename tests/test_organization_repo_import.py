"""
Tests for the two organization endpoints the web UI called but the API never
defined:

    GET  /organizations/{org_name}/search-github-repos
    POST /organizations/{org_name}/import-repo

Both returned 404 for every request. The repository picker on the
Organizations admin page therefore did nothing, and nothing failed loudly
enough to say why -- the UI reported "Search Failed: Not Found", which reads
as "GitHub has no such repository".

Also covers apply_github_repo_fields(). The GitHub-to-Repository field mapping
existed in three copies (import, import-repo, sync-repos); a column added to
one copy was silently absent from the other two, so the same repository held
different data depending on which button was pressed. These tests pin the
field list so a fourth divergence fails here.

These run inside the container, against the real Postgres, because the models
use JSONB and UUID columns that SQLite cannot compile:

    docker exec auditgh_api python -m pytest tests/test_organization_repo_import.py -q

Nothing is written: the session is bound to a connection whose outer
transaction is rolled back at teardown, so the endpoints' own commit() calls
release savepoints inside it and disappear.
"""

import uuid
from datetime import datetime

import pytest
import requests
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from src.api import models
from src.api.database import engine
from src.api.dependencies import get_tenant_db
from src.api.main import app
from src.api.routers import organizations as orgs_router
from src.auth.dependencies import get_current_user
from src.auth.models import User


GITHUB_REPO_PAYLOAD = {
    "name": "payments-api",
    "full_name": "acme/payments-api",
    "html_url": "https://github.com/acme/payments-api",
    "description": "Card processing",
    "default_branch": "trunk",
    "language": "Go",
    "pushed_at": "2026-09-01T12:00:00Z",
    "created_at": "2021-01-02T03:04:05Z",
    "updated_at": "2026-09-02T09:00:00Z",
    "stargazers_count": 7,
    "watchers_count": 8,
    "forks_count": 9,
    "open_issues_count": 10,
    "size": 4096,
    "fork": True,
    "archived": True,
    "disabled": False,
    "private": True,
    "visibility": "internal",
    "topics": ["payments", "pci"],
    "has_wiki": True,
    "has_pages": True,
    "has_discussions": True,
    "license": {"spdx_id": "Apache-2.0", "name": "Apache License 2.0"},
}


# --------------------------------------------------------------------------- #
# Fake GitHub
# --------------------------------------------------------------------------- #

class FakeResponse:
    def __init__(self, payload, status_code=200):
        self._payload = payload
        self.status_code = status_code

    def json(self):
        return self._payload

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.exceptions.HTTPError(
                f"{self.status_code} error", response=self
            )


class FakeGitHub:
    """Records the calls made so the query string can be asserted on."""

    def __init__(self):
        self.calls = []
        self.response = FakeResponse({})

    def get(self, url, headers=None, params=None, timeout=None):
        self.calls.append({"url": url, "headers": headers or {}, "params": params or {}})
        return self.response

    @property
    def last_query(self):
        return self.calls[-1]["params"].get("q", "")


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def db():
    """A session whose writes are thrown away.

    join_transaction_mode="create_savepoint" is what makes the endpoints'
    db.commit() calls harmless: each becomes a RELEASE SAVEPOINT inside the
    outer transaction rolled back below, rather than a real commit to
    auditgh_kb.
    """
    connection = engine.connect()
    transaction = connection.begin()
    session = Session(bind=connection, join_transaction_mode="create_savepoint")
    try:
        yield session
    finally:
        session.close()
        transaction.rollback()
        connection.close()


@pytest.fixture
def org(db):
    organization = models.Organization(
        id=uuid.uuid4(),
        name=f"testorg-{uuid.uuid4().hex[:8]}",
        github_org="acme",
        display_name="Test Org",
        is_active=True,
    )
    db.add(organization)
    db.flush()
    return organization


@pytest.fixture
def github(monkeypatch):
    fake = FakeGitHub()
    monkeypatch.setattr(requests, "get", fake.get)
    return fake


@pytest.fixture
def token(monkeypatch):
    """Stub the secrets manager. Returns a setter so a test can remove the
    token and check the 'not configured' path."""
    state = {"value": "ghp_testtoken"}

    class FakeManager:
        async def get_secret(self, key):
            return state["value"]

    import secrets_manager

    monkeypatch.setattr(secrets_manager, "get_secrets_manager", lambda: FakeManager())
    return state


@pytest.fixture
def client(db, monkeypatch):
    monkeypatch.setenv("AUTH_REQUIRED", "false")
    monkeypatch.setenv("AUTH_DISABLED", "true")

    def fake_user():
        return User(email="tester@example.com", name="Tester", sub="test-subject",
                    provider="okta", role="super_admin")

    app.dependency_overrides[get_current_user] = fake_user
    app.dependency_overrides[get_tenant_db] = lambda: db
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)
        app.dependency_overrides.pop(get_tenant_db, None)


@pytest.fixture
def no_real_scans(monkeypatch):
    """TestClient runs background tasks before returning, so without this an
    auto_scan test would launch an actual scan of an actual repository."""
    from src.api.routers import scans

    launched = []
    monkeypatch.setattr(
        scans, "run_scan_background",
        lambda *args, **kwargs: launched.append(args),
    )
    return launched


# --------------------------------------------------------------------------- #
# apply_github_repo_fields -- the three-way duplication
# --------------------------------------------------------------------------- #

EXPECTED_FIELDS = {
    "full_name", "url", "description", "default_branch", "language",
    "pushed_at", "github_created_at", "github_updated_at",
    "stargazers_count", "watchers_count", "forks_count", "open_issues_count",
    "size_kb", "is_fork", "is_archived", "is_disabled", "is_private",
    "visibility", "topics", "has_wiki", "has_pages", "has_discussions",
    "license_name",
}


def test_every_github_backed_column_is_mapped():
    """The field list, pinned. A column added to the GitHub payload handling
    without being added here means one of the three callers is writing a row
    the others do not."""
    repo = models.Repository(name="payments-api")
    orgs_router.apply_github_repo_fields(repo, GITHUB_REPO_PAYLOAD)
    for field in EXPECTED_FIELDS:
        assert getattr(repo, field) is not None, f"{field} not mapped"


def test_mapped_values_are_the_payload_values():
    repo = models.Repository(name="payments-api")
    orgs_router.apply_github_repo_fields(repo, GITHUB_REPO_PAYLOAD)
    assert repo.full_name == "acme/payments-api"
    assert repo.url == "https://github.com/acme/payments-api"
    assert repo.default_branch == "trunk"
    assert repo.language == "Go"
    assert repo.size_kb == 4096
    assert repo.topics == ["payments", "pci"]
    assert repo.is_fork is True
    assert repo.is_archived is True
    assert repo.visibility == "internal"


def test_name_is_not_overwritten_by_the_mapping():
    """name identifies the row and is set by the caller; the mapping must not
    touch it, or a rename on GitHub would orphan the findings attached to it."""
    repo = models.Repository(name="chosen-name")
    orgs_router.apply_github_repo_fields(repo, GITHUB_REPO_PAYLOAD)
    assert repo.name == "chosen-name"


def test_spdx_id_preferred_over_license_name():
    repo = models.Repository(name="r")
    orgs_router.apply_github_repo_fields(repo, GITHUB_REPO_PAYLOAD)
    assert repo.license_name == "Apache-2.0"


def test_license_name_used_when_spdx_absent():
    payload = dict(GITHUB_REPO_PAYLOAD, license={"name": "Weird Custom License"})
    repo = models.Repository(name="r")
    orgs_router.apply_github_repo_fields(repo, payload)
    assert repo.license_name == "Weird Custom License"


def test_absent_license_leaves_the_existing_value_alone():
    """GitHub omits 'license' for unlicensed repos. Blanking a known license on
    every sync would churn the column for no reason."""
    repo = models.Repository(name="r", license_name="MIT")
    orgs_router.apply_github_repo_fields(repo, dict(GITHUB_REPO_PAYLOAD, license=None))
    assert repo.license_name == "MIT"


def test_defaults_applied_for_a_sparse_payload():
    repo = models.Repository(name="r")
    orgs_router.apply_github_repo_fields(repo, {"name": "r"})
    assert repo.stargazers_count == 0
    assert repo.size_kb == 0
    assert repo.is_fork is False
    assert repo.default_branch == "main"
    assert repo.is_private is True  # closed by default, not open


@pytest.mark.parametrize("value", [None, "", "not-a-date", "2026-13-45T99:99:99Z"])
def test_unparseable_timestamps_become_none_not_an_exception(value):
    assert orgs_router.parse_github_datetime(value) is None


def test_trailing_z_is_parsed():
    parsed = orgs_router.parse_github_datetime("2026-09-01T12:00:00Z")
    assert parsed is not None
    assert parsed.year == 2026 and parsed.month == 9 and parsed.day == 1


def test_the_duplicate_mapping_blocks_are_gone():
    """Regression guard on the de-duplication itself: all three callers go
    through the helper, and none of them still assigns the columns inline."""
    with open(orgs_router.__file__) as handle:
        text = handle.read()
    assert text.count("apply_github_repo_fields(") >= 4  # 1 def + 3 call sites
    assert "existing_repo.stargazers_count" not in text
    assert "new_repo.license_name" not in text
    assert text.count("def parse_github_datetime") == 1


def test_the_module_defines_the_logger_it_uses():
    """Every error path in this router called logger.error() and the name was
    never bound: a per-repository import failure raised NameError instead of
    being logged, turning a skipped repository into a 500."""
    assert orgs_router.logger is not None
    with open(orgs_router.__file__) as handle:
        text = handle.read()
    assert "from loguru import logger" in text


# --------------------------------------------------------------------------- #
# Route ordering
# --------------------------------------------------------------------------- #

def test_literal_routes_are_declared_before_the_catch_all():
    """/{org_name} matches any single segment, so a literal route declared
    after it is unreachable -- the request is answered by get_organization()
    with 404 "Organization 'configured' not found", which reads as a missing
    organization rather than a missing route. /configured was dead this way.

    Asserted over every route rather than the one known case, because the next
    literal endpoint added to the bottom of this file would fail silently the
    same way.
    """
    paths = [
        (sorted(route.methods or []), route.path)
        for route in orgs_router.router.routes
    ]
    catch_all = next(
        index for index, (methods, path) in enumerate(paths)
        if path == "/organizations/{org_name}" and "GET" in methods
    )
    shadowed = [
        path for methods, path in paths[catch_all + 1:]
        if "GET" in methods
        and path.count("/") == 2           # /organizations/<one-segment>
        and "{" not in path.split("/")[-1]  # a literal, not a parameter
    ]
    assert shadowed == [], f"unreachable behind /{{org_name}}: {shadowed}"


def test_configured_is_reachable(client, monkeypatch):
    """Not a 404 whose body names an organization called 'configured'."""
    import secrets_manager

    async def fake_list():
        return ["acme", "globex"]

    monkeypatch.setattr(secrets_manager, "list_configured_orgs", fake_list)
    response = client.get("/organizations/configured")
    assert response.status_code == 200
    assert response.json() == {"configured_organizations": ["acme", "globex"]}


# --------------------------------------------------------------------------- #
# Error translation
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("github_status,expected", [
    (404, 404), (401, 401), (403, 403), (422, 502), (500, 502),
])
def test_github_errors_map_to_the_status_the_caller_should_see(github_status, expected):
    from fastapi import HTTPException

    error = requests.exceptions.HTTPError(response=FakeResponse({}, github_status))
    with pytest.raises(HTTPException) as exc:
        orgs_router._raise_for_github_error(error, github_org="acme")
    assert exc.value.status_code == expected


def test_403_is_not_reported_as_an_invalid_token():
    """A 403 means the token is valid but the request was refused -- rate
    limit, SSO authorization or a missing scope. Calling it invalid sends the
    operator to rotate a working PAT."""
    from fastapi import HTTPException

    error = requests.exceptions.HTTPError(response=FakeResponse({}, 403))
    with pytest.raises(HTTPException) as exc:
        orgs_router._raise_for_github_error(error, github_org="acme")
    assert "invalid" not in exc.value.detail.lower()
    assert "rate limit" in exc.value.detail.lower()


def test_headers_carry_the_token_and_pin_the_api_version():
    headers = orgs_router._github_headers("ghp_abc")
    assert headers["Authorization"] == "token ghp_abc"
    assert headers["Accept"] == "application/vnd.github.v3+json"
    assert headers["User-Agent"]


# --------------------------------------------------------------------------- #
# GET /{org_name}/search-github-repos
# --------------------------------------------------------------------------- #

def test_search_returns_mapped_results(client, org, github, token):
    github.response = FakeResponse({
        "total_count": 1,
        "items": [GITHUB_REPO_PAYLOAD],
    })
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert len(body["results"]) == 1
    result = body["results"][0]
    assert result["name"] == "payments-api"
    assert result["full_name"] == "acme/payments-api"
    assert result["language"] == "Go"
    assert result["visibility"] == "internal"
    assert result["is_archived"] is True


def test_search_restricts_to_the_organizations_github_org(client, org, github, token):
    github.response = FakeResponse({"total_count": 0, "items": []})
    client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert "org:acme" in github.last_query


def test_search_matches_names_not_readme_text(client, org, github, token):
    """Without in:name GitHub also matches descriptions and READMEs, so the
    picker returns repositories whose names the operator never typed."""
    github.response = FakeResponse({"total_count": 0, "items": []})
    client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert "in:name" in github.last_query


def test_search_includes_forks_and_archived_repositories(client, org, github, token):
    """GitHub search excludes both by default, and each is exactly the kind of
    unmaintained code worth scanning."""
    github.response = FakeResponse({"total_count": 0, "items": []})
    client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert "fork:true" in github.last_query
    assert "archived:true" in github.last_query


def test_search_marks_repositories_already_in_the_database(client, db, org, github, token):
    db.add(models.Repository(id=uuid.uuid4(), organization_id=org.id, name="payments-api"))
    db.flush()
    github.response = FakeResponse({
        "total_count": 2,
        "items": [GITHUB_REPO_PAYLOAD, dict(GITHUB_REPO_PAYLOAD, name="payments-ui",
                                            full_name="acme/payments-ui")],
    })
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    by_name = {r["name"]: r for r in response.json()["results"]}
    assert by_name["payments-api"]["already_imported"] is True
    assert by_name["payments-ui"]["already_imported"] is False


def test_already_imported_is_scoped_to_this_organization(client, db, org, github, token):
    """A repository of the same name under a different organization must not
    make this one look imported."""
    other = models.Organization(id=uuid.uuid4(), name=f"other-{uuid.uuid4().hex[:8]}",
                                github_org="globex", is_active=True)
    db.add(other)
    db.flush()
    db.add(models.Repository(id=uuid.uuid4(), organization_id=other.id,
                             name="payments-api"))
    db.flush()
    github.response = FakeResponse({"total_count": 1, "items": [GITHUB_REPO_PAYLOAD]})
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert response.json()["results"][0]["already_imported"] is False


def test_search_reports_truncation_when_github_has_more(client, org, github, token):
    """GitHub returns total_count for the whole index but never more than 1000
    results. Showing 1 of 4000 without saying so reads as a broken search."""
    github.response = FakeResponse({"total_count": 4000, "items": [GITHUB_REPO_PAYLOAD]})
    body = client.get(f"/organizations/{org.name}/search-github-repos?q=pay").json()
    assert body["total"] == 4000
    assert body["truncated"] is True


def test_search_is_not_truncated_when_everything_fits(client, org, github, token):
    github.response = FakeResponse({"total_count": 1, "items": [GITHUB_REPO_PAYLOAD]})
    body = client.get(f"/organizations/{org.name}/search-github-repos?q=pay").json()
    assert body["truncated"] is False


def test_search_derives_visibility_when_github_omits_it(client, org, github, token):
    payload = {k: v for k, v in GITHUB_REPO_PAYLOAD.items() if k != "visibility"}
    github.response = FakeResponse({"total_count": 1, "items": [payload]})
    body = client.get(f"/organizations/{org.name}/search-github-repos?q=pay").json()
    assert body["results"][0]["visibility"] == "private"


def test_search_honours_the_limit(client, org, github, token):
    github.response = FakeResponse({"total_count": 0, "items": []})
    client.get(f"/organizations/{org.name}/search-github-repos?q=pay&limit=5")
    assert github.calls[-1]["params"]["per_page"] == 5


def test_search_rejects_a_one_character_query(client, org, github, token):
    """Two characters minimum: a single letter matches most of an org and burns
    a request against the 30-per-minute search limit."""
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=p")
    assert response.status_code == 422
    assert github.calls == []


def test_search_requires_a_query(client, org, github, token):
    assert client.get(
        f"/organizations/{org.name}/search-github-repos"
    ).status_code == 422


def test_search_rejects_an_oversized_limit(client, org, github, token):
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay&limit=500")
    assert response.status_code == 422


def test_search_on_an_unknown_organization_is_404(client, github, token):
    response = client.get("/organizations/no-such-org/search-github-repos?q=pay")
    assert response.status_code == 404
    assert github.calls == []


def test_missing_token_is_a_400_naming_the_fix(client, org, github, token):
    """This path used to surface as a 500: the 400 was raised inside a try
    whose bare 'except Exception' re-wrapped it, so an unconfigured token was
    indistinguishable from a server fault."""
    token["value"] = None
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert response.status_code == 400
    assert "credentials" in response.json()["detail"]
    assert github.calls == []


def test_search_propagates_a_github_401(client, org, github, token):
    github.response = FakeResponse({}, 401)
    response = client.get(f"/organizations/{org.name}/search-github-repos?q=pay")
    assert response.status_code == 401


# --------------------------------------------------------------------------- #
# POST /{org_name}/import-repo
# --------------------------------------------------------------------------- #

def _import(client, org_name, repo_name="payments-api", auto_scan=False):
    return client.post(
        f"/organizations/{org_name}/import-repo",
        json={"repo_name": repo_name, "auto_scan": auto_scan},
    )


def test_import_creates_the_repository(client, db, org, github, token):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    response = _import(client, org.name)
    assert response.status_code == 200
    assert response.json() == {
        "repository": "payments-api",
        "action": "created",
        "scan_started": False,
        "scan_id": None,
        "scan_error": None,
    }
    row = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id,
        models.Repository.name == "payments-api",
    ).one()
    assert row.full_name == "acme/payments-api"
    assert row.language == "Go"


def test_import_asks_github_for_the_exact_repository(client, org, github, token):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    _import(client, org.name)
    assert github.calls[-1]["url"].endswith("/repos/acme/payments-api")


def test_import_stores_the_casing_github_uses(client, db, org, github, token):
    """The row is looked up by name elsewhere. Storing what was typed rather
    than what GitHub calls it produces a second row on the next import."""
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    response = _import(client, org.name, repo_name="Payments-API")
    assert response.json()["repository"] == "payments-api"
    assert db.query(models.Repository).filter(
        models.Repository.organization_id == org.id,
        models.Repository.name == "payments-api",
    ).count() == 1


def test_reimport_updates_in_place(client, db, org, github, token):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    assert _import(client, org.name).json()["action"] == "created"

    github.response = FakeResponse(dict(GITHUB_REPO_PAYLOAD, description="Rewritten"))
    second = _import(client, org.name)
    assert second.json()["action"] == "updated"

    rows = db.query(models.Repository).filter(
        models.Repository.organization_id == org.id,
        models.Repository.name == "payments-api",
    ).all()
    assert len(rows) == 1
    assert rows[0].description == "Rewritten"


def test_import_surrounding_whitespace_is_ignored(client, org, github, token):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    assert _import(client, org.name, repo_name="  payments-api  ").status_code == 200


def test_import_rejects_an_owner_qualified_name(client, org, github, token):
    """'acme/payments-api' would build /repos/acme/acme/payments-api, which
    GitHub answers 404 -- a confusing way to report a malformed input."""
    response = _import(client, org.name, repo_name="acme/payments-api")
    assert response.status_code == 400
    assert github.calls == []


def test_import_rejects_an_empty_name(client, org, github, token):
    response = _import(client, org.name, repo_name="   ")
    assert response.status_code == 400
    assert github.calls == []


def test_import_requires_repo_name(client, org, github, token):
    response = client.post(f"/organizations/{org.name}/import-repo", json={})
    assert response.status_code == 422


def test_import_of_an_unknown_repository_is_404(client, org, github, token):
    github.response = FakeResponse({}, 404)
    response = _import(client, org.name)
    assert response.status_code == 404
    assert "payments-api" in response.json()["detail"]


def test_import_on_an_unknown_organization_is_404(client, github, token):
    response = _import(client, "no-such-org")
    assert response.status_code == 404
    assert github.calls == []


def test_import_without_a_token_is_400(client, org, github, token):
    token["value"] = None
    assert _import(client, org.name).status_code == 400


def test_auto_scan_off_queues_nothing(client, db, org, github, token, no_real_scans):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    body = _import(client, org.name, auto_scan=False).json()
    assert body["scan_started"] is False
    assert body["scan_id"] is None
    assert no_real_scans == []
    assert db.query(models.ScanRun).filter(
        models.ScanRun.triggered_by == "import"
    ).count() == 0


def test_auto_scan_records_a_scan_run_and_queues_the_work(
    client, db, org, github, token, no_real_scans
):
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    body = _import(client, org.name, auto_scan=True).json()

    assert body["scan_started"] is True
    assert body["scan_id"]
    assert body["scan_error"] is None

    run = db.query(models.ScanRun).filter(
        models.ScanRun.id == uuid.UUID(body["scan_id"])
    ).one()
    assert run.triggered_by == "import"
    assert run.scan_type == "full"
    assert run.status in ("queued", "running", "completed", "failed")
    repo = db.query(models.Repository).filter(
        models.Repository.id == run.repository_id
    ).one()
    assert repo.name == "payments-api"

    assert len(no_real_scans) == 1
    assert no_real_scans[0][1] == "payments-api"


def test_auto_scan_on_a_reimport_finds_the_existing_row(
    client, db, org, github, token, no_real_scans
):
    """The repository_id has to come from the row that already existed, not
    from a re-query that has not been flushed."""
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)
    _import(client, org.name)
    body = _import(client, org.name, auto_scan=True).json()
    assert body["action"] == "updated"
    assert body["scan_started"] is True
    run = db.query(models.ScanRun).filter(
        models.ScanRun.id == uuid.UUID(body["scan_id"])
    ).one()
    assert run.repository_id is not None


def test_a_scan_that_cannot_be_queued_does_not_fail_the_import(
    client, db, org, github, token, monkeypatch
):
    """The import already happened and the row is already committed. Returning
    500 would tell the operator to retry work that succeeded."""
    github.response = FakeResponse(GITHUB_REPO_PAYLOAD)

    from src.api.routers import scans

    def explode(*args, **kwargs):
        raise RuntimeError("scan queue unavailable")

    monkeypatch.setattr(scans, "run_scan_background", explode)
    monkeypatch.setattr(
        orgs_router.models, "ScanRun",
        lambda **kwargs: (_ for _ in ()).throw(RuntimeError("scan queue unavailable")),
    )

    body = _import(client, org.name, auto_scan=True).json()
    assert body["action"] == "created"
    assert body["scan_started"] is False
    assert body["scan_error"] == "scan queue unavailable"
    assert db.query(models.Repository).filter(
        models.Repository.organization_id == org.id,
        models.Repository.name == "payments-api",
    ).count() == 1
