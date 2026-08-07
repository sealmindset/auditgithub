"""Probes for `src/api/utils/repo_origin.py`.

The defect these exist for: "generate System Architecture" failed with
`remote: Repository not found.` on `https://github.com/SleepNumberInc/web-webadmin/`, while
the repository was sitting at `sleepnumberlabs/web-webadmin`, private and not archived. The
caller took the clone URL from `Repository.url` and the credential from
`Repository.organization_id`, and 483 of 2,540 rows have those two disagreeing - so it
presented one organization's token to another organization's path.

Nothing raised. The git message was accurate. Every test here fixes a behavior that a
correct-looking failure message actively hid.
"""
from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.api.utils import repo_origin as RO  # noqa: E402


class _Repo:
    def __init__(self, name, url, organization_id=None):
        self.name = name
        self.url = url
        self.organization_id = organization_id


class _Org:
    def __init__(self, name, id_):
        self.name = name
        self.id = id_


class _FakeDB:
    """Enough of a Session for `OrgDirectory`, which does its matching in Python.

    That is the point of the seam: the real `OrgDirectory` runs against this, so the
    production lookup path is under test rather than substituted. A real Session is not an
    option here - these models declare Postgres ARRAY and JSONB columns that SQLite will
    not compile, which is why the tenant-isolation suites error on this database.
    """

    def __init__(self, orgs):
        self._orgs = orgs
        self.committed = 0
        self.rolled_back = 0

    def query(self, model):
        return _FakeQuery(self._orgs)

    def commit(self):
        self.committed += 1

    def rollback(self):
        self.rolled_back += 1


class _FakeQuery:
    def __init__(self, orgs):
        self._orgs = orgs

    def all(self):
        return list(self._orgs)


def _resolve(db, repo, statuses, token_map=None, persist=True):
    """Drive `resolve_clone_target` with GitHub's answers supplied as a dict.

    `statuses` maps "org/name" -> (payload, status). Absent keys answer 404, which is what
    GitHub does and is the whole reason the caller could not tell a missing repository from
    a mislabeled one.
    """
    calls = []

    class _Reader:
        def __init__(self, token):
            self.token = token

        def _get(self, path):
            calls.append(path)
            key = path[len("/repos/"):]
            return statuses.get(key, ({}, 404))

    async def _token_for_org(db_, org_name):
        if token_map is not None and org_name not in token_map:
            return None, "none"
        return (token_map or {}).get(org_name, f"tok-{org_name}"), f"secrets store ({org_name})"

    import src.api.utils.github_reader as GR
    orig_reader, orig_token = GR.GitHubReader, RO.get_token_for_org
    GR.GitHubReader = _Reader
    RO.get_token_for_org = _token_for_org
    try:
        return asyncio.run(RO.resolve_clone_target(db, repo, persist=persist)), calls
    finally:
        GR.GitHubReader, RO.get_token_for_org = orig_reader, orig_token


ORGS = [_Org("sleepnumberinc", "id-inc"), _Org("sleepnumberlabs", "id-labs"),
        _Org("sleepnumber", "id-sn")]


# ----------------------------------------------------------------------------------
# The incident, exactly as it happened.
# ----------------------------------------------------------------------------------

def test_the_repository_is_found_under_the_org_the_url_does_not_name():
    """url says SleepNumberInc, foreign key says labs, GitHub says labs. Labs wins."""
    db = _FakeDB(ORGS)
    repo = _Repo("web-webadmin", "https://github.com/SleepNumberInc/web-webadmin", "id-labs")
    target, calls = _resolve(db, repo, {
        "sleepnumberlabs/web-webadmin": ({"full_name": "sleepnumberlabs/web-webadmin"}, 200)})
    assert target.url == "https://github.com/sleepnumberlabs/web-webadmin"
    assert target.org == "sleepnumberlabs"
    assert calls == ["/repos/SleepNumberInc/web-webadmin",
                     "/repos/sleepnumberlabs/web-webadmin"]


def test_the_token_belongs_to_the_org_that_answered():
    """The original bug in one line: the credential and the path came from different rows."""
    db = _FakeDB(ORGS)
    repo = _Repo("web-webadmin", "https://github.com/SleepNumberInc/web-webadmin", "id-labs")
    target, _ = _resolve(db, repo, {
        "sleepnumberlabs/web-webadmin": ({"full_name": "sleepnumberlabs/web-webadmin"}, 200)})
    assert target.token == "tok-sleepnumberlabs"
    assert "sleepnumberlabs" in target.token_source


def test_the_wrong_url_is_written_back():
    """A repair that is not persisted spends a request on the same lookup forever."""
    db = _FakeDB(ORGS)
    repo = _Repo("web-webadmin", "https://github.com/SleepNumberInc/web-webadmin", "id-labs")
    target, _ = _resolve(db, repo, {
        "sleepnumberlabs/web-webadmin": ({"full_name": "sleepnumberlabs/web-webadmin"}, 200)})
    assert target.corrected is True
    assert repo.url == "https://github.com/sleepnumberlabs/web-webadmin"
    assert repo.organization_id == "id-labs"
    assert db.committed == 1


def test_a_correct_row_is_not_rewritten():
    db = _FakeDB(ORGS)
    repo = _Repo("api", "https://github.com/sleepnumberinc/api", "id-inc")
    target, calls = _resolve(db, repo, {
        "sleepnumberinc/api": ({"full_name": "sleepnumberinc/api"}, 200)})
    assert target.corrected is False
    assert db.committed == 0
    assert len(calls) == 1          # the common case stays one request


# ----------------------------------------------------------------------------------
# The other direction. 38 rows have url=sleepnumberlabs with fk=sleepnumberinc, so a rule
# of "trust the foreign key" is wrong for those. Both directions must resolve by asking.
# ----------------------------------------------------------------------------------

def test_the_foreign_key_is_not_authoritative_either():
    db = _FakeDB(ORGS)
    repo = _Repo("asimov-mock-service",
                 "https://github.com/sleepnumberlabs/asimov-mock-service", "id-inc")
    target, _ = _resolve(db, repo, {
        "sleepnumberlabs/asimov-mock-service":
            ({"full_name": "sleepnumberlabs/asimov-mock-service"}, 200)})
    assert target.org == "sleepnumberlabs"
    assert repo.organization_id == "id-labs"   # the FK is the thing corrected this time


# ----------------------------------------------------------------------------------
# Renames. GitHub answers under the old name via a redirect, so `full_name` from the
# response is the only spelling that will not go stale again.
# ----------------------------------------------------------------------------------

def test_githubs_own_spelling_wins_over_ours():
    db = _FakeDB(ORGS)
    repo = _Repo("old-name", "https://github.com/sleepnumberinc/old-name", "id-inc")
    target, _ = _resolve(db, repo, {
        "sleepnumberinc/old-name": ({"full_name": "sleepnumberinc/new-name"}, 200)})
    assert target.name == "new-name"
    assert repo.url == "https://github.com/sleepnumberinc/new-name"


# ----------------------------------------------------------------------------------
# Genuine absence. §0.6: the failure has to say what was asked and what would settle it.
# ----------------------------------------------------------------------------------

def test_a_repository_in_no_known_org_names_every_org_it_tried():
    db = _FakeDB(ORGS)
    repo = _Repo("deleted-thing", "https://github.com/sleepnumberinc/deleted-thing", "id-inc")
    with pytest.raises(RO.RepositoryOriginError) as exc:
        _resolve(db, repo, {})
    message = str(exc.value)
    for org in ("sleepnumberinc", "sleepnumberlabs", "sleepnumber"):
        assert org in message, org
    assert "HTTP 404" in message


def test_the_absence_message_prices_the_privilege_that_would_settle_it():
    """A 404 does not distinguish "gone" from "invisible to this token"; say so, and say
    what closes the gap. Reporting it as proof of deletion is the false positive."""
    db = _FakeDB(ORGS)
    repo = _Repo("x", "https://github.com/sleepnumberinc/x", "id-inc")
    with pytest.raises(RO.RepositoryOriginError) as exc:
        _resolve(db, repo, {})
    message = str(exc.value)
    assert "repo` scope" in message
    assert "proof of absence" in message


def test_an_org_with_no_credential_is_recorded_not_skipped_silently():
    db = _FakeDB(ORGS)
    repo = _Repo("x", "https://github.com/sleepnumberinc/x", "id-inc")
    with pytest.raises(RO.RepositoryOriginError) as exc:
        _resolve(db, repo, {}, token_map={"sleepnumberlabs": "tok-labs"})
    probes = {p.org: (p.status, p.token_source) for p in exc.value.probes}
    assert probes["sleepnumberinc"] == (0, "none")
    assert probes["sleepnumberlabs"][0] == 404


def test_a_repository_with_no_name_cannot_be_probed():
    db = _FakeDB(ORGS)
    with pytest.raises(RO.RepositoryOriginError):
        _resolve(db, _Repo("", "https://github.com/sleepnumberinc/", "id-inc"), {})


# ----------------------------------------------------------------------------------
# A failed write must not fail the clone. The resolved values are already good.
# ----------------------------------------------------------------------------------

def test_a_failed_correction_still_returns_a_usable_target():
    class _FailingDB(_FakeDB):
        def commit(self):
            raise RuntimeError("read-only replica")

    db = _FailingDB(ORGS)
    repo = _Repo("web-webadmin", "https://github.com/SleepNumberInc/web-webadmin", "id-labs")
    target, _ = _resolve(db, repo, {
        "sleepnumberlabs/web-webadmin": ({"full_name": "sleepnumberlabs/web-webadmin"}, 200)})
    assert target.url == "https://github.com/sleepnumberlabs/web-webadmin"
    assert db.rolled_back == 1


def test_persist_false_leaves_the_row_alone():
    db = _FakeDB(ORGS)
    repo = _Repo("web-webadmin", "https://github.com/SleepNumberInc/web-webadmin", "id-labs")
    target, _ = _resolve(db, repo, {
        "sleepnumberlabs/web-webadmin": ({"full_name": "sleepnumberlabs/web-webadmin"}, 200)},
        persist=False)
    assert target.corrected is True
    assert repo.url == "https://github.com/SleepNumberInc/web-webadmin"
    assert db.committed == 0
