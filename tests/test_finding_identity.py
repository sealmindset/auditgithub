"""
Tests for resolving the finding identifier the API publishes.

`findings.id` and `findings.finding_uuid` are separate columns with independent
`gen_random_uuid()` defaults. Every read endpoint returns `finding_uuid` as the
finding's `id`, so a writer that filters on `Finding.id` matches nothing --
measured on this estate, `SELECT count(*) FROM findings WHERE id = finding_uuid`
returns 0 of 769,825 rows.

`POST /ai/remediate` did exactly that. It generated remediation text, failed the
`if finding:` check silently, returned the text to the browser and saved nothing:
0 rows in `remediations` and 0 populated `ai_remediation_text` across the whole
estate. These tests pin the resolution and the FK target so the next writer to
touch this path cannot reintroduce it.
"""

import uuid

import pytest

from src.api import models
from src.api.routers.ai import _resolve_finding


class _FakeQuery:
    """Enough SQLAlchemy surface to observe which column was filtered on.

    `filter(Finding.finding_uuid == x)` builds a BinaryExpression whose left is
    the column and whose right is a bound parameter, so the comparison can be
    read back without a database.
    """

    def __init__(self, rows):
        self._rows = rows
        self._result = None

    def filter(self, expression):
        column = expression.left.name
        value = str(expression.right.value)
        self._result = self._rows.get((column, value))
        return self

    def first(self):
        return self._result


class _FakeSession:
    def __init__(self, rows):
        self._rows = rows
        self.queried_columns = []

    def query(self, _model):
        query = _FakeQuery(self._rows)
        original = query.filter

        def _recording_filter(expression):
            self.queried_columns.append(expression.left.name)
            return original(expression)

        query.filter = _recording_filter
        return query


_PK = uuid.uuid4()
_PUBLIC = uuid.uuid4()


def _finding():
    finding = models.Finding()
    finding.id = _PK
    finding.finding_uuid = _PUBLIC
    return finding


def test_the_two_identifiers_are_genuinely_different():
    """If these ever became the same column the rest of this file is moot --
    and so was the bug."""
    assert _PK != _PUBLIC


def test_public_identifier_resolves():
    """This is what the browser sends. Under the old code it matched nothing."""
    finding = _finding()
    session = _FakeSession({("finding_uuid", str(_PUBLIC)): finding})
    assert _resolve_finding(session, str(_PUBLIC)) is finding


def test_primary_key_still_resolves():
    """Internal callers holding the PK must keep working."""
    finding = _finding()
    session = _FakeSession({("id", str(_PK)): finding})
    assert _resolve_finding(session, str(_PK)) is finding


def test_public_identifier_is_tried_first():
    """Order matters: the published identifier is the common case, and trying
    the primary key first would cost a wasted query on every call."""
    finding = _finding()
    session = _FakeSession({("finding_uuid", str(_PUBLIC)): finding})
    _resolve_finding(session, str(_PUBLIC))
    assert session.queried_columns[0] == "finding_uuid"
    # Resolved on the first attempt, so the fallback never ran.
    assert session.queried_columns == ["finding_uuid"]


def test_unknown_identifier_returns_none_after_trying_both():
    session = _FakeSession({})
    assert _resolve_finding(session, str(uuid.uuid4())) is None
    assert session.queried_columns == ["finding_uuid", "id"]


def test_malformed_identifier_returns_none_without_querying():
    """A bad UUID is a caller error, not a database round trip, and it must not
    raise -- persistence is best-effort and the generated text is still owed to
    the caller."""
    session = _FakeSession({})
    assert _resolve_finding(session, "not-a-uuid") is None
    assert session.queried_columns == []


def test_missing_identifier_returns_none():
    session = _FakeSession({})
    assert _resolve_finding(session, None) is None
    assert _resolve_finding(session, "") is None
    assert session.queried_columns == []


def test_remediation_foreign_key_targets_the_primary_key_not_the_public_id():
    """The fix is only half done if the resolved row's PK is not what gets
    written. `remediations.finding_id` references `findings(id)`; writing the
    caller's `finding_uuid` there violates the constraint."""
    target = list(models.Remediation.__table__.c.finding_id.foreign_keys)[0]
    assert target.column.table.name == "findings"
    assert target.column.name == "id"


def test_the_old_behaviour_is_what_this_replaces():
    """Pinned so the regression is legible if anyone filters on `Finding.id`
    alone again: given what the browser sends, it finds nothing."""
    finding = _finding()
    rows = {("finding_uuid", str(_PUBLIC)): finding, ("id", str(_PK)): finding}

    old = _FakeQuery(rows).filter(models.Finding.id == _PUBLIC).first()
    assert old is None

    new = _resolve_finding(_FakeSession(rows), str(_PUBLIC))
    assert new is finding


@pytest.mark.parametrize("identifier", [str(_PUBLIC), str(_PUBLIC).upper()])
def test_case_of_the_uuid_string_does_not_matter(identifier):
    """UUIDs arrive from JSON as strings and casing is not guaranteed."""
    finding = _finding()
    session = _FakeSession({("finding_uuid", str(_PUBLIC)): finding})
    assert _resolve_finding(session, identifier) is finding
