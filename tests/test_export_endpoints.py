"""
End-to-end tests for the six zero-day export endpoints.

These endpoints had never been called. Everything under them was unit-tested — the
renderer, the Markdown builders, the briefing — but no test had gone in through FastAPI,
which is where the parts that only exist at the boundary live: the response media type,
the `Content-Disposition` filename, and whether a payload posted back by the browser
still carries what the document needs.

They need the API's own dependency graph, so unlike `test_report_rendering.py` and
`test_briefing.py` these run **inside the container**, where loguru, psycopg2 and
WeasyPrint's pango/cairo backend exist:

    docker exec auditgh_api python -m pytest tests/test_export_endpoints.py -q

Authentication is stubbed rather than exercised — RBAC on these routes is already covered
by `tests/test_rbac_enforcement.py`, and what is untested here is the document.
"""

import re
import zipfile
from io import BytesIO

import pytest
from fastapi.testclient import TestClient

from src.api.main import app
from src.auth.dependencies import get_current_user
from src.auth.models import User


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

@pytest.fixture
def client(monkeypatch):
    """A client whose caller is authenticated and holds every permission.

    Three separate gates stand in front of these routes and each needs its own key:

    * `AuthenticationMiddleware` reads `AUTH_REQUIRED` and returns 401 before any
      dependency is resolved, so `dependency_overrides` cannot reach it. Both env vars
      are read per request rather than at import, which is what makes `monkeypatch`
      effective on an app object that was imported at module load.
    * `require_permissions(...)` reads `AUTH_DISABLED` and returns early.
    * `get_current_user` still has to resolve to a user object even when the permission
      check is bypassed, which is what the override supplies.
    """
    monkeypatch.setenv("AUTH_REQUIRED", "false")
    monkeypatch.setenv("AUTH_DISABLED", "true")

    def fake_user():
        return User(email="tester@example.com", name="Tester", sub="test-subject",
                    provider="okta", role="super_admin")

    app.dependency_overrides[get_current_user] = fake_user
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.pop(get_current_user, None)


ANALYSIS_PAYLOAD = {
    "query": "keyv supply chain compromise",
    "scope": ["all"],
    "timestamp": "2026-08-07T10:00:00Z",
    "analysis": (
        "## Findings\n\n"
        "A **confirmed malicious** version was published.\n\n"
        "| Spec | Verdict |\n|---|---|\n| `keyv@4.5.4` | Confirmed |\n"
    ),
    "affected_repositories": [
        {"repository": "org/payments-api", "source": "sbom", "reason": "Context match"},
        {"repository": "org/legacy|tool", "source": "code-search"},
    ],
    "hunt_evidence": {
        "hunt_dependency_exposure": {
            "matches": [
                {
                    "repository": "org/payments-api",
                    "matched_spec": "keyv@4.5.4",
                    "severity": "critical",
                    "declared_version": "^4.5.0",
                    "exposure": "direct",
                    "environments": ["production"],
                },
            ],
        },
    },
    "coverage_notes": ["Endpoint telemetry was not queried for this run."],
    "hunt_enabled": True,
    "organizations_in_scope": ["SleepNumberInc"],
}

REPO_LIST_PAYLOAD = {
    "query": "keyv",
    "timestamp": "2026-08-07T10:00:00Z",
    "scope": ["all"],
    "total_repositories": 2,
    "repositories": ANALYSIS_PAYLOAD["affected_repositories"],
    "coverage_notes": ANALYSIS_PAYLOAD["coverage_notes"],
    "hunt_enabled": True,
}


def _docx_text(payload: bytes) -> str:
    """Every bit of text in a DOCX, without needing python-docx's object model."""
    with zipfile.ZipFile(BytesIO(payload)) as archive:
        xml = archive.read("word/document.xml").decode("utf-8")
    return re.sub(r"<[^>]+>", "", xml)


# --------------------------------------------------------------------------- #
# The six endpoints produce the format they claim to
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("path,payload,filename", [
    ("/ai/zero-day/export/pdf", ANALYSIS_PAYLOAD, "zda-analysis.pdf"),
    ("/ai/zero-day/export/docx", ANALYSIS_PAYLOAD, "zda-analysis.docx"),
    ("/ai/zero-day/export/md", ANALYSIS_PAYLOAD, "zda-analysis.md"),
    ("/ai/zero-day/export/repos/pdf", REPO_LIST_PAYLOAD, "affected-repos.pdf"),
    ("/ai/zero-day/export/repos/docx", REPO_LIST_PAYLOAD, "affected-repos.docx"),
    ("/ai/zero-day/export/repos/md", REPO_LIST_PAYLOAD, "affected-repos.md"),
])
def test_every_export_endpoint_returns_its_format(client, path, payload, filename):
    response = client.post(path, json=payload)
    assert response.status_code == 200, response.text

    body = response.content
    assert body, "an empty download is a success response the browser saves as a broken file"
    assert filename in response.headers.get("content-disposition", "")

    if filename.endswith(".pdf"):
        assert body.startswith(b"%PDF")
        assert response.headers["content-type"] == "application/pdf"
    elif filename.endswith(".docx"):
        assert body.startswith(b"PK")
        assert "wordprocessingml" in response.headers["content-type"]
    else:
        assert response.headers["content-type"].startswith("text/markdown")
        assert body.decode("utf-8").startswith("---\ntitle:")


def test_the_markdown_export_can_be_fed_back_to_the_renderer(client):
    """
    The `.md` download is a source document. Feeding it to `scripts/report/md2pdf.py`
    must reproduce the same PDF, which means the cover metadata has to travel with it
    rather than living only in the renderer call that produced the PDF.
    """
    from src.reporting import markdown_to_pdf, meta_from_front_matter, split_front_matter

    markdown = client.post("/ai/zero-day/export/md",
                           json=ANALYSIS_PAYLOAD).content.decode("utf-8")
    data, body = split_front_matter(markdown)
    assert data.get("title") == "Zero Day Analysis Report"
    assert data.get("classification"), "the marking a reader checks before forwarding"
    meta = meta_from_front_matter(data, fallback_title="Untitled")
    assert markdown_to_pdf(body, meta).startswith(b"%PDF")


# --------------------------------------------------------------------------- #
# The document a reader actually receives
# --------------------------------------------------------------------------- #

def test_the_exported_analysis_is_the_three_part_document(client):
    markdown = client.post("/ai/zero-day/export/md",
                           json=ANALYSIS_PAYLOAD).content.decode("utf-8")

    for heading in ("# Part 1 — What Happened",
                    "# Part 2 — What To Do, In Order",
                    "# Part 3 — Evidence, Targets and Fixes",
                    "## 3.1 Proof", "## 3.2 Target Resources",
                    "## 3.3 Mitigations and Safeguards"):
        assert heading in markdown, heading

    # The evidence is still there in full -- it moved, it was not summarised.
    assert "keyv@4.5.4" in markdown
    assert "confirmed malicious" in markdown
    # ...and so are the limits on what the run could see. A hunt report without its
    # blind spots reads as an all-clear.
    assert "Endpoint telemetry was not queried" in markdown


def test_a_pipe_in_a_repository_name_cannot_shift_the_table(client):
    markdown = client.post("/ai/zero-day/export/md",
                           json=ANALYSIS_PAYLOAD).content.decode("utf-8")
    assert r"legacy\|tool" in markdown


def test_the_pdf_and_the_docx_agree_with_the_markdown(client):
    """One builder, three formats. Two of them disagreeing is the bug this replaced."""
    markdown = client.post("/ai/zero-day/export/md",
                           json=ANALYSIS_PAYLOAD).content.decode("utf-8")
    docx = _docx_text(client.post("/ai/zero-day/export/docx",
                                  json=ANALYSIS_PAYLOAD).content)

    for claim in ("What To Do, In Order", "Endpoint telemetry was not queried"):
        assert claim in markdown and claim in docx, claim
    # Markdown syntax must have become structure, not survived as literal text.
    assert "## 3.1 Proof" not in docx
    assert "**" not in docx


def test_the_repository_list_carries_its_coverage_section(client):
    markdown = client.post("/ai/zero-day/export/repos/md",
                           json=REPO_LIST_PAYLOAD).content.decode("utf-8")
    assert "Coverage and Blind Spots" in markdown
    assert "Endpoint telemetry was not queried" in markdown


# --------------------------------------------------------------------------- #
# The briefing survives the round trip through the browser
# --------------------------------------------------------------------------- #

def test_a_briefing_posted_back_is_the_one_that_gets_rendered(client):
    """
    Authoring happens once, at analysis time; the browser posts the result back here.
    If that link is broken the export silently falls back to the rule-written wording --
    a difference nobody notices until two copies of one report disagree.
    """
    from src.reporting.briefing import (author_briefing, briefing_to_dict,
                                        findings_from_zda)

    class Provider:
        def create_message(self, **kwargs):
            return {
                "model": "test-model",
                "content": (
                    '{"bottom_line": "A supplier update carried hostile code into '
                    '{affected_resources} systems.", "situation": [{"text": "One system '
                    'reaches customers.", "refs": ["E1"]}], "rationales": {}}'
                ),
            }

    findings = findings_from_zda(ANALYSIS_PAYLOAD)
    stored = briefing_to_dict(author_briefing(findings, ANALYSIS_PAYLOAD,
                                              provider=Provider()))
    assert stored["authored_by"] == "test-model"

    markdown = client.post(
        "/ai/zero-day/export/md",
        json={**ANALYSIS_PAYLOAD, "briefing": stored},
    ).content.decode("utf-8")

    assert "A supplier update carried hostile code into 2 systems." in markdown
    assert "One system reaches customers." in markdown
    assert "drafted by test-model" in markdown


def test_a_briefing_from_a_different_analysis_is_refused(client):
    """Part 2 telling the reader to fix something Part 3 does not show is worse than
    plainer words."""
    from src.reporting.briefing import (briefing_to_dict, deterministic_briefing,
                                        findings_from_zda)

    stale = briefing_to_dict(deterministic_briefing(
        findings_from_zda({"affected_repositories": [{"repository": "org/unrelated"}]})
    ))
    markdown = client.post(
        "/ai/zero-day/export/md",
        json={**ANALYSIS_PAYLOAD, "briefing": stale},
    ).content.decode("utf-8")

    assert "org/unrelated" not in markdown
    assert "# Part 2 — What To Do, In Order" in markdown
    assert "org/payments-api" in markdown


def test_an_export_with_no_briefing_still_produces_a_whole_document(client):
    """Reports saved before the briefing existed, and any run where authoring failed."""
    markdown = client.post("/ai/zero-day/export/md",
                           json=ANALYSIS_PAYLOAD).content.decode("utf-8")
    assert "# Part 1 — What Happened" in markdown
    assert "assembled by rule" in markdown


# --------------------------------------------------------------------------- #
# Degenerate payloads: the browser sends these
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("payload", [
    {},
    {"analysis": None, "affected_repositories": None, "coverage_notes": None},
    {"analysis": "", "affected_repositories": []},
])
def test_a_thin_payload_exports_rather_than_raising(client, payload):
    """`dict.get(key, default)` returns None for a present-but-null key, which the
    AI-generated payload does routinely."""
    response = client.post("/ai/zero-day/export/pdf", json=payload)
    assert response.status_code == 200, response.text
    assert response.content.startswith(b"%PDF")


def test_an_analysis_that_is_missing_says_so_rather_than_printing_none(client):
    markdown = client.post("/ai/zero-day/export/md",
                           json={"analysis": None}).content.decode("utf-8")
    assert "No analysis text" in markdown
    assert "None" not in markdown.split("---\n", 2)[-1]


# --------------------------------------------------------------------------- #
# The rendered artefact
# --------------------------------------------------------------------------- #

def test_the_pdf_has_more_than_a_cover_page(client):
    """A one-page PDF means the cover swallowed the document."""
    from tests.pdf_probes import page_count

    pdf = client.post("/ai/zero-day/export/pdf", json=ANALYSIS_PAYLOAD).content
    # Cover, contents, and the three parts: fewer than four pages means content was lost,
    # not that the document was short.
    assert page_count(pdf) >= 4, f"page count: {page_count(pdf)}"
