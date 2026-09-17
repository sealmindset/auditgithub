"""
Tests that a secret-scanner snippet cannot reach an external tracker.

AuditBoard issues cannot be deleted and their descriptions cannot be edited
after create, so a credential written into a body is permanent. Measured on
this estate: GRC issue I#1716 carries a live Google API key in its body in
plaintext, filed before this check existed.

The browser already withholds these snippets when it builds the body. These
tests pin the server-side enforcement, which is the part that holds when the
caller is a stale tab, a replayed request or a script posting straight to the
endpoint.
"""

import pytest

from src.api.services.issue_redaction import (
    MIN_FRAGMENT,
    SNIPPET_WITHHELD,
    is_secret_family,
    redact_snippet,
)


class _Finding:
    def __init__(self, scanner_name=None, code_snippet=None):
        self.scanner_name = scanner_name
        self.code_snippet = code_snippet


@pytest.mark.parametrize(
    "scanner",
    ["gitleaks", "trufflehog", "whispers", "detect-secrets", "GitLeaks", "ggshield"],
)
def test_secret_scanners_are_recognized(scanner):
    assert is_secret_family(scanner)


@pytest.mark.parametrize("scanner", ["grype", "semgrep", "checkov", "trivy", "horusec"])
def test_other_scanners_are_not_touched(scanner):
    """Their snippets are context, and an issue without context is harder to fix."""
    assert not is_secret_family(scanner)


def test_no_scanner_name_is_not_treated_as_a_secret_scanner():
    assert not is_secret_family(None)
    assert not is_secret_family("")


def test_a_verbatim_snippet_is_replaced():
    secret = '"password": "Sleep1234!",'
    body = f"Code context\n{secret}\n\nTags\nauditgithub"
    out, changed = redact_snippet(body, _Finding("gitleaks", secret))
    assert changed
    assert secret not in out
    assert SNIPPET_WITHHELD in out
    # Everything around it survives; only the credential goes.
    assert "Tags" in out


def test_a_single_line_of_a_multiline_snippet_is_replaced():
    """The browser truncates long snippets, and half a credential is still one."""
    snippet = 'const config = {\n  apiKey: "AIzaSyFAKE0000000000000000000000000000",\n}'
    body = 'Code context\n  apiKey: "AIzaSyFAKE0000000000000000000000000000",\n'
    out, changed = redact_snippet(body, _Finding("whispers", snippet))
    assert changed
    assert "AIzaSyFAKE0000000000000000000000000000" not in out


def test_a_non_secret_scanner_keeps_its_snippet():
    snippet = 'requests.get(url, verify=False)'
    body = f"Code context\n{snippet}"
    out, changed = redact_snippet(body, _Finding("semgrep", snippet))
    assert not changed
    assert snippet in out


def test_a_body_without_the_snippet_is_returned_unchanged():
    body = "Severity: Critical\nScanner: gitleaks"
    out, changed = redact_snippet(body, _Finding("gitleaks", '"password": "x"'))
    assert not changed
    assert out == body


def test_a_finding_with_no_snippet_is_returned_unchanged():
    body = "Severity: Critical"
    out, changed = redact_snippet(body, _Finding("gitleaks", None))
    assert not changed
    assert out == body


def test_short_fragments_are_left_alone():
    """A brace or a quote appears throughout a body; replacing each would shred it."""
    snippet = "{\n}\n;"
    body = "Description\n{\n}\nmore text"
    out, changed = redact_snippet(body, _Finding("gitleaks", snippet))
    assert not changed
    assert out == body
    assert MIN_FRAGMENT > 1


def test_an_empty_body_is_handled():
    out, changed = redact_snippet("", _Finding("gitleaks", '"password": "x"'))
    assert not changed
    assert out == ""


def test_the_replacement_says_why_and_where_to_look():
    """A reader who cannot see the evidence needs to know it exists and where."""
    assert "withheld" in SNIPPET_WITHHELD.lower()
    assert "AuditGitHub" in SNIPPET_WITHHELD
