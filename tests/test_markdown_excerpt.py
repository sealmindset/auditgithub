"""
Tests for Markdown excerpting.

The behaviour under test is mostly about honesty: an excerpt that does not
announce itself is how a model comes to reason about an eighth of a document
while believing it has the whole thing.
"""

import pytest

from src.services.markdown_excerpt import excerpt_markdown

_DOC = (
    "# Overview\n"
    "The service fronts an internal API.\n\n"
    "## Data flow\n"
    "Requests arrive at the gateway and are authenticated there.\n\n"
    "## Trust boundaries\n"
    "The gateway is the only component reachable from outside the VPC.\n\n"
    "## Dependencies\n"
    "Postgres, Redis, and an internal identity service.\n"
)


def test_document_within_budget_is_returned_whole_and_marked_untruncated():
    """A caller must be able to tell 'this is everything' from 'this is what fit'."""
    result = excerpt_markdown(_DOC, 10_000)
    assert result.text == _DOC
    assert result.is_truncated is False
    assert result.note() == ""
    assert result.sections_included == result.sections_total


def test_truncation_says_what_it_dropped():
    """The failure this exists to prevent: a silent slice."""
    result = excerpt_markdown(_DOC, 140)
    assert result.is_truncated is True
    assert "omitted" in result.text
    assert f"of {result.sections_total} sections" in result.text


def test_cut_lands_on_a_heading_boundary():
    """A section is cut whole or not at all, so the model never reads half a
    trust-boundary description and completes the rest itself."""
    result = excerpt_markdown(_DOC, 140)
    body = result.text.split("[...")[0]
    # Whatever survived must end at a section end, not inside one.
    assert "## Data flow" not in body or body.rstrip().endswith(
        "Requests arrive at the gateway and are authenticated there."
    )


def test_oversized_first_section_is_cut_at_a_sentence_not_mid_word():
    long_para = "# Only\n" + ("The gateway authenticates every request. " * 200)
    result = excerpt_markdown(long_para, 500)
    body = result.text.split("[...")[0].rstrip()
    assert result.is_truncated is True
    # Ends on a sentence, not a severed word.
    assert body.endswith(".")


def test_a_document_with_no_headings_still_truncates_safely():
    plain = "word " * 400
    result = excerpt_markdown(plain, 300)
    assert result.is_truncated is True
    assert not result.text.split("[...")[0].rstrip().endswith("wor")


def test_note_reports_both_sections_and_characters():
    result = excerpt_markdown(_DOC, 140)
    note = result.note()
    assert "sections omitted" in note
    assert "characters shown" in note
    assert str(result.chars_original) in note.replace(",", "")


def test_empty_input_is_not_an_error():
    result = excerpt_markdown("", 1000)
    assert result.text == ""
    assert result.is_truncated is False
    assert excerpt_markdown(None, 1000).text == ""


def test_zero_budget_is_rejected_rather_than_silently_emptying():
    with pytest.raises(ValueError):
        excerpt_markdown(_DOC, 0)


def test_the_old_behaviour_is_what_this_replaces():
    """A bare slice at the old 2,000-character budget against a 14,000-character
    report keeps 14% of it, ends mid-word, and says nothing. Pinned here so the
    regression is legible if anyone reintroduces it."""
    report = "# Section\n" + ("architecture prose that continues for a while. " * 300)
    assert len(report) > 13_000

    old = report[:2000]
    assert not old.rstrip().endswith(".")
    assert "omitted" not in old

    new = excerpt_markdown(report, 8000)
    assert new.is_truncated is True
    assert "omitted" in new.text or "truncated" in new.text
    assert new.chars_kept > len(old)
