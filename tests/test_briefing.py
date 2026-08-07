"""
Tests for the three-part briefing: Situation, Action Plan, Evidence.

The document exists because one reader opens the same report with three different
questions. Two properties make that structure trustworthy rather than merely tidy, and
almost everything here guards one of them:

  * **No figure in the prose was written by a model.** The model emits `{critical}`, never
    "3", and prose containing a literal digit is discarded. A summary that misstates a
    count is worse than no summary, because it is confidently wrong in the one section a
    non-technical reader repeats verbatim to their management.
  * **Effort never changes what is urgent.** Cost and risk are separate axes. Multiplying
    them would let a two-week fix rank below a five-minute one of the same severity, which
    is exactly how genuinely urgent, genuinely hard work sinks to the bottom of a list and
    stays there.

Run on the host with:
    python3 -m pytest --noconftest tests/test_briefing.py
(the repo conftest imports src/api/main.py, which needs loguru).
"""

import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.reporting import DocumentMeta, markdown_to_html  # noqa: E402
from src.reporting.briefing import (  # noqa: E402
    PART_TITLES,
    ActionItem,
    Briefing,
    BriefingRejected,
    Finding,
    author_briefing,
    briefing_from_dict,
    briefing_to_dict,
    compose_document,
    deterministic_briefing,
    estimate_effort,
    findings_from_scan,
    findings_from_zda,
    group_effort,
    metrics,
    part_anchor,
    rank_actions,
    verify_prose,
    verify_refs,
    _demote_headings,
)
from src.reporting.pdf_generator import build_scan_markdown  # noqa: E402


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def _finding(**kwargs) -> Finding:
    base = dict(id="F1", title="Something is wrong", severity="high", resource="org/a")
    base.update(kwargs)
    return Finding(**base)


class FakeProvider:
    """Records what it was asked and replays a scripted answer."""

    def __init__(self, *responses, raises: Exception = None):
        self.responses = list(responses)
        self.raises = raises
        self.calls = []

    def create_message(self, *, messages, system, max_tokens=0, temperature=0.0):
        self.calls.append({"messages": messages, "system": system})
        if self.raises is not None:
            raise self.raises
        if not self.responses:
            raise AssertionError("provider called more times than it was scripted for")
        return {"content": self.responses.pop(0), "model": "test-model"}


# --------------------------------------------------------------------------- #
# The digit prohibition: the guarantee the whole design rests on
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("text", [
    "3 systems are affected.",
    "Roughly 40% of the estate is exposed.",
    "One repository, CVE-2026-1234, is affected.",
])
def test_prose_containing_a_literal_digit_is_rejected(text):
    with pytest.raises(BriefingRejected, match="literal digit"):
        verify_prose(text, {"critical": "3"}, where="bottom_line")


def test_placeholders_are_not_mistaken_for_digits():
    """The substituted value has digits in it; the text the model wrote does not."""
    verify_prose("{critical} systems are affected.", {"critical": "3"}, where="x")


def test_unknown_placeholder_is_rejected_with_the_available_names():
    with pytest.raises(BriefingRejected) as excinfo:
        verify_prose("{repos_pwned} systems affected.", {"critical": "3"}, where="x")
    # The message is fed back to the model on retry, so it has to name the alternatives.
    assert "repos_pwned" in str(excinfo.value)
    assert "critical" in str(excinfo.value)


def test_citing_a_finding_that_does_not_exist_is_rejected():
    with pytest.raises(BriefingRejected, match="E9"):
        verify_refs(["E1", "E9"], ["E1", "E2"], where="situation[1]")


def test_model_prose_with_a_digit_is_discarded_and_the_report_still_renders():
    findings = [_finding(severity="critical")]
    provider = FakeProvider(
        '{"bottom_line": "2 systems are affected.", "situation": '
        '[{"text": "Bad.", "refs": ["F1"]}], "rationales": {}}',
        '{"bottom_line": "Still 2 systems.", "situation": '
        '[{"text": "Bad.", "refs": ["F1"]}], "rationales": {}}',
    )
    briefing = author_briefing(findings, {}, provider=provider)

    assert briefing.authored_by == "deterministic"
    assert "literal digit" in briefing.degraded_reason
    assert len(provider.calls) == 2, "a rejected attempt must be retried once"
    # The retry has to tell the model what was wrong, or it just repeats itself.
    assert "rejected" in provider.calls[1]["messages"][0]["content"]
    assert briefing.bottom_line  # degraded, not empty


def test_accepted_model_prose_has_its_numbers_substituted_by_code():
    findings = [_finding(id="F1", severity="critical"), _finding(id="F2", severity="high",
                                                                resource="org/b")]
    provider = FakeProvider(
        '{"bottom_line": "{critical_and_high} issues need attention.",'
        ' "situation": [{"text": "Across {affected_resources} systems.",'
        ' "refs": ["F1", "F2"]}], "rationales": {}}'
    )
    briefing = author_briefing(findings, {}, provider=provider)

    assert briefing.authored_by == "test-model"
    assert briefing.bottom_line == "2 issues need attention."
    assert briefing.situation[0] == "Across 2 systems."


def test_a_model_claim_that_cites_nothing_is_rejected():
    provider = FakeProvider(
        '{"bottom_line": "Bad.", "situation": [{"text": "Trust me."}], "rationales": {}}',
        '{"bottom_line": "Bad.", "situation": [{"text": "Still trust me."}], '
        '"rationales": {}}',
    )
    briefing = author_briefing([_finding()], {}, provider=provider)
    assert briefing.authored_by == "deterministic"
    assert "cites no findings" in briefing.degraded_reason


def test_provider_failure_degrades_rather_than_raising():
    briefing = author_briefing(
        [_finding()], {}, provider=FakeProvider(raises=RuntimeError("connection reset")),
    )
    assert briefing.authored_by == "deterministic"
    assert "connection reset" in briefing.degraded_reason
    assert briefing.actions, "the plan is computed in code and survives an LLM outage"


def test_the_document_says_which_way_it_was_written():
    """A reader repeating this to their management is entitled to know who phrased it."""
    modelled = compose_document(
        author_briefing([_finding()], {}, provider=FakeProvider(
            '{"bottom_line": "It is bad.", "situation": '
            '[{"text": "Quite bad.", "refs": ["F1"]}], "rationales": {}}')),
        [_finding()],
    )
    assert "drafted by test-model" in modelled
    assert "prevented from writing a number" in modelled

    ruled = compose_document(deterministic_briefing([_finding()]), [_finding()])
    assert "assembled by rule" in ruled


# --------------------------------------------------------------------------- #
# Risk and effort are separate axes
# --------------------------------------------------------------------------- #

def test_an_expensive_critical_is_still_immediate():
    """"Hard to fix" is not an argument for "less urgent"."""
    findings = [_finding(
        severity="critical",
        mitigation="Re-architect the build pipeline across every repository.",
    )]
    action = rank_actions(findings)[0]
    assert action.effort == "XL"
    assert action.wave == "Immediate"


def test_effort_orders_within_a_wave_but_never_across_one():
    findings = [
        # Higher risk (production), higher cost.
        _finding(id="A", resource="org/a", severity="critical", reach="production",
                 mitigation="Rotate every credential the runner holds."),
        # Lower risk, trivial cost -- clears the board while A is being staffed.
        _finding(id="B", resource="org/b", severity="critical", reach="unknown",
                 mitigation="Pin the package version."),
        # Lower wave entirely: cheapness must not lift it above either critical.
        _finding(id="C", resource="org/c", severity="low",
                 mitigation="Pin the package version."),
    ]
    actions = rank_actions(findings)
    by_ref = {a.refs[0]: a for a in actions}

    assert by_ref["B"].effort == "S" and by_ref["A"].effort == "L"
    assert by_ref["B"].rank < by_ref["A"].rank, "cheapest first inside a wave"
    assert by_ref["C"].rank > by_ref["A"].rank, "a cheap low never outranks a critical"
    waves = [a.wave for a in actions]
    assert waves == sorted(waves, key=["Immediate", "This week", "Planned"].index)


def test_the_plan_states_that_effort_did_not_reorder_it():
    findings = [_finding(severity="critical", mitigation="Migrate every repository.")]
    document = compose_document(deterministic_briefing(findings), findings)
    assert "never moved an item between bands" in document


def test_the_same_fix_across_many_resources_costs_more_than_one_of_them():
    one = [_finding(id="F1", mitigation="Pin the package version.")]
    many = [_finding(id=f"F{i}", resource=f"org/{i}", mitigation="Pin the package version.")
            for i in range(12)]
    assert group_effort(one)[0] == "S"
    band, why = group_effort(many)
    assert band != "S", "twelve copies of a one-line fix is a coordination problem"
    assert "12 findings" in why


def test_an_unsized_finding_is_assumed_mid_range_and_labelled_as_unsized():
    """Guessed cheap is the estimate that wrecks a plan; guessed mid is merely wrong."""
    band, why = estimate_effort(_finding(mitigation="", detail="", title="Odd"))
    assert band == "M"
    assert "not estimated" in why


def test_an_explicit_effort_in_the_payload_beats_the_inferred_one():
    findings = findings_from_scan([
        {"title": "x", "severity": "high", "remediation": "Pin the version.",
         "effort": "XL"},
    ])
    assert findings[0].effort_band == "XL"
    assert estimate_effort(findings[0])[1] == "as recorded in the finding"


def test_quick_wins_are_called_out_because_they_are_actionable_in_the_meeting():
    findings = [_finding(severity="critical", mitigation="Pin the package version.")]
    briefing = deterministic_briefing(findings)
    assert briefing.actions[0].is_quick_win
    document = compose_document(briefing, findings)
    assert "Start there" in document


# --------------------------------------------------------------------------- #
# Unknown blast radius is counted, not silently treated as small
# --------------------------------------------------------------------------- #

def test_an_unknown_reach_is_printed_rather_than_assumed_harmless():
    findings = [_finding(reach="unknown"), _finding(id="F2", resource="org/b",
                                                    reach="production")]
    document = compose_document(deterministic_briefing(findings), findings)
    assert "Ranking caveat" in document
    assert "no recorded blast radius" in document
    assert "`unknown` means it was never established, not that it is small" in document


def test_production_reach_outranks_a_higher_severity_that_reaches_nowhere():
    production_high = _finding(id="P", resource="org/p", severity="high",
                               reach="production")            # 60 * 3.0 = 180
    archived_critical = _finding(id="A", resource="org/a", severity="critical",
                                 reach="archived")            # 100 * 0.6 = 60
    assert production_high.score > archived_critical.score
    # ...but the critical is still Immediate. Reach may raise urgency; it is never
    # allowed to argue a critical down, because reach is the less trustworthy input.
    waves = {a.refs[0]: a.wave for a in rank_actions([production_high, archived_critical])}
    assert waves["A"] == "Immediate"


def test_counts_are_arithmetic_over_the_findings_not_prose():
    findings = [
        _finding(id="1", severity="critical", resource="a", reach="production"),
        _finding(id="2", severity="high", resource="b"),
        _finding(id="3", severity="not-a-severity", resource="c"),
    ]
    values = metrics(findings, {"coverage_notes": ["endpoint telemetry not queried"]})
    assert values["critical"] == "1"
    assert values["critical_and_high"] == "2"
    assert values["unknown_severity"] == "1", "an odd severity is counted, never dropped"
    assert values["total_findings"] == "3"
    assert values["affected_resources"] == "3"
    assert values["production_resources"] == "1"
    assert values["reach_known"] == "1"
    assert values["coverage_gaps"] == "1"


# --------------------------------------------------------------------------- #
# Document structure
# --------------------------------------------------------------------------- #

def test_all_three_parts_are_present_and_in_order():
    findings = [_finding(severity="critical", mitigation="Pin the version.")]
    document = compose_document(deterministic_briefing(findings), findings,
                                evidence_body="## Hunt Evidence\n\nDetail.\n")
    positions = [document.index(f"# {PART_TITLES[n]}") for n in (1, 2, 3)]
    assert positions == sorted(positions)
    for heading in ("## 3.1 Proof", "## 3.2 Target Resources",
                    "## 3.3 Mitigations and Safeguards"):
        assert heading in document


def test_cross_references_between_parts_resolve_to_real_anchors():
    """
    An unresolvable target does not fail -- it renders as a link to nothing and a blank
    page number, which is the one class of error a reader cannot detect. This caught a
    hand-written anchor that no longer matched its heading.
    """
    findings = [_finding(severity="critical")]
    document = compose_document(deterministic_briefing(findings), findings)
    html = markdown_to_html(document, DocumentMeta(title="T", cover=False))

    anchors = set(re.findall(r'<h[1-6] id="([^"]+)"', html))
    targets = set(re.findall(r'<a href="#([^"]+)"', html))
    assert targets, "the document cross-references its own parts"
    assert targets <= anchors
    assert {part_anchor(2), part_anchor(3)} <= anchors


def test_renaming_a_part_moves_its_references_with_it(monkeypatch):
    """The anchor is derived from the title, never written out beside it."""
    monkeypatch.setitem(PART_TITLES, 2, "Part 2 — Do These Things")
    assert part_anchor(2) == "part-2-do-these-things"

    findings = [_finding()]
    document = compose_document(deterministic_briefing(findings), findings)
    assert "# Part 2 — Do These Things" in document
    assert f"](#{part_anchor(2)})" in document, "the reference followed the rename"


def test_part_one_carries_no_identifiers_or_tables():
    """Part 1 is written to be read out loud. A finding id in it is a leak of Part 3."""
    findings = [_finding(id="E1", severity="critical", reach="production")]
    document = compose_document(deterministic_briefing(findings), findings)
    part_one = document.split(f"# {PART_TITLES[2]}")[0]
    assert "|" not in part_one
    assert "E1" not in part_one


def test_an_embedded_evidence_body_is_demoted_under_its_host_heading():
    findings = [_finding()]
    document = compose_document(deterministic_briefing(findings), findings,
                                evidence_body="## Hunt Evidence\n\ntext\n")
    assert "### Hunt Evidence" in document, "level with '3.1 Proof' would flatten the TOC"


def test_demoting_headings_leaves_comments_inside_code_fences_alone():
    source = "## Section\n\n```bash\n# not a heading\necho hi\n```\n\n## Next\n"
    demoted = _demote_headings(source, by=1)
    assert "### Section" in demoted and "### Next" in demoted
    assert "# not a heading" in demoted
    assert "## not a heading" not in demoted


def test_a_sixth_level_heading_does_not_grow_a_seventh_hash():
    assert _demote_headings("###### Deep\n", by=1).strip() == "###### Deep"


def test_an_empty_report_states_what_it_examined_rather_than_declaring_all_clear():
    document = compose_document(deterministic_briefing([]), [])
    assert "no issues requiring action" in document
    assert "not about everything that exists" in document
    assert "No action is required from this report" in document


def test_findings_missing_a_mitigation_are_named_rather_than_omitted():
    findings = [
        _finding(id="F1", mitigation="Pin the version."),
        _finding(id="F2", resource="org/b", mitigation=""),
    ]
    document = compose_document(deterministic_briefing(findings), findings)
    assert "No mitigation is recorded for 1 of 2 findings (F2)" in document


def test_findings_on_one_resource_become_one_step():
    """Three numbered steps against one repository get done once and marked duplicate."""
    findings = [_finding(id=f"F{i}", resource="org/a") for i in range(3)]
    actions = rank_actions(findings)
    assert len(actions) == 1
    assert actions[0].refs == ["F0", "F1", "F2"]
    assert "3 findings in org/a" in actions[0].title


# --------------------------------------------------------------------------- #
# Persistence: authored once, rendered many times
# --------------------------------------------------------------------------- #

def test_a_stored_briefing_round_trips():
    findings = [_finding(severity="critical")]
    original = author_briefing(findings, {}, provider=FakeProvider(
        '{"bottom_line": "It is bad.", "situation": [{"text": "Quite bad.",'
        ' "refs": ["F1"]}], "rationales": {"1": "Because it reaches production."}}'))

    restored = briefing_from_dict(briefing_to_dict(original), findings)
    assert restored is not None
    assert restored.bottom_line == original.bottom_line
    assert restored.situation == original.situation
    assert restored.authored_by == "test-model"
    assert restored.actions[0].rationale == "Because it reaches production."
    # Byte-identical re-render is the point of storing it at all.
    assert compose_document(restored, findings) == compose_document(original, findings)


def test_a_stored_plan_that_no_longer_matches_the_findings_is_discarded():
    """
    Part 2 telling the reader to fix something Part 3 does not show is a report that
    contradicts itself. Better to fall back to plainer words than to render that.
    """
    stored = briefing_to_dict(deterministic_briefing([_finding(id="F1",
                                                               resource="org/gone")]))
    assert briefing_from_dict(stored, [_finding(id="F1", resource="org/new")]) is None


def test_stored_rationales_are_matched_by_title_not_by_position():
    """Rank shifts whenever the finding set changes; a title does not."""
    findings = [
        _finding(id="A", resource="org/a", severity="critical",
                 mitigation="Rotate the credential."),
        _finding(id="B", resource="org/b", severity="critical",
                 mitigation="Pin the version."),
    ]
    briefing = deterministic_briefing(findings)
    for action in briefing.actions:
        action.rationale = f"reason for {action.refs[0]}"
    stored = briefing_to_dict(briefing)

    # Reverse the input order: ranking is recomputed, so positions may move.
    restored = briefing_from_dict(stored, list(reversed(findings)))
    assert restored is not None
    for action in restored.actions:
        assert action.rationale == f"reason for {action.refs[0]}"


def test_a_briefing_without_prose_is_not_restored():
    assert briefing_from_dict({"bottom_line": "", "situation": []}, [_finding()]) is None
    assert briefing_from_dict({}, [_finding()]) is None


# --------------------------------------------------------------------------- #
# Payload normalisation
# --------------------------------------------------------------------------- #

def test_zero_day_dependency_matches_outrank_bare_context_matches():
    payload = {
        "hunt_evidence": {"hunt_dependency_exposure": {"matches": [
            {"repository": "org/a", "matched_spec": "keyv@4.5.4", "severity": "critical",
             "environments": ["production"]},
        ]}},
        "affected_repositories": [
            {"repository": "org/a"},          # already covered by the exposure match
            {"repository": "org/b", "source": "sbom"},
        ],
    }
    findings = findings_from_zda(payload)
    ids = {f.id: f for f in findings}
    assert set(ids) == {"E1", "C2"}, "the confirmed repo is not listed twice"
    assert ids["E1"].reach == "production"
    assert ids["E1"].score > ids["C2"].score
    # A context match is a reason to look, and the plan has to say so rather than
    # presenting it as a confirmed finding.
    assert "not a finding" in ids["C2"].mitigation


def test_a_reach_that_was_never_recorded_reads_as_unknown_not_as_development():
    assert findings_from_zda({"affected_repositories": [{"repository": "org/a"}]})[0].reach \
        == "unknown"
    assert findings_from_scan([{"title": "x", "archived": True}])[0].reach == "archived"


@pytest.mark.parametrize("environment,expected", [
    ("production", "production"),
    ("prod-us-east", "production"),
    ("development", "development"),
    ("dev", "development"),
    ("sandbox", "development"),
    # Named but unrecognised. The entry did say where it runs, so it is not "unknown";
    # it is just not a name this maps, and "internal" is the honest middle.
    ("staging", "internal"),
    ("uat", "internal"),
])
def test_an_environment_name_lands_in_its_own_band(environment, expected):
    """
    Every non-production name used to collapse to "internal", which made the
    `development` band unreachable from an environment string. A sandbox-only finding
    was weighted 1.5x instead of 1.0x and described to the reader as "Internal-facing."
    — a wrong number and a wrong sentence, both of which look entirely plausible.
    """
    finding = findings_from_zda({
        "affected_repositories": [{"repository": "org/a", "environments": [environment]}],
    })[0]
    assert finding.reach == expected


def test_a_development_only_finding_scores_below_the_same_finding_internally():
    def score(environment):
        return findings_from_zda({"affected_repositories": [
            {"repository": "org/a", "severity": "high", "environments": [environment]},
        ]})[0].score

    assert score("development") < score("staging") < score("production")


def test_scan_findings_carry_their_location_into_the_target_table():
    findings = findings_from_scan([
        {"title": "Hardcoded key", "severity": "critical", "file_path": "src/x.py",
         "line_number": 12, "description": "Committed credential.",
         "remediation": "Rotate the key."},
    ])
    assert findings[0].resource == "src/x.py:12"
    assert findings[0].effort_band == "L", "a rotation is not a config change"


# --------------------------------------------------------------------------- #
# The scan report is the same document
# --------------------------------------------------------------------------- #

def test_a_scan_report_is_briefed_by_default_and_keeps_its_evidence():
    markdown = build_scan_markdown(
        {"repo_name": "org/a"},
        [{"title": "Hardcoded key", "severity": "critical", "file_path": "src/x.py",
          "description": "Committed credential.", "remediation": "Rotate the key."}],
    )
    for number in (1, 2, 3):
        assert f"# {PART_TITLES[number]}" in markdown
    # The scanner detail is still there in full -- it moved, it was not summarised.
    assert "Hardcoded key" in markdown
    assert "Committed credential." in markdown
    assert "### Detailed Findings" in markdown, "demoted under 3.1 Proof"


def test_a_scan_report_can_still_be_asked_for_the_evidence_alone():
    markdown = build_scan_markdown({"repo_name": "org/a"}, [], briefed=False)
    assert markdown.startswith("## Summary")
    assert PART_TITLES[1] not in markdown


def test_a_scan_report_renders_end_to_end():
    markdown = build_scan_markdown(
        {"repo_name": "org/a"},
        [{"title": "Hardcoded key", "severity": "critical", "file_path": "src/x.py",
          "remediation": "Rotate the key."}],
    )
    html = markdown_to_html(markdown, DocumentMeta(title="Scan"))
    anchors = set(re.findall(r'<h[1-6] id="([^"]+)"', html))
    targets = set(re.findall(r'<a href="#([^"]+)"', html))
    assert targets <= anchors


# --------------------------------------------------------------------------- #
# Determinism
# --------------------------------------------------------------------------- #

def test_the_same_findings_produce_the_same_document_every_time():
    """A priority list that reshuffles between renders is not a plan."""
    findings = [
        _finding(id="A", resource="org/a", severity="high"),
        _finding(id="B", resource="org/b", severity="high"),
        _finding(id="C", resource="org/c", severity="high"),
    ]
    first = compose_document(deterministic_briefing(findings), findings)
    second = compose_document(deterministic_briefing(list(reversed(findings))),
                              list(reversed(findings)))
    assert first == second


def test_equal_scoring_items_are_ordered_by_name_not_by_dict_insertion():
    findings = [_finding(id=x, resource=f"org/{x}", severity="high") for x in "cab"]
    assert [a.refs[0] for a in rank_actions(findings)] == ["a", "b", "c"]
