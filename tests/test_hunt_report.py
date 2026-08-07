"""Probes for `scripts/hunt/render_hunt_report.py`.

Every defect fixed here rendered a complete, well-formatted, plausible report. None raised,
none logged, none changed the page count. The report told an executive that laptops could
not be checked, on a tenant that had granted the permission months earlier; and it printed
two different sections both numbered 3.9, one of which its own cross-references pointed at.
A reader had no way to tell either from the output. So each fix ships with the probe that
would have caught it.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "render_hunt_report", REPO_ROOT / "scripts/hunt/render_hunt_report.py")
render_hunt_report = importlib.util.module_from_spec(_spec)
sys.modules["render_hunt_report"] = render_hunt_report
_spec.loader.exec_module(render_hunt_report)

R = render_hunt_report


def _vector(name: str, status: str, **extra) -> dict:
    base = {"name": name, "status": status, "scope": "-", "counts": {},
            "coverage": [], "findings": []}
    base.update(extra)
    return base


def _render(vectors) -> str:
    """Drive `render` with empty detail artifacts.

    The detail sections are suppressed by empty inputs, which is the point: it isolates
    the parts of the document that are emitted unconditionally.
    """
    verdict = R.compute_verdict(vectors)
    return R.render(
        vectors=vectors, verdict=verdict, delta=[], actions=[],
        ioc={"counts": {}}, ci={"counts": {}}, registry={"counts": {}},
        owners=None, reusable={}, as_of="2026-08-07", campaign="test")


# ----------------------------------------------------------------------------------
# The endpoint vector's fallback. A missing artifact means the collector did not run. It
# has never meant, and must never again mean, that access was refused.
# ----------------------------------------------------------------------------------

def test_a_missing_endpoint_artifact_is_not_run_not_blocked():
    vector = R.vector_endpoint(None)
    assert vector["status"] == R.NOT_RUN
    assert vector["status"] != R.BLOCKED


def test_the_endpoint_fallback_makes_no_claim_about_credentials():
    """The old text named three environment variables and called their absence the blocker.

    `GraphClient.from_db` reads the encrypted credential store and never looks at the
    environment, so the sentence was evidence for a conclusion it could not support. This
    asserts the renderer has stopped reasoning about credentials it cannot see.
    """
    prose = " ".join(R.vector_endpoint(None)["coverage"]).upper()
    for env_var in ("GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET"):
        assert env_var not in prose
    assert "blocked_by" not in R.vector_endpoint(None)


def test_a_supplied_endpoint_artifact_is_passed_through_untouched():
    supplied = _vector("Endpoint / identity (Microsoft Defender)", R.CLEAR,
                       counts={"Hunting queries executed": 6})
    assert R.vector_endpoint(supplied) is supplied


# ----------------------------------------------------------------------------------
# The action the fallback used to generate. Asking for a permission that is already held
# costs a reader weeks in a queue, so which action fires has to follow from which status.
# ----------------------------------------------------------------------------------

def _endpoint_actions(endpoint: dict):
    return R.build_actions(ci={"counts": {}}, endpoint=endpoint, ioc={"counts": {}},
                           owners=None, registry={}, reusable={})


def test_not_run_asks_someone_to_run_it_not_to_request_access():
    actions = _endpoint_actions(R.vector_endpoint(None))
    titles = " ".join(a["title"] for a in actions).lower()
    assert "run the endpoint hunt" in titles
    assert "get read access" not in titles
    ask = next(a for a in actions if "run the endpoint hunt" in a["title"].lower())
    assert ask["targets"] == ["python3 scripts/hunt/hunt_endpoint_defender.py"]
    assert ask["blocked_by"] is None


GAP = {
    "api": "Microsoft Graph",
    "endpoint": "GET /auditLogs/signIns",
    "permission": "AuditLog.Read.All",
    "grant_type": "application (app-only), admin consent",
    "granted_by": "Microsoft 365 Global Administrator",
    "proves": "sign-in history for a suspected account",
}


def test_blocked_still_asks_for_access():
    """The access request is correct when access is genuinely the blocker; keep it reachable."""
    blocked = _vector("Endpoint / identity (Microsoft Defender)", R.BLOCKED,
                      access_required=[GAP])
    titles = " ".join(a["title"] for a in _endpoint_actions(blocked)).lower()
    assert "get read access" in titles


def test_the_access_request_names_the_privilege_the_collector_reported():
    """The ask used to be one hardcoded string, and it named the wrong permission.

    ThreatHunting.Read.All was already granted on the run that produced a BLOCKED endpoint
    vector, so the report raised a priority-1 request for the one thing it did not need.
    The ask now comes from the collector, which is the only component that has spoken to
    the tenant.
    """
    blocked = _vector("Endpoint / identity (Microsoft Defender)", R.BLOCKED,
                      access_required=[GAP])
    ask = next(a for a in _endpoint_actions(blocked)
               if "get read access" in a["title"].lower())
    body = " ".join(ask["targets"])
    assert "AuditLog.Read.All" in body
    assert "ThreatHunting.Read.All" not in body
    # Every field a tenant admin needs, so nobody has to come back and ask.
    for field in ("Microsoft Graph", "/auditLogs/signIns", "app-only",
                  "sign-in history for a suspected account"):
        assert field in body, field
    assert ask["owners"] == ["Microsoft 365 Global Administrator"]


# ----------------------------------------------------------------------------------
# Doctrine §0.6 - nothing is reported that cannot be proven, and every gap is priced in
# exact privileges. Enforced before the document is written, because every violation this
# guards against produced a report that looked complete on every page.
# ----------------------------------------------------------------------------------

def test_a_status_with_no_coverage_evidence_is_refused():
    problems = R.validate_vectors([_vector("V", R.CLEAR)])
    assert any("no coverage evidence" in p for p in problems)


def test_not_run_needs_no_coverage_evidence():
    """NOT RUN is the one status that asserts nothing about the estate."""
    assert R.validate_vectors([_vector("V", R.NOT_RUN)]) == []


def test_blocked_without_a_priced_privilege_is_refused():
    problems = R.validate_vectors([_vector("V", R.BLOCKED, coverage=["c"])])
    assert any("no access_required" in p for p in problems)


def test_a_half_filled_access_gap_is_refused():
    """The six fields are the difference between a work item and a research project."""
    partial = {k: v for k, v in GAP.items() if k not in ("granted_by", "proves")}
    problems = R.validate_vectors(
        [_vector("V", R.BLOCKED, coverage=["c"], access_required=[partial])])
    assert any("granted_by" in p and "proves" in p for p in problems)


def test_an_incomplete_vector_must_name_its_residue():
    problems = R.validate_vectors([_vector("V", R.INCOMPLETE, coverage=["c"])])
    assert any("no named unresolved items" in p for p in problems)


def test_findings_with_nothing_named_is_refused():
    """§0.6(c). A finding nobody can point at is volume, not signal."""
    problems = R.validate_vectors([_vector("V", R.FINDINGS, coverage=["c"])])
    assert any("FINDINGS with nothing named" in p for p in problems)


def test_findings_named_as_exposure_passes_without_being_an_incident():
    exposure = _vector("CI / GitHub Actions posture", R.FINDINGS, coverage=["c"],
                       evidence_for_status=["4 action refs on a mutable ref"])
    assert R.validate_vectors([exposure]) == []
    assert R.compute_verdict([exposure])["rag"] == "AMBER"


def test_validate_reports_every_violation_not_just_the_first():
    problems = R.validate_vectors([_vector("A", R.CLEAR), _vector("B", R.CLEAR)])
    assert len(problems) == 2


def test_an_incomplete_endpoint_turns_its_residue_into_a_work_item():
    """This report's stated rule: doubt is expressed as a work item or not at all.

    An endpoint hunt whose own queries could not answer everything is exactly that case,
    and before this the residue sat in Section 3 as a caveat nobody was asked to close.
    """
    incomplete = _vector(
        "Endpoint / identity (Microsoft Defender)", R.INCOMPLETE,
        unresolved_items=["Bun question unanswered - control returned no rows",
                          "Bun network fetch window too narrow"])
    actions = _endpoint_actions(incomplete)
    residue_action = next(a for a in actions if "could not answer" in a["title"].lower())
    assert residue_action["targets"] == incomplete["unresolved_items"]
    # Ours to close, so nobody outside the team is named and nothing is blocked.
    assert residue_action["owners"] == ["Security operations"]
    assert residue_action["blocked_by"] is None


def test_a_clean_endpoint_generates_no_endpoint_action():
    clean = _vector("Endpoint / identity (Microsoft Defender)", R.CLEAR)
    titles = " ".join(a["title"] for a in _endpoint_actions(clean)).lower()
    assert "endpoint" not in titles


# ----------------------------------------------------------------------------------
# Two axes: result and coverage.
#
# The endpoint vector found no trace of the campaign on 3,424 devices, with controls
# proving the queries could have found it - and reported INCOMPLETE, and drove the whole
# report to AMBER, because 1,379 other devices send no telemetry at all. That reads as
# though the hunt found something worrying. The worrying thing was our instrumentation, it
# will not change no matter how much hunting is done, and folding it into the color meant
# the color said AMBER every day - including the day it would have meant something.
#
# So a population we cannot observe is reported on its own axis, priced, enumerable, and
# kept out of the verdict entirely.
# ----------------------------------------------------------------------------------

COVERAGE_GAP = {
    "gap": "Devices in Defender onboarding state 'Can be onboarded'",
    "population": "570 of 4,801 devices Defender has seen in the last 7 days",
    "named_by": "`DeviceInfo | where OnboardingStatus == \"Can be onboarded\" | project "
                "DeviceId, DeviceName`",
    "cannot_confirm_or_deny": "whether any Bun execution occurred on them",
    "closed_by": "running the Defender onboarding package on each device",
    "owner": "Endpoint management",
}


def _clean_with_gap():
    return _vector("Endpoint / identity (Microsoft Defender)", R.CLEAR, coverage=["control"],
                   coverage_gaps=[COVERAGE_GAP])


def test_an_unobservable_population_does_not_stop_a_vector_being_clear():
    """The result axis is judged on the population the check could observe."""
    assert R.validate_vectors([_clean_with_gap()]) == []
    assert R.compute_verdict([_clean_with_gap()])["rag"] == "GREEN"


def test_an_unobservable_population_never_colours_the_verdict():
    """Two vectors, identical results; one has a blind spot. Same color, different coverage."""
    without = [_vector("V", R.CLEAR, coverage=["control"])]
    with_gap = [_clean_with_gap()]
    assert R.compute_verdict(without)["rag"] == R.compute_verdict(with_gap)["rag"]
    assert R.compute_coverage(without)["state"] == "COMPLETE"
    assert R.compute_coverage(with_gap)["state"] == "PARTIAL"


def test_a_gap_nobody_can_enumerate_is_refused():
    """Rob's rule: if we cannot name the resource, nobody can fix it, so it is not a gap.

    Reporting an unenumerable population adds a worry with no work item attached, which is
    a false positive on the coverage axis.
    """
    unnameable = {k: v for k, v in COVERAGE_GAP.items() if k != "named_by"}
    problems = R.validate_vectors(
        [_vector("V", R.CLEAR, coverage=["c"], coverage_gaps=[unnameable])])
    assert any("named_by" in p for p in problems)


def test_a_gap_with_no_owner_or_no_remedy_is_refused():
    partial = {k: v for k, v in COVERAGE_GAP.items() if k not in ("closed_by", "owner")}
    problems = R.validate_vectors(
        [_vector("V", R.CLEAR, coverage=["c"], coverage_gaps=[partial])])
    assert any("closed_by" in p and "owner" in p for p in problems)


def test_the_report_says_what_it_cannot_say():
    """"We can neither confirm nor deny" has to appear as text, not be left as an inference."""
    document = _render([_clean_with_gap()])
    assert "neither confirm nor deny" in document
    assert COVERAGE_GAP["population"] in document
    assert COVERAGE_GAP["closed_by"] in document


def test_the_enumeration_query_reaches_the_reader_unmangled():
    """KQL is made of pipes, and an unescaped pipe silently splits a Markdown row.

    The query is the field that makes a gap actionable, so it is the one field that must
    survive rendering intact.
    """
    document = _render([_clean_with_gap()])
    assert COVERAGE_GAP["named_by"] in document
    # No table row anywhere may carry a raw pipe from a cell value.
    for line in document.splitlines():
        if line.startswith("|") and "OnboardingStatus" in line:
            assert "\\|" in line, line


def test_a_blind_spot_becomes_a_priced_work_item_not_a_caveat():
    action = next(a for a in _endpoint_actions(_clean_with_gap())
                  if "blind spot" in a["title"].lower())
    assert action["owners"] == ["Endpoint management"]
    assert COVERAGE_GAP["closed_by"] in " ".join(action["targets"])
    # Explicitly not evidence of anything. The action exists so nobody reads it as one.
    assert "not a finding" in action["why_now"]


def test_a_clean_result_over_a_partial_estate_is_not_stated_as_estate_wide():
    document = _render([_clean_with_gap()])
    assert "Nothing we can observe matches this campaign" in document
    assert "Nothing in the estate matches" not in document


def test_the_first_run_of_the_register_does_not_invent_new_blind_spots():
    """A schema change must not manufacture findings.

    The previous state file predates the coverage register, so diffing against it would
    announce every existing gap as brand new - four false findings caused by our own
    refactor, on the axis whose entire purpose is not doing that.
    """
    current = {"rag": "AMBER", "coverage": {"state": "PARTIAL", "gaps": ["g1", "g2"]},
               "vectors": {}}
    lines = " ".join(R.render_delta({"rag": "AMBER", "vectors": {}}, current, []))
    assert "New blind spot" not in lines
    assert "own axis" in lines


def test_a_blind_spot_that_genuinely_opens_is_reported():
    previous = {"rag": "GREEN", "coverage": {"state": "COMPLETE", "gaps": []}, "vectors": {}}
    current = {"rag": "GREEN", "coverage": {"state": "PARTIAL", "gaps": ["g1"]},
               "vectors": {}}
    lines = " ".join(R.render_delta(previous, current, []))
    assert "**New blind spot:** g1" in lines


def test_a_blind_spot_that_closes_is_reported():
    previous = {"rag": "GREEN", "coverage": {"state": "PARTIAL", "gaps": ["g1"]},
                "vectors": {}}
    current = {"rag": "GREEN", "coverage": {"state": "COMPLETE", "gaps": []}, "vectors": {}}
    lines = " ".join(R.render_delta(previous, current, []))
    assert "**Blind spot closed:** g1" in lines


# ----------------------------------------------------------------------------------
# Section numbering. The per-vector loop counted up from 3.2 and the detail sections were
# written as literals starting at 3.9, which agreed only while there were seven vectors.
# ----------------------------------------------------------------------------------

SEVEN = [_vector(f"Vector {i}", R.CLEAR) for i in range(7)]


@pytest.mark.parametrize("count", [1, 5, 7, 8, 9, 15])
def test_section_numbers_are_unique_at_any_vector_count(count):
    document = _render([_vector(f"Vector {i}", R.CLEAR) for i in range(count)])
    headings = re.findall(r"^### (3\.\d+)", document, flags=re.MULTILINE)
    assert len(headings) == len(set(headings)), \
        f"duplicate section number(s) at {count} vectors: {sorted(headings)}"


def test_section_numbers_are_consecutive():
    document = _render(SEVEN)
    numbers = [int(h.split(".")[1]) for h in
               re.findall(r"^### (3\.\d+)", document, flags=re.MULTILINE)]
    assert numbers == list(range(1, len(numbers) + 1))


# ----------------------------------------------------------------------------------
# Section 1 prints a count of unread items. Section 3 has to say what they are, or the one
# number the reader is asked to act on is the one number they cannot look up.
# ----------------------------------------------------------------------------------

def test_unresolved_items_are_named_in_the_evidence_section():
    items = ["571 device(s) in onboarding state 'Can be onboarded'",
             "SHA256 is empty on every DeviceProcessEvents row for Linux"]
    document = _render([_vector("Endpoint / identity (Microsoft Defender)", R.INCOMPLETE,
                                unresolved_items=items)])
    for item in items:
        assert item in document
    assert f"{len(items)} item(s)" in document


def test_the_decisions_block_follows_the_endpoint_status():
    """It used to read 'approve the access request' on every cycle, unconditionally.

    On a cycle where the hunt ran, that told a reader the laptops were unseen and asked
    them to authorize something already granted.
    """
    def decisions(status: str, **extra) -> str:
        document = _render([_vector("Endpoint / identity (Microsoft Defender)",
                                    status, **extra)])
        return document.split("**Decisions needed from you.**", 1)[1].lower()

    assert "approve the access request" in decisions(R.BLOCKED)
    assert "approve the access request" not in decisions(R.NOT_RUN)
    assert "was not queried this cycle" in decisions(R.NOT_RUN)
    assert "approve the access request" not in decisions(R.CLEAR)
    # A decision is something the reader can decide. Unread items are our backlog and need
    # nobody's approval, so they raise no decision; an unobservable population needs somebody
    # to fund the change or sign that the estate stays partly dark, so it raises one.
    assert "decide" not in decisions(R.INCOMPLETE, unresolved_items=["one gap"])
    with_gap = decisions(R.CLEAR, coverage=["control"], coverage_gaps=[COVERAGE_GAP])
    assert "neither confirm nor deny" in with_gap
    assert "accept in writing" in with_gap


# ----------------------------------------------------------------------------------
# The repository sweep's buckets have to sum. `repo_trees_r3_coverage.json` carried
# `tree_failed: 50` with an empty `resolution_accounting` and an empty `unresolved_repos`,
# and the vector rendered CLEAR over 2,760 of 2,810 repositories. Fifty repositories left
# no trace anywhere in the document - not a caveat, not a count, nothing. The renderer had
# asked the artifact whether anything was unresolved instead of working it out.
# ----------------------------------------------------------------------------------

def _trees(**totals) -> dict:
    base = {"repos": 2810, "tree_ok": 2760, "repos_with_indicator_hits": 0}
    base.update(totals)
    return {"totals": base, "orgs": {}, "bun_artifacts": {}}


def test_a_sweep_whose_buckets_do_not_sum_is_not_clean():
    vector = R.vector_repo_files(_trees(tree_failed=50))
    assert vector["status"] == R.INCOMPLETE
    assert vector["counts"]["UNRESOLVED - enumerated but not read"] == 50


def test_unnameable_failures_are_still_carried_as_a_count():
    """The collector counted fifty and named none. Unnameable is not absent."""
    vector = R.vector_repo_files(_trees(tree_failed=50))
    residue = " ".join(vector["unresolved_items"])
    assert "50 repository tree(s) enumerated but not read" in residue
    assert "tree_failed=50" in residue
    assert any("Buckets do not sum: 50" in line for line in vector["coverage"])


def test_buckets_that_sum_earn_clear():
    vector = R.vector_repo_files(
        {"totals": {"repos": 2810, "repos_with_indicator_hits": 0},
         "resolution_accounting": {"read": 2800, "no_files": 10},
         "orgs": {}, "bun_artifacts": {}})
    assert vector["status"] == R.CLEAR
    assert vector["unresolved_items"] == []
    assert any("Buckets sum to the enumerated total" in line for line in vector["coverage"])


def test_a_repository_named_as_unresolved_is_not_double_counted():
    """One named failure and one unaccounted repository is two items, not three."""
    trees = _trees(repos=2810, tree_ok=2808)
    trees["resolution_accounting"] = {"read": 2808, "no_files": 0}
    trees["unresolved_repos"] = [{"repo": "org/a", "why": "403"}]
    vector = R.vector_repo_files(trees)
    assert len(vector["unresolved_items"]) == 2
    assert vector["unresolved_items"][0] == "org/a"


# ----------------------------------------------------------------------------------
# `bun_artifacts_changed` is a field on each commit record. The branches vector read it
# off the sweep's top-level dict, so it always took the default and always printed zero -
# and zero was the truth, which is why it survived. A metric that cannot be non-zero is
# not a zero; it is a blank wearing a number. These two tests fix the number in place by
# proving it moves.
# ----------------------------------------------------------------------------------

def _branches(flagged) -> dict:
    return {"repos_in_estate": 2810, "repos_inspected": 83, "branches_enumerated": 900,
            "commits_inspected": 83, "campaign_branches_found": [],
            "flagged_commits": flagged,
            "branch_enumeration_query_proven": True,
            "commit_inspection_query_proven": True,
            "coverage_supports_negative_finding": True}


def test_a_commit_carrying_bun_files_is_counted():
    vector = R.vector_branches(_branches([
        {"sha": "aaa", "bun_artifacts_changed": ["bun.exe"], "flags": ["bun_artifact_written"]},
        {"sha": "bbb", "bun_artifacts_changed": [], "flags": ["campaign_file_written"]},
    ]))
    assert vector["counts"]["Bun-artifact commits"] == 1
    assert vector["counts"]["Flagged commits"] == 2


def test_the_bun_count_is_not_read_from_the_top_level_dict():
    """The old bug: the key at the top level was authoritative and the commits were not."""
    branches = _branches([
        {"sha": "aaa", "bun_artifacts_changed": ["bunx.exe"], "flags": ["bun_artifact_written"]},
    ])
    branches["bun_artifacts_changed"] = []          # what the collector never writes here
    assert R.vector_branches(branches)["counts"]["Bun-artifact commits"] == 1


# ----------------------------------------------------------------------------------
# The delta. A vector that gains a word in its name is a rename; a vector that disappears
# with nothing in its place is lost coverage. The section printed the same WARNING for
# both, and then admitted in its own sentence that it could not tell them apart - so the
# one line that would have flagged real lost coverage was pre-discredited.
# ----------------------------------------------------------------------------------

def _delta(previous_names, current_names) -> str:
    previous = {"rag": "AMBER", "vectors": {n: {"status": R.CLEAR} for n in previous_names}}
    current = {"rag": "AMBER", "vectors": {n: {"status": R.CLEAR} for n in current_names}}
    return " ".join(R.render_delta(previous, current, []))


def test_a_renamed_vector_does_not_raise_a_lost_coverage_warning():
    text = _delta(["GitHub code search"], ["GitHub code search (corroborating only)"])
    assert "WARNING" not in text
    assert "rename" in text.lower()


def test_a_vector_that_vanishes_with_no_replacement_is_lost_coverage():
    text = _delta(["Registry ground truth", "Endpoint / identity"], ["Registry ground truth"])
    assert "WARNING - vector no longer reported: Endpoint / identity" in text
    assert "not as clean" in text


# ----------------------------------------------------------------------------------
# Artifact selection. The bucket arithmetic above was correct and still produced a false
# statement, because it was applied to the wrong file: the renderer defaulted to
# `repo_trees_r3_coverage.json` while `repo_trees_r4_coverage.json` sat beside it, three
# hours newer, carrying the accounting that resolved all 50 of r3's `tree_failed` entries
# as repositories with no commits. The report said 50 repositories were unread. GitHub had
# already answered `HTTP 409: Git Repository is empty` for 49 of them and `file_count: 0`
# for the last. Nothing was unread; the answer was on disk and the default did not reach it.
# ----------------------------------------------------------------------------------

def test_the_newest_round_is_selected(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "HUNT", tmp_path)
    for name in ("repo_trees_r3_coverage.json", "repo_trees_r4_coverage.json",
                 "repo_trees_r10_coverage.json"):
        (tmp_path / name).write_text("{}")
    chosen = R.latest_round("repo_trees_r*_coverage.json", "repo_trees_r3_coverage.json")
    # Lexical sorting would pick r4 over r10. Round numbers are numbers.
    assert chosen.name == "repo_trees_r10_coverage.json"


def test_no_rounds_on_disk_falls_back_rather_than_raising(tmp_path, monkeypatch):
    monkeypatch.setattr(R, "HUNT", tmp_path)
    chosen = R.latest_round("repo_trees_r*_coverage.json", "repo_trees_r3_coverage.json")
    assert chosen.name == "repo_trees_r3_coverage.json"
    assert R.read_json(chosen) is None


def test_a_repository_with_no_commits_is_resolved_not_unread():
    """49 of the 50 returned GitHub's own 409 'Git Repository is empty'.

    A repository with no files cannot hold a file-based indicator, so counting it as
    unread manufactures a gap that no amount of re-running the collector can close.
    """
    vector = R.vector_repo_files(
        {"totals": {"repos": 2810, "tree_ok": 2760, "tree_failed": 50,
                    "repos_with_indicator_hits": 0},
         "resolution_accounting": {"read": 2760, "no_files": 50, "unresolved": 0},
         "orgs": {}, "bun_artifacts": {}})
    assert vector["status"] == R.CLEAR
    assert vector["unresolved_items"] == []
    assert vector["counts"]["Resolved - repository holds no files at all"] == 50
    assert vector["counts"]["UNRESOLVED - enumerated but not read"] == 0
