"""Probes for the side-branch sweep in scripts/hunt/hunt_commit_messages.py.

The sweep exists because commit search does not index commits that live only on a non-default
branch, which is exactly where this campaign pushes. Its offline half needs no network, so the
part that decides whether the vector's zero can mean anything is testable here rather than at
render time.
"""

import json
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts/hunt"))

H = pytest.importorskip("hunt_commit_messages")


def _branches(tmp_path, records):
    path = tmp_path / "branches.json"
    path.write_text("".join(json.dumps(r) + "\n" for r in records))
    return path


def _record(**overrides):
    record = {"full_name": "org/repo", "org": "org", "default_branch": "main",
              "commits_inspected": [], "activity_in_window": []}
    record.update(overrides)
    return record


def _commit(message, ref="refs/heads/feature/x", sha="aaaaaaaaaaaa", error=None):
    entry = {"sha": sha, "ref": ref}
    if error:
        entry["error"] = error
    else:
        entry["message_first_line"] = message
    return entry


def test_the_extortion_string_is_found_on_a_side_branch_the_index_cannot_see():
    """The whole point of the sweep: text on a non-default ref, matched without the index."""
    markers = H.match_markers(
        "IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients")
    assert H.EXTORTION_STRING.lower() in markers
    assert H.EXTORTION_PREFIX.lower() in markers


def test_matching_is_case_insensitive_because_a_commit_message_is_not_normalized():
    assert H.match_markers("Chore: Update Config") == ["chore: update config"]


def test_a_benign_message_matches_nothing():
    assert H.match_markers("fix(auth): correct the token expiry comparison") == []


def test_commits_on_a_non_default_ref_are_counted_as_the_population_search_misses(tmp_path):
    path = _branches(tmp_path, [_record(commits_inspected=[
        _commit("feat: add thing", ref="refs/heads/feature/x"),
        _commit("chore: release", ref="refs/heads/main"),
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["stored_messages_read"] == 2
    assert sweep["stored_messages_off_default_ref"] == 1


def test_a_commit_the_collector_could_not_fetch_is_unreadable_not_clean(tmp_path):
    """An HTTP 422 placeholder must never be counted among the messages that were read."""
    path = _branches(tmp_path, [_record(commits_inspected=[
        _commit("", ref="refs/heads/gone", sha="0" * 12, error="HTTP 422"),
        _commit("feat: kept", ref="refs/heads/kept"),
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["stored_messages_read"] == 1
    assert len(sweep["stored_messages_unreadable"]) == 1
    assert sweep["stored_messages_unreadable"][0]["error"] == "HTTP 422"


def test_a_marker_hit_in_stored_text_is_reported_with_the_ref_it_was_pushed_to(tmp_path):
    path = _branches(tmp_path, [_record(commits_inspected=[
        _commit(f"{H.EXTORTION_STRING} now", ref="refs/heads/dependabot/x", sha="bbbbbbbbbbbb"),
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert len(sweep["stored_marker_hits"]) == 1
    hit = sweep["stored_marker_hits"][0]
    assert hit["ref"] == "dependabot/x"
    assert hit["sha"] == "bbbbbbbbbbbb"
    assert H.EXTORTION_STRING.lower() in hit["markers"]


def test_the_matcher_control_is_measured_against_text_the_sweep_actually_read(tmp_path):
    """A zero from an unproven matcher is silence. The control token comes from the data."""
    path = _branches(tmp_path, [_record(commits_inspected=[
        _commit("release: cut 1.2.3"), _commit("release: cut 1.2.4"),
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["matcher_control_token"] == "release:"
    assert sweep["matcher_control_matches"] == 2


def test_a_deleted_ref_is_an_unreadable_range_rather_than_a_range_that_read_clean(tmp_path):
    path = _branches(tmp_path, [_record(activity_in_window=[
        {"activity_type": "branch_deletion", "ref": "refs/heads/gone",
         "before": "7beb057f917a", "after": "0" * 12},
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["ranges_readable"] == 0
    assert len(sweep["ranges_unreadable"]) == 1
    assert "deleted inside the window" in sweep["ranges_unreadable"][0]["unreadable_reason"]


def test_a_branch_creation_is_compared_against_the_default_branch(tmp_path):
    """It has no `before`, so without this it would be dropped as unreadable."""
    path = _branches(tmp_path, [_record(activity_in_window=[
        {"activity_type": "branch_creation", "ref": "refs/heads/new",
         "before": "0" * 12, "after": "cccccccccccc"},
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["ranges_readable"] == 1
    assert len(sweep["ranges_unreadable"]) == 0


def test_a_cap_that_drops_ranges_is_reported_rather_than_read_as_coverage(tmp_path):
    path = _branches(tmp_path, [_record(activity_in_window=[
        {"activity_type": "push", "ref": f"refs/heads/b{i}",
         "before": "a" * 12, "after": "b" * 12} for i in range(5)
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 2)
    assert sweep["ranges_dropped_for_cap"] == 3
    assert sweep["full_range_coverage_complete"] is False


def test_no_token_makes_a_range_an_error_not_a_clean_read(tmp_path):
    """Silence from a missing credential must not be counted as a range that read clean."""
    path = _branches(tmp_path, [_record(activity_in_window=[
        {"activity_type": "push", "ref": "refs/heads/b", "before": "a" * 12,
         "after": "b" * 12},
    ])])
    sweep = H.sweep_side_branch_messages(path, {}, 0.0, 0)
    assert sweep["ranges_read"] == 0
    assert len(sweep["range_errors"]) == 1
    assert "no token" in sweep["range_errors"][0]["error"]
