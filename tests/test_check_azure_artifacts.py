"""Probes for the coverage verdict in scripts/hunt/check_azure_artifacts.py.

This collector's whole output rests on one question: is a feed's empty npm list an answer or
silence? It got that wrong in a specific way - the rule was stated correctly in the artifact's
own `interpretation` (an unreadable feed matters only where it has an npmjs upstream to cache
from) and then contradicted by the verdict expression, which vetoed the estate on ANY feed
error. One 403 on a feed with no upstream therefore made the other four unreadable-by-fiat.

These probes are pure functions over records, so none of them touches Azure DevOps.
"""

import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO_ROOT / "scripts/hunt"))

A = pytest.importorskip("check_azure_artifacts")


def _feed(org="sn-tim", feed="f", rows=False, read=True, upstream=False, error=None):
    return {"org": org, "feed": feed, "feed_id": f"id-{feed}",
            "control_endpoint_returns_rows": rows,
            "identity_has_read_packages": read,
            "npmjs_upstream_configured": upstream,
            "read_packages_probe_detail": None if read else "HTTP 403 lacks ReadPackages",
            "listing_error": error, "control_error": None}


def test_a_sibling_feed_in_the_same_org_is_a_positive_control_for_an_empty_feed():
    """Same endpoint, same host, same token - only the feed id differs."""
    records = [_feed(feed="empty", rows=False), _feed(feed="full", rows=True)]
    A.classify_feed_coverage(records)
    assert records[0]["coverage_verdict"] == A.MEASURED_WITH_CONTROL
    assert records[0]["positive_control_source"] == "sn-tim/full"


def test_a_control_does_not_reach_across_organizations():
    """A row in one Azure DevOps organization proves nothing about a feed in another."""
    records = [_feed(org="a", feed="empty"), _feed(org="b", feed="full", rows=True)]
    A.classify_feed_coverage(records)
    assert records[0]["coverage_verdict"] == A.MEASURED_BY_PERMISSION_PROBE
    assert records[0]["positive_control_source"] is None


def test_a_denial_is_unmeasured_rather_than_a_weak_measurement():
    records = [_feed(feed="denied", read=False, error="HTTP 403")]
    A.classify_feed_coverage(records)
    assert records[0]["coverage_verdict"] == A.UNMEASURED
    assert records[0]["npm_zero_is_measured"] is False


def test_an_unreadable_feed_without_an_npmjs_upstream_does_not_block_the_result():
    """The bug this file exists for. It cannot cache what it does not proxy."""
    records = [_feed(feed="full", rows=True, upstream=True),
               _feed(org="other", feed="denied", read=False, upstream=False,
                     error="HTTP 403 FeedNeedsPermissionsException")]
    A.classify_feed_coverage(records)
    assert A.blocking_feeds(records) == []


def test_an_unreadable_feed_with_an_npmjs_upstream_does_block_the_result():
    records = [_feed(feed="full", rows=True),
               _feed(feed="denied", read=False, upstream=True, error="HTTP 403")]
    A.classify_feed_coverage(records)
    blocking = A.blocking_feeds(records)
    assert [b["feed"] for b in blocking] == ["sn-tim/denied"]
    assert "cached before the withdrawal" in blocking[0]["why_it_blocks"]


def test_a_readable_upstream_feed_that_errored_still_blocks():
    """ReadPackages held is not the same as the listing having succeeded."""
    records = [_feed(feed="full", rows=True),
               _feed(feed="flaky", read=True, upstream=True, error="HTTP 500")]
    A.classify_feed_coverage(records)
    assert [b["reason"] for b in A.blocking_feeds(records)] == ["HTTP 500"]


def test_an_empty_feed_is_not_treated_as_a_failed_control():
    """Publishing into production to manufacture a row is exactly what this must not need."""
    records = [_feed(feed="empty", rows=False, upstream=True), _feed(feed="full", rows=True)]
    A.classify_feed_coverage(records)
    assert A.blocking_feeds(records) == []


def test_the_access_request_for_an_upstream_feed_says_it_bounds_the_answer():
    gap = A.access_required_for(_feed(feed="denied", read=False, upstream=True))
    assert all(gap[field] for field in
               ("api", "endpoint", "permission", "grant_type", "granted_by", "proves"))
    assert "bounds the vector's answer" in gap["proves"]


def test_the_access_request_for_a_feed_without_an_upstream_names_what_stays_unread():
    """Forgiving it for the cache question must not read as forgiving it entirely."""
    gap = A.access_required_for(_feed(feed="denied", read=False, upstream=False))
    assert "published directly into it" in gap["proves"]
    assert "ReadPackages on feed sn-tim/denied" == gap["permission"]


def test_the_endpoint_in_an_access_request_is_the_one_that_was_denied():
    gap = A.access_required_for(_feed(org="SleepNumberIndigo", feed="k8s", read=False))
    assert gap["endpoint"].startswith(
        "GET https://feeds.dev.azure.com/SleepNumberIndigo/_apis/packaging/Feeds/id-k8s")
