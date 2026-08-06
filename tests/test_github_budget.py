"""
Tests for the shared GitHub API budget governor.

The property under test: low-priority (cron) work must yield to interactive and
operator-triggered work on a single shared PAT, and a refusal must always carry
a reason so a deferred scan is visible rather than silent.

Tests run against whatever backend is present (Redis in the container, the
process-local fallback otherwise) and clear governor state between cases.
"""
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

# Must be set before import: the key names are bound at module load, and these
# tests delete their keys - they must never touch a running estate's budget.
os.environ.setdefault("GITHUB_BUDGET_KEY_PREFIX", "ghtest")

from src.api.utils import github_budget as gb  # noqa: E402

assert gb._KEY_BUDGET.startswith("ghtest:"), "tests must not use live budget keys"


def _clear():
    client = gb._redis()
    if client is not None:
        try:
            client.delete(gb._KEY_BUDGET)
            for pattern in (f"{gb._KEY_LEASE_PREFIX}:*", f"{gb._KEY_ACTIVITY}:*"):
                for key in client.scan_iter(match=pattern, count=100):
                    client.delete(key)
        except Exception:
            pass
    gb._local.update({"remaining": None, "reset_epoch": None, "used": None,
                      "observed_at": None, "leases": {}, "activity": {}})


@pytest.fixture(autouse=True)
def clean_state():
    _clear()
    yield
    _clear()


def _headers(remaining, used=None, reset_in=1800):
    return {
        "X-RateLimit-Limit": "5000",
        "X-RateLimit-Remaining": str(remaining),
        "X-RateLimit-Used": str(used if used is not None else 5000 - remaining),
        "X-RateLimit-Reset": str(int(time.time()) + reset_in),
    }


class TestObservation:
    def test_headers_become_the_shared_budget(self):
        assert gb.observe_headers(_headers(3200)) == 3200
        assert gb.snapshot()["remaining"] == 3200

    def test_response_without_headers_is_ignored(self):
        gb.observe_headers(_headers(3200))
        assert gb.observe_headers({}) is None
        assert gb.snapshot()["remaining"] == 3200

    def test_zero_remaining_is_a_real_value_not_missing(self):
        gb.observe_headers(_headers(0, used=5019))
        assert gb.snapshot()["remaining"] == 0


class TestTierFloors:
    def test_interactive_is_never_gated(self):
        gb.observe_headers(_headers(0))
        allowed, reason, _ = gb.can_run(gb.TIER_INTERACTIVE, need=500)
        assert allowed is True
        assert reason

    def test_background_refused_below_its_floor(self):
        gb.observe_headers(_headers(1500))  # floor is 2000
        allowed, reason, _ = gb.can_run(gb.TIER_BACKGROUND, need=150)
        assert allowed is False
        assert "must leave" in reason

    def test_on_demand_still_runs_where_background_would_not(self):
        gb.observe_headers(_headers(1500))
        assert gb.can_run(gb.TIER_ON_DEMAND, need=150)[0] is True
        assert gb.can_run(gb.TIER_BACKGROUND, need=150)[0] is False

    def test_on_demand_refused_below_its_own_floor(self):
        gb.observe_headers(_headers(420))  # floor 400, needs 150
        allowed, reason, _ = gb.can_run(gb.TIER_ON_DEMAND, need=150)
        assert allowed is False
        assert "400" in reason

    def test_background_refused_without_any_observation(self):
        # No observation means no evidence there is budget; refusing is the
        # honest default for the lowest-priority tier.
        allowed, reason, _ = gb.can_run(gb.TIER_BACKGROUND, need=150)
        assert allowed is False
        assert "observation" in reason


class TestPriorityYielding:
    def test_active_on_demand_lease_blocks_background(self):
        gb.observe_headers(_headers(4900))
        lease = gb.begin(gb.TIER_ON_DEMAND, "deployment_topology_sync")
        try:
            allowed, reason, _ = gb.can_run(gb.TIER_BACKGROUND, need=150)
            assert allowed is False
            assert "higher-priority work in flight" in reason
        finally:
            gb.end(gb.TIER_ON_DEMAND, lease)

    def test_recent_higher_priority_activity_blocks_background(self):
        gb.observe_headers(_headers(4900))
        lease = gb.begin(gb.TIER_INTERACTIVE, "repo sync")
        gb.end(gb.TIER_INTERACTIVE, lease)  # finished, but only just now
        allowed, reason, _ = gb.can_run(gb.TIER_BACKGROUND, need=150)
        assert allowed is False
        assert "idle threshold" in reason

    def test_background_runs_when_idle_and_budget_is_healthy(self, monkeypatch):
        gb.observe_headers(_headers(4900))
        monkeypatch.setattr(gb, "IDLE_SECONDS", 0)
        allowed, reason, _ = gb.can_run(gb.TIER_BACKGROUND, need=150)
        assert allowed is True
        assert "above the" in reason


class TestWindowExpiry:
    def test_expired_window_is_treated_as_full_budget(self):
        gb.observe_headers(_headers(0, reset_in=-60))
        snap = gb.snapshot()
        assert snap["window_expired"] is True
        allowed, reason, _ = gb.can_run(gb.TIER_ON_DEMAND, need=150)
        assert allowed is True
        assert "reset" in reason
