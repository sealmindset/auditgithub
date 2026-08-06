"""
Tests for deployment observation (phase P2: GitHub Deployments API).

The properties under test are the ones that would quietly corrupt the map if
they broke: a deployment payload must never reach the database as values, a
repository with no deployment records must produce an explicit unresolved row
rather than nothing, and "GitHub reported no status" must not read the same as
"we chose not to spend a call on the status".
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from api.utils.deployment_observation_service import (  # noqa: E402
    CONFIDENCE_STATUS_UNKNOWN,
    METHOD,
    DeploymentObservationService,
    _environment_kind,
    _latest_per_environment,
    _payload_keys,
    build_environment_rows,
    per_repo_cost,
)
from api.utils.reusable_workflow_parser import UNRESOLVED_ENVIRONMENT  # noqa: E402


def deployment(dep_id, environment, created_at, **kwargs):
    base = {
        "id": dep_id,
        "environment": environment,
        "original_environment": environment,
        "created_at": created_at,
        "updated_at": created_at,
        "sha": "a" * 40,
        "ref": "main",
        "task": "deploy",
        "description": "Deployed by CD",
        "creator": {"login": "svc-cd-bot", "type": "Bot"},
        "production_environment": environment.startswith("prd"),
        "transient_environment": False,
        "payload": {},
    }
    base.update(kwargs)
    return base


def rows_for(deployments, status_by_id=None, active_days=365, pages=1):
    latest = _latest_per_environment(deployments)
    return build_environment_rows(
        "SleepNumberInc", "snint-example", latest, status_by_id or {}, active_days, pages
    )


class TestGrouping:
    def test_latest_per_environment_keeps_newest_not_first_seen(self):
        deps = [
            deployment(1, "prd", "2026-01-01T00:00:00Z"),
            deployment(2, "prd", "2026-08-01T00:00:00Z"),
            deployment(3, "dev", "2026-07-01T00:00:00Z"),
        ]
        # Deliberately out of GitHub's newest-first order.
        grouped = _latest_per_environment(deps)
        assert set(grouped) == {"prd", "dev"}
        assert grouped["prd"]["latest"]["id"] == 2
        assert grouped["prd"]["count"] == 2
        assert grouped["prd"]["oldest_created_at"] == "2026-01-01T00:00:00Z"

    def test_missing_environment_becomes_the_unresolved_sentinel(self):
        grouped = _latest_per_environment([deployment(1, "", "2026-08-01T00:00:00Z")])
        assert UNRESOLVED_ENVIRONMENT in grouped

    def test_distinct_deployers_collected(self):
        deps = [
            deployment(1, "prd", "2026-08-01T00:00:00Z", creator={"login": "alice", "type": "User"}),
            deployment(2, "prd", "2026-07-01T00:00:00Z", creator={"login": "svc-cd", "type": "Bot"}),
            deployment(3, "prd", "2026-06-01T00:00:00Z", creator={"login": "alice", "type": "User"}),
        ]
        grouped = _latest_per_environment(deps)
        assert grouped["prd"]["deployers"] == ["alice", "svc-cd"]


class TestCoverageIsData:
    def test_no_deployments_produces_an_explicit_unresolved_row(self):
        rows = rows_for([])
        assert len(rows) == 1
        row = rows[0]
        assert row["is_resolved"] is False
        assert row["environment"] == UNRESOLVED_ENVIRONMENT
        assert row["unresolved_reason"] == "no_deployments_observed"
        # The row must say what it does NOT prove, so it is never read as
        # "this repository deploys nowhere".
        assert "not visible to this method" in row["evidence"]["note"]

    def test_one_row_per_environment(self):
        rows = rows_for([
            deployment(1, "prd", "2026-08-01T00:00:00Z"),
            deployment(2, "prd", "2026-07-01T00:00:00Z"),
            deployment(3, "stg", "2026-07-15T00:00:00Z"),
        ])
        assert sorted(r["environment"] for r in rows) == ["prd", "stg"]
        assert all(r["is_resolved"] for r in rows)


class TestEnvironmentKind:
    def test_name_classification_wins_when_it_resolves(self):
        assert _environment_kind("prd-ncus", deployment(1, "prd-ncus", "2026-08-01T00:00:00Z")) == "production"

    def test_github_production_flag_rescues_an_unclassifiable_name(self):
        dep = deployment(1, "blue", "2026-08-01T00:00:00Z", production_environment=True)
        assert _environment_kind("blue", dep) == "production"
        row = rows_for([dep])[0]
        assert row["environment_kind"] == "production"
        assert row["evidence"]["environment_kind_source"] == "github_production_environment_flag"

    def test_transient_flag_marks_ephemeral(self):
        dep = deployment(1, "pr-1234", "2026-08-01T00:00:00Z",
                         production_environment=False, transient_environment=True)
        assert _environment_kind("pr-1234", dep) in ("ephemeral",)

    def test_region_inferred_from_regional_suffix(self):
        row = rows_for([deployment(1, "prd-ncus", "2026-08-01T00:00:00Z")])[0]
        assert row["region"]


class TestConfidence:
    def test_success_status_outranks_unfetched_status(self):
        dep = deployment(1, "prd", "2026-08-05T00:00:00Z")
        with_status = rows_for([dep], {1: {"state": "success", "created_at": "2026-08-05T00:10:00Z"}})[0]
        without = rows_for([dep])[0]
        assert with_status["confidence"] > without["confidence"]
        assert without["confidence"] == CONFIDENCE_STATUS_UNKNOWN

    def test_failed_deploy_still_evidences_the_targeted_environment(self):
        row = rows_for(
            [deployment(1, "prd", "2026-08-05T00:00:00Z")],
            {1: {"state": "failure", "created_at": "2026-08-05T00:10:00Z"}},
        )[0]
        assert row["is_resolved"] is True
        assert row["confidence"] == pytest.approx(0.85)

    def test_status_source_distinguishes_unknown_from_unqueried(self):
        fetched = rows_for(
            [deployment(1, "prd", "2026-08-05T00:00:00Z")],
            {1: {"state": "success", "created_at": "2026-08-05T00:10:00Z"}},
        )[0]
        unfetched = rows_for([deployment(1, "prd", "2026-08-05T00:00:00Z")])[0]
        assert fetched["evidence"]["status_source"] == "statuses_api"
        assert unfetched["evidence"]["status_source"] == "not_fetched_budget_cap"
        assert unfetched["evidence"]["latest_status"] is None

    def test_stale_deploy_is_flagged_and_discounted(self):
        recent = rows_for([deployment(1, "prd", "2026-08-05T00:00:00Z")], active_days=365)[0]
        old = rows_for([deployment(1, "prd", "2019-01-01T00:00:00Z")], active_days=365)[0]
        assert old["evidence"]["stale"] is True
        assert recent["evidence"]["stale"] is False
        assert old["confidence"] < recent["confidence"]
        assert old["evidence"]["days_since_last_deployment"] > 365


class TestSecrets:
    def test_payload_values_are_never_kept(self):
        keys = _payload_keys({"AZURE_CLIENT_SECRET": "hunter2", "image": "acr.io/app:1"})
        assert keys == ["AZURE_CLIENT_SECRET", "image"]

    def test_row_evidence_carries_key_names_only(self):
        dep = deployment(1, "prd", "2026-08-05T00:00:00Z",
                         payload={"token": "ghp_realsecretvalue", "region": "eastus"})
        row = rows_for([dep])[0]
        assert row["evidence"]["payload_keys"] == ["region", "token"]
        assert "ghp_realsecretvalue" not in str(row)

    def test_opaque_string_payload_is_not_stored_verbatim(self):
        assert _payload_keys("Bearer abc123") == ["__opaque_string_payload__"]
        assert _payload_keys(None) is None


class TestBudgetAccounting:
    def test_per_repo_cost_counts_pages_and_status_calls(self):
        assert per_repo_cost(1, 4) == 5
        assert per_repo_cost(2, 6) == 8

    def test_method_is_additive_not_a_replacement(self):
        # P1 rows use 'reusable_workflow'; P2 must write its own method so the
        # unique index keeps both rows for the same (repo, environment).
        assert METHOD == "github_deployment"

    def test_service_inherits_the_shared_throttle_classifier(self):
        service = DeploymentObservationService("t0ken")
        assert hasattr(service, "_is_rate_limited")
        assert service.rights_gaps == {}
