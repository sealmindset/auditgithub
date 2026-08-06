"""
Tests for the deployment-topology reusable workflow parser (phase P1).

Fixtures are trimmed but structurally faithful copies of the SleepNumberInc
central CD workflows: environment taken from the deployment event, ternary
runner-label expressions, terraform backend config, and secrets handed wholesale
to a composite action.
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from api.utils.reusable_workflow_parser import (  # noqa: E402
    UNRESOLVED_ENVIRONMENT,
    classify_environment_kind,
    infer_region,
    parse_reusable_workflow,
)
from api.utils.deployment_topology_service import (  # noqa: E402
    DeploymentTopologyService,
)


AZURE_FUNCTION_APP_CD = """
name: Node Function App CD
on:
  workflow_call:
    inputs:
      runner_label:
        type: string
        default: 'onprem-runner'
        required: false
      environment:
        type: string
        default: null
        required: false
env:
  TF_LOG: ${{ vars.TF_LOG }}
jobs:
  plan-terraform:
    runs-on:
      - ${{ inputs.runner_label == 'ubuntu-latest' && inputs.runner_label || 'self-hosted' }}
      - ${{ inputs.runner_label }}
      - ${{ inputs.runner_label == 'azure-runner' && github.event.deployment.environment || inputs.runner_label }}
    if: contains(vars.CD_PLAN_ENVIRONMENTS, github.event.deployment.environment) && vars.CREATE_SERVICE_NOW_CR == 'true'
    permissions:
      contents: read
    environment:
      name: ${{ github.event.deployment.environment }}
    steps:
      - name: Run initial terraform steps
        uses: SleepNumberInc/terraform-setup-composite-action@v2
        with:
          subscription_id: ${{ vars.SUBSCRIPTION_ID != null && vars.SUBSCRIPTION_ID || secrets.SUBSCRIPTION_ID }}
          secrets_json: ${{ toJSON(secrets) }}
      - name: Init
        run: |
          terraform init -backend-config="resource_group_name=${{ vars.TF_BACKEND_RESOURCE_GROUP }}"
      - name: Plan
        run: terraform plan -out=tfplan
  apply-terraform:
    runs-on: [self-hosted, azure-runner]
    environment:
      name: ${{ github.event.deployment.environment }}
    steps:
      - name: Apply
        run: terraform apply -auto-approve tfplan
  deploy-function-app:
    runs-on: [self-hosted]
    environment:
      name: ${{ github.event.deployment.environment }}
    steps:
      - name: Deploy
        uses: Azure/functions-action@v1
        with:
          app-name: ${{ needs.apply-terraform.outputs.function_app_name }}
  promote:
    uses: SleepNumberInc/promote-release-and-deployment-workflow/.github/workflows/promote.yaml@v1
    secrets: inherit
"""

LINT_ONLY_CI = """
name: PR Lint
on:
  workflow_call:
    inputs:
      node_version:
        type: string
        default: '18'
jobs:
  lint:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: morrisoncole/pr-lint-action@v1
"""

AWS_OIDC_CD = """
name: Deploy to ECS
on:
  workflow_call: {}
jobs:
  deploy:
    runs-on: ubuntu-latest
    permissions:
      id-token: write
      contents: read
    environment: production
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_ROLE_ARN }}
      - run: aws ecs update-service --cluster prod --service api
"""


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------

class TestAzureFunctionAppContract:
    @pytest.fixture
    def parsed(self):
        return parse_reusable_workflow(
            AZURE_FUNCTION_APP_CD,
            "SleepNumberInc/node-function-app-cd-gha-workflow",
            ".github/workflows/node-function-app-cd.yaml",
            "v3",
        )

    def test_parses_cleanly(self, parsed):
        assert parsed["parse_status"] == "ok"
        assert parsed["workflow_name"] == "Node Function App CD"
        assert parsed["kind"] == "cd"

    def test_identifies_azure_and_workload(self, parsed):
        assert parsed["cloud_providers"] == ["azure"]
        assert "function_app" in parsed["resource_types"]
        assert "terraform_infra" in parsed["resource_types"]
        assert parsed["is_deploying"] is True

    def test_plan_only_marker_collapsed_when_apply_present(self, parsed):
        # terraform plan and apply both appear; only apply changes cloud state.
        assert "terraform_plan" not in parsed["resource_types"]

    def test_environment_comes_from_deployment_event(self, parsed):
        assert parsed["environment_source"] == "deployment_event"
        assert parsed["literal_environments"] == []

    def test_environment_gate_vars_exclude_feature_flags(self, parsed):
        assert parsed["environment_gate_vars"] == ["CD_PLAN_ENVIRONMENTS"]
        assert "CREATE_SERVICE_NOW_CR" in parsed["evidence"]["condition_vars"]

    def test_extracts_runner_labels_from_ternaries(self, parsed):
        for label in ("azure-runner", "self-hosted", "ubuntu-latest"):
            assert label in parsed["runner_labels"]

    def test_records_inputs_schema(self, parsed):
        assert parsed["inputs"]["runner_label"]["default"] == "onprem-runner"
        assert parsed["inputs"]["runner_label"]["required"] is False

    def test_flags_bulk_secret_exposure(self, parsed):
        mechanisms = {e["mechanism"] for e in parsed["secrets_bulk_exposure"]}
        assert "toJSON(secrets)" in mechanisms
        assert "secrets: inherit" in mechanisms
        sinks = {e["sink"] for e in parsed["secrets_bulk_exposure"]}
        assert "SleepNumberInc/terraform-setup-composite-action@v2" in sinks

    def test_records_nested_reusable_workflow(self, parsed):
        assert parsed["nested_workflows"][0]["uses"].startswith(
            "SleepNumberInc/promote-release-and-deployment-workflow"
        )

    def test_captures_variable_names_not_values(self, parsed):
        assert "TF_BACKEND_RESOURCE_GROUP" in parsed["referenced_vars"]
        assert "SUBSCRIPTION_ID" in parsed["referenced_secrets"]

    def test_evidence_markers_carry_line_numbers(self, parsed):
        markers = parsed["evidence"]["cloud_markers"]
        assert markers and all(m["line"] > 0 for m in markers)


class TestNonDeployingWorkflow:
    def test_lint_workflow_is_not_deploying(self):
        parsed = parse_reusable_workflow(
            LINT_ONLY_CI, "SleepNumberInc/cicd-workflows",
            ".github/workflows/pr_lint.yml", "main",
        )
        assert parsed["is_deploying"] is False
        assert parsed["cloud_providers"] == []
        assert parsed["kind"] == "ci"


class TestAwsOidcWorkflow:
    @pytest.fixture
    def parsed(self):
        return parse_reusable_workflow(
            AWS_OIDC_CD, "Example/deploy", ".github/workflows/deploy.yml", "v1"
        )

    def test_detects_aws(self, parsed):
        assert "aws" in parsed["cloud_providers"]
        assert parsed["is_deploying"] is True

    def test_detects_oidc_federation(self, parsed):
        assert parsed["oidc_used"] is True

    def test_literal_environment(self, parsed):
        assert parsed["environment_source"] == "literal"
        assert parsed["literal_environments"] == ["production"]


class TestDegradedInput:
    def test_broken_yaml_still_yields_a_row(self):
        parsed = parse_reusable_workflow(
            "jobs:\n  a:\n   - [unclosed\n", "o/r", ".github/workflows/x.yml", "v1"
        )
        assert parsed["parse_status"] == "parse_error"
        assert parsed["parse_confidence"] > 0
        assert "parse_error" in parsed["evidence"]

    def test_empty_document(self):
        parsed = parse_reusable_workflow("", "o/r", ".github/workflows/x.yml", "v1")
        assert parsed["parse_status"] == "parse_error"


# ---------------------------------------------------------------------------
# Environment classification
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    "environment,expected",
    [
        ("prd", "production"),
        ("prd-ncus", "production"),
        ("prod", "production"),
        ("stg", "staging"),
        ("stg-ncus", "staging"),
        ("tst", "test"),
        ("dev", "development"),
        ("copilot", "ephemeral"),
        ("pr-1234", "ephemeral"),
        ("mystery", "unknown"),
        (UNRESOLVED_ENVIRONMENT, "unknown"),
    ],
)
def test_classify_environment_kind(environment, expected):
    assert classify_environment_kind(environment) == expected


@pytest.mark.parametrize(
    "environment,expected",
    [("prd-ncus", "northcentralus"), ("stg-eus2", "eastus2"), ("prd", None), ("dev", None)],
)
def test_infer_region(environment, expected):
    assert infer_region(environment) == expected


# ---------------------------------------------------------------------------
# Variable-to-environment resolution
# ---------------------------------------------------------------------------

class TestVariableResolution:
    REPO_VARS = {
        "AZURE_ACF_DEV_SUBSCRIPTION_ID": "dev-sub",
        "AZURE_ACF_PROD_SUBSCRIPTION_ID": "prd-sub",
        "TF_DEV_BACKEND_RESOURCE_GROUP": "terradevrgp001",
        "TF_DEV_BACKEND_STORAGE_ACCOUNT": "terradevasa001",
    }

    def test_prod_alias_matches_prd_environment(self):
        selected = DeploymentTopologyService._variables_for_environment(
            "prd", self.REPO_VARS, {}, {}
        )
        assert selected["subscription_id"]["value"] == "prd-sub"
        assert selected["subscription_id"]["variable_name"] == "AZURE_ACF_PROD_SUBSCRIPTION_ID"

    def test_dev_variables_do_not_leak_into_prd(self):
        selected = DeploymentTopologyService._variables_for_environment(
            "prd", self.REPO_VARS, {}, {}
        )
        assert "tf_resource_group" not in selected

    def test_regional_environment_uses_base_token(self):
        selected = DeploymentTopologyService._variables_for_environment(
            "prd-ncus", self.REPO_VARS, {}, {}
        )
        assert selected["subscription_id"]["value"] == "prd-sub"

    def test_environment_scope_wins_over_repo_scope(self):
        selected = DeploymentTopologyService._variables_for_environment(
            "dev",
            {"CLIENT_ID": "repo-level"},
            {"CLIENT_ID": "env-level"},
            {},
        )
        assert selected["client_id"]["value"] == "env-level"
        assert selected["client_id"]["scope"] == "environment"

    def test_org_scope_is_last_resort(self):
        selected = DeploymentTopologyService._variables_for_environment(
            "dev", {}, {}, {"AZURE_TENANT_ID": "tenant-abc"}
        )
        assert selected["tenant_id"]["scope"] == "org"


class TestWorkflowRefSplitting:
    def test_splits_owner_repo_and_path(self):
        assert DeploymentTopologyService._split_workflow_ref(
            "SleepNumberInc/cicd-workflows/.github/workflows/pr_lint.yml"
        ) == ("SleepNumberInc/cicd-workflows", ".github/workflows/pr_lint.yml")

    @pytest.mark.parametrize(
        "name",
        [
            "./.github/workflows/e2e_runner-all-packages.yml",
            "/tmp/repo_scan_a6wvkda2/SQLAutomation/.github/workflows/ci.yml",
            ".github/workflows/ci.yml",
            "",
            "not-a-workflow",
        ],
    )
    def test_rejects_local_and_temp_refs(self, name):
        assert DeploymentTopologyService._split_workflow_ref(name) is None


class TestResourceIdentifierDerivation:
    def test_function_app_name_strips_fna_suffix(self):
        derived = DeploymentTopologyService._derive_resource_identifier(
            "snint-fedex-proxy-fna", ["function_app", "terraform_infra"]
        )
        assert derived["identifier"] == "snint-fedex-proxy"
        assert derived["rule"] == "repo_slug_minus_fna_suffix"

    def test_no_derivation_without_function_app_contract(self):
        assert DeploymentTopologyService._derive_resource_identifier(
            "snint-fedex-proxy-fna", ["terraform_infra"]
        ) is None

    def test_no_derivation_without_suffix(self):
        assert DeploymentTopologyService._derive_resource_identifier(
            "some-service", ["function_app"]
        ) is None


class TestResolveRepositoryHonesty:
    """Unresolved must stay unresolved - never silently become 'deploys nowhere'."""

    CONTRACT = {
        "source_repo": "SleepNumberInc/node-function-app-cd-gha-workflow",
        "workflow_path": ".github/workflows/node-function-app-cd.yaml",
        "ref": "v3",
        "resource_types": ["function_app", "terraform_infra"],
        "cloud_providers": ["azure"],
        "environment_source": "deployment_event",
        "environment_gate_vars": ["CD_PLAN_ENVIRONMENTS"],
        "runner_labels": ["azure-runner", "self-hosted"],
    }

    def _service(self):
        return DeploymentTopologyService("dummy-token")

    def test_no_environments_yields_unresolved_row(self):
        rows = self._service().resolve_repository(
            "snint-x-fna", "SleepNumberInc", self.CONTRACT,
            {"environments": [], "repo_variables": {}, "env_variables": {}, "gaps": []},
            {}, True,
        )
        assert len(rows) == 1
        assert rows[0]["is_resolved"] is False
        assert rows[0]["environment"] == UNRESOLVED_ENVIRONMENT
        assert rows[0]["unresolved_reason"] == "no_environments_defined"

    def test_forbidden_environments_recorded_as_such(self):
        rows = self._service().resolve_repository(
            "snint-x-fna", "SleepNumberInc", self.CONTRACT,
            {"environments": [], "repo_variables": {}, "env_variables": {},
             "gaps": ["environments_forbidden"]},
            {}, True,
        )
        assert rows[0]["unresolved_reason"] == "environments_forbidden"

    def test_resolved_row_carries_subscription_and_identity(self):
        ctx = {
            "environments": [{"name": "prd", "protection_rules": ["required_reviewers"]}],
            "repo_variables": {"AZURE_ACF_PROD_SUBSCRIPTION_ID": "prd-sub"},
            "env_variables": {"prd": {"CLIENT_ID": "sp-client-id"}},
            "secret_names": ["CLIENT_SECRET"],
            "gaps": [],
        }
        rows = self._service().resolve_repository(
            "snint-fedex-proxy-fna", "SleepNumberInc", self.CONTRACT, ctx, {}, True
        )
        row = rows[0]
        assert row["is_resolved"] is True
        assert row["environment_kind"] == "production"
        assert row["subscription_or_account"] == "prd-sub"
        assert row["deploy_identity"] == "sp-client-id"
        assert row["resource_identifier"] == "snint-fedex-proxy"
        assert row["confidence"] >= 0.85
        assert row["evidence"]["claim"] == "deployment_capability_not_observation"

    def test_missing_org_variables_lowers_confidence_with_reason(self):
        ctx = {
            "environments": [{"name": "prd", "protection_rules": []}],
            "repo_variables": {},
            "env_variables": {},
            "gaps": [],
        }
        rows = self._service().resolve_repository(
            "snint-x-fna", "SleepNumberInc", self.CONTRACT, ctx, {}, False
        )
        assert rows[0]["unresolved_reason"] == "org_variables_forbidden"
        assert rows[0]["confidence"] < 0.75

    def test_one_row_per_environment(self):
        ctx = {
            "environments": [{"name": n, "protection_rules": []}
                             for n in ("dev", "tst", "stg", "prd", "prd-ncus")],
            "repo_variables": {},
            "env_variables": {},
            "gaps": [],
        }
        rows = self._service().resolve_repository(
            "snint-x-fna", "SleepNumberInc", self.CONTRACT, ctx, {}, True
        )
        assert len(rows) == 5
        assert {r["environment"] for r in rows} == {"dev", "tst", "stg", "prd", "prd-ncus"}
        ncus = next(r for r in rows if r["environment"] == "prd-ncus")
        assert ncus["region"] == "northcentralus"
        assert ncus["environment_kind"] == "production"


class TestRateLimitIsNotARightsGap:
    """A throttled run must never be reported as a permission problem."""

    class _Resp:
        def __init__(self, status, headers=None, body=""):
            self.status_code = status
            self.headers = headers or {}
            self.text = body

    def test_403_with_zero_remaining_is_rate_limit(self):
        resp = self._Resp(403, {"X-RateLimit-Remaining": "0"})
        assert DeploymentTopologyService._is_rate_limited(resp) is True

    def test_403_with_budget_left_is_permission_denial(self):
        resp = self._Resp(403, {"X-RateLimit-Remaining": "4300"}, "Must have admin rights")
        assert DeploymentTopologyService._is_rate_limited(resp) is False

    def test_secondary_rate_limit_detected_from_body(self):
        resp = self._Resp(403, {}, "You have exceeded a secondary rate limit")
        assert DeploymentTopologyService._is_rate_limited(resp) is True

    def test_429_is_rate_limit(self):
        assert DeploymentTopologyService._is_rate_limited(self._Resp(429)) is True
