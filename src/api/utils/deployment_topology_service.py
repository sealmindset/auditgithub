"""
Deployment Topology Service (phase P1: reusable-workflow propagation).

Answers "where does this repository's code run" by parsing the small number of
centrally-shared reusable workflows once, then propagating each workflow's
deployment contract to every repository that calls it, resolving the concrete
environment list and cloud identifiers from per-repository GitHub Environments
and Actions variables.

Access used (all covered by an existing classic PAT with `repo` + `workflow`):
    GET /repos/{o}/{r}/contents/{path}?ref=       central workflow text
    GET /repos/{o}/{r}/environments               environment names
    GET /repos/{o}/{r}/actions/variables          repo-scope variable values
    GET /repos/{o}/{r}/environments/{e}/variables environment-scope values
    GET /repos/{o}/{r}/actions/secrets            secret NAMES only

Not used and not required: any endpoint returning secret values (none exists),
and org-scope Actions variables, which return 403 for non-admin members. When
that 403 occurs the affected rows are marked is_resolved=false with
unresolved_reason='org_variables_forbidden' rather than being silently dropped.

Every write records `method`, `confidence`, and `evidence`. P1 claims deployment
*capability* (this repo has this environment and calls a workflow that deploys
to the environment named by the deployment event), not observed deployments -
that is phase P2's job via the GitHub Deployments API.
"""
import logging
import re
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import text as sa_text
from sqlalchemy.orm import Session

from . import github_budget
from .github_reader import RATE_LIMITED, GitHubReader
from .reusable_workflow_parser import (
    PARSER_VERSION,
    UNRESOLVED_ENVIRONMENT,
    classify_environment_kind,
    infer_region,
    parse_reusable_workflow,
)

logger = logging.getLogger(__name__)

METHOD = "reusable_workflow"

# RATE_LIMITED is defined in github_reader and re-exported here because callers
# and scripts branch on it as `deployment_topology_service.RATE_LIMITED`.
__all__ = ["METHOD", "RATE_LIMITED", "DeploymentTopologyService"]

# Environment name aliases, used to match env-scoped variable names such as
# AZURE_ACF_PROD_SUBSCRIPTION_ID to the environment 'prd'.
_ENV_ALIASES: Dict[str, List[str]] = {
    "prd": ["prd", "prod", "production"],
    "prod": ["prd", "prod", "production"],
    "stg": ["stg", "stage", "staging"],
    "tst": ["tst", "test", "qa"],
    "dev": ["dev", "develop", "development"],
}

_VAR_ROLES: List[Tuple[str, str]] = [
    (r"SUBSCRIPTION_ID$", "subscription_id"),
    (r"^(?:.*_)?CLIENT_ID$", "client_id"),
    (r"TENANT_ID$", "tenant_id"),
    (r"BACKEND_RESOURCE_GROUP$", "tf_resource_group"),
    (r"BACKEND_STORAGE_ACCOUNT$", "tf_storage_account"),
    (r"BACKEND_STORAGE_CONTAINER$", "tf_container"),
    (r"BACKEND_CLIENT_ID$", "tf_client_id"),
    (r"BACKEND_SUBSCRIPTION_ID$", "tf_subscription_id"),
    (r"^AWS_ACCOUNT_ID$", "aws_account_id"),
    (r"^AWS_REGION$", "region"),
]

# Dependency `name` values that are not real cross-repo workflow references.
_LOCAL_REF = re.compile(r"^(?:\./|/|\.github/)")


class DeploymentTopologyService(GitHubReader):
    """Collects and resolves deployment topology from reusable workflows.

    The HTTP layer (throttle-vs-denial classification, budget publication,
    rights-gap recording) lives in ``GitHubReader`` and is shared with the P2
    deployment observer.
    """

    # -- Discovery --------------------------------------------------------

    @staticmethod
    def _split_workflow_ref(name: str) -> Optional[Tuple[str, str]]:
        """Split a dependency name into (owner/repo, workflow_path).

        Accepts 'Owner/Repo/.github/workflows/x.yaml'. Rejects local refs
        ('./.github/...') and scanner temp paths ('/tmp/repo_scan_*/...'),
        which describe the consumer's own file, not a shared workflow.
        """
        if not name or _LOCAL_REF.match(name) or name.startswith("/tmp/"):
            return None
        parts = name.split("/")
        if len(parts) < 4 or ".github" not in parts:
            return None
        idx = parts.index(".github")
        if idx < 2:
            return None
        return "/".join(parts[:idx]), "/".join(parts[idx:])

    def discover_central_workflows(
        self, db: Session, organization_id: str, min_consumers: int = 1
    ) -> List[Dict[str, Any]]:
        """Find shared reusable workflows and their consumer repositories.

        Reads the already-populated `dependencies` table
        (package_manager='github-action-workflow'), so no GitHub calls are
        needed to establish reach.

        Returns:
            List of {source_repo, workflow_path, ref, consumer_count,
            consumer_repository_ids} sorted by consumer_count descending.
        """
        rows = db.execute(
            sa_text(
                """
                SELECT d.name, COALESCE(d.version, '') AS ref,
                       ARRAY_AGG(DISTINCT d.repository_id::text) AS repo_ids
                FROM dependencies d
                JOIN repositories r ON r.id = d.repository_id
                WHERE d.package_manager = 'github-action-workflow'
                  AND (:org_id IS NULL OR r.organization_id = CAST(:org_id AS uuid))
                GROUP BY d.name, COALESCE(d.version, '')
                """
            ),
            {"org_id": organization_id},
        ).fetchall()

        grouped: List[Dict[str, Any]] = []
        for name, ref, repo_ids in rows:
            split = self._split_workflow_ref(name)
            if not split:
                continue
            source_repo, workflow_path = split
            repo_ids = [r for r in (repo_ids or []) if r]
            if len(repo_ids) < min_consumers:
                continue
            grouped.append(
                {
                    "source_repo": source_repo,
                    "workflow_path": workflow_path,
                    "ref": ref or "main",
                    "consumer_count": len(repo_ids),
                    "consumer_repository_ids": repo_ids,
                }
            )
        grouped.sort(key=lambda g: g["consumer_count"], reverse=True)
        return grouped

    # -- Central workflow ingest -----------------------------------------

    def fetch_and_parse(
        self, source_repo: str, workflow_path: str, ref: str
    ) -> Dict[str, Any]:
        """Fetch one reusable workflow and parse its deployment contract."""
        body, status = self._get(
            f"/repos/{source_repo}/contents/{workflow_path}",
            params={"ref": ref},
            raw=True,
        )
        if status == 200 and body:
            parsed = parse_reusable_workflow(body, source_repo, workflow_path, ref)
            parsed["fetch_status"] = "ok"
            parsed["resolved_sha"] = self._resolve_sha(source_repo, ref)
            return parsed

        if status == 403:
            self._record_gap(
                "workflow_contents_forbidden",
                f"/repos/{source_repo}/contents/{workflow_path}",
                403,
                "Token cannot read this shared workflow's contents.",
            )
        fetch_status = {
            403: "forbidden",
            404: "not_found",
            RATE_LIMITED: "rate_limited",
        }.get(status, "error")
        return {
            "source_repo": source_repo,
            "workflow_path": workflow_path,
            "ref": ref,
            "workflow_name": None,
            "kind": "unknown",
            "cloud_providers": [],
            "resource_types": [],
            "is_deploying": False,
            "environment_source": "unknown",
            "environment_gate_vars": [],
            "literal_environments": [],
            "runner_labels": [],
            "inputs": {},
            "declared_secrets": {},
            "referenced_vars": [],
            "referenced_secrets": [],
            "nested_workflows": [],
            "actions_used": [],
            "permissions": {},
            "oidc_used": False,
            "secrets_bulk_exposure": [],
            "parse_confidence": 0.0,
            "parser_version": PARSER_VERSION,
            "evidence": {"http_status": status},
            "parse_status": fetch_status,
            "fetch_status": fetch_status,
            "resolved_sha": None,
        }

    def _resolve_sha(self, repo: str, ref: str) -> Optional[str]:
        payload, status = self._get(f"/repos/{repo}/commits/{ref}", params={"per_page": 1})
        if status == 200 and isinstance(payload, dict):
            return payload.get("sha")
        return None

    def upsert_workflow_target(
        self, db: Session, organization_id: str, parsed: Dict[str, Any]
    ) -> str:
        """Insert or update one reusable_workflow_targets row, returning its id."""
        params = {
            "org_id": organization_id,
            "source_repo": parsed["source_repo"],
            "workflow_path": parsed["workflow_path"],
            "ref": parsed["ref"],
            "resolved_sha": parsed.get("resolved_sha"),
            "workflow_name": parsed.get("workflow_name"),
            "kind": parsed.get("kind"),
            "consumer_count": parsed.get("consumer_count", 0),
            "cloud_providers": _json(parsed["cloud_providers"]),
            "resource_types": _json(parsed["resource_types"]),
            "is_deploying": parsed["is_deploying"],
            "environment_source": parsed["environment_source"],
            "environment_gate_vars": _json(parsed["environment_gate_vars"]),
            "literal_environments": _json(parsed["literal_environments"]),
            "runner_labels": _json(parsed["runner_labels"]),
            "inputs": _json(parsed["inputs"]),
            "declared_secrets": _json(parsed["declared_secrets"]),
            "referenced_vars": _json(parsed["referenced_vars"]),
            "referenced_secrets": _json(parsed["referenced_secrets"]),
            "nested_workflows": _json(parsed["nested_workflows"]),
            "actions_used": _json(parsed["actions_used"]),
            "permissions": _json(parsed["permissions"]),
            "oidc_used": parsed["oidc_used"],
            "secrets_bulk_exposure": _json(parsed["secrets_bulk_exposure"]),
            "parse_confidence": parsed["parse_confidence"],
            "parser_version": parsed["parser_version"],
            "evidence": _json(parsed["evidence"]),
            "fetch_status": parsed.get("fetch_status", "ok"),
            "fetch_error": parsed.get("fetch_error"),
        }
        row = db.execute(
            sa_text(
                """
                INSERT INTO reusable_workflow_targets (
                    organization_id, source_repo, workflow_path, ref, resolved_sha,
                    workflow_name, kind, consumer_count, cloud_providers, resource_types,
                    is_deploying, environment_source, environment_gate_vars,
                    literal_environments, runner_labels, inputs, declared_secrets,
                    referenced_vars, referenced_secrets, nested_workflows, actions_used,
                    permissions, oidc_used, secrets_bulk_exposure, parse_confidence,
                    parser_version, evidence, fetch_status, fetch_error, fetched_at
                ) VALUES (
                    CAST(:org_id AS uuid), :source_repo, :workflow_path, :ref, :resolved_sha,
                    :workflow_name, :kind, :consumer_count, CAST(:cloud_providers AS jsonb),
                    CAST(:resource_types AS jsonb), :is_deploying, :environment_source,
                    CAST(:environment_gate_vars AS jsonb), CAST(:literal_environments AS jsonb),
                    CAST(:runner_labels AS jsonb), CAST(:inputs AS jsonb),
                    CAST(:declared_secrets AS jsonb), CAST(:referenced_vars AS jsonb),
                    CAST(:referenced_secrets AS jsonb), CAST(:nested_workflows AS jsonb),
                    CAST(:actions_used AS jsonb), CAST(:permissions AS jsonb), :oidc_used,
                    CAST(:secrets_bulk_exposure AS jsonb), :parse_confidence, :parser_version,
                    CAST(:evidence AS jsonb), :fetch_status, :fetch_error, NOW()
                )
                ON CONFLICT (organization_id, source_repo, workflow_path, ref)
                DO UPDATE SET
                    resolved_sha = EXCLUDED.resolved_sha,
                    workflow_name = EXCLUDED.workflow_name,
                    kind = EXCLUDED.kind,
                    consumer_count = EXCLUDED.consumer_count,
                    cloud_providers = EXCLUDED.cloud_providers,
                    resource_types = EXCLUDED.resource_types,
                    is_deploying = EXCLUDED.is_deploying,
                    environment_source = EXCLUDED.environment_source,
                    environment_gate_vars = EXCLUDED.environment_gate_vars,
                    literal_environments = EXCLUDED.literal_environments,
                    runner_labels = EXCLUDED.runner_labels,
                    inputs = EXCLUDED.inputs,
                    declared_secrets = EXCLUDED.declared_secrets,
                    referenced_vars = EXCLUDED.referenced_vars,
                    referenced_secrets = EXCLUDED.referenced_secrets,
                    nested_workflows = EXCLUDED.nested_workflows,
                    actions_used = EXCLUDED.actions_used,
                    permissions = EXCLUDED.permissions,
                    oidc_used = EXCLUDED.oidc_used,
                    secrets_bulk_exposure = EXCLUDED.secrets_bulk_exposure,
                    parse_confidence = EXCLUDED.parse_confidence,
                    parser_version = EXCLUDED.parser_version,
                    evidence = EXCLUDED.evidence,
                    fetch_status = EXCLUDED.fetch_status,
                    fetch_error = EXCLUDED.fetch_error,
                    fetched_at = NOW(),
                    updated_at = NOW()
                RETURNING id::text
                """
            ),
            params,
        ).fetchone()
        return row[0]

    # -- Per-repository resolution ---------------------------------------

    def fetch_repo_context(self, owner: str, repo: str) -> Dict[str, Any]:
        """Fetch environments, variables (repo + per environment) and secret names.

        Variable VALUES are returned - Actions variables are not secrets. Secret
        NAMES only are returned for secrets; no endpoint exposes their values.
        """
        ctx: Dict[str, Any] = {
            "environments": [],
            "repo_variables": {},
            "env_variables": {},
            "secret_names": [],
            "gaps": [],
        }

        payload, status = self._get(f"/repos/{owner}/{repo}/environments", params={"per_page": 100})
        if status == 200 and isinstance(payload, dict):
            ctx["environments"] = [
                {
                    "name": env.get("name"),
                    "protection_rules": [
                        r.get("type") for r in (env.get("protection_rules") or [])
                    ],
                }
                for env in (payload.get("environments") or [])
                if env.get("name")
            ]
        elif status == RATE_LIMITED:
            ctx["gaps"].append("rate_limited")
        elif status == 403:
            ctx["gaps"].append("environments_forbidden")
            self._record_gap(
                "environments_forbidden",
                f"/repos/{owner}/{repo}/environments",
                403,
                "Token cannot list repository environments.",
            )

        payload, status = self._get(
            f"/repos/{owner}/{repo}/actions/variables", params={"per_page": 100}
        )
        if status == 200 and isinstance(payload, dict):
            ctx["repo_variables"] = {
                v["name"]: v.get("value") for v in (payload.get("variables") or [])
            }
        elif status == RATE_LIMITED:
            ctx["gaps"].append("rate_limited")
        elif status == 403:
            ctx["gaps"].append("repo_variables_forbidden")
            self._record_gap(
                "repo_variables_forbidden",
                f"/repos/{owner}/{repo}/actions/variables",
                403,
                "Token cannot read repository Actions variables.",
            )

        for env in ctx["environments"]:
            payload, status = self._get(
                f"/repos/{owner}/{repo}/environments/{env['name']}/variables",
                params={"per_page": 100},
            )
            if status == 200 and isinstance(payload, dict):
                ctx["env_variables"][env["name"]] = {
                    v["name"]: v.get("value") for v in (payload.get("variables") or [])
                }
            elif status == RATE_LIMITED:
                ctx["gaps"].append("rate_limited")
            elif status == 403:
                ctx["gaps"].append("env_variables_forbidden")
                self._record_gap(
                    "env_variables_forbidden",
                    f"/repos/{owner}/{repo}/environments/{env['name']}/variables",
                    403,
                    "Token cannot read environment-scoped Actions variables.",
                )

        payload, status = self._get(
            f"/repos/{owner}/{repo}/actions/secrets", params={"per_page": 100}
        )
        if status == 200 and isinstance(payload, dict):
            ctx["secret_names"] = [s["name"] for s in (payload.get("secrets") or [])]
        elif status == RATE_LIMITED:
            ctx["gaps"].append("rate_limited")
        elif status == 403:
            ctx["gaps"].append("repo_secret_names_forbidden")
            self._record_gap(
                "repo_secret_names_forbidden",
                f"/repos/{owner}/{repo}/actions/secrets",
                403,
                "Token cannot list repository secret names.",
            )

        return ctx

    def probe_org_variables(self, org_login: str) -> Dict[str, Any]:
        """Attempt to read org-scope Actions variables.

        These hold the estate-wide TF_BACKEND_* / AZURE_TENANT_ID values that
        many consumer repositories rely on rather than defining locally. A
        non-admin PAT gets 403 here, which is recorded as a rights gap so the
        affected map rows are honestly marked partially resolved.
        """
        payload, status = self._get(
            f"/orgs/{org_login}/actions/variables", params={"per_page": 100}
        )
        if status == 200 and isinstance(payload, dict):
            return {
                "available": True,
                "variables": {v["name"]: v.get("value") for v in (payload.get("variables") or [])},
            }
        if status == RATE_LIMITED:
            return {"available": False, "variables": {}, "rate_limited": True}
        if status == 403:
            self._record_gap(
                "org_variables_forbidden",
                f"/orgs/{org_login}/actions/variables",
                403,
                "Org-scope Actions variables require org admin or the fine-grained "
                "'organization_actions_variables: read' permission. Without them, "
                "org-level TF_BACKEND_*/AZURE_TENANT_ID values cannot be resolved.",
            )
        return {"available": False, "variables": {}, "status": status}

    @staticmethod
    def _env_tokens(environment: str) -> List[str]:
        base = re.split(r"[-_]", environment.strip().lower())[0]
        return _ENV_ALIASES.get(base, [base])

    @classmethod
    def _variables_for_environment(
        cls,
        environment: str,
        repo_vars: Dict[str, str],
        env_vars: Dict[str, str],
        org_vars: Dict[str, str],
    ) -> Dict[str, Any]:
        """Select the variables that apply to one environment, by role.

        Precedence: environment scope > repo scope (name-matched to the env) >
        repo scope (unqualified) > org scope. Returns {role: {value, name,
        scope}} so every resolved identifier keeps its provenance.
        """
        tokens = cls._env_tokens(environment)
        resolved: Dict[str, Any] = {}

        def consider(name: str, value: Any, scope: str, qualified: bool) -> None:
            for pattern, role in _VAR_ROLES:
                if not re.search(pattern, name):
                    continue
                existing = resolved.get(role)
                rank = {"environment": 3, "repo_qualified": 2, "repo": 1, "org": 0}[scope]
                if existing is None or rank > existing["rank"]:
                    resolved[role] = {
                        "value": value,
                        "variable_name": name,
                        "scope": scope,
                        "rank": rank,
                        "env_qualified": qualified,
                    }
                break

        for name, value in (env_vars or {}).items():
            consider(name, value, "environment", True)

        for name, value in (repo_vars or {}).items():
            name_tokens = set(re.split(r"[-_]", name.lower()))
            qualified = bool(name_tokens & set(tokens))
            other_env_tokens = {
                t
                for aliases in _ENV_ALIASES.values()
                for t in aliases
                if t not in tokens
            }
            if name_tokens & other_env_tokens and not qualified:
                # Belongs to a different environment, e.g. TF_DEV_* while
                # resolving 'prd'. Skip rather than cross-contaminate.
                continue
            consider(name, value, "repo_qualified" if qualified else "repo", qualified)

        for name, value in (org_vars or {}).items():
            consider(name, value, "org", False)

        for role in resolved:
            resolved[role].pop("rank", None)
        return resolved

    @staticmethod
    def _derive_resource_identifier(
        repo_name: str, resource_types: Iterable[str]
    ) -> Optional[Dict[str, str]]:
        """Derive the cloud resource name from the repository name.

        The Function App CD workflow computes the app name as the repository
        slug with a trailing '-fna' stripped
        (`sed "s/\\-fna//" <<< CI_REPOSITORY_NAME_SLUG`), so the mapping is
        deterministic for that template.
        """
        types = set(resource_types or [])
        if "function_app" in types and repo_name.endswith("-fna"):
            return {
                "identifier": repo_name[: -len("-fna")],
                "rule": "repo_slug_minus_fna_suffix",
            }
        return None

    def resolve_repository(
        self,
        repo_name: str,
        owner: str,
        contract: Dict[str, Any],
        ctx: Dict[str, Any],
        org_vars: Dict[str, str],
        org_vars_available: bool,
    ) -> List[Dict[str, Any]]:
        """Turn one (repo, contract) pair into repo_deployment_map rows.

        Returns:
            One row per environment the repository can deploy to via this
            contract, or a single is_resolved=false row when no environment
            could be determined.
        """
        rows: List[Dict[str, Any]] = []
        resource_types = contract.get("resource_types") or []
        providers = contract.get("cloud_providers") or []
        provider = providers[0] if len(providers) == 1 else ("multi" if providers else "unknown")
        primary_resource = _primary_resource_type(resource_types)
        derived = self._derive_resource_identifier(repo_name, resource_types)
        env_names = [e["name"] for e in ctx.get("environments") or []]

        base_evidence = {
            "method_detail": (
                "Repository calls a shared reusable workflow whose environment is "
                "taken from the GitHub deployment event; environment list read "
                "from the Environments API."
            ),
            "source_workflow": f"{contract['source_repo']}/{contract['workflow_path']}@{contract['ref']}",
            "workflow_resource_types": resource_types,
            "workflow_environment_source": contract.get("environment_source"),
            "environment_gate_vars": contract.get("environment_gate_vars"),
            "api_endpoints": [
                f"/repos/{owner}/{repo_name}/environments",
                f"/repos/{owner}/{repo_name}/actions/variables",
            ],
            "claim": "deployment_capability_not_observation",
        }

        if not env_names:
            reason = (
                "environments_forbidden"
                if "environments_forbidden" in (ctx.get("gaps") or [])
                else "no_environments_defined"
            )
            rows.append(
                {
                    "environment": UNRESOLVED_ENVIRONMENT,
                    "environment_kind": "unknown",
                    "cloud_provider": provider,
                    "resource_type": primary_resource,
                    "resource_identifier": derived["identifier"] if derived else None,
                    "subscription_or_account": None,
                    "region": None,
                    "runner_labels": contract.get("runner_labels"),
                    "deploy_identity": None,
                    "tf_backend": None,
                    "confidence": 0.35,
                    "is_resolved": False,
                    "unresolved_reason": reason,
                    "evidence": {**base_evidence, "environments_found": []},
                }
            )
            return rows

        for env_name in env_names:
            selected = self._variables_for_environment(
                env_name,
                ctx.get("repo_variables") or {},
                (ctx.get("env_variables") or {}).get(env_name) or {},
                org_vars,
            )
            subscription = _role_value(selected, "subscription_id") or _role_value(
                selected, "tf_subscription_id"
            )
            client_id = _role_value(selected, "client_id")
            tf_backend = {
                key: _role_value(selected, role)
                for key, role in (
                    ("subscription_id", "tf_subscription_id"),
                    ("resource_group", "tf_resource_group"),
                    ("storage_account", "tf_storage_account"),
                    ("container", "tf_container"),
                    ("client_id", "tf_client_id"),
                )
            }
            if any(tf_backend.values()):
                # The CD template keys state as <repo-slug>-<environment>.tfstate
                tf_backend["key"] = f"{repo_name}-{env_name}.tfstate"
                tf_backend["key_rule"] = "CI_REPOSITORY_NAME_SLUG-environment.tfstate"
            else:
                tf_backend = None

            unresolved_reason = None
            confidence = 0.75
            if subscription:
                confidence += 0.1
            if client_id:
                confidence += 0.05
            if not subscription and not org_vars_available:
                unresolved_reason = "org_variables_forbidden"
                confidence -= 0.15
            elif not subscription:
                unresolved_reason = "no_cloud_identifier_in_variables"
                confidence -= 0.10

            protection = next(
                (
                    e.get("protection_rules")
                    for e in ctx["environments"]
                    if e["name"] == env_name
                ),
                [],
            )

            rows.append(
                {
                    "environment": env_name,
                    "environment_kind": classify_environment_kind(env_name),
                    "cloud_provider": provider,
                    "resource_type": primary_resource,
                    "resource_identifier": derived["identifier"] if derived else None,
                    "subscription_or_account": subscription,
                    "region": infer_region(env_name),
                    "runner_labels": contract.get("runner_labels"),
                    "deploy_identity": client_id,
                    "tf_backend": tf_backend,
                    "confidence": round(max(min(confidence, 0.95), 0.1), 2),
                    "is_resolved": True,
                    "unresolved_reason": unresolved_reason,
                    "evidence": {
                        **base_evidence,
                        "environments_found": env_names,
                        "environment_protection_rules": protection,
                        "resolved_variables": {
                            role: {
                                "variable_name": info["variable_name"],
                                "scope": info["scope"],
                            }
                            for role, info in selected.items()
                        },
                        "resource_identifier_rule": derived["rule"] if derived else None,
                        "repo_secret_names": ctx.get("secret_names"),
                    },
                }
            )
        return rows

    def upsert_map_rows(
        self,
        db: Session,
        organization_id: str,
        repository_id: str,
        source_workflow_id: str,
        rows: List[Dict[str, Any]],
    ) -> int:
        """Upsert map rows for one repository/contract pair."""
        written = 0
        for row in rows:
            db.execute(
                sa_text(
                    """
                    INSERT INTO repo_deployment_map (
                        organization_id, repository_id, environment, environment_kind,
                        cloud_provider, resource_type, resource_identifier,
                        subscription_or_account, region, runner_labels, deploy_identity,
                        tf_backend, method, confidence, source_workflow_id, is_resolved,
                        unresolved_reason, evidence, first_observed_at, last_observed_at
                    ) VALUES (
                        CAST(:org_id AS uuid), CAST(:repo_id AS uuid), :environment,
                        :environment_kind, :cloud_provider, :resource_type,
                        :resource_identifier, :subscription, :region,
                        CAST(:runner_labels AS jsonb), :deploy_identity,
                        CAST(:tf_backend AS jsonb), :method, :confidence,
                        CAST(:source_workflow_id AS uuid), :is_resolved,
                        :unresolved_reason, CAST(:evidence AS jsonb), NOW(), NOW()
                    )
                    ON CONFLICT (repository_id, environment, method,
                                 COALESCE(resource_identifier, ''),
                                 COALESCE(resource_type, ''))
                    DO UPDATE SET
                        environment_kind = EXCLUDED.environment_kind,
                        cloud_provider = EXCLUDED.cloud_provider,
                        subscription_or_account = EXCLUDED.subscription_or_account,
                        region = EXCLUDED.region,
                        runner_labels = EXCLUDED.runner_labels,
                        deploy_identity = EXCLUDED.deploy_identity,
                        tf_backend = EXCLUDED.tf_backend,
                        confidence = EXCLUDED.confidence,
                        source_workflow_id = EXCLUDED.source_workflow_id,
                        is_resolved = EXCLUDED.is_resolved,
                        unresolved_reason = EXCLUDED.unresolved_reason,
                        evidence = EXCLUDED.evidence,
                        last_observed_at = NOW(),
                        is_current = true,
                        updated_at = NOW()
                    """
                ),
                {
                    "org_id": organization_id,
                    "repo_id": repository_id,
                    "environment": row["environment"],
                    "environment_kind": row["environment_kind"],
                    "cloud_provider": row["cloud_provider"],
                    "resource_type": row["resource_type"],
                    "resource_identifier": row["resource_identifier"],
                    "subscription": row["subscription_or_account"],
                    "region": row["region"],
                    "runner_labels": _json(row["runner_labels"]),
                    "deploy_identity": row["deploy_identity"],
                    "tf_backend": _json(row["tf_backend"]),
                    "method": METHOD,
                    "confidence": row["confidence"],
                    "source_workflow_id": source_workflow_id,
                    "is_resolved": row["is_resolved"],
                    "unresolved_reason": row["unresolved_reason"],
                    "evidence": _json(row["evidence"]),
                },
            )
            written += 1
        return written

    # -- Orchestration ----------------------------------------------------

    def sync(
        self,
        db: Session,
        organization_id: str,
        org_login: str,
        min_consumers: int = 5,
        deploying_only: bool = True,
        repo_limit: Optional[int] = None,
        commit_every: int = 25,
    ) -> Dict[str, Any]:
        """Run phase P1 end to end.

        Args:
            db: Tenant session.
            organization_id: Organization UUID owning the repositories.
            org_login: GitHub org login, used for the org-variable probe.
            min_consumers: Skip shared workflows with fewer consumers than this.
            deploying_only: Resolve consumers only for workflows that mutate
                cloud state. Non-deploying contracts are still recorded.
            repo_limit: Cap the number of (repo, contract) resolutions, for
                incremental runs.
            commit_every: Commit cadence, so a long run is resumable.

        Returns:
            Stats dict including `rights_gaps`, which lists every permission
            denial encountered with the exact endpoint and impact.
        """
        started = datetime.utcnow()
        stats: Dict[str, Any] = {
            "central_workflows_discovered": 0,
            "central_workflows_parsed": 0,
            "central_workflows_failed": 0,
            "deploying_workflows": 0,
            # Counted per (repository, contract) pair: one repo calling four
            # contracts counts four times. Distinct repositories are reported
            # separately so the two are never confused.
            "resolutions_resolved": 0,
            "resolutions_unresolved": 0,
            "distinct_repositories_resolved": 0,
            "distinct_repositories_unresolved": 0,
            "map_rows_written": 0,
            "skipped_low_consumers": 0,
            "rate_limited": False,
            "rights_gaps": {},
        }

        # Announce this run as on-demand work for its whole duration, so cron
        # scans defer instead of racing it for the same 5000/hr budget.
        lease = github_budget.begin(github_budget.TIER_ON_DEMAND, "deployment_topology_sync")
        try:
            return self._sync_inner(
                db, organization_id, org_login, min_consumers, deploying_only,
                repo_limit, commit_every, stats, started,
            )
        finally:
            github_budget.end(github_budget.TIER_ON_DEMAND, lease)

    def _sync_inner(
        self,
        db: Session,
        organization_id: str,
        org_login: str,
        min_consumers: int,
        deploying_only: bool,
        repo_limit: Optional[int],
        commit_every: int,
        stats: Dict[str, Any],
        started: datetime,
    ) -> Dict[str, Any]:
        budget = self.rate_limit_status()
        stats["rate_limit_at_start"] = budget
        if budget.get("available") and (budget.get("remaining") or 0) < 200:
            stats["rate_limited"] = True
            stats["aborted"] = (
                f"Only {budget.get('remaining')} core API calls left; resets at "
                f"{budget.get('reset_utc')}. Aborted before writing partial rows."
            )
            return stats

        org_probe = self.probe_org_variables(org_login)
        if org_probe.get("rate_limited"):
            # Throttled before a single contract was read. Abort here rather than
            # writing rows that would look like coverage.
            stats["rate_limited"] = True
            stats["aborted"] = (
                "GitHub rate limit already exhausted on the first real request; "
                f"nothing written. Re-run after {self._reset_utc()}. This is a "
                "throttling condition, not a permissions problem."
            )
            stats["rights_gaps"] = self.rights_gaps
            stats["api_requests"] = self.request_count
            return stats
        org_vars = org_probe.get("variables") or {}
        org_vars_available = bool(org_probe.get("available"))

        groups = self.discover_central_workflows(db, organization_id, min_consumers=1)
        stats["central_workflows_discovered"] = len(groups)

        repo_lookup = {
            str(rid): (name, bool(archived))
            for rid, name, archived in db.execute(
                sa_text(
                    "SELECT id::text, name, COALESCE(is_archived, false) "
                    "FROM repositories WHERE organization_id = CAST(:org_id AS uuid)"
                ),
                {"org_id": organization_id},
            ).fetchall()
        }

        repo_ctx_cache: Dict[str, Dict[str, Any]] = {}
        resolutions = 0
        resolved_repos: set = set()
        unresolved_repos: set = set()

        for group in groups:
            if group["consumer_count"] < min_consumers:
                stats["skipped_low_consumers"] += 1
                continue

            parsed = self.fetch_and_parse(
                group["source_repo"], group["workflow_path"], group["ref"]
            )
            parsed["consumer_count"] = group["consumer_count"]
            target_id = self.upsert_workflow_target(db, organization_id, parsed)
            db.commit()

            if parsed.get("fetch_status") == "rate_limited":
                stats["rate_limited"] = True
                stats["aborted"] = (
                    "GitHub rate limit reached mid-run; stopped so partial results "
                    "are not mistaken for complete coverage. Re-run after "
                    f"{self._reset_utc()} - completed rows are already committed."
                )
                break
            if parsed.get("fetch_status") != "ok":
                stats["central_workflows_failed"] += 1
                continue
            stats["central_workflows_parsed"] += 1

            if parsed["is_deploying"]:
                stats["deploying_workflows"] += 1
            elif deploying_only:
                # Contract is recorded above; consumers are not resolved because
                # this workflow does not mutate cloud state.
                continue

            for repo_id in group["consumer_repository_ids"]:
                if repo_limit is not None and resolutions >= repo_limit:
                    stats["truncated"] = True
                    stats["truncated_note"] = (
                        f"repo_limit={repo_limit} reached; remaining consumers not resolved"
                    )
                    break
                entry = repo_lookup.get(repo_id)
                if not entry:
                    continue
                repo_name, _archived = entry

                if repo_name not in repo_ctx_cache:
                    repo_ctx_cache[repo_name] = self.fetch_repo_context(org_login, repo_name)
                ctx = repo_ctx_cache[repo_name]

                if "rate_limited" in (ctx.get("gaps") or []):
                    stats["rate_limited"] = True
                    stats["aborted"] = (
                        f"Rate limit reached while reading {repo_name}; stopped. "
                        f"Re-run after {self._reset_utc()}."
                    )
                    repo_ctx_cache.pop(repo_name, None)
                    break

                rows = self.resolve_repository(
                    repo_name, org_login, parsed, ctx, org_vars, org_vars_available
                )
                stats["map_rows_written"] += self.upsert_map_rows(
                    db, organization_id, repo_id, target_id, rows
                )
                if any(r["is_resolved"] for r in rows):
                    stats["resolutions_resolved"] += 1
                    resolved_repos.add(repo_id)
                else:
                    stats["resolutions_unresolved"] += 1
                    unresolved_repos.add(repo_id)
                resolutions += 1
                if resolutions % commit_every == 0:
                    db.commit()

            db.commit()
            if stats.get("truncated") or stats["rate_limited"]:
                break

        db.commit()
        stats["distinct_repositories_resolved"] = len(resolved_repos)
        stats["distinct_repositories_unresolved"] = len(unresolved_repos - resolved_repos)
        stats["rights_gaps"] = self.rights_gaps
        stats["api_requests"] = self.request_count
        stats["duration_seconds"] = round(
            (datetime.utcnow() - started).total_seconds(), 1
        )
        return stats


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_RESOURCE_PRIORITY = [
    "function_app",
    "app_service",
    "managed_api",
    "kubernetes_workload",
    "ecs_service",
    "lambda_function",
    "cloud_run",
    "cloud_function",
    "app_engine",
    "cloudformation_stack",
    "static_site",
    "s3_site",
    "container_image",
    "npm_package",
    "terraform_infra",
    "terraform_destroy",
    "terraform_import",
    "terraform_state_mutation",
    "terraform_plan",
]


def _primary_resource_type(resource_types: Iterable[str]) -> Optional[str]:
    """Pick the most specific workload type from a contract's resource types."""
    types = set(resource_types or [])
    for candidate in _RESOURCE_PRIORITY:
        if candidate in types:
            return candidate
    return None


def _role_value(selected: Dict[str, Any], role: str) -> Optional[str]:
    info = selected.get(role)
    return info["value"] if info else None


def _json(value: Any) -> Optional[str]:
    import json

    if value is None:
        return None
    return json.dumps(value, default=str)
