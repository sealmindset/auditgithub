"""
Reusable Workflow Parser (deployment topology phase P1).

Deterministic, non-LLM parser for GitHub Actions reusable workflows. Given the
YAML text of a centrally-shared `workflow_call` workflow, it extracts the
deployment contract: which cloud it targets, what resource type it creates,
how the environment name is chosen, which runner labels execute it, and which
Actions variables/secrets it consumes.

Parsing the handful of central workflows once yields topology for the hundreds
of repositories that call them, instead of parsing every repository separately.

Secret VALUES are never read here - only `secrets.<NAME>` references, which are
names. Callers may resolve variable values separately (variables are not
secrets), and must respect the data classification noted in
migrations/020_deployment_topology.sql.
"""
import logging
import re
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

logger = logging.getLogger(__name__)

PARSER_VERSION = "p1.1"

# Sentinel environment used when a workflow deploys but the environment name
# cannot be determined from the workflow text alone. Never treated as "no env".
UNRESOLVED_ENVIRONMENT = "__unresolved__"

# ---------------------------------------------------------------------------
# Marker tables
# ---------------------------------------------------------------------------

# (regex, provider). Matched case-insensitively against action refs and run bodies.
_CLOUD_MARKERS: List[Tuple[str, str]] = [
    (r"\bazure/login\b", "azure"),
    (r"\bazure/webapps-deploy\b", "azure"),
    (r"\bazure/functions-action\b", "azure"),
    (r"\bazure/static-web-apps-deploy\b", "azure"),
    (r"\bazure/docker-login\b", "azure"),
    (r"\bazure/container-scan\b", "azure"),
    (r"\bazure/k8s-deploy\b", "azure"),
    (r"\bazure/aks-set-context\b", "azure"),
    (r"\bazure/arm-deploy\b", "azure"),
    (r"\bARM_(?:CLIENT_ID|CLIENT_SECRET|SUBSCRIPTION_ID|TENANT_ID|USE_AZUREAD|USE_OIDC)\b", "azure"),
    (r"\bAZURE_(?:TENANT_ID|SUBSCRIPTION_ID|CREDENTIALS|CLIENT_ID)\b", "azure"),
    (r"\bazurerm\b", "azure"),
    (r"\bazurecr\.io\b", "azure"),
    (r"(?:^|[^\w])az\s+(?:account|functionapp|webapp|aks|acr|group|login|storage)\b", "azure"),
    (r"\baws-actions/", "aws"),
    (r"\bAWS_(?:ACCESS_KEY_ID|SECRET_ACCESS_KEY|REGION|ROLE_ARN|ACCOUNT_ID)\b", "aws"),
    (r"\bdkr\.ecr\.[a-z0-9-]+\.amazonaws\.com\b", "aws"),
    (r"(?:^|[^\w])aws\s+(?:s3|ecs|ecr|lambda|eks|cloudformation)\b", "aws"),
    (r"\bgoogle-github-actions/", "gcp"),
    (r"(?:^|[^\w])gcloud\s+", "gcp"),
    (r"\bGOOGLE_(?:CREDENTIALS|PROJECT)\b", "gcp"),
    (r"(?:^|[^\w])kubectl\s+", "kubernetes"),
    (r"(?:^|[^\w])helm\s+(?:upgrade|install|template)\b", "kubernetes"),
]

# (regex, resource_type). Ordered most specific first for reporting stability.
_RESOURCE_MARKERS: List[Tuple[str, str]] = [
    (r"\bazure/functions-action\b", "function_app"),
    (r"\bTF_VAR_function_app_name\b", "function_app"),
    (r"\bfunc\s+azure\s+functionapp\s+publish\b", "function_app"),
    (r"\baz\s+functionapp\b", "function_app"),
    (r"\bazure/webapps-deploy\b", "app_service"),
    (r"\baz\s+webapp\b", "app_service"),
    (r"\bazure/static-web-apps-deploy\b", "static_site"),
    (r"\bapi[_-]?management\b|\bapim\b|\bmanaged[_-]api\b", "managed_api"),
    (r"\bazure/k8s-deploy\b|\bkubectl\s+apply\b|\bhelm\s+upgrade\b", "kubernetes_workload"),
    (r"\bdocker/build-push-action\b|\bdocker\s+push\b|\bacr\s+build\b", "container_image"),
    (r"\baws-actions/amazon-ecs-deploy-task-definition\b|\baws\s+ecs\s+(?:update-service|deploy)\b", "ecs_service"),
    (r"\baws\s+lambda\s+(?:update-function-code|deploy)\b|\baws-actions/aws-lambda-deploy\b", "lambda_function"),
    (r"\baws\s+cloudformation\s+(?:deploy|create-stack|update-stack)\b", "cloudformation_stack"),
    (r"\baws\s+s3\s+(?:sync|cp)\b", "s3_site"),
    (r"\bgcloud\s+run\s+deploy\b", "cloud_run"),
    (r"\bgcloud\s+functions\s+deploy\b", "cloud_function"),
    (r"\bgcloud\s+app\s+deploy\b", "app_engine"),
    (r"\bnpm\s+publish\b|\bsemantic-release\b", "npm_package"),
    (r"\bterraform\s+apply\b", "terraform_infra"),
    (r"\bterraform\s+destroy\b", "terraform_destroy"),
    (r"\bterraform\s+import\b", "terraform_import"),
    (r"\bterraform\s+state\s+(?:rm|mv)\b|\bforce-unlock\b", "terraform_state_mutation"),
    (r"\bterraform\s+plan\b", "terraform_plan"),
]

# Resource types that mean cloud state actually changes.
_MUTATING_RESOURCE_TYPES = {
    "function_app",
    "app_service",
    "static_site",
    "managed_api",
    "kubernetes_workload",
    "container_image",
    "ecs_service",
    "lambda_function",
    "cloudformation_stack",
    "s3_site",
    "cloud_run",
    "cloud_function",
    "app_engine",
    "npm_package",
    "terraform_infra",
    "terraform_destroy",
    "terraform_import",
    "terraform_state_mutation",
}

# Workflow "kind" inferred from filename/name, used only for grouping.
_KIND_PATTERNS: List[Tuple[str, str]] = [
    (r"(?:^|[_-])cd(?:[_-]|\.|$)|deploy|promote", "cd"),
    (r"(?:^|[_-])ci(?:[_-]|\.|$)|lint|test|build", "ci"),
    (r"terraform|infra", "infra"),
    (r"release|semantic|npm[_-]package", "release"),
]

# Environment token -> canonical kind. Handles regional suffixes (prd-ncus).
_ENV_KIND_TOKENS: List[Tuple[str, str]] = [
    (r"^(prd|prod|production)\b", "production"),
    (r"^(stg|stage|staging|uat|preprod|pre-prod)\b", "staging"),
    (r"^(tst|test|qa|sit)\b", "test"),
    (r"^(dev|develop|development|sbx|sandbox)\b", "development"),
    (r"^(pr-|copilot|ephemeral|review)", "ephemeral"),
]

# Azure region tokens seen in this estate's environment names.
_REGION_TOKENS: Dict[str, str] = {
    "ncus": "northcentralus",
    "scus": "southcentralus",
    "eus": "eastus",
    "eus2": "eastus2",
    "wus": "westus",
    "wus2": "westus2",
    "cus": "centralus",
    "weu": "westeurope",
    "neu": "northeurope",
}

_EXPR_VARS = re.compile(r"vars\.([A-Za-z_][A-Za-z0-9_]*)")
_EXPR_SECRETS = re.compile(r"secrets\.([A-Za-z_][A-Za-z0-9_]*)")
_EXPR_INPUTS = re.compile(r"inputs\.([A-Za-z_][A-Za-z0-9_]*)")
_BULK_SECRETS = re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)
_DEPLOYMENT_EVENT_ENV = re.compile(r"github\.event\.deployment\.environment")
_SHA_PIN = re.compile(r"^[0-9a-f]{40}$")


def classify_environment_kind(environment: str) -> str:
    """Classify an environment name into a canonical kind.

    Handles regional suffixes: 'prd-ncus' classifies as production.

    Args:
        environment: Raw environment name from GitHub.

    Returns:
        production | staging | test | development | ephemeral | unknown
    """
    if not environment or environment == UNRESOLVED_ENVIRONMENT:
        return "unknown"
    name = environment.strip().lower()
    for pattern, kind in _ENV_KIND_TOKENS:
        if re.match(pattern, name):
            return kind
    return "unknown"


def infer_region(environment: str) -> Optional[str]:
    """Infer a cloud region from a regional environment suffix (e.g. prd-ncus)."""
    if not environment:
        return None
    parts = re.split(r"[-_]", environment.strip().lower())
    for part in reversed(parts[1:]):
        if part in _REGION_TOKENS:
            return _REGION_TOKENS[part]
    return None


def _iter_lines_with_markers(text: str, markers: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Match marker regexes line by line so every hit carries a line number."""
    hits: List[Dict[str, Any]] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        for pattern, label in markers:
            if re.search(pattern, line, re.IGNORECASE):
                hits.append({"line": lineno, "label": label, "text": stripped[:240]})
    return hits


def _walk(node: Any, path: str = "") -> List[Tuple[str, Any]]:
    """Flatten a YAML tree into (dotted_path, value) pairs."""
    out: List[Tuple[str, Any]] = [(path, node)]
    if isinstance(node, dict):
        for key, value in node.items():
            out.extend(_walk(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(node, list):
        for idx, value in enumerate(node):
            out.extend(_walk(value, f"{path}[{idx}]"))
    return out


def _as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _stringify(value: Any) -> str:
    """Render a YAML value back to searchable text."""
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    try:
        return yaml.safe_dump(value, default_flow_style=False)
    except Exception:
        return str(value)


def _detect_environment_source(
    env_exprs: List[str], has_env_input: bool
) -> Tuple[str, List[str]]:
    """Decide where the environment name comes from, plus any literal envs.

    Returns:
        (environment_source, literal_environments)
    """
    literals: List[str] = []
    from_deployment = False
    from_input = False
    from_matrix = False

    for expr in env_exprs:
        if not isinstance(expr, str):
            continue
        if _DEPLOYMENT_EVENT_ENV.search(expr):
            from_deployment = True
        if "matrix." in expr:
            from_matrix = True
        if _EXPR_INPUTS.search(expr):
            from_input = True
        if "${{" not in expr:
            literal = expr.strip()
            if literal:
                literals.append(literal)

    if from_deployment:
        source = "deployment_event"
    elif from_matrix:
        source = "matrix"
    elif from_input:
        source = "input"
    elif literals:
        source = "literal"
    elif has_env_input:
        source = "input"
    else:
        source = "unknown"

    return source, sorted(set(literals))


def _infer_kind(workflow_path: str, workflow_name: str, resource_types: Set[str]) -> str:
    haystack = f"{workflow_path} {workflow_name}".lower()
    for pattern, kind in _KIND_PATTERNS:
        if re.search(pattern, haystack):
            return kind
    if resource_types & _MUTATING_RESOURCE_TYPES:
        return "cd"
    return "unknown"


def parse_reusable_workflow(
    yaml_text: str,
    source_repo: str,
    workflow_path: str,
    ref: str,
) -> Dict[str, Any]:
    """Parse a reusable workflow into its deployment contract.

    Args:
        yaml_text: Raw workflow YAML.
        source_repo: owner/repo hosting the workflow.
        workflow_path: Path within that repo.
        ref: Tag or branch consumers pin.

    Returns:
        A dict matching the reusable_workflow_targets column set, plus
        `parse_status`. On unparseable YAML, returns a row with
        parse_status='parse_error' and whatever regex-level markers were found,
        so a broken central workflow is still recorded rather than dropped.
    """
    result: Dict[str, Any] = {
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
        "evidence": {},
        "parse_status": "ok",
    }

    # The workflow's own path and name carry signal the body sometimes omits
    # (e.g. managed-api-cd.yaml never says "apim" in a step), so they are
    # scanned as line 0 - flagged as such in the evidence.
    identity_line = f"{workflow_path} {source_repo}"
    cloud_hits = _iter_lines_with_markers(yaml_text, _CLOUD_MARKERS)
    resource_hits = _iter_lines_with_markers(yaml_text, _RESOURCE_MARKERS)
    for hit in _iter_lines_with_markers(identity_line, _RESOURCE_MARKERS):
        resource_hits.append({**hit, "line": 0, "source": "workflow_path"})
    result["cloud_providers"] = sorted({h["label"] for h in cloud_hits})
    resource_types: Set[str] = {h["label"] for h in resource_types_labels(resource_hits)}
    result["resource_types"] = sorted(resource_types)

    # Regex-level facts are available even if YAML parsing fails.
    result["referenced_vars"] = sorted(set(_EXPR_VARS.findall(yaml_text)))
    result["referenced_secrets"] = sorted(set(_EXPR_SECRETS.findall(yaml_text)))
    result["evidence"] = {
        "cloud_markers": cloud_hits[:60],
        "resource_markers": resource_hits[:60],
    }

    try:
        doc = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        result["parse_status"] = "parse_error"
        result["parse_confidence"] = 0.2
        result["evidence"]["parse_error"] = str(exc)[:500]
        result["is_deploying"] = bool(resource_types & _MUTATING_RESOURCE_TYPES)
        return result

    if not isinstance(doc, dict):
        result["parse_status"] = "parse_error"
        result["parse_confidence"] = 0.2
        result["evidence"]["parse_error"] = "workflow root is not a mapping"
        return result

    result["workflow_name"] = doc.get("name")

    # PyYAML resolves a bare `on:` key to boolean True (YAML 1.1 truthiness).
    triggers = doc.get("on", doc.get(True, {})) or {}
    workflow_call = triggers.get("workflow_call") if isinstance(triggers, dict) else None
    if isinstance(workflow_call, dict):
        inputs = workflow_call.get("inputs") or {}
        if isinstance(inputs, dict):
            result["inputs"] = {
                name: {
                    "type": (spec or {}).get("type") if isinstance(spec, dict) else None,
                    "default": (spec or {}).get("default") if isinstance(spec, dict) else None,
                    "required": bool((spec or {}).get("required")) if isinstance(spec, dict) else False,
                    "description": (spec or {}).get("description") if isinstance(spec, dict) else None,
                }
                for name, spec in inputs.items()
            }
        declared = workflow_call.get("secrets") or {}
        if isinstance(declared, dict):
            result["declared_secrets"] = {
                name: {"required": bool((spec or {}).get("required")) if isinstance(spec, dict) else False}
                for name, spec in declared.items()
            }
        elif declared == "inherit":
            result["secrets_bulk_exposure"].append(
                {"sink": "workflow_call.secrets", "mechanism": "inherit"}
            )

    jobs = doc.get("jobs") or {}
    env_exprs: List[str] = []
    runner_labels: Set[str] = set()
    gate_vars: Set[str] = set()
    actions_used: List[Dict[str, Any]] = []
    nested: List[Dict[str, Any]] = []
    permissions: Dict[str, Any] = {}

    if isinstance(doc.get("permissions"), dict):
        permissions["__workflow__"] = doc["permissions"]

    if isinstance(jobs, dict):
        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue

            # Environment
            environment = job.get("environment")
            if isinstance(environment, dict):
                env_exprs.append(_stringify(environment.get("name")))
            elif environment is not None:
                env_exprs.append(_stringify(environment))

            # Runner labels
            for label in _as_list(job.get("runs-on")):
                text = _stringify(label).strip()
                if not text:
                    continue
                if "${{" in text:
                    # Extract quoted literals out of the ternary expressions this
                    # estate uses, e.g. inputs.runner_label == 'azure-runner' && ...
                    runner_labels.update(re.findall(r"'([^']+)'", text))
                    runner_labels.add("<expression>")
                else:
                    runner_labels.add(text)

            # Job-level `uses:` == nested reusable workflow
            job_uses = job.get("uses")
            if isinstance(job_uses, str):
                nested.append({"job": job_name, "uses": job_uses})
                if job.get("secrets") == "inherit":
                    result["secrets_bulk_exposure"].append(
                        {"sink": job_uses, "mechanism": "secrets: inherit", "job": job_name}
                    )

            # Permissions
            if isinstance(job.get("permissions"), dict):
                permissions[job_name] = job["permissions"]
                if str(job["permissions"].get("id-token", "")).lower() == "write":
                    result["oidc_used"] = True

            # Gate variables referenced in job `if:` conditions
            condition = _stringify(job.get("if"))
            for var in _EXPR_VARS.findall(condition):
                gate_vars.add(var)

            # Steps
            for step in _as_list(job.get("steps")):
                if not isinstance(step, dict):
                    continue
                uses = step.get("uses")
                if isinstance(uses, str):
                    ref_part = uses.split("@", 1)[1] if "@" in uses else ""
                    actions_used.append(
                        {
                            "uses": uses,
                            "job": job_name,
                            "pinned_sha": bool(_SHA_PIN.match(ref_part)),
                            "is_internal": uses.lower().startswith(
                                ("sleepnumberinc/", "sleepnumberlabs/", "./")
                            ),
                        }
                    )
                step_text = _stringify(step)
                if _BULK_SECRETS.search(step_text):
                    result["secrets_bulk_exposure"].append(
                        {
                            "sink": uses or f"{job_name}:{step.get('name') or 'run'}",
                            "mechanism": "toJSON(secrets)",
                            "job": job_name,
                        }
                    )

    # Environment-gate variables also appear at top level (env: / with:) blocks.
    for path, value in _walk(doc):
        if isinstance(value, str) and re.search(r"CD_[A-Z_]*ENVIRONMENTS", value):
            gate_vars.update(re.findall(r"(CD_[A-Z_]*ENVIRONMENTS)", value))
        if path.endswith(".if") and isinstance(value, str):
            gate_vars.update(_EXPR_VARS.findall(value))

    has_env_input = "environment" in (result["inputs"] or {})
    env_source, literal_envs = _detect_environment_source(env_exprs, has_env_input)

    # Only variables that actually gate which environments run belong in
    # environment_gate_vars; other `if:` variables (feature flags such as
    # CREATE_SERVICE_NOW_CR) are kept as evidence instead.
    env_gate_vars = {v for v in gate_vars if "ENVIRONMENT" in v.upper()}

    result["environment_source"] = env_source
    result["literal_environments"] = literal_envs
    result["environment_gate_vars"] = sorted(env_gate_vars)
    result["evidence"]["condition_vars"] = sorted(gate_vars - env_gate_vars)
    result["runner_labels"] = sorted(runner_labels)
    result["actions_used"] = actions_used
    result["nested_workflows"] = nested
    result["permissions"] = permissions
    result["is_deploying"] = bool(resource_types & _MUTATING_RESOURCE_TYPES)
    result["kind"] = _infer_kind(workflow_path, result["workflow_name"] or "", resource_types)
    result["parse_confidence"] = _score_parse(result)
    result["evidence"]["environment_expressions"] = sorted(
        {e for e in env_exprs if e}
    )[:20]
    return result


def resource_types_labels(resource_hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Collapse plan-only markers when a real apply marker is present.

    `terraform plan` and `terraform apply` both appear in these CD workflows;
    only the apply changes cloud state, so terraform_plan is dropped when
    terraform_infra is also present to keep resource_types meaningful.
    """
    labels = {h["label"] for h in resource_hits}
    if "terraform_infra" in labels:
        return [h for h in resource_hits if h["label"] != "terraform_plan"]
    return resource_hits


def _score_parse(parsed: Dict[str, Any]) -> float:
    """Confidence that this parse captured the workflow's deployment contract."""
    score = 0.4
    if parsed["cloud_providers"]:
        score += 0.2
    if parsed["resource_types"]:
        score += 0.2
    if parsed["environment_source"] != "unknown":
        score += 0.1
    if parsed["inputs"]:
        score += 0.1
    return round(min(score, 0.95), 2)
