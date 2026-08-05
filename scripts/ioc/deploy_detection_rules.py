#!/usr/bin/env python3
"""
Deploy Microsoft Defender XDR custom detection rules from a rules-as-code file.

    POST https://graph.microsoft.com/beta/security/rules/detectionRules

Dry run is the default. Nothing reaches Microsoft unless --apply is passed.

Why this is a separate client
-----------------------------
src/api/integrations/msgraph.py is read-only by construction: its _POST_ALLOWLIST
permits exactly one POST (runHuntingQuery) and _request() refuses everything else. That
guard is load-bearing — the whole platform imports that client, and widening it to allow
rule creation would silently grant write capability to every caller. So this script
carries its own narrowly scoped writer and reuses only the pure validation helpers
(lint_kql) from the shared module.

API facts worth not rediscovering
---------------------------------
* beta only. There is no v1.0 /security/rules/detectionRules as of 2026-08-05, and the
  Graph SDKs default to v1.0, so SDK-based examples silently target a path that 404s.
* Global cloud only. Not available in US Gov L4/L5 or 21Vianet.
* `id` is client-provided and required. That makes deployment idempotent: the same rules
  file re-applied updates in place instead of creating duplicates.
* Use `status`, not `isEnabled`. Use `schedule.frequency` (ISO-8601 duration), not
  `schedule.period`. isEnabled, detectorId, lastRunDetails, period and nextRunDateTime
  are all removed 2026-10-01.
* The query must return Timestamp and ReportId, plus every column named by an
  entityMappings entry. A mapping naming an unprojected column fails at create time —
  validated locally here so the failure is a diff, not a 400.

Kill switch
-----------
Automated response (device isolation, file quarantine, forensic collection) is declared
per rule under `killSwitch` and needs TWO independent keys to fire:

    key 1   killSwitch.armed: true in the rules file — a git-reviewable change
    key 2   --arm on this command — deliberate operator intent, typed confirmation

A plain --apply strips automatedActions and says so. Neither key alone does anything.
--disarm --apply is the emergency rollback and needs no confirmation, because it only
ever reduces capability. --kill-switch-status reads the tenant rather than the file,
because a rule armed weeks ago and never re-applied is not actually armed.

Isolation takes the device off the network, including mid-build. That is the trade being
made deliberately: this campaign exfiltrates credentials before doing anything else, so
the window where human triage helps is shorter than the window where it spreads.

Device-group scope
------------------
An unscoped rule applies to every onboarded device, which for us includes the self-hosted
CI runners — an armed rule firing there stops builds org-wide. --scope emits
detectionAction.organizationalScope so arming can be piloted on one device group first.

Scope only ever narrows implicitly. Omitting --scope on a re-apply leaves whatever scope
is already deployed (PATCH does not clear an omitted complex property), so a rule cannot
silently widen back to the whole tenant. Widening is explicit: --scope-all-devices.

Usage:
    python scripts/ioc/deploy_detection_rules.py                       # validate only
    python scripts/ioc/deploy_detection_rules.py --show npm-shaihulud-c2-contact
    python scripts/ioc/deploy_detection_rules.py --list                # existing rules
    python scripts/ioc/deploy_detection_rules.py --apply               # create/update
    python scripts/ioc/deploy_detection_rules.py --apply --status disabled
    python scripts/ioc/deploy_detection_rules.py --apply --arm         # + auto-response
    python scripts/ioc/deploy_detection_rules.py --apply --arm --force # incl. low-confidence
    python scripts/ioc/deploy_detection_rules.py --apply --arm --scope "Dev Workstations"
    python scripts/ioc/deploy_detection_rules.py --apply --scope-all-devices
    python scripts/ioc/deploy_detection_rules.py --kill-switch-status
    python scripts/ioc/deploy_detection_rules.py --disarm --apply      # rollback
    python scripts/ioc/deploy_detection_rules.py --delete npm-shaihulud-bun-from-node

Credentials (app-only). Resolved in this order, first one wins:

    1. AZURE_FEDERATED_TOKEN_FILE          workload identity federation (AKS, Azure
                                           Workload Identity). Re-read on every token
                                           acquisition because the file is rotated.
    2. ACTIONS_ID_TOKEN_REQUEST_URL +      GitHub Actions OIDC. Requires `permissions:
       ACTIONS_ID_TOKEN_REQUEST_TOKEN      id-token: write` on the job.
    3. GRAPH_CLIENT_ASSERTION              a pre-fetched federated JWT (Azure DevOps,
                                           other OIDC providers).
    4. GRAPH_CLIENT_SECRET                 fallback. Warns, because a standing secret that
                                           can arm device isolation is the thing federation
                                           exists to remove.

    GRAPH_TENANT_ID and GRAPH_CLIENT_ID are required in all four cases.

Federated assertions are short-lived, so they are fetched per token request rather than
cached, and never logged — only the credential *kind* is printed and audited.

Exit codes:
    0  success (or dry run with no validation errors)
    1  error
    3  token lacks CustomDetection.ReadWrite.All
    4  local validation failed — nothing was sent
"""

import argparse
import base64
import importlib.util
import json
import os
import re
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_RULES = REPO_ROOT / "github_conf" / "detections" / "npm_supply_chain_rules.json"

GRAPH_BETA = "https://graph.microsoft.com/beta"
LOGIN_BASE = "https://login.microsoftonline.com"
RULES_PATH = "/security/rules/detectionRules"

REQUIRED_ROLE = "CustomDetection.ReadWrite.All"

# Inferred from the deprecated `period` enum (0, 1H, 3H, 12H, 24H), which frequency
# replaced. The frequency property is documented only as "ISO 8601 duration" with no
# enum, so an unlisted value may be accepted — but every value outside this set was
# rejected by the portal equivalent, and a 400 from Graph carries no useful detail.
ALLOWED_FREQUENCIES = {
    "PT0S": "continuous (near real time)",
    "PT1H": "hourly",
    "PT3H": "every 3 hours",
    "PT12H": "every 12 hours",
    "P1D": "daily",
}

ALLOWED_SEVERITIES = {"informational", "low", "medium", "high"}
ALLOWED_STATUSES = {"enabled", "disabled"}

# ---------------------------------------------------------------------------
# Federated credentials
# ---------------------------------------------------------------------------
# The audience Entra expects on a federated credential exchange. Fixed by the platform;
# a different audience is rejected with AADSTS700212 rather than anything descriptive.
FEDERATED_AUDIENCE = "api://AzureADTokenExchange"
CLIENT_ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

# ---------------------------------------------------------------------------
# Device-group scope
# ---------------------------------------------------------------------------
# detectionAction.organizationalScope, verified against the resource doc:
#     {"scopeType": "deviceGroup", "scopeNames": ["Dev Workstations"]}
# scopeType's enum is {deviceGroup, unknownFutureValue}. unknownFutureValue is the OData
# forward-compatibility sentinel — it is a value the service may *return*, never one to
# send, so it is not accepted here.
SCOPE_TYPES = {"deviceGroup"}
DEFAULT_SCOPE_TYPE = "deviceGroup"

# ---------------------------------------------------------------------------
# Kill switch: automated response actions
# ---------------------------------------------------------------------------
# detectionAction.automatedActions (type automatedActionSet) replaces the deprecated
# responseActions collection, which is removed 2026-10-01. Most third-party examples still
# show the old shape — responseActions[] with @odata.type isolateDeviceResponseAction and
# an `identifier` property. That shape will stop working; this one is current.
#
# Only the action types whose column properties are verified against the Microsoft
# reference are listed. automatedActionSet also exposes blockFiles, allowFiles,
# disableUsers, forceUserPasswordResets, markUsersAsCompromised and six email actions —
# their nested property names are NOT verified here, so they are rejected rather than
# guessed. A guessed payload either 400s or, worse, sends a wrong-shaped body that a
# schema change later reinterprets. Verify the resource doc, then add to this table.
AUTOMATED_ACTIONS: Dict[str, Dict[str, Any]] = {
    "isolateDevices": {
        "required": ("deviceIdColumn",),
        "optional": ("isolationType",),
        "disruptive": True,
        "effect": "cuts the device off the network",
    },
    "restrictAppExecutions": {
        "required": ("deviceIdColumn",),
        "optional": (),
        "disruptive": True,
        "effect": "blocks unsigned app execution on the device",
    },
    "stopAndQuarantineFiles": {
        "required": ("deviceIdColumn", "sha1Column"),
        "optional": (),
        "disruptive": True,
        "effect": "kills the process and quarantines the file",
    },
    "collectInvestigationPackages": {
        "required": ("deviceIdColumn",),
        "optional": (),
        "disruptive": False,
        "effect": "collects forensic package",
    },
    "initiateInvestigations": {
        "required": ("deviceIdColumn",),
        "optional": (),
        "disruptive": False,
        "effect": "starts automated investigation",
    },
    "runAntivirusScans": {
        "required": ("deviceIdColumn",),
        "optional": (),
        "disruptive": False,
        "effect": "runs an AV scan",
    },
}

ISOLATION_TYPES = {"full", "selective"}

# Appended on every arm/disarm. A control that can take an engineer offline needs an
# attributable record that does not depend on anyone remembering to write one.
AUDIT_LOG = REPO_ROOT / "exports" / "kill-switch-audit.jsonl"

# Columns a scheduled custom detection must return regardless of table.
REQUIRED_COLUMNS = ("Timestamp", "ReportId")

# Properties Graph accepts on create/update. Anything else in the rules file is local
# annotation (killSwitch, operational_caveats, notes) and must be stripped before the
# POST — Graph rejects unknown properties rather than ignoring them. killSwitch is the
# declaration; only to_wire(arm=True) folds its automatedActions into detectionAction.
WIRE_PROPERTIES = (
    "id", "displayName", "description", "status", "queryCondition", "schedule",
    "detectionAction",
)

ODATA_TYPE = "#microsoft.graph.security.detectionRule"


# =============================================================================
# Reuse the shared KQL linter without importing the read-only client's package
# =============================================================================

def _load_lint_kql():
    """
    Load lint_kql from the platform client by file path.

    Imported by path rather than as src.api.integrations.msgraph because that package's
    __init__ chain pulls in the FastAPI app and the DB session. Only module-level code
    runs here, and msgraph.py's relative imports are all inside function bodies, so
    nothing from the API package is touched.
    """
    path = REPO_ROOT / "src" / "api" / "integrations" / "msgraph.py"
    if not path.exists():
        return None, None
    spec = importlib.util.spec_from_file_location("_msgraph_lint", path)
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # pragma: no cover - degrade to no linting
        print(f"[warn] could not load shared KQL linter ({exc}); skipping lint",
              file=sys.stderr)
        return None, None
    return module.lint_kql, module.KqlLintError


lint_kql, KqlLintError = _load_lint_kql()


# =============================================================================
# Validation — everything checkable without a token
# =============================================================================

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")


def _projected_columns(query: str) -> List[str]:
    """
    Collect column names the query makes available to entity mapping.

    Heuristic on purpose: a full KQL parser is not worth writing here. It gathers names
    from project/project-away/extend/summarize-by clauses and from `X = Y` aliases, which
    is enough to catch the realistic failure — a mapping referencing a column that was
    never projected, or a typo in a column name.
    """
    columns: List[str] = []
    for clause in re.findall(r"\|\s*(?:project|project-rename|extend|summarize)\b([^|]*)",
                             query, re.IGNORECASE):
        for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", clause):
            columns.append(token)
    # `by DeviceName, AccountName` in a summarize is captured by the same sweep.
    return columns


def validate_organizational_scope(scope: Any, where: str) -> List[str]:
    """
    Validate an organizationalScope object. Returns errors only.

    Used for both the per-rule declaration in the file and the --scope arguments, so a
    typo'd device-group name is the one failure this cannot catch: Graph accepts a
    scopeNames entry that matches no group, and the rule then matches nothing. That is
    why --scope prints the names back for the operator to read before confirming.
    """
    errors: List[str] = []
    if scope is None:
        return errors
    if not isinstance(scope, dict):
        errors.append(f"{where} must be an object with scopeType and scopeNames")
        return errors

    unknown = set(scope) - {"scopeType", "scopeNames", "@odata.type"}
    if unknown:
        errors.append(f"{where} has unrecognized propert(ies) {sorted(unknown)}")

    scope_type = scope.get("scopeType")
    if not scope_type:
        errors.append(f"{where}.scopeType is required (only {sorted(SCOPE_TYPES)} accepted)")
    elif scope_type not in SCOPE_TYPES:
        errors.append(
            f"{where}.scopeType {scope_type!r} is not accepted. Only "
            f"{sorted(SCOPE_TYPES)} may be sent — `unknownFutureValue` is the OData "
            f"forward-compatibility sentinel, valid in a response, never in a request"
        )

    names = scope.get("scopeNames")
    if not isinstance(names, list) or not names:
        errors.append(f"{where}.scopeNames must be a non-empty list of device group names. "
                      f"To scope to all devices, omit organizationalScope entirely rather "
                      f"than passing an empty list")
    else:
        for index, name in enumerate(names):
            if not isinstance(name, str) or not name.strip():
                errors.append(f"{where}.scopeNames[{index}] must be a non-empty string")
    return errors


def validate_kill_switch(rule: Dict[str, Any], available: set) -> Tuple[List[str], List[str]]:
    """
    Validate a rule's killSwitch declaration against the verified action schema.

    `available` is the set of columns the query returns. Every action names a column, and
    a column that is not projected means the action silently has no target — the rule
    deploys, fires, and does nothing. That failure is invisible in the portal, which is
    why it is an error here rather than a warning.
    """
    errors: List[str] = []
    warnings: List[str] = []

    kill_switch = rule.get("killSwitch")
    if not kill_switch:
        return errors, warnings

    if not isinstance(kill_switch.get("armed"), bool):
        errors.append("killSwitch.armed must be an explicit true or false — an absent "
                      "value is not a safe default in either direction")
    if not kill_switch.get("justification"):
        errors.append("killSwitch.justification is required: an automated action that can "
                      "take an engineer offline needs a stated reason in the file")

    actions = kill_switch.get("automatedActions") or {}
    if not actions:
        errors.append("killSwitch declares no automatedActions")
        return errors, warnings

    for name, entries in actions.items():
        spec = AUTOMATED_ACTIONS.get(name)
        if not spec:
            errors.append(
                f"killSwitch.automatedActions.{name} is not in this deployer's verified "
                f"action set {sorted(AUTOMATED_ACTIONS)}. It may well exist in "
                f"automatedActionSet, but its column property names are unverified here — "
                f"check the resource doc and add it to AUTOMATED_ACTIONS rather than "
                f"guessing the payload shape"
            )
            continue
        if not isinstance(entries, list) or not entries:
            errors.append(f"killSwitch.automatedActions.{name} must be a non-empty list")
            continue

        for index, entry in enumerate(entries):
            where = f"killSwitch.automatedActions.{name}[{index}]"
            for prop in spec["required"]:
                column = (entry or {}).get(prop)
                if not column:
                    errors.append(f"{where} is missing required property `{prop}`")
                elif column not in available:
                    errors.append(
                        f"{where}.{prop} = {column!r} is not returned by the query, so the "
                        f"action would have no target to act on"
                    )
            unknown = set((entry or {})) - set(spec["required"]) - set(spec["optional"])
            if unknown:
                errors.append(f"{where} has unrecognized propert(ies) {sorted(unknown)}")
            if name == "isolateDevices":
                isolation = (entry or {}).get("isolationType")
                if isolation and isolation not in ISOLATION_TYPES:
                    errors.append(f"{where}.isolationType must be one of "
                                  f"{sorted(ISOLATION_TYPES)}, got {isolation!r}")
                if not isolation:
                    warnings.append(f"{where} has no isolationType; the service default "
                                    f"applies — state it explicitly")

    # A disruptive action on a rule that is not high severity is the false-positive
    # scenario that makes teams disable automated response entirely.
    severity = (((rule.get("detectionAction") or {}).get("alertTemplate") or {})
                .get("severity"))
    disruptive = [n for n in actions if AUTOMATED_ACTIONS.get(n, {}).get("disruptive")]
    if disruptive and severity != "high" and kill_switch.get("armed"):
        errors.append(
            f"killSwitch is armed with disruptive action(s) {disruptive} on a "
            f"{severity!r}-severity rule. Set killSwitch.requiresForce and arm it "
            f"explicitly with --arm --force, or raise the severity if it warrants it"
        )

    if kill_switch.get("armed") and kill_switch.get("requiresForce"):
        warnings.append("killSwitch is both armed and marked requiresForce; --arm alone "
                        "will skip it, --arm --force applies it")

    return errors, warnings


def validate_rule(rule: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    """Return (errors, warnings) for one rule. Errors block deployment."""
    errors: List[str] = []
    warnings: List[str] = []

    rule_id = rule.get("id")
    if not rule_id:
        errors.append("missing required property `id` (client-provided, required on create)")
    elif not _ID_RE.match(str(rule_id)):
        errors.append(f"id {rule_id!r} should be a lowercase kebab-case slug of 3-63 chars")

    if not rule.get("displayName"):
        errors.append("missing required property `displayName`")

    status = rule.get("status")
    if status not in ALLOWED_STATUSES:
        errors.append(f"status must be one of {sorted(ALLOWED_STATUSES)}, got {status!r}")
    if "isEnabled" in rule:
        errors.append("`isEnabled` is deprecated and removed 2026-10-01 — use `status`")

    schedule = rule.get("schedule") or {}
    if "period" in schedule:
        errors.append("`schedule.period` is deprecated and removed 2026-10-01 — use "
                      "`schedule.frequency` with an ISO-8601 duration")
    frequency = schedule.get("frequency")
    if not frequency:
        errors.append("missing required property `schedule.frequency`")
    elif frequency not in ALLOWED_FREQUENCIES:
        errors.append(f"schedule.frequency {frequency!r} is outside the accepted set "
                      f"{sorted(ALLOWED_FREQUENCIES)}")

    query = ((rule.get("queryCondition") or {}).get("queryText") or "").strip()
    if not query:
        errors.append("missing required property `queryCondition.queryText`")
        return errors, warnings

    # Required output columns.
    for column in REQUIRED_COLUMNS:
        if not re.search(rf"\b{column}\b", query):
            errors.append(f"query does not return `{column}`, which every scheduled "
                          f"custom detection must project")

    # Lookback should match the run frequency: a wider window re-alerts on the same
    # event each run, a narrower one drops events between runs.
    lookback = re.search(r"ago\s*\(\s*(\d+)\s*([smhd])\s*\)", query, re.IGNORECASE)
    if not lookback:
        warnings.append("query has no ago() lookback; the rule will scan the default "
                        "window and may re-alert on the same events")
    elif frequency in ("PT1H", "PT0S"):
        amount, unit = int(lookback.group(1)), lookback.group(2).lower()
        if not (unit == "h" and amount == 1) and not (unit == "m" and amount <= 60):
            warnings.append(f"frequency {frequency} but lookback is ago({amount}{unit}) — "
                            f"mismatched windows cause duplicate or missed alerts")

    # Entity mappings must reference columns the query actually returns.
    template = ((rule.get("detectionAction") or {}).get("alertTemplate") or {})
    severity = template.get("severity")
    if severity and severity not in ALLOWED_SEVERITIES:
        errors.append(f"alertTemplate.severity {severity!r} not in {sorted(ALLOWED_SEVERITIES)}")
    if not template.get("title"):
        warnings.append("alertTemplate has no title; the alert inherits the rule name")

    available = set(_projected_columns(query))
    for group, entries in (template.get("entityMappings") or {}).items():
        for index, mapping in enumerate(entries or []):
            for key, column in (mapping or {}).items():
                if not key.endswith("Column") or not isinstance(column, str):
                    continue
                if column not in available:
                    errors.append(
                        f"entityMappings.{group}[{index}].{key} = {column!r} is not "
                        f"returned by the query — Graph rejects the rule at create time"
                    )

    if not template.get("entityMappings"):
        warnings.append("no entityMappings: the alert will not link to a device or "
                        "account, so it cannot be triaged from the incident graph")

    if (rule.get("detectionAction") or {}).get("automatedActions"):
        errors.append("automatedActions must not be inlined in detectionAction — declare "
                      "them under the rule's `killSwitch` so arming requires both a "
                      "reviewed file change and --arm at deploy time")

    if "organizationalScope" in (rule.get("detectionAction") or {}):
        errors.extend(validate_organizational_scope(
            rule["detectionAction"]["organizationalScope"],
            "detectionAction.organizationalScope"))

    ks_errors, ks_warnings = validate_kill_switch(rule, available)
    errors.extend(ks_errors)
    warnings.extend(ks_warnings)

    # Shared linter: traps that produce plausible-but-wrong results.
    if lint_kql:
        try:
            for message in lint_kql(query, strict=True):
                warnings.append(f"kql: {message}")
        except KqlLintError as exc:
            errors.append(f"kql lint: {exc}")

    return errors, warnings


def kill_switch_applies(rule: Dict[str, Any], arm: bool, force: bool) -> bool:
    """
    Both keys, or nothing.

    Key 1 is killSwitch.armed in the rules file — a reviewed, attributable change.
    Key 2 is --arm on the command line — deliberate operator intent at deploy time.
    requiresForce adds a third for rules whose confidence does not justify disruption
    unattended.
    """
    kill_switch = rule.get("killSwitch") or {}
    if not arm or not kill_switch.get("armed") or not kill_switch.get("automatedActions"):
        return False
    if kill_switch.get("requiresForce") and not force:
        return False
    return True


def scope_object(names: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    """Build an organizationalScope from device group names, or None for no restriction."""
    if not names:
        return None
    return {"scopeType": DEFAULT_SCOPE_TYPE, "scopeNames": list(names)}


def effective_scope(rule: Dict[str, Any],
                    cli_scope: Optional[List[str]]) -> Optional[Dict[str, Any]]:
    """
    Resolve which scope a rule deploys with. --scope beats the file.

    Returns None when neither supplies one, which means "leave the deployed scope alone"
    rather than "all devices" — see to_wire.
    """
    if cli_scope:
        return scope_object(cli_scope)
    return (rule.get("detectionAction") or {}).get("organizationalScope") or None


def to_wire(rule: Dict[str, Any], status_override: Optional[str] = None,
            arm: bool = False, force: bool = False,
            disarm: bool = False, scope: Optional[List[str]] = None,
            scope_all: bool = False) -> Dict[str, Any]:
    """
    Strip local annotations, add the OData type discriminator, and fold in automated
    actions only when both arming keys are present.

    disarm=True sends automatedActions: null explicitly. PATCH semantics on a complex
    property are not documented clearly enough to assume that omitting it clears it, and
    a disarm that silently leaves isolation live is the worst possible outcome here — so
    state the clear, then verify with --kill-switch-status.

    Scope follows the same reasoning in the opposite direction. Because an omitted complex
    property is left untouched by PATCH, omitting organizationalScope is the *safe* default:
    a re-apply cannot silently widen a rule that was piloted on one device group back to
    the whole tenant. Widening is therefore explicit — scope_all=True sends null.
    """
    payload = {"@odata.type": ODATA_TYPE}
    for key in WIRE_PROPERTIES:
        if key in rule:
            payload[key] = rule[key]
    if status_override:
        payload["status"] = status_override

    action = json.loads(json.dumps(payload.get("detectionAction") or {}))
    action.pop("automatedActions", None)
    if disarm:
        action["automatedActions"] = None
    elif kill_switch_applies(rule, arm, force):
        action["automatedActions"] = json.loads(
            json.dumps(rule["killSwitch"]["automatedActions"]))

    action.pop("organizationalScope", None)
    if scope_all:
        action["organizationalScope"] = None
    else:
        resolved = effective_scope(rule, scope)
        if resolved:
            action["organizationalScope"] = json.loads(json.dumps(resolved))

    if action:
        payload["detectionAction"] = action
    return payload


def kill_switch_plan(rules: List[dict], arm: bool, force: bool,
                     scope: Optional[List[str]] = None,
                     scope_all: bool = False) -> List[dict]:
    """Rows describing exactly what arming would do, for the confirmation prompt."""
    plan: List[dict] = []
    for rule in rules:
        kill_switch = rule.get("killSwitch") or {}
        if not kill_switch.get("automatedActions"):
            continue
        applying = kill_switch_applies(rule, arm, force)
        effects: List[str] = []
        for name, entries in kill_switch["automatedActions"].items():
            spec = AUTOMATED_ACTIONS.get(name, {})
            detail = spec.get("effect", name)
            if name == "isolateDevices":
                types = {e.get("isolationType", "default") for e in entries}
                detail = f"{detail} ({'/'.join(sorted(types))})"
            effects.append(detail)
        resolved = None if scope_all else effective_scope(rule, scope)
        plan.append({
            "id": rule.get("id"),
            "tier": kill_switch.get("tier", "—"),
            "armed_in_file": bool(kill_switch.get("armed")),
            "requires_force": bool(kill_switch.get("requiresForce")),
            "applying": applying,
            "effects": effects,
            "disruptive": any(AUTOMATED_ACTIONS.get(n, {}).get("disruptive")
                              for n in kill_switch["automatedActions"]),
            # None means no scope is being sent. On a create that is tenant-wide; on a
            # re-apply it means whatever scope is already deployed survives untouched.
            "scope_names": (resolved or {}).get("scopeNames"),
            "scope_widened": bool(scope_all),
        })
    return plan


def audit(event: str, detail: Dict[str, Any]) -> None:
    """Append an attributable record. Never blocks the operation it is recording."""
    record = {
        "at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "event": event,
        "actor": os.environ.get("USER") or os.environ.get("USERNAME") or "unknown",
        **detail,
    }
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        with open(AUDIT_LOG, "a") as handle:
            handle.write(json.dumps(record) + "\n")
    except OSError as exc:
        print(f"[warn] could not write audit record to {AUDIT_LOG}: {exc}", file=sys.stderr)


# =============================================================================
# Credential resolution — federation first, secret last
# =============================================================================

class CredentialError(SystemExit):
    """Raised for credential problems. Never carries the credential itself."""


def _github_oidc_assertion(timeout: int = 30) -> str:
    """
    Exchange the GitHub Actions OIDC request token for an ID token Entra will accept.

    Two things are easy to get wrong and produce unhelpful errors:
      * the audience must be api://AzureADTokenExchange, matching the federated credential
        on the app registration — a mismatch yields AADSTS700212 with no useful detail;
      * the job needs `permissions: id-token: write`. Without it the request URL is not
        even present in the environment, which is why that is checked before the call.
    """
    url = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "").strip()
    request_token = os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "").strip()
    if not (url and request_token):
        raise CredentialError(
            "GitHub Actions OIDC is only half configured. Both "
            "ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are set by "
            "the runner when the job declares `permissions: id-token: write`."
        )
    resp = requests.get(
        url,
        params={"audience": FEDERATED_AUDIENCE},
        headers={"Authorization": f"Bearer {request_token}"},
        timeout=timeout,
    )
    if resp.status_code != 200:
        # The response body can echo the request token; report the status only.
        raise CredentialError(
            f"GitHub OIDC token request failed: HTTP {resp.status_code}. "
            f"Confirm the job has `permissions: id-token: write`."
        )
    assertion = (resp.json() or {}).get("value")
    if not assertion:
        raise CredentialError("GitHub OIDC response contained no token value.")
    return assertion


def _federated_token_file_assertion() -> str:
    """
    Read the projected service-account token (Azure Workload Identity / AKS).

    Read on every call rather than cached: the token file is rotated by the kubelet well
    inside its own lifetime, and a cached copy outlives its validity.
    """
    path = Path(os.environ["AZURE_FEDERATED_TOKEN_FILE"])
    try:
        assertion = path.read_text().strip()
    except OSError as exc:
        raise CredentialError(f"Could not read AZURE_FEDERATED_TOKEN_FILE at {path}: {exc}")
    if not assertion:
        raise CredentialError(f"AZURE_FEDERATED_TOKEN_FILE at {path} is empty.")
    return assertion


def resolve_credential() -> Tuple[str, Optional[Any], Optional[str]]:
    """
    Pick a credential from the environment.

    Returns (kind, assertion_provider, client_secret). Exactly one of the last two is set.
    The provider is a callable, not a value, because a federated assertion is short-lived
    and must be re-fetched per token request.

    Order is deliberate: every federated source ranks above the secret, because a standing
    secret that can arm device isolation is precisely what federation removes. The secret
    path still works — an environment with no OIDC provider is a real constraint, not a
    reason to have no deployment path at all.
    """
    if os.environ.get("AZURE_FEDERATED_TOKEN_FILE", "").strip():
        return "workload-identity-federation", _federated_token_file_assertion, None
    if os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", "").strip():
        return "github-actions-oidc", _github_oidc_assertion, None
    assertion = os.environ.get("GRAPH_CLIENT_ASSERTION", "").strip()
    if assertion:
        # Pre-fetched, so it may already be near expiry. Nothing here can refresh it.
        return "client-assertion", (lambda: assertion), None
    secret = os.environ.get("GRAPH_CLIENT_SECRET", "").strip()
    if secret:
        return "client-secret", None, secret
    raise CredentialError(
        "No credential found. Set one of:\n"
        "  AZURE_FEDERATED_TOKEN_FILE                      (workload identity federation)\n"
        "  ACTIONS_ID_TOKEN_REQUEST_URL/..._TOKEN          (GitHub Actions OIDC)\n"
        "  GRAPH_CLIENT_ASSERTION                          (pre-fetched federated JWT)\n"
        "  GRAPH_CLIENT_SECRET                             (fallback, not recommended)\n"
        "GRAPH_TENANT_ID and GRAPH_CLIENT_ID are required in all cases."
    )


# =============================================================================
# Write-scoped Graph client
# =============================================================================

class DetectionRuleClient:
    """
    App-only Graph client permitted to touch exactly one resource path.

    The allowlist is checked on every request rather than trusted from call sites, for
    the same reason the read-only client does it: a future caller passing a different
    path should fail closed.
    """

    _PATH_ALLOWLIST = (RULES_PATH,)

    def __init__(self, tenant_id: str, client_id: str,
                 client_secret: Optional[str] = None,
                 assertion_provider: Optional[Any] = None,
                 credential_kind: str = "client-secret",
                 timeout: int = 60):
        if not (tenant_id and client_id):
            raise CredentialError(
                "Missing GRAPH_TENANT_ID and/or GRAPH_CLIENT_ID."
            )
        if not (client_secret or assertion_provider):
            raise CredentialError(
                "No client secret and no federated assertion provider — see "
                "resolve_credential()."
            )
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.credential_kind = credential_kind
        self._client_secret = client_secret
        self._assertion_provider = assertion_provider
        self.timeout = timeout
        self._token: Optional[str] = None
        self._expires_at = 0.0
        self._roles: List[str] = []

    def _credential_form(self) -> Dict[str, str]:
        """
        The credential half of the token request body.

        Federated assertions are fetched here, per request, rather than at construction:
        they are minutes-lived, and this process can outlive one during a staged apply.
        """
        if self._assertion_provider is not None:
            return {
                "client_assertion_type": CLIENT_ASSERTION_TYPE,
                "client_assertion": self._assertion_provider(),
            }
        return {"client_secret": self._client_secret}

    def _acquire_token(self) -> str:
        now = time.time()
        if self._token and now < self._expires_at - 60:
            return self._token
        resp = requests.post(
            f"{LOGIN_BASE}/{self.tenant_id}/oauth2/v2.0/token",
            data={
                "client_id": self.client_id,
                "scope": "https://graph.microsoft.com/.default",
                "grant_type": "client_credentials",
                **self._credential_form(),
            },
            timeout=self.timeout,
        )
        if resp.status_code != 200:
            # Report the AAD error code only. Never echo the request body.
            try:
                body = resp.json()
                detail = f"{body.get('error')}: {str(body.get('error_description'))[:200]}"
            except Exception:
                detail = f"HTTP {resp.status_code}"
            hint = ""
            if self._assertion_provider is not None:
                # AADSTS70021 / 700213: the assertion's subject does not match any
                # federated credential on the app. Almost always the environment or ref
                # in the subject, not the audience.
                hint = ("\nFederated credential in use. Check that the app's federated "
                        "credential subject matches this workload exactly (repo, "
                        "environment/branch) and that its audience is "
                        f"{FEDERATED_AUDIENCE}.")
            raise SystemExit(
                f"Token acquisition failed for app {self.client_id[:8]}… "
                f"via {self.credential_kind}: {detail}{hint}")
        payload = resp.json()
        self._token = payload["access_token"]
        self._expires_at = now + int(payload.get("expires_in", 3600))
        self._roles = _decode_roles(self._token)
        return self._token

    def roles(self) -> List[str]:
        self._acquire_token()
        return list(self._roles)

    def require_write_role(self) -> None:
        """
        Fail loudly when the role is absent.

        Without this the first POST returns 403 and, on a partial run, some rules would
        already exist while later ones do not. Checking the token up front keeps
        deployment all-or-nothing.
        """
        have = self.roles()
        if REQUIRED_ROLE not in have:
            print(
                f"\nToken for app {self.client_id[:8]}… does not carry {REQUIRED_ROLE}.\n"
                f"Roles present: {', '.join(have) or '(none)'}\n\n"
                "Grant it as an application permission on the app registration, with\n"
                "admin consent, then re-run. Nothing was sent.",
                file=sys.stderr,
            )
            raise SystemExit(3)

    def _request(self, method: str, path: str, body: Optional[dict] = None) -> requests.Response:
        if not any(path == allowed or path.startswith(allowed + "/")
                   for allowed in self._PATH_ALLOWLIST):
            raise SystemExit(f"{method} {path} is not on this client's allowlist "
                             f"{list(self._PATH_ALLOWLIST)}")
        resp = requests.request(
            method,
            f"{GRAPH_BETA}{path}",
            headers={
                "Authorization": f"Bearer {self._acquire_token()}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            data=json.dumps(body) if body is not None else None,
            timeout=self.timeout,
        )
        return resp

    def list_rules(self) -> List[dict]:
        resp = self._request("GET", RULES_PATH)
        if resp.status_code != 200:
            raise SystemExit(f"GET {RULES_PATH} -> {resp.status_code}: {resp.text[:400]}")
        return resp.json().get("value", [])

    def get_rule(self, rule_id: str) -> Optional[dict]:
        resp = self._request("GET", f"{RULES_PATH}/{rule_id}")
        if resp.status_code == 200:
            return resp.json()
        if resp.status_code == 404:
            return None
        raise SystemExit(f"GET {RULES_PATH}/{rule_id} -> {resp.status_code}: {resp.text[:400]}")

    def upsert(self, payload: dict) -> Tuple[str, dict]:
        """Create, or PATCH when a rule with this client-provided id already exists."""
        rule_id = payload["id"]
        if self.get_rule(rule_id) is not None:
            body = {k: v for k, v in payload.items() if k != "id"}
            resp = self._request("PATCH", f"{RULES_PATH}/{rule_id}", body)
            action = "updated"
        else:
            resp = self._request("POST", RULES_PATH, payload)
            action = "created"
        if resp.status_code not in (200, 201, 204):
            raise SystemExit(f"{action} {rule_id} failed -> {resp.status_code}: "
                             f"{resp.text[:600]}")
        try:
            return action, resp.json()
        except Exception:
            return action, {}

    def delete(self, rule_id: str) -> None:
        resp = self._request("DELETE", f"{RULES_PATH}/{rule_id}")
        if resp.status_code not in (200, 204, 404):
            raise SystemExit(f"DELETE {rule_id} -> {resp.status_code}: {resp.text[:400]}")


def _decode_roles(access_token: str) -> List[str]:
    """Read the roles claim without validating the signature — informational only."""
    try:
        segment = access_token.split(".")[1]
        segment += "=" * (-len(segment) % 4)
        claims = json.loads(base64.urlsafe_b64decode(segment))
        return list(claims.get("roles") or [])
    except Exception:
        return []


# =============================================================================
# CLI
# =============================================================================

def _client_from_env(quiet: bool = False) -> DetectionRuleClient:
    kind, provider, secret = resolve_credential()
    if kind == "client-secret" and not quiet:
        print(
            "[warn] authenticating with a client secret. A standing secret that can arm "
            "device isolation is what workload identity federation exists to remove — "
            "prefer AZURE_FEDERATED_TOKEN_FILE or GitHub Actions OIDC.",
            file=sys.stderr,
        )
    return DetectionRuleClient(
        tenant_id=os.environ.get("GRAPH_TENANT_ID", "").strip(),
        client_id=os.environ.get("GRAPH_CLIENT_ID", "").strip(),
        client_secret=secret,
        assertion_provider=provider,
        credential_kind=kind,
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--rules", type=Path, default=DEFAULT_RULES,
                        help="rules-as-code JSON (default: "
                             "github_conf/detections/npm_supply_chain_rules.json)")
    parser.add_argument("--apply", action="store_true",
                        help="actually create/update the rules in the tenant "
                             "(default is validate-only)")
    parser.add_argument("--only", action="append", default=None, metavar="RULE_ID",
                        help="restrict to this rule id; repeatable")
    parser.add_argument("--status", choices=sorted(ALLOWED_STATUSES), default=None,
                        help="override status for every rule — use `disabled` to stage "
                             "rules and enable them from the portal after review")
    parser.add_argument("--show", metavar="RULE_ID", default=None,
                        help="print the exact JSON payload for one rule and exit")
    parser.add_argument("--list", action="store_true",
                        help="list custom detection rules already in the tenant")
    parser.add_argument("--delete", metavar="RULE_ID", default=None,
                        help="delete one rule by id (requires --apply)")

    scope_group = parser.add_argument_group(
        "device-group scope",
        "An unscoped rule applies to every onboarded device, self-hosted CI runners "
        "included. Scope narrows it.")
    scope_group.add_argument("--scope", action="append", default=None,
                             metavar="DEVICE_GROUP",
                             help="restrict every rule to this Defender device group; "
                                  "repeatable. Overrides any scope in the rules file.")
    scope_group.add_argument("--scope-all-devices", action="store_true",
                             help="explicitly clear the deployed scope so rules apply "
                                  "tenant-wide. Required to widen, because omitting "
                                  "--scope leaves an existing scope untouched.")

    kill = parser.add_argument_group(
        "kill switch",
        "Automated response. Requires BOTH killSwitch.armed in the rules file and --arm "
        "here. Isolation takes the device off the network — including mid-build.")
    kill.add_argument("--arm", action="store_true",
                     help="apply each rule's killSwitch.automatedActions (second key)")
    kill.add_argument("--force", action="store_true",
                     help="also arm rules marked killSwitch.requiresForce — the "
                          "lower-confidence ones most likely to hit a false positive")
    kill.add_argument("--disarm", action="store_true",
                     help="strip automatedActions from the deployed rules. Emergency "
                          "rollback; needs no confirmation because it only reduces "
                          "capability. Combine with --apply.")
    kill.add_argument("--kill-switch-status", action="store_true",
                     help="read the TENANT (not this file) and report which deployed "
                          "rules currently carry automated actions")
    kill.add_argument("--yes", action="store_true",
                     help="skip the typed arming confirmation (for automation only)")
    args = parser.parse_args()

    if args.arm and args.disarm:
        print("--arm and --disarm are mutually exclusive.", file=sys.stderr)
        return 1
    if args.force and not args.arm:
        print("--force only means anything with --arm.", file=sys.stderr)
        return 1
    if args.scope and args.scope_all_devices:
        print("--scope and --scope-all-devices are mutually exclusive: one narrows, the "
              "other clears.", file=sys.stderr)
        return 1
    if args.scope:
        scope_errors = validate_organizational_scope(scope_object(args.scope), "--scope")
        if scope_errors:
            for message in scope_errors:
                print(f"ERROR: {message}", file=sys.stderr)
            return 1

    if not args.rules.exists():
        print(f"Rules file not found: {args.rules}", file=sys.stderr)
        return 1

    document = json.loads(args.rules.read_text())
    rules: List[dict] = document.get("rules") or []
    if args.only:
        wanted = set(args.only)
        rules = [r for r in rules if r.get("id") in wanted]
        missing = wanted - {r.get("id") for r in rules}
        if missing:
            print(f"No such rule id(s) in {args.rules.name}: {sorted(missing)}",
                  file=sys.stderr)
            return 1

    # --show: print the wire payload, send nothing.
    if args.show:
        match = next((r for r in document.get("rules", []) if r.get("id") == args.show), None)
        if not match:
            print(f"No such rule id: {args.show}", file=sys.stderr)
            return 1
        print(json.dumps(to_wire(match, args.status, arm=args.arm, force=args.force,
                                 disarm=args.disarm, scope=args.scope,
                                 scope_all=args.scope_all_devices), indent=2))
        return 0

    # --kill-switch-status: the tenant is the only authority on what is live. The rules
    # file records intent; a rule armed six weeks ago and never re-applied is not armed.
    if args.kill_switch_status:
        client = _client_from_env()
        deployed = client.list_rules()
        if not deployed:
            print("No custom detection rules in this tenant — nothing armed.")
            return 0
        live = 0
        print(f"Kill-switch status in tenant {client.tenant_id}:\n")
        for rule in deployed:
            actions = ((rule.get("detectionAction") or {}).get("automatedActions")) or {}
            names = [name for name, value in actions.items() if value]
            marker = "ARMED" if names else "  -  "
            if names:
                live += 1
            print(f"  [{marker}] {rule.get('id')}  (status={rule.get('status')})")
            for name in names:
                spec = AUTOMATED_ACTIONS.get(name, {})
                print(f"            {name}: {spec.get('effect', 'unverified action type')}")
            if names:
                # Blast radius is action x scope. Reporting one without the other reads as
                # narrower than it is.
                live_scope = ((rule.get("detectionAction") or {})
                              .get("organizationalScope")) or {}
                groups = live_scope.get("scopeNames")
                where = (", ".join(groups) if groups
                         else "ALL DEVICES (tenant-wide, CI runners included)")
                print(f"            scope: {where}")
        print(f"\n{live} of {len(deployed)} deployed rule(s) carry automated actions.")
        if live:
            print("Disarm all: deploy_detection_rules.py --disarm --apply")
        return 0

    # --list / --delete talk to the tenant and do not need the local rules file.
    if args.list:
        client = _client_from_env()
        existing = client.list_rules()
        if not existing:
            print("No custom detection rules in this tenant.")
            return 0
        print(f"{len(existing)} custom detection rule(s):\n")
        for rule in existing:
            schedule = (rule.get("schedule") or {}).get("frequency") or \
                       (rule.get("schedule") or {}).get("period") or "?"
            live_scope = ((rule.get("detectionAction") or {})
                          .get("organizationalScope")) or {}
            groups = live_scope.get("scopeNames")
            print(f"  {rule.get('id')}")
            print(f"      {rule.get('displayName')}")
            print(f"      status={rule.get('status')}  frequency={schedule}  "
                  f"modified={rule.get('lastModifiedDateTime')}")
            print(f"      scope={', '.join(groups) if groups else 'all devices'}")
        return 0

    if args.delete:
        if not args.apply:
            print(f"Would DELETE rule {args.delete!r}. Re-run with --apply to do it.")
            return 0
        client = _client_from_env()
        client.require_write_role()
        client.delete(args.delete)
        print(f"deleted {args.delete}")
        return 0

    if not rules:
        print(f"No rules found in {args.rules}", file=sys.stderr)
        return 1

    # ---- validate everything before touching the network -------------------
    # relative_to() raises for a path outside the repo, so fall back to the full path.
    try:
        shown_path = args.rules.resolve().relative_to(REPO_ROOT)
    except ValueError:
        shown_path = args.rules
    print(f"Validating {len(rules)} rule(s) from {shown_path}\n")
    total_errors = 0
    for rule in rules:
        errors, warnings = validate_rule(rule)
        total_errors += len(errors)
        mark = "FAIL" if errors else ("warn" if warnings else "ok")
        frequency = (rule.get("schedule") or {}).get("frequency")
        print(f"  [{mark:4}] {rule.get('id')}  "
              f"({rule.get('status')}, {frequency} — "
              f"{ALLOWED_FREQUENCIES.get(frequency, 'unknown cadence')})")
        for message in errors:
            print(f"         ERROR: {message}")
        for message in warnings:
            print(f"         warn:  {message}")

    if total_errors:
        print(f"\n{total_errors} validation error(s). Nothing sent.", file=sys.stderr)
        return 4

    # ---- scope ---------------------------------------------------------------
    if args.scope:
        print(f"\nScope: every rule restricted to device group(s) "
              f"{', '.join(args.scope)}.")
        print("  Read those names back carefully. Graph accepts a group name that matches "
              "nothing,\n  and the rule then matches nothing — a scoped rule with a typo "
              "is indistinguishable\n  from a clean estate.")
    elif args.scope_all_devices:
        print("\nScope: --scope-all-devices — organizationalScope will be CLEARED. "
              "Rules apply\n  tenant-wide, including the self-hosted CI runners.")
    else:
        declared = [r.get("id") for r in rules
                    if (r.get("detectionAction") or {}).get("organizationalScope")]
        if declared:
            print(f"\nScope: from the rules file for {len(declared)} rule(s): "
                  f"{', '.join(declared)}")
        else:
            print("\nScope: none specified. New rules apply tenant-wide; already-deployed "
                  "rules keep\n  whatever scope they have (PATCH leaves an omitted "
                  "property alone). Narrow with --scope.")

    # ---- kill-switch plan --------------------------------------------------
    plan = kill_switch_plan(rules, args.arm, args.force, args.scope,
                            args.scope_all_devices)
    if plan:
        if args.disarm:
            print("\nKILL SWITCH: --disarm — automated actions will be stripped from "
                  "every rule below.")
        else:
            print(f"\nKill switch ({'ARMING' if args.arm else 'declared, not arming'}):")
        for row in plan:
            if args.disarm:
                state = "strip"
            elif row["applying"]:
                state = "APPLY"
            elif not row["armed_in_file"]:
                state = "skip: armed=false in file"
            elif row["requires_force"]:
                state = "skip: requiresForce, pass --force"
            else:
                state = "skip: no --arm"
            where = (", ".join(row["scope_names"]) if row["scope_names"]
                     else "all devices" if row["scope_widened"] else "unscoped")
            print(f"  [{state}] {row['id']}  tier={row['tier']}  scope={where}")
            for effect in row["effects"]:
                print(f"           - {effect}")

    applying = [row for row in plan if row["applying"]] if not args.disarm else []

    if not args.apply:
        print(f"\nDry run — {len(rules)} rule(s) validated, nothing sent.")
        if applying:
            print(f"With --apply this WOULD arm {len(applying)} rule(s) for automated "
                  f"response, including "
                  f"{sum(1 for r in applying if r['disruptive'])} disruptive.")
        print("Re-run with --apply to deploy. Add --status disabled to stage them "
              "without alerting.")
        print(f"Inspect a payload with: --show {rules[0].get('id')}")
        return 0

    # ---- arming confirmation ------------------------------------------------
    # Deliberately not caveman, and deliberately typed rather than y/N: this is the step
    # that can take a working engineer off the network without a human in the loop.
    disruptive_rules = [row for row in applying if row["disruptive"]]
    if disruptive_rules and not args.yes:
        print("\n" + "=" * 72)
        print("You are about to enable AUTOMATED DEVICE ISOLATION.")
        print("=" * 72)
        print(f"\n{len(disruptive_rules)} rule(s) will act on devices with no human "
              f"review, every hour:\n")
        for row in disruptive_rules:
            print(f"  {row['id']} ({row['tier']})")
            for effect in row["effects"]:
                print(f"      {effect}")

        # Scope is half the blast radius. An unscoped armed rule reaches the self-hosted
        # CI runners, and isolating one of those stops builds for everybody.
        unscoped = [row for row in disruptive_rules if not row["scope_names"]]
        if unscoped:
            print(f"\n  !! {len(unscoped)} of these carr{'ies' if len(unscoped) == 1 else 'y'}"
                  f" NO device-group scope.")
            print("     On first deployment that is every onboarded device, including "
                  "self-hosted")
            print("     CI runners — which run package installs constantly and are exactly "
                  "what")
            print("     this worm targets. Isolating one stops builds org-wide.")
            print("     To pilot instead:  --arm --scope \"<device group>\"")
        else:
            groups = sorted({name for row in disruptive_rules
                             for name in (row["scope_names"] or [])})
            print(f"\n  Scoped to device group(s): {', '.join(groups)}")

        print("\nConsequences to be clear about:")
        print("  - An isolated device loses network access. A build, a deploy, or an")
        print("    incident response running on that device stops.")
        print("  - `selective` isolation still severs git, npm and registry access; it")
        print("    only preserves Outlook/Teams/Skype so you can reach the person.")
        print("  - Release is manual and out of band: Defender portal, or")
        print("    POST /api/machines/{id}/unisolate on api.securitycenter.microsoft.com.")
        print("  - A device released while the loader is still on disk will re-isolate")
        print("    on the next hourly run.")
        print("\nType ARM to proceed, anything else to abort: ", end="")
        try:
            answer = input().strip()
        except EOFError:
            answer = ""
        if answer != "ARM":
            print("Aborted. Nothing sent.")
            return 1

    # ---- apply -------------------------------------------------------------
    client = _client_from_env()
    client.require_write_role()
    print(f"\nApplying to tenant {client.tenant_id} as app {client.client_id[:8]}… "
          f"(credential: {client.credential_kind})\n")

    for rule in rules:
        payload = to_wire(rule, args.status, arm=args.arm, force=args.force,
                          disarm=args.disarm, scope=args.scope,
                          scope_all=args.scope_all_devices)
        action, result = client.upsert(payload)
        detection_action = payload.get("detectionAction") or {}
        armed = bool(detection_action.get("automatedActions"))
        flag = "  [ARMED]" if armed else ""
        sent_scope = (detection_action.get("organizationalScope") or {}).get("scopeNames")
        if sent_scope:
            flag += f"  [scope: {', '.join(sent_scope)}]"
        elif args.scope_all_devices:
            flag += "  [scope cleared: all devices]"
        print(f"  {action}: {rule['id']}  "
              f"status={result.get('status', args.status or rule.get('status'))}{flag}")

    if args.disarm or applying:
        audit(
            "disarm" if args.disarm else "arm",
            {
                "tenant": client.tenant_id,
                "app": client.client_id,
                "credential_kind": client.credential_kind,
                "rules": [r["id"] for r in (plan if args.disarm else applying)],
                "forced": bool(args.force),
                "unattended": bool(args.yes),
                # Recorded because "which rules were armed" is only half the question a
                # post-incident review asks; "over which devices" is the other half.
                "scope": args.scope or ("ALL_DEVICES" if args.scope_all_devices else None),
            },
        )
        try:
            print(f"\nAudit record appended: {AUDIT_LOG.relative_to(REPO_ROOT)}")
        except ValueError:
            print(f"\nAudit record appended: {AUDIT_LOG}")

    if args.disarm:
        print("Disarm sent. VERIFY it took effect — PATCH semantics on a complex property "
              "are not guaranteed to clear it:\n  --kill-switch-status")
    elif applying:
        print(f"\n{len(applying)} rule(s) now armed for automated response. Confirm with "
              f"--kill-switch-status. Emergency rollback: --disarm --apply")

    print(f"\n{len(rules)} rule(s) applied.")
    print("Custom detections run on a schedule, not retroactively: existing evidence "
          "older than the first run is not evaluated. Run the hunting queries in "
          "the rules file once to cover the 30-day backlog.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
