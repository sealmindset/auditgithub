#!/usr/bin/env python3
"""
Enhanced Terraform/IaC Scanner Module

Three capabilities:
  A. Drift Detection     - terraform plan -detailed-exitcode or .tfstate staleness
  B. Blast Radius        - plan JSON resource change analysis
  C. OPA/Rego Policy     - policy enforcement via Open Policy Agent

Follows the existing scanner convention:
  run_terraform_enhanced(repo_path, repo_name, report_dir, ...) -> Optional[CompletedProcess]
"""

import datetime
import json
import logging
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# ---------------------------------------------------------------------------
# Database imports (optional -- mirrors pattern in scan_repos.py)
# ---------------------------------------------------------------------------
try:
    from src.api.database import SessionLocal
    from src.api import models
    DATABASE_AVAILABLE = True
except ImportError:
    DATABASE_AVAILABLE = False
    models = None  # type: ignore[assignment]

# ---------------------------------------------------------------------------
# Progress monitoring (optional)
# ---------------------------------------------------------------------------
try:
    from src.progress_wrapper import run_with_progress_monitoring
    PROGRESS_MONITOR_AVAILABLE = True
except ImportError:
    PROGRESS_MONITOR_AVAILABLE = False

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CRITICAL_RESOURCE_TYPES: Set[str] = {
    "aws_rds_instance",
    "aws_rds_cluster",
    "aws_dynamodb_table",
    "aws_s3_bucket",
    "aws_elasticsearch_domain",
    "aws_elasticache_cluster",
    "aws_db_instance",
    "aws_redshift_cluster",
}

# Security-impacting attribute keywords used to classify drift severity
SECURITY_DRIFT_KEYWORDS: Set[str] = {
    "security_group",
    "iam",
    "policy",
    "encryption",
    "kms",
    "acl",
    "public",
    "cidr",
    "ingress",
    "egress",
    "ssl",
    "tls",
    "logging",
    "flow_log",
    "password",
    "secret",
    "key",
    "certificate",
}

SCANNER_NAME = "terraform-enhanced"


# ===================================================================
# Helpers
# ===================================================================

def _find_terraform_dirs(repo_path: str) -> List[str]:
    """Return directories that contain .tf files, excluding .terraform/ subtrees."""
    tf_dirs: List[str] = []
    for root, dirs, files in os.walk(repo_path):
        # Prune .terraform directories
        dirs[:] = [d for d in dirs if d != ".terraform"]
        if any(f.endswith(".tf") for f in files):
            tf_dirs.append(root)
    return tf_dirs


def _run_cmd(
    cmd: List[str],
    cwd: Optional[str] = None,
    timeout: int = 600,
    scanner_label: str = "terraform-enhanced",
    repo_name: str = "",
) -> subprocess.CompletedProcess:
    """Run a subprocess with optional progress monitoring."""
    if PROGRESS_MONITOR_AVAILABLE and repo_name:
        return run_with_progress_monitoring(
            cmd=cmd,
            repo_name=repo_name,
            scanner_name=scanner_label,
            cwd=cwd,
            timeout=timeout,
        )
    return subprocess.run(cmd, capture_output=True, text=True, cwd=cwd, timeout=timeout)


def _has_aws_creds() -> bool:
    """Return True when minimal AWS credentials are present in the environment."""
    return bool(
        os.environ.get("AWS_ACCESS_KEY_ID")
        or os.environ.get("AWS_PROFILE")
        or os.environ.get("AWS_ROLE_ARN")
        or os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE")
        or os.environ.get("AWS_SESSION_TOKEN")
    )


def _severity_for_drift(attribute: str) -> str:
    """Classify drift severity by attribute name."""
    attr_lower = attribute.lower()
    for kw in SECURITY_DRIFT_KEYWORDS:
        if kw in attr_lower:
            return "HIGH"
    return "LOW"


def _persist_findings(
    db_session: Any,
    repository_id: str,
    findings: List[Dict[str, Any]],
    scanner_name: str = SCANNER_NAME,
) -> None:
    """Persist findings to the database (mirrors _persist_scan_findings in scan_repos.py)."""
    if not db_session or not repository_id or not DATABASE_AVAILABLE or models is None:
        return
    try:
        repo = db_session.query(models.Repository).filter(models.Repository.id == repository_id).first()
        if not repo:
            logger.error("Could not find repository %s for persistence", repository_id)
            return

        organization_id = repo.organization_id
        count = 0
        for f in findings:
            finding = models.Finding(
                repository_id=repository_id,
                organization_id=organization_id,
                scanner_name=scanner_name,
                finding_type="iac",
                title=f.get("title", "Unknown Issue"),
                description=f.get("description", ""),
                severity=f.get("severity", "MEDIUM").upper(),
                file_path=f.get("file_path"),
                line_start=f.get("line_start"),
                line_end=f.get("line_end"),
                code_snippet=f.get("code_snippet", "")[:1000] if f.get("code_snippet") else None,
                cve_id=f.get("cve_id"),
                cwe_id=f.get("cwe_id"),
                risk_factors=f.get("risk_factors"),
                status="open",
            )
            db_session.add(finding)
            count += 1

        db_session.commit()
        logger.info("Persisted %d %s findings to database", count, scanner_name)
    except Exception as exc:
        logger.error("Failed to persist %s findings: %s", scanner_name, exc)
        db_session.rollback()


# ===================================================================
# A. Drift Detection
# ===================================================================

def _detect_drift(
    tf_dir: str,
    repo_name: str,
) -> List[Dict[str, Any]]:
    """Detect configuration drift for a single Terraform directory.

    Strategy:
      1. Try ``terraform init`` + ``terraform plan -detailed-exitcode -json``.
      2. If init fails (e.g. no backend creds), fall back to .tfstate staleness analysis.

    Returns a list of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    rel_dir = os.path.relpath(tf_dir)
    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        return findings

    # ---------- attempt terraform plan ----------------------------------
    if _has_aws_creds():
        try:
            init_result = _run_cmd(
                [terraform_bin, "init", "-input=false", "-no-color", "-backend=true"],
                cwd=tf_dir,
                timeout=300,
                repo_name=repo_name,
            )
            if init_result.returncode == 0:
                plan_result = _run_cmd(
                    [terraform_bin, "plan", "-detailed-exitcode", "-json", "-input=false", "-no-color"],
                    cwd=tf_dir,
                    timeout=600,
                    repo_name=repo_name,
                )
                # Exit code 2 means changes detected (drift)
                if plan_result.returncode == 2:
                    findings.extend(_parse_plan_drift(plan_result.stdout, rel_dir))
                elif plan_result.returncode == 0:
                    logger.info("No drift detected in %s", rel_dir)
                else:
                    logger.warning("terraform plan returned %d for %s", plan_result.returncode, rel_dir)
                return findings
        except subprocess.TimeoutExpired:
            logger.warning("terraform plan timed out in %s", rel_dir)
        except Exception as exc:
            logger.warning("terraform plan failed in %s: %s", rel_dir, exc)

    # ---------- fallback: tfstate staleness analysis --------------------
    findings.extend(_analyze_tfstate_staleness(tf_dir, rel_dir))
    return findings


def _parse_plan_drift(plan_json_output: str, rel_dir: str) -> List[Dict[str, Any]]:
    """Parse streaming JSON lines from ``terraform plan -json`` for resource changes."""
    findings: List[Dict[str, Any]] = []
    for line in plan_json_output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue

        if msg.get("type") != "resource_drift":
            continue

        change = msg.get("change", {})
        resource = change.get("resource", {})
        addr = resource.get("addr", "unknown")
        resource_type = resource.get("resource_type", "")

        # Determine which attributes drifted
        before = change.get("before", {}) or {}
        after = change.get("after", {}) or {}
        drifted_attrs = _diff_keys(before, after)

        # Severity: security-impacting or cosmetic
        severity = "LOW"
        for attr in drifted_attrs:
            s = _severity_for_drift(attr)
            if s == "HIGH":
                severity = "HIGH"
                break

        if resource_type in CRITICAL_RESOURCE_TYPES:
            severity = "CRITICAL" if severity == "HIGH" else "HIGH"

        findings.append({
            "title": f"Drift detected: {addr}",
            "description": (
                f"Configuration drift detected in {rel_dir} for resource {addr}. "
                f"Changed attributes: {', '.join(drifted_attrs[:20]) if drifted_attrs else 'unknown'}."
            ),
            "severity": severity,
            "file_path": rel_dir,
            "cwe_id": "CWE-1188",  # Insecure Default Initialization of Resource
            "risk_factors": {
                "drift_type": "live",
                "resource_type": resource_type,
                "drifted_attributes": drifted_attrs[:50],
                "security_impacting": severity in ("HIGH", "CRITICAL"),
            },
        })
    return findings


def _diff_keys(before: dict, after: dict) -> List[str]:
    """Return attribute names that differ between two flat dicts."""
    all_keys = set(before.keys()) | set(after.keys())
    return sorted(k for k in all_keys if before.get(k) != after.get(k))


def _analyze_tfstate_staleness(tf_dir: str, rel_dir: str) -> List[Dict[str, Any]]:
    """Fallback: inspect .tfstate files for staleness (age) analysis."""
    findings: List[Dict[str, Any]] = []
    state_files: List[str] = []
    for fname in os.listdir(tf_dir):
        if fname.endswith(".tfstate"):
            state_files.append(os.path.join(tf_dir, fname))

    # Also check terraform.tfstate in .terraform if present
    tf_state_default = os.path.join(tf_dir, "terraform.tfstate")
    if os.path.isfile(tf_state_default) and tf_state_default not in state_files:
        state_files.append(tf_state_default)

    if not state_files:
        return findings

    now = datetime.datetime.now(datetime.timezone.utc)

    for sf in state_files:
        try:
            with open(sf, "r") as fh:
                state_data = json.load(fh)
        except (json.JSONDecodeError, OSError) as exc:
            logger.debug("Cannot parse %s: %s", sf, exc)
            continue

        serial = state_data.get("serial", 0)
        tf_version = state_data.get("terraform_version", "unknown")

        # Staleness based on file modification time
        mtime = datetime.datetime.fromtimestamp(os.path.getmtime(sf), tz=datetime.timezone.utc)
        age_days = (now - mtime).days

        if age_days > 90:
            severity = "HIGH"
        elif age_days > 30:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Count resources
        resources = state_data.get("resources", [])
        resource_count = len(resources)

        findings.append({
            "title": f"Stale Terraform state: {os.path.basename(sf)} ({age_days} days old)",
            "description": (
                f"State file {os.path.relpath(sf)} is {age_days} days old (serial {serial}, "
                f"tf {tf_version}). Contains {resource_count} managed resources. "
                f"Stale state may mask configuration drift."
            ),
            "severity": severity,
            "file_path": os.path.relpath(sf),
            "cwe_id": "CWE-1188",
            "risk_factors": {
                "drift_type": "staleness",
                "age_days": age_days,
                "serial": serial,
                "terraform_version": tf_version,
                "resource_count": resource_count,
            },
        })

        # Check individual resources for types we care about
        for res in resources:
            res_type = res.get("type", "")
            res_name = res.get("name", "")
            if res_type in CRITICAL_RESOURCE_TYPES:
                findings.append({
                    "title": f"Critical resource in stale state: {res_type}.{res_name}",
                    "description": (
                        f"Critical resource {res_type}.{res_name} found in state file that is "
                        f"{age_days} days old. Drift in this resource could have security implications."
                    ),
                    "severity": "HIGH" if age_days > 30 else "MEDIUM",
                    "file_path": os.path.relpath(sf),
                    "cwe_id": "CWE-1188",
                    "risk_factors": {
                        "drift_type": "staleness_critical_resource",
                        "resource_type": res_type,
                        "resource_name": res_name,
                        "age_days": age_days,
                    },
                })

    return findings


# ===================================================================
# B. Blast Radius Estimation
# ===================================================================

def _estimate_blast_radius(
    tf_dir: str,
    repo_name: str,
) -> List[Dict[str, Any]]:
    """Estimate blast radius by analyzing ``terraform plan -json`` output.

    Returns a list of finding dicts (one per Terraform directory).
    """
    findings: List[Dict[str, Any]] = []
    rel_dir = os.path.relpath(tf_dir)
    terraform_bin = shutil.which("terraform")
    if not terraform_bin:
        return findings

    # We need init first (may already be done by drift step, but idempotent)
    try:
        init_result = _run_cmd(
            [terraform_bin, "init", "-input=false", "-no-color", "-backend=false"],
            cwd=tf_dir,
            timeout=300,
            repo_name=repo_name,
        )
        if init_result.returncode != 0:
            logger.debug("terraform init failed for blast radius in %s", rel_dir)
            return findings
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.debug("terraform init error in %s: %s", rel_dir, exc)
        return findings

    # Generate plan
    plan_file = os.path.join(tf_dir, "tfplan.bin")
    try:
        plan_result = _run_cmd(
            [terraform_bin, "plan", "-out", plan_file, "-input=false", "-no-color"],
            cwd=tf_dir,
            timeout=600,
            repo_name=repo_name,
        )
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.debug("terraform plan error for blast radius in %s: %s", rel_dir, exc)
        return findings

    # Convert to JSON
    try:
        show_result = _run_cmd(
            [terraform_bin, "show", "-json", plan_file],
            cwd=tf_dir,
            timeout=120,
            repo_name=repo_name,
        )
        if show_result.returncode != 0:
            logger.debug("terraform show failed in %s", rel_dir)
            return findings

        plan_data = json.loads(show_result.stdout)
    except (json.JSONDecodeError, subprocess.TimeoutExpired, Exception) as exc:
        logger.debug("Cannot parse plan JSON in %s: %s", rel_dir, exc)
        return findings
    finally:
        # Cleanup plan binary
        if os.path.exists(plan_file):
            try:
                os.remove(plan_file)
            except OSError:
                pass

    resource_changes = plan_data.get("resource_changes", [])
    if not resource_changes:
        return findings

    creates = 0
    updates = 0
    destroys = 0
    replaces = 0
    critical_destroys: List[str] = []
    stateful_destroys: List[str] = []

    for rc in resource_changes:
        actions = rc.get("change", {}).get("actions", [])
        rtype = rc.get("type", "")
        addr = rc.get("address", "unknown")

        if "create" in actions and "delete" in actions:
            replaces += 1
        elif "create" in actions:
            creates += 1
        elif "delete" in actions:
            destroys += 1
            if rtype in CRITICAL_RESOURCE_TYPES:
                critical_destroys.append(addr)
            else:
                stateful_destroys.append(addr)
        elif "update" in actions:
            updates += 1

    total_changes = creates + updates + destroys + replaces

    # Score severity
    if critical_destroys:
        severity = "CRITICAL"
        reason = f"Destroys data-bearing resources: {', '.join(critical_destroys[:5])}"
    elif total_changes > 20 or stateful_destroys:
        severity = "HIGH"
        reason = f"{total_changes} total changes"
        if stateful_destroys:
            reason += f" including stateful destroys: {', '.join(stateful_destroys[:5])}"
    elif total_changes > 5 or replaces > 0:
        severity = "MEDIUM"
        reason = f"{total_changes} changes ({replaces} replacements)"
    elif total_changes > 0:
        severity = "LOW"
        reason = f"{total_changes} changes (creates/updates only)"
    else:
        return findings  # No changes

    # Compute dependency depth (simple: count unique module paths)
    module_depths: Set[str] = set()
    for rc in resource_changes:
        module_addr = rc.get("module_address", "")
        if module_addr:
            module_depths.add(module_addr)
    max_depth = max((ma.count(".") + 1 for ma in module_depths), default=0)

    findings.append({
        "title": f"Blast radius: {total_changes} changes in {rel_dir}",
        "description": (
            f"Terraform plan for {rel_dir} shows {total_changes} resource changes: "
            f"{creates} create, {updates} update, {destroys} destroy, {replaces} replace. "
            f"{reason}. Module dependency depth: {max_depth}."
        ),
        "severity": severity,
        "file_path": rel_dir,
        "cwe_id": "CWE-1188",
        "risk_factors": {
            "analysis_type": "blast_radius",
            "creates": creates,
            "updates": updates,
            "destroys": destroys,
            "replaces": replaces,
            "total_changes": total_changes,
            "critical_destroys": critical_destroys[:10],
            "stateful_destroys": stateful_destroys[:10],
            "module_dependency_depth": max_depth,
            "reason": reason,
        },
    })

    return findings


# ===================================================================
# C. OPA / Rego Policy Enforcement
# ===================================================================

def _find_policy_dir(repo_path: str) -> Optional[str]:
    """Locate the Rego policy directory.

    Search order:
      1. <repo_root>/policies/terraform/
      2. <project_root>/policies/terraform/  (auditgithub itself)
    """
    # Check inside the scanned repo first
    candidate = os.path.join(repo_path, "policies", "terraform")
    if os.path.isdir(candidate) and any(f.endswith(".rego") for f in os.listdir(candidate)):
        return candidate

    # Fall back to auditgithub's own policy directory
    project_root = Path(__file__).resolve().parent.parent.parent
    candidate = os.path.join(project_root, "policies", "terraform")
    if os.path.isdir(candidate) and any(f.endswith(".rego") for f in os.listdir(candidate)):
        return candidate

    return None


def _run_opa_policies(
    tf_dir: str,
    repo_name: str,
    policy_dir: str,
) -> List[Dict[str, Any]]:
    """Run OPA policy evaluation against a Terraform plan.

    Steps:
      1. ``terraform show -json tfplan`` to get plan JSON
      2. ``opa eval -d <policy_dir> -i <plan.json> 'data.terraform'``
      3. Parse violations

    Returns a list of finding dicts.
    """
    findings: List[Dict[str, Any]] = []
    rel_dir = os.path.relpath(tf_dir)
    terraform_bin = shutil.which("terraform")
    opa_bin = shutil.which("opa")

    if not terraform_bin or not opa_bin:
        return findings

    # Generate plan file + JSON
    plan_file = os.path.join(tf_dir, "tfplan_opa.bin")
    plan_json_path = None
    try:
        # Init (backend=false for policy eval -- we only need the config, not remote state)
        init_result = _run_cmd(
            [terraform_bin, "init", "-input=false", "-no-color", "-backend=false"],
            cwd=tf_dir,
            timeout=300,
            repo_name=repo_name,
        )
        if init_result.returncode != 0:
            logger.debug("terraform init for OPA failed in %s", rel_dir)
            return findings

        # Plan
        plan_result = _run_cmd(
            [terraform_bin, "plan", "-out", plan_file, "-input=false", "-no-color"],
            cwd=tf_dir,
            timeout=600,
            repo_name=repo_name,
        )
        if plan_result.returncode not in (0, 2):
            logger.debug("terraform plan for OPA failed in %s (rc=%d)", rel_dir, plan_result.returncode)
            return findings

        # Show as JSON
        show_result = _run_cmd(
            [terraform_bin, "show", "-json", plan_file],
            cwd=tf_dir,
            timeout=120,
            repo_name=repo_name,
        )
        if show_result.returncode != 0:
            logger.debug("terraform show for OPA failed in %s", rel_dir)
            return findings

        # Write plan JSON to a temp file for OPA input
        fd, plan_json_path = tempfile.mkstemp(suffix=".json", prefix="tfplan_")
        with os.fdopen(fd, "w") as tmp:
            tmp.write(show_result.stdout)

        # Run OPA eval
        opa_result = _run_cmd(
            [
                opa_bin, "eval",
                "--data", policy_dir,
                "--input", plan_json_path,
                "--format", "json",
                "data.terraform",
            ],
            timeout=120,
            repo_name=repo_name,
        )

        if opa_result.returncode != 0:
            logger.warning("OPA eval failed in %s (rc=%d): %s", rel_dir, opa_result.returncode, opa_result.stderr)
            return findings

        # Parse OPA output
        findings.extend(_parse_opa_output(opa_result.stdout, rel_dir))

    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("OPA policy evaluation error in %s: %s", rel_dir, exc)
    finally:
        # Cleanup temp files
        for path in [plan_file, plan_json_path]:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except OSError:
                    pass

    return findings


def _parse_opa_output(opa_json: str, rel_dir: str) -> List[Dict[str, Any]]:
    """Parse OPA eval JSON output and extract deny violations."""
    findings: List[Dict[str, Any]] = []
    try:
        data = json.loads(opa_json)
    except json.JSONDecodeError:
        return findings

    # OPA output structure: {"result": [{"expressions": [{"value": {...}}]}]}
    results = data.get("result", [])
    for result in results:
        for expr in result.get("expressions", []):
            value = expr.get("value", {})
            if not isinstance(value, dict):
                continue

            # Each key under data.terraform is a policy package (s3, iam, etc.)
            for policy_name, policy_result in value.items():
                if not isinstance(policy_result, dict):
                    continue

                deny_messages = policy_result.get("deny", [])
                if not deny_messages:
                    continue

                for msg in deny_messages:
                    if not isinstance(msg, str):
                        msg = str(msg)

                    # Determine severity based on policy type
                    severity = _opa_severity(policy_name, msg)

                    findings.append({
                        "title": f"OPA policy violation ({policy_name}): {msg[:120]}",
                        "description": (
                            f"Policy '{policy_name}' violation in {rel_dir}: {msg}"
                        ),
                        "severity": severity,
                        "file_path": rel_dir,
                        "cwe_id": _opa_cwe(policy_name),
                        "risk_factors": {
                            "analysis_type": "opa_policy",
                            "policy_name": policy_name,
                            "violation_message": msg,
                        },
                    })

    return findings


def _opa_severity(policy_name: str, msg: str) -> str:
    """Map OPA policy name and message to severity."""
    msg_lower = msg.lower()
    # Critical: admin access, wildcard everything
    if "admin access" in msg_lower or "*:*" in msg_lower:
        return "CRITICAL"
    # High: IAM wildcards, public access, no encryption, open security groups
    if policy_name in ("iam", "encryption"):
        return "HIGH"
    if "public" in msg_lower or "0.0.0.0/0" in msg_lower or "::/0" in msg_lower:
        return "HIGH"
    if "wildcard" in msg_lower:
        return "HIGH"
    if "encrypt" in msg_lower:
        return "HIGH"
    # Medium: versioning, logging, networking
    if policy_name in ("logging", "networking"):
        return "MEDIUM"
    if "versioning" in msg_lower or "flow log" in msg_lower:
        return "MEDIUM"
    return "MEDIUM"


def _opa_cwe(policy_name: str) -> str:
    """Map OPA policy category to CWE identifier."""
    mapping = {
        "s3": "CWE-311",           # Missing Encryption of Sensitive Data
        "iam": "CWE-250",          # Execution with Unnecessary Privileges
        "security_groups": "CWE-284",  # Improper Access Control
        "encryption": "CWE-311",   # Missing Encryption of Sensitive Data
        "networking": "CWE-284",   # Improper Access Control
        "logging": "CWE-778",      # Insufficient Logging
    }
    return mapping.get(policy_name, "CWE-1188")


# ===================================================================
# Report writers
# ===================================================================

def _write_json_report(filepath: str, data: Any) -> None:
    """Write data as pretty-printed JSON."""
    os.makedirs(os.path.dirname(filepath), exist_ok=True)
    with open(filepath, "w") as fh:
        json.dump(data, fh, indent=2, default=str)


def _write_markdown_report(
    filepath: str,
    repo_name: str,
    drift_findings: List[Dict[str, Any]],
    blast_findings: List[Dict[str, Any]],
    opa_findings: List[Dict[str, Any]],
) -> None:
    """Write a combined Markdown summary report."""
    all_findings = drift_findings + blast_findings + opa_findings
    os.makedirs(os.path.dirname(filepath), exist_ok=True)

    sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in all_findings:
        sev = f.get("severity", "MEDIUM").upper()
        if sev in sev_counts:
            sev_counts[sev] += 1
        else:
            sev_counts["INFO"] += 1

    with open(filepath, "w") as md:
        md.write(f"# Enhanced Terraform Scanner Report\n\n")
        md.write(f"**Repository:** {repo_name}\n")
        md.write(f"**Scanned:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        md.write(f"**Scanner:** {SCANNER_NAME}\n\n")

        # Summary
        md.write("## Summary\n\n")
        md.write(f"| Severity | Count |\n")
        md.write(f"|----------|-------|\n")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            md.write(f"| {sev} | {sev_counts[sev]} |\n")
        md.write(f"| **Total** | **{len(all_findings)}** |\n\n")

        # Drift section
        md.write("## Drift Detection\n\n")
        if drift_findings:
            for f in drift_findings:
                md.write(f"### [{f['severity']}] {f['title']}\n\n")
                md.write(f"{f['description']}\n\n")
                rf = f.get("risk_factors", {})
                if rf.get("drift_type") == "live":
                    attrs = rf.get("drifted_attributes", [])
                    if attrs:
                        md.write(f"**Drifted attributes:** {', '.join(attrs[:10])}\n\n")
                elif rf.get("drift_type") == "staleness":
                    md.write(f"**Age:** {rf.get('age_days', '?')} days | **Resources:** {rf.get('resource_count', '?')}\n\n")
        else:
            md.write("No drift detected or drift detection was skipped (no AWS credentials).\n\n")

        # Blast Radius section
        md.write("## Blast Radius Analysis\n\n")
        if blast_findings:
            for f in blast_findings:
                md.write(f"### [{f['severity']}] {f['title']}\n\n")
                md.write(f"{f['description']}\n\n")
                rf = f.get("risk_factors", {})
                md.write(f"| Metric | Value |\n")
                md.write(f"|--------|-------|\n")
                md.write(f"| Creates | {rf.get('creates', 0)} |\n")
                md.write(f"| Updates | {rf.get('updates', 0)} |\n")
                md.write(f"| Destroys | {rf.get('destroys', 0)} |\n")
                md.write(f"| Replaces | {rf.get('replaces', 0)} |\n")
                md.write(f"| Module depth | {rf.get('module_dependency_depth', 0)} |\n\n")
                if rf.get("critical_destroys"):
                    md.write(f"**Critical resource destroys:** {', '.join(rf['critical_destroys'])}\n\n")
        else:
            md.write("No plan changes detected or blast radius analysis was skipped.\n\n")

        # OPA section
        md.write("## OPA Policy Violations\n\n")
        if opa_findings:
            for f in opa_findings:
                md.write(f"### [{f['severity']}] {f['title']}\n\n")
                md.write(f"{f['description']}\n\n")
                rf = f.get("risk_factors", {})
                md.write(f"**Policy:** {rf.get('policy_name', 'unknown')} | **CWE:** {f.get('cwe_id', 'N/A')}\n\n")
        else:
            md.write("No OPA policy violations detected or OPA was not available.\n\n")


# ===================================================================
# Main entry point
# ===================================================================

def run_terraform_enhanced(
    repo_path: str,
    repo_name: str,
    report_dir: str,
    db_session: Any = None,
    repository_id: Optional[str] = None,
) -> Optional[subprocess.CompletedProcess]:
    """Run the Enhanced Terraform/IaC scanner.

    Combines three capabilities:
      A. Drift Detection
      B. Blast Radius Estimation
      C. OPA/Rego Policy Enforcement

    Writes per-capability JSON reports plus a combined JSON and Markdown report.

    Returns a synthetic CompletedProcess summarizing the scan, or None if no .tf
    files were found.
    """
    os.makedirs(report_dir, exist_ok=True)

    # ---- Pre-flight checks ------------------------------------------------
    tf_dirs = _find_terraform_dirs(repo_path)
    if not tf_dirs:
        logger.info("No Terraform files found in %s -- skipping terraform-enhanced", repo_name)
        return None

    terraform_bin = shutil.which("terraform")
    opa_bin = shutil.which("opa")
    has_creds = _has_aws_creds()
    policy_dir = _find_policy_dir(repo_path)

    skipped: List[str] = []
    if not terraform_bin:
        skipped.append("terraform CLI not found")
    if not opa_bin:
        skipped.append("opa CLI not found")
    if not has_creds:
        skipped.append("AWS credentials not set (drift detection via plan unavailable, using tfstate fallback)")
    if not policy_dir:
        skipped.append("No Rego policy directory found")

    logger.info(
        "terraform-enhanced: scanning %d TF directories in %s (terraform=%s, opa=%s, aws_creds=%s, policies=%s)",
        len(tf_dirs),
        repo_name,
        bool(terraform_bin),
        bool(opa_bin),
        has_creds,
        bool(policy_dir),
    )

    # ---- Run analyses -----------------------------------------------------
    all_drift: List[Dict[str, Any]] = []
    all_blast: List[Dict[str, Any]] = []
    all_opa: List[Dict[str, Any]] = []

    for tf_dir in tf_dirs:
        # A. Drift detection
        if terraform_bin:
            try:
                all_drift.extend(_detect_drift(tf_dir, repo_name))
            except Exception as exc:
                logger.error("Drift detection failed in %s: %s", tf_dir, exc)

        # B. Blast radius
        if terraform_bin:
            try:
                all_blast.extend(_estimate_blast_radius(tf_dir, repo_name))
            except Exception as exc:
                logger.error("Blast radius estimation failed in %s: %s", tf_dir, exc)

        # C. OPA policy enforcement
        if terraform_bin and opa_bin and policy_dir:
            try:
                all_opa.extend(_run_opa_policies(tf_dir, repo_name, policy_dir))
            except Exception as exc:
                logger.error("OPA policy evaluation failed in %s: %s", tf_dir, exc)

    # ---- Write reports ----------------------------------------------------
    drift_json_path = os.path.join(report_dir, f"{repo_name}_tf_drift.json")
    blast_json_path = os.path.join(report_dir, f"{repo_name}_tf_blast_radius.json")
    opa_json_path = os.path.join(report_dir, f"{repo_name}_tf_opa.json")
    combined_json_path = os.path.join(report_dir, f"{repo_name}_terraform_enhanced.json")
    combined_md_path = os.path.join(report_dir, f"{repo_name}_terraform_enhanced.md")

    _write_json_report(drift_json_path, {"scanner": SCANNER_NAME, "capability": "drift", "findings": all_drift, "skipped": [s for s in skipped if "drift" in s.lower() or "terraform" in s.lower() or "aws" in s.lower()]})
    _write_json_report(blast_json_path, {"scanner": SCANNER_NAME, "capability": "blast_radius", "findings": all_blast, "skipped": [s for s in skipped if "terraform" in s.lower()]})
    _write_json_report(opa_json_path, {"scanner": SCANNER_NAME, "capability": "opa_policy", "findings": all_opa, "skipped": [s for s in skipped if "opa" in s.lower() or "policy" in s.lower() or "terraform" in s.lower()]})

    all_findings = all_drift + all_blast + all_opa
    _write_json_report(combined_json_path, {
        "scanner": SCANNER_NAME,
        "repository": repo_name,
        "scanned_at": datetime.datetime.now().isoformat(),
        "terraform_dirs_scanned": len(tf_dirs),
        "skipped_capabilities": skipped,
        "summary": {
            "drift_findings": len(all_drift),
            "blast_radius_findings": len(all_blast),
            "opa_findings": len(all_opa),
            "total_findings": len(all_findings),
        },
        "findings": all_findings,
    })

    _write_markdown_report(combined_md_path, repo_name, all_drift, all_blast, all_opa)

    # ---- Persist to database ----------------------------------------------
    if db_session and repository_id and all_findings:
        _persist_findings(db_session, repository_id, all_findings)

    # ---- Synthetic CompletedProcess result --------------------------------
    summary_text = (
        f"terraform-enhanced scan complete for {repo_name}: "
        f"{len(all_drift)} drift, {len(all_blast)} blast-radius, "
        f"{len(all_opa)} OPA policy findings ({len(all_findings)} total). "
        f"Scanned {len(tf_dirs)} Terraform directories."
    )
    if skipped:
        summary_text += f" Skipped: {'; '.join(skipped)}."

    logger.info(summary_text)

    return subprocess.CompletedProcess(
        args=["terraform-enhanced", repo_path],
        returncode=0 if not all_findings else 1,
        stdout=summary_text,
        stderr="",
    )
