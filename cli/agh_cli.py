#!/usr/bin/env python3
"""AGH CLI — AuditGH security scanning from the command line.

Subcommands:
    agh scan              Run all scanners against CWD
    agh scan --tool X     Run a single scanner
    agh findings          Fetch server findings for current repo
    agh auth login        Authenticate via Device Flow or API key
    agh policy check      Evaluate policy gates
    agh status            Show auth state + tool availability
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import webbrowser
from pathlib import Path

import agh_config
import agh_formatters

SCANNERS = {
    "gitleaks": {
        "binary": "gitleaks",
        "description": "Secret detection",
        "run": "_run_gitleaks",
    },
    "semgrep": {
        "binary": "semgrep",
        "description": "SAST (semgrep)",
        "run": "_run_semgrep",
    },
    "bandit": {
        "binary": "bandit",
        "description": "Python SAST",
        "run": "_run_bandit",
    },
    "checkov": {
        "binary": "checkov",
        "description": "IaC scanning",
        "run": "_run_checkov",
    },
    "trivy": {
        "binary": "trivy",
        "description": "Dependency vulnerabilities",
        "run": "_run_trivy",
    },
}


# ---------------------------------------------------------------------------
# Scanner runners — each returns a list of normalized finding dicts
# ---------------------------------------------------------------------------

def _run_gitleaks(target_path, report_dir):
    """Run gitleaks and return normalized findings."""
    report_file = os.path.join(report_dir, "gitleaks.json")
    cmd = [
        "gitleaks", "detect",
        "--source", target_path,
        "--report-format", "json",
        "--report-path", report_file,
        "--no-git",
    ]
    subprocess.run(cmd, capture_output=True, text=True)

    if not os.path.exists(report_file):
        return []

    with open(report_file) as f:
        data = json.load(f)

    findings = []
    for item in (data if isinstance(data, list) else []):
        findings.append({
            "scanner": "gitleaks",
            "severity": "critical",
            "file_path": item.get("File", ""),
            "line": item.get("StartLine", 1),
            "column": item.get("StartColumn", 1),
            "title": f"[{item.get('RuleID', 'secret')}] {item.get('Description', 'Secret detected')}",
            "rule_id": item.get("RuleID", "secret"),
        })
    return findings


def _run_semgrep(target_path, report_dir):
    """Run semgrep and return normalized findings."""
    # Look for custom rules directory
    semgrep_rules = os.path.join(target_path, "semgrep-rules")
    cmd = ["semgrep", "scan", "--json", "--config", "auto"]
    if os.path.isdir(semgrep_rules):
        cmd.extend(["--config", semgrep_rules])
    cmd.append(target_path)

    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        return []

    severity_map = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra", {})
        raw_sev = extra.get("severity", "WARNING")
        findings.append({
            "scanner": "semgrep",
            "severity": severity_map.get(raw_sev.upper(), "medium"),
            "file_path": item.get("path", ""),
            "line": item.get("start", {}).get("line", 1),
            "column": item.get("start", {}).get("col", 1),
            "title": extra.get("message", item.get("check_id", "Finding")),
            "rule_id": item.get("check_id", "semgrep"),
        })
    return findings


def _run_bandit(target_path, report_dir):
    """Run bandit and return normalized findings."""
    cmd = ["bandit", "-r", target_path, "-f", "json", "-q"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        return []

    severity_map = {"HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for item in data.get("results", []):
        raw_sev = item.get("issue_severity", "MEDIUM")
        findings.append({
            "scanner": "bandit",
            "severity": severity_map.get(raw_sev.upper(), "medium"),
            "file_path": item.get("filename", ""),
            "line": item.get("line_number", 1),
            "column": 1,
            "title": f"[{item.get('test_id', 'B000')}] {item.get('issue_text', 'Issue')}",
            "rule_id": item.get("test_id", "B000"),
        })
    return findings


def _run_checkov(target_path, report_dir):
    """Run checkov and return normalized findings."""
    cmd = ["checkov", "-d", target_path, "-o", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        return []

    # Normalize checkov output (list of frameworks or single dict)
    if isinstance(data, list):
        frameworks = data
    elif isinstance(data, dict) and "results" in data:
        frameworks = [data]
    else:
        return []

    findings = []
    for fw in frameworks:
        for check in fw.get("results", {}).get("failed_checks", []):
            line_range = check.get("file_line_range", [1, 1])
            line = line_range[0] if isinstance(line_range, list) and line_range else 1
            sev = check.get("severity", "MEDIUM")
            sev_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
            findings.append({
                "scanner": "checkov",
                "severity": sev_map.get(sev.upper(), "medium"),
                "file_path": check.get("file_path", ""),
                "line": line,
                "column": 1,
                "title": f"[{check.get('check_id', 'CKV')}] {check.get('name', 'IaC issue')}",
                "rule_id": check.get("check_id", "CKV_UNKNOWN"),
            })
    return findings


def _run_trivy(target_path, report_dir):
    """Run trivy fs and return normalized findings."""
    cmd = ["trivy", "fs", "-q", "-f", "json", "--scanners", "vuln", target_path]
    result = subprocess.run(cmd, capture_output=True, text=True)

    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        return []

    severity_map = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low"}
    findings = []
    for result_item in data.get("Results", []):
        target = result_item.get("Target", "unknown")
        for vuln in (result_item.get("Vulnerabilities") or []):
            raw_sev = vuln.get("Severity", "UNKNOWN")
            pkg = vuln.get("PkgName", "")
            ver = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")
            title = f"[{vuln.get('VulnerabilityID', 'UNKNOWN')}] {vuln.get('Title', 'Vulnerability')}"
            if pkg:
                title += f" ({pkg}@{ver}"
                if fixed:
                    title += f" -> {fixed}"
                title += ")"
            findings.append({
                "scanner": "trivy",
                "severity": severity_map.get(raw_sev.upper(), "low"),
                "file_path": target,
                "line": 1,
                "column": 1,
                "title": title,
                "rule_id": vuln.get("VulnerabilityID", "UNKNOWN"),
            })
    return findings


RUNNER_MAP = {
    "gitleaks": _run_gitleaks,
    "semgrep": _run_semgrep,
    "bandit": _run_bandit,
    "checkov": _run_checkov,
    "trivy": _run_trivy,
}


# ---------------------------------------------------------------------------
# Subcommand: scan
# ---------------------------------------------------------------------------

def cmd_scan(args):
    """Run local scanners."""
    target = os.path.abspath(args.path)
    tools = [args.tool] if args.tool else list(SCANNERS.keys())

    # Check tool availability
    for tool in tools:
        if tool not in SCANNERS:
            print(f"Unknown scanner: {tool}", file=sys.stderr)
            print(f"Available: {', '.join(SCANNERS.keys())}", file=sys.stderr)
            return 1
        if not shutil.which(SCANNERS[tool]["binary"]):
            print(f"Scanner not found: {SCANNERS[tool]['binary']} (install it or add to PATH)", file=sys.stderr)
            return 1

    report_dir = args.output or tempfile.mkdtemp(prefix="agh-reports-")
    os.makedirs(report_dir, exist_ok=True)

    all_findings = []
    for tool in tools:
        print(f"Running {tool}...", file=sys.stderr)
        runner = RUNNER_MAP[tool]
        findings = runner(target, report_dir)
        all_findings.extend(findings)
        print(f"  {tool}: {len(findings)} finding(s)", file=sys.stderr)

    print(f"\nTotal: {len(all_findings)} finding(s)\n", file=sys.stderr)

    # Output
    if args.format == "json":
        agh_formatters.format_json(all_findings)
    elif args.format == "sarif":
        agh_formatters.format_sarif(all_findings)
    else:
        agh_formatters.format_table(all_findings)

    return 1 if all_findings else 0


# ---------------------------------------------------------------------------
# Subcommand: findings
# ---------------------------------------------------------------------------

def cmd_findings(args):
    """Fetch findings from AGH server."""
    cfg = agh_config.load_config()
    if not cfg.is_authenticated:
        print("Not authenticated. Run: agh auth login --api-key <key>", file=sys.stderr)
        return 1

    repo_name = args.repo or agh_config.detect_repo_name()
    params = {"page": args.page, "page_size": args.page_size, "repo_name": repo_name}

    if args.severity:
        params["severity"] = args.severity
    if args.status:
        params["status"] = args.status

    try:
        import requests

        resp = requests.get(
            f"{cfg.api_url}/findings/paginated",
            headers=cfg.headers,
            params=params,
            timeout=30,
        )
        resp.raise_for_status()
        data = resp.json()
    except Exception as e:
        print(f"Failed to fetch findings: {e}", file=sys.stderr)
        return 1

    items = data.get("items", [])
    # Normalize to our format
    findings = []
    for item in items:
        findings.append({
            "scanner": item.get("scanner_name", ""),
            "severity": item.get("severity", ""),
            "file_path": item.get("file_path", ""),
            "line": item.get("line_start", 1),
            "title": item.get("title", ""),
            "status": item.get("status", ""),
            "risk_score": item.get("risk_score", ""),
        })

    if args.format == "json":
        agh_formatters.format_json(data)
    elif args.format == "sarif":
        agh_formatters.format_sarif(findings)
    else:
        columns = [
            ("SEVERITY", "severity", 10),
            ("SCANNER", "scanner", 12),
            ("FILE", "file_path", 40),
            ("LINE", "line", 6),
            ("STATUS", "status", 10),
            ("TITLE", "title", 50),
        ]
        agh_formatters.format_table(findings, columns)

    page_info = f"Page {data.get('page', 1)}/{data.get('total_pages', 1)} ({data.get('total', 0)} total)"
    print(f"\n{page_info}", file=sys.stderr)
    return 0


# ---------------------------------------------------------------------------
# Subcommand: auth login
# ---------------------------------------------------------------------------

def cmd_auth_login(args):
    """Authenticate via API key or Device Flow."""
    if args.api_key:
        # Direct API key storage
        agh_config.save_credentials(
            api_key=args.api_key,
            api_url=args.api_url,
            org_id=args.org_id,
        )
        print(f"Credentials saved to {agh_config.CREDENTIALS_FILE}")
        # Verify the key works
        cfg = agh_config.load_config()
        try:
            import requests

            resp = requests.get(f"{cfg.api_url}/", headers=cfg.headers, timeout=10)
            if resp.ok:
                print("Authentication verified.")
            else:
                print(f"Warning: API returned {resp.status_code}. Check your API key and URL.", file=sys.stderr)
        except Exception as e:
            print(f"Warning: Could not reach API: {e}", file=sys.stderr)
        return 0

    # Device Flow
    api_url = args.api_url or agh_config.load_config().api_url
    try:
        import requests

        # Step 1: Request device code
        resp = requests.post(
            f"{api_url}/auth/device/code",
            json={
                "client_id": "auditgh-cli",
                "client_name": "AuditGH CLI",
                "scopes": [],
            },
            timeout=10,
        )
        resp.raise_for_status()
        device_data = resp.json()
    except Exception as e:
        print(f"Failed to initiate device flow: {e}", file=sys.stderr)
        print("Use --api-key instead: agh auth login --api-key agh_...", file=sys.stderr)
        return 1

    user_code = device_data["user_code"]
    verification_uri = device_data["verification_uri_complete"]
    device_code = device_data["device_code"]
    interval = device_data.get("interval", 5)
    expires_in = device_data.get("expires_in", 600)

    print(f"\nTo authenticate, visit:\n  {verification_uri}\n")
    print(f"Or enter code manually: {user_code}\n")

    # Try to open browser
    try:
        webbrowser.open(verification_uri)
        print("Browser opened. Waiting for authorization...")
    except Exception:
        print("Open the URL above in your browser. Waiting for authorization...")

    # Step 2: Poll for token
    deadline = time.time() + expires_in
    while time.time() < deadline:
        time.sleep(interval)
        try:
            token_resp = requests.post(
                f"{api_url}/auth/device/token",
                json={
                    "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    "device_code": device_code,
                    "client_id": "auditgh-cli",
                },
                timeout=10,
            )
            if token_resp.status_code == 200:
                token_data = token_resp.json()
                agh_config.save_credentials(
                    api_key=token_data["access_token"],
                    api_url=api_url,
                )
                print("\nAuthentication successful!")
                print(f"Credentials saved to {agh_config.CREDENTIALS_FILE}")
                return 0

            error = token_resp.json().get("error", "")
            if error == "authorization_pending":
                print(".", end="", flush=True)
                continue
            elif error == "slow_down":
                interval += 1
                continue
            elif error in ("expired_token", "access_denied"):
                print(f"\nAuthorization {error.replace('_', ' ')}.", file=sys.stderr)
                return 1
        except Exception:
            continue

    print("\nDevice flow expired.", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Subcommand: policy check
# ---------------------------------------------------------------------------

def cmd_policy_check(args):
    """Evaluate policy gates against scan results."""
    policy_path = args.policy or _find_policy_file()
    if not policy_path or not os.path.exists(policy_path):
        print("No policy.yaml found. Create one or use --policy <path>.", file=sys.stderr)
        return 1

    try:
        import yaml
    except ImportError:
        print("pyyaml required: pip install pyyaml", file=sys.stderr)
        return 1

    with open(policy_path) as f:
        policy = yaml.safe_load(f)

    mode = policy.get("policy", {}).get("mode", "fail")
    short_circuit = policy.get("policy", {}).get("short_circuit_fail", False)
    gates = policy.get("gates", {})

    # Run scans to get findings
    target = os.path.abspath(args.path)
    report_dir = tempfile.mkdtemp(prefix="agh-policy-")
    all_findings = []

    for tool_name, runner in RUNNER_MAP.items():
        if tool_name not in gates and _gate_alias(tool_name) not in gates:
            continue
        if not shutil.which(SCANNERS[tool_name]["binary"]):
            continue
        print(f"Running {tool_name}...", file=sys.stderr)
        findings = runner(target, report_dir)
        all_findings.extend(findings)

    # Evaluate gates
    gate_results = []
    overall_pass = True

    for gate_name, gate_cfg in gates.items():
        result = _evaluate_gate(gate_name, gate_cfg, all_findings)
        gate_results.append(result)
        if result["status"] == "fail":
            overall_pass = False
            if short_circuit:
                break

    agh_formatters.format_policy_result(gate_results, mode)

    if not overall_pass and mode == "fail":
        return 1
    return 0


def _gate_alias(tool_name):
    """Map scanner tool names to policy gate names."""
    return {
        "gitleaks": "secrets",
        "trivy": "trivy_fs",
    }.get(tool_name, tool_name)


def _evaluate_gate(gate_name, gate_cfg, all_findings):
    """Evaluate a single policy gate against findings."""
    # Map gate names to scanner names
    scanner_map = {
        "secrets": "gitleaks",
        "trivy_fs": "trivy",
        "grype": "grype",
    }
    scanner_name = scanner_map.get(gate_name, gate_name)
    gate_findings = [f for f in all_findings if f.get("scanner") == scanner_name]

    # Check max_findings
    max_findings = gate_cfg.get("max_findings")
    if max_findings is not None and len(gate_findings) > max_findings:
        return {
            "gate": gate_name,
            "status": "fail",
            "reason": f"{len(gate_findings)} findings exceed max {max_findings}",
        }

    # Check max_flows (semgrep_taint)
    max_flows = gate_cfg.get("max_flows")
    if max_flows is not None and len(gate_findings) > max_flows:
        return {
            "gate": gate_name,
            "status": "fail",
            "reason": f"{len(gate_findings)} flows exceed max {max_flows}",
        }

    # Check max_severity
    severity_order = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    max_severity = gate_cfg.get("max_severity")
    if max_severity:
        threshold = severity_order.get(max_severity.lower(), 3)
        for f in gate_findings:
            f_sev = severity_order.get(f.get("severity", "").lower(), 0)
            if f_sev >= threshold:
                return {
                    "gate": gate_name,
                    "status": "fail",
                    "reason": f"Finding with severity '{f.get('severity')}' exceeds max '{max_severity}'",
                }

    # Check max_counts
    max_counts = gate_cfg.get("max_counts", {})
    for sev_name, max_count in max_counts.items():
        actual = sum(1 for f in gate_findings if f.get("severity", "").lower() == sev_name.lower())
        if actual > max_count:
            return {
                "gate": gate_name,
                "status": "fail",
                "reason": f"{actual} {sev_name} findings exceed max {max_count}",
            }

    return {
        "gate": gate_name,
        "status": "pass",
        "reason": f"{len(gate_findings)} findings within thresholds",
    }


def _find_policy_file():
    """Search for policy.yaml in CWD and parent dirs."""
    cwd = Path.cwd()
    for d in [cwd] + list(cwd.parents):
        candidate = d / "policy.yaml"
        if candidate.exists():
            return str(candidate)
    return None


# ---------------------------------------------------------------------------
# Subcommand: status
# ---------------------------------------------------------------------------

def cmd_status(args):
    """Show auth state and tool availability."""
    cfg = agh_config.load_config()

    auth_info = {
        "authenticated": cfg.is_authenticated,
        "api_url": cfg.api_url,
        "org_id": cfg.org_id,
    }

    # Check server health if authenticated
    if cfg.is_authenticated:
        try:
            import requests

            resp = requests.get(f"{cfg.api_url}/", headers=cfg.headers, timeout=5)
            auth_info["server_reachable"] = resp.ok
        except Exception:
            auth_info["server_reachable"] = False

    tools_info = []
    for name, info in SCANNERS.items():
        tools_info.append({
            "name": name,
            "available": shutil.which(info["binary"]) is not None,
        })

    agh_formatters.format_status(auth_info, tools_info)
    return 0


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog="agh",
        description="AuditGH security scanning CLI",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_p = subparsers.add_parser("scan", help="Run local security scanners")
    scan_p.add_argument("--tool", "-t", choices=list(SCANNERS.keys()), help="Run a specific scanner")
    scan_p.add_argument("--path", "-p", default=".", help="Target path (default: CWD)")
    scan_p.add_argument("--output", "-o", help="Report output directory")
    scan_p.add_argument("--format", "-f", choices=["table", "json", "sarif"], default="table", help="Output format")
    scan_p.set_defaults(func=cmd_scan)

    # findings
    find_p = subparsers.add_parser("findings", help="Fetch findings from AGH server")
    find_p.add_argument("--repo", "-r", help="Repository name (auto-detected if omitted)")
    find_p.add_argument("--severity", "-s", help="Filter by severity (comma-separated)")
    find_p.add_argument("--status", help="Filter by status")
    find_p.add_argument("--page", type=int, default=1, help="Page number")
    find_p.add_argument("--page-size", type=int, default=25, help="Items per page")
    find_p.add_argument("--format", "-f", choices=["table", "json", "sarif"], default="table", help="Output format")
    find_p.set_defaults(func=cmd_findings)

    # auth
    auth_p = subparsers.add_parser("auth", help="Authentication commands")
    auth_sub = auth_p.add_subparsers(dest="auth_command", required=True)

    login_p = auth_sub.add_parser("login", help="Authenticate with AGH")
    login_p.add_argument("--api-key", help="API key (format: agh_...)")
    login_p.add_argument("--api-url", help="AGH API URL")
    login_p.add_argument("--org-id", help="Organization ID")
    login_p.set_defaults(func=cmd_auth_login)

    # policy
    policy_p = subparsers.add_parser("policy", help="Policy gate commands")
    policy_sub = policy_p.add_subparsers(dest="policy_command", required=True)

    check_p = policy_sub.add_parser("check", help="Evaluate policy gates")
    check_p.add_argument("--policy", help="Path to policy.yaml")
    check_p.add_argument("--path", "-p", default=".", help="Target path (default: CWD)")
    check_p.set_defaults(func=cmd_policy_check)

    # status
    status_p = subparsers.add_parser("status", help="Show auth state and tool availability")
    status_p.set_defaults(func=cmd_status)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == "__main__":
    main()
