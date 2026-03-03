"""AGH CLI output formatters.

Provides Table, JSON, and SARIF output for CLI commands.
"""

import json
import sys


def format_table(findings, columns=None):
    """Print findings as an aligned ASCII table.

    Args:
        findings: List of dicts with finding data.
        columns: Ordered list of (header, key, max_width) tuples.
                 Defaults to a standard set if not provided.
    """
    if not findings:
        print("No findings.")
        return

    if columns is None:
        columns = [
            ("SEVERITY", "severity", 10),
            ("SCANNER", "scanner", 12),
            ("FILE", "file_path", 50),
            ("LINE", "line", 6),
            ("TITLE", "title", 60),
        ]

    # Build rows
    rows = []
    for f in findings:
        row = []
        for header, key, max_w in columns:
            val = str(f.get(key, ""))
            if len(val) > max_w:
                val = val[: max_w - 3] + "..."
            row.append(val)
        rows.append(row)

    # Calculate column widths
    headers = [c[0] for c in columns]
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    # Print header
    header_line = "  ".join(h.ljust(widths[i]) for i, h in enumerate(headers))
    print(header_line)
    print("  ".join("-" * w for w in widths))

    # Print rows
    for row in rows:
        print("  ".join(cell.ljust(widths[i]) for i, cell in enumerate(row)))

    print(f"\n{len(findings)} finding(s)")


def format_json(findings):
    """Print findings as pretty-printed JSON."""
    json.dump(findings, sys.stdout, indent=2, default=str)
    print()


def format_sarif(findings, tool_name="agh"):
    """Print findings in SARIF 2.1.0 format.

    See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
    """
    severity_to_level = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "info": "note",
    }

    results = []
    rules = {}
    for f in findings:
        rule_id = f.get("rule_id", f.get("scanner", "unknown"))
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "shortDescription": {"text": f.get("title", rule_id)},
            }

        result = {
            "ruleId": rule_id,
            "level": severity_to_level.get(f.get("severity", "").lower(), "warning"),
            "message": {"text": f.get("title", "Finding")},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": f.get("file_path", "")},
                        "region": {
                            "startLine": f.get("line", 1),
                            "startColumn": f.get("column", 1),
                        },
                    }
                }
            ],
        }
        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "version": "0.1.0",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    json.dump(sarif, sys.stdout, indent=2, default=str)
    print()


def format_policy_result(gate_results, mode="fail"):
    """Print policy gate evaluation results as a table.

    Args:
        gate_results: List of dicts with keys: gate, status (pass/fail/warn), reason.
        mode: Policy mode (fail or warn).
    """
    if not gate_results:
        print("No policy gates evaluated.")
        return

    passed = sum(1 for g in gate_results if g["status"] == "pass")
    failed = sum(1 for g in gate_results if g["status"] == "fail")
    warned = sum(1 for g in gate_results if g["status"] == "warn")

    columns = [
        ("GATE", "gate", 20),
        ("STATUS", "status", 8),
        ("REASON", "reason", 60),
    ]

    format_table(gate_results, columns)

    print(f"\nPolicy mode: {mode}")
    print(f"Results: {passed} passed, {failed} failed, {warned} warned")

    if failed > 0 and mode == "fail":
        print("\nPolicy check: FAIL")
    elif warned > 0:
        print("\nPolicy check: WARN")
    else:
        print("\nPolicy check: PASS")


def format_status(auth_info, tools_info):
    """Print status information."""
    print("AGH Status")
    print("=" * 40)

    print("\nAuthentication:")
    if auth_info.get("authenticated"):
        print(f"  Authenticated: yes")
        if auth_info.get("api_url"):
            print(f"  API URL: {auth_info['api_url']}")
        if auth_info.get("org_id"):
            print(f"  Organization: {auth_info['org_id']}")
    else:
        print(f"  Authenticated: no")
        print(f"  Run: agh auth login --api-key <key>")

    print("\nScanner Tools:")
    for tool in tools_info:
        status = "available" if tool["available"] else "not found"
        print(f"  {tool['name']:12s} {status}")
