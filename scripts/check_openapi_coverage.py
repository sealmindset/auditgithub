#!/usr/bin/env python3
"""
Validate OpenAPI documentation coverage.

Checks that every endpoint in the schema has:
- A summary (short description for Swagger UI sidebar)
- A description (detailed docstring)
- At least one success response (200 or 201)

Usage:
    python scripts/export_openapi.py                 # Generate openapi.json first
    python scripts/check_openapi_coverage.py          # Check coverage
    python scripts/check_openapi_coverage.py --strict  # Fail on any issue

Exit codes:
    0 — All checks passed
    1 — Coverage issues found (with --strict)
"""

import json
import sys
import os
import argparse


def check(schema_path: str = "openapi.json", strict: bool = False):
    """Check OpenAPI documentation coverage."""
    if not os.path.exists(schema_path):
        print(f"ERROR: {schema_path} not found. Run scripts/export_openapi.py first.")
        sys.exit(1)

    with open(schema_path) as f:
        schema = json.load(f)

    issues = []
    warnings = []
    stats = {
        "total_endpoints": 0,
        "has_summary": 0,
        "has_description": 0,
        "has_success_response": 0,
        "has_error_responses": 0,
    }

    http_methods = {"get", "post", "put", "patch", "delete"}

    for path, methods in schema.get("paths", {}).items():
        for method, spec in methods.items():
            if method not in http_methods:
                continue

            stats["total_endpoints"] += 1
            endpoint = f"{method.upper()} {path}"

            # Check summary
            if spec.get("summary"):
                stats["has_summary"] += 1
            else:
                issues.append(f"  MISSING summary: {endpoint}")

            # Check description
            if spec.get("description"):
                stats["has_description"] += 1
            else:
                warnings.append(f"  MISSING description: {endpoint}")

            # Check success response
            responses = spec.get("responses", {})
            has_success = any(str(code).startswith("2") for code in responses)
            if has_success:
                stats["has_success_response"] += 1
            else:
                warnings.append(f"  MISSING success response: {endpoint}")

            # Check error responses
            has_errors = any(str(code).startswith(("4", "5")) for code in responses)
            if has_errors:
                stats["has_error_responses"] += 1

    # Print report
    total = stats["total_endpoints"]
    print(f"OpenAPI Coverage Report ({total} endpoints)")
    print(f"{'='*50}")
    print(f"  Summaries:        {stats['has_summary']}/{total} ({_pct(stats['has_summary'], total)})")
    print(f"  Descriptions:     {stats['has_description']}/{total} ({_pct(stats['has_description'], total)})")
    print(f"  Success responses: {stats['has_success_response']}/{total} ({_pct(stats['has_success_response'], total)})")
    print(f"  Error responses:  {stats['has_error_responses']}/{total} ({_pct(stats['has_error_responses'], total)})")

    if issues:
        print(f"\nIssues ({len(issues)}):")
        for issue in issues:
            print(issue)

    if warnings:
        print(f"\nWarnings ({len(warnings)}):")
        for warning in warnings[:20]:
            print(warning)
        if len(warnings) > 20:
            print(f"  ... and {len(warnings) - 20} more")

    if not issues and not warnings:
        print("\nAll endpoints fully documented!")

    if strict and issues:
        print(f"\nFAILED: {len(issues)} issues found (strict mode)")
        sys.exit(1)

    return len(issues)


def _pct(part: int, total: int) -> str:
    if total == 0:
        return "N/A"
    return f"{part * 100 // total}%"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Check OpenAPI documentation coverage")
    parser.add_argument("--schema", default="openapi.json", help="Path to OpenAPI JSON file")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if issues found")
    args = parser.parse_args()

    check(schema_path=args.schema, strict=args.strict)
