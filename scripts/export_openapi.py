#!/usr/bin/env python3
"""
Export the complete OpenAPI schema to JSON and YAML files.

Usage:
    python scripts/export_openapi.py
    python scripts/export_openapi.py --json-only
    python scripts/export_openapi.py --output-dir ./docs

Outputs:
    openapi.json  — Full OpenAPI 3.1 schema (JSON)
    openapi.yaml  — Full OpenAPI 3.1 schema (YAML, requires PyYAML)
"""

import json
import sys
import os
import argparse

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def export(output_dir: str = ".", json_only: bool = False):
    """Export the OpenAPI schema from the running FastAPI app."""
    from src.api.main import app

    schema = app.openapi()

    # Export JSON
    json_path = os.path.join(output_dir, "openapi.json")
    with open(json_path, "w") as f:
        json.dump(schema, f, indent=2, default=str)
    print(f"Exported JSON: {json_path}")

    # Export YAML (optional)
    if not json_only:
        try:
            import yaml

            yaml_path = os.path.join(output_dir, "openapi.yaml")
            with open(yaml_path, "w") as f:
                yaml.dump(schema, f, default_flow_style=False, sort_keys=False, allow_unicode=True)
            print(f"Exported YAML: {yaml_path}")
        except ImportError:
            print("PyYAML not installed — skipping YAML export (pip install pyyaml)")

    # Report statistics
    paths = schema.get("paths", {})
    endpoint_count = sum(
        len([m for m in methods if m in ("get", "post", "put", "patch", "delete")])
        for methods in paths.values()
    )
    schema_count = len(schema.get("components", {}).get("schemas", {}))
    tag_count = len(schema.get("tags", []))
    security_schemes = len(schema.get("components", {}).get("securitySchemes", {}))

    print(f"\nOpenAPI Schema Statistics:")
    print(f"  Title:            {schema.get('info', {}).get('title')}")
    print(f"  Version:          {schema.get('info', {}).get('version')}")
    print(f"  Endpoints:        {endpoint_count}")
    print(f"  Schemas:          {schema_count}")
    print(f"  Tags:             {tag_count}")
    print(f"  Security Schemes: {security_schemes}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Export OpenAPI schema")
    parser.add_argument("--output-dir", default=".", help="Output directory (default: current dir)")
    parser.add_argument("--json-only", action="store_true", help="Skip YAML export")
    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)
    export(output_dir=args.output_dir, json_only=args.json_only)
