#!/usr/bin/env python3
"""
Collect credentials from local .env files and emit the bootstrap payload on stdout.

Runs on the host, where the .env files live. Pipe the output straight into
bootstrap_credentials.py inside the API container so the secrets travel over a pipe
rather than through a command line, an environment variable, or a temporary file:

    python3 scripts/collect_credentials.py | docker exec -i auditgh_api \
        python /app/scripts/bootstrap_credentials.py --verify

Nothing is printed to stderr except a summary by name and length. Redirecting stdout
to a terminal is refused, because the payload contains cleartext credentials and would
otherwise land in scrollback.

Sources:
  - <repo>/.env                          GitHub PATs
  - ~/Documents/sec-diligence/.env       Microsoft Graph application credential
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# Map: env var holding the token -> the GitHub organization it belongs to.
# GITHUB_ORG in .env is SleepNumberInc, so the bare GITHUB_TOKEN is that org's token
# rather than a generic one. It is stored tenant-wide as well, because scanners with no
# organization context fall back to it.
GITHUB_TOKEN_VARS = [
    ("ORG_SLEEPNUMBERLABS_TOKEN", "sleepnumberlabs"),
    ("ORG_SLEEPNUMBERINC_TOKEN", "SleepNumberInc"),
    ("GITHUB_TOKEN", None),  # None = tenant-wide fallback
]

ORGANIZATIONS = [
    {"name": "sleepnumber", "github_org": "sleepnumber",
     "display_name": "Sleep Number (primary)"},
    {"name": "sleepnumberlabs", "github_org": "sleepnumberlabs",
     "display_name": "Sleep Number Labs"},
    {"name": "sleepnumberinc", "github_org": "SleepNumberInc",
     "display_name": "Sleep Number Inc"},
]


def read_env(path: Path) -> dict:
    """Minimal .env parser. Does not execute the file or expand variables."""
    values = {}
    if not path.exists():
        return values
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph-env", default=str(Path.home() / "Documents/sec-diligence/.env"),
                    help="Path to the .env holding GRAPH_* variables")
    ap.add_argument("--repo-env", default=".env", help="Path to the repository .env")
    ap.add_argument("--allow-tty", action="store_true",
                    help="Permit writing the payload to a terminal (not recommended)")
    args = ap.parse_args()

    if sys.stdout.isatty() and not args.allow_tty:
        print("Refusing to write cleartext credentials to a terminal. Pipe stdout into "
              "bootstrap_credentials.py, or pass --allow-tty deliberately.",
              file=sys.stderr)
        return 2

    repo_env = read_env(Path(args.repo_env))
    graph_env = read_env(Path(args.graph_env))

    payload = {"organizations": ORGANIZATIONS, "github": []}
    summary = []

    for var, org in GITHUB_TOKEN_VARS:
        token = (repo_env.get(var) or os.environ.get(var) or "").strip()
        if not token:
            summary.append(f"  {var:<28} MISSING")
            continue
        payload["github"].append({
            "organization": org,
            "token": token,
            "name": "default",
            "description": f"Imported from {var} on bootstrap",
        })
        summary.append(f"  {var:<28} length {len(token)}  -> "
                       f"{org or '<tenant-wide>'}")

    client_secret = (graph_env.get("GRAPH_CLIENT_SECRET")
                     or os.environ.get("GRAPH_CLIENT_SECRET") or "").strip()
    client_id = (graph_env.get("GRAPH_CLIENT_ID")
                 or os.environ.get("GRAPH_CLIENT_ID") or "").strip()
    tenant_id = (graph_env.get("GRAPH_TENANT_ID")
                 or os.environ.get("GRAPH_TENANT_ID") or "").strip()

    if client_secret and client_id and tenant_id:
        payload["graph"] = {
            "client_id": client_id,
            "client_secret": client_secret,
            "tenant_id": tenant_id,
            # Roles the app is believed to hold. Recorded as an assertion; the Graph
            # client verifies them against the issued token's roles claim, and a
            # mismatch is reported rather than assumed away.
            "app_roles": [
                r.strip() for r in (graph_env.get("GRAPH_APP_ROLES", "")).split(",")
                if r.strip()
            ],
            "description": "Microsoft Graph - RobV app registration, app-only auth",
        }
        summary.append(f"  GRAPH_CLIENT_SECRET          length {len(client_secret)}"
                       f"  client_id {client_id[:8]}…  tenant {tenant_id[:8]}…")
    else:
        missing = [n for n, v in (("GRAPH_CLIENT_ID", client_id),
                                  ("GRAPH_CLIENT_SECRET", client_secret),
                                  ("GRAPH_TENANT_ID", tenant_id)) if not v]
        summary.append(f"  GRAPH_*                      SKIPPED (missing: {', '.join(missing)})")

    print("Collected:", file=sys.stderr)
    for line in summary:
        print(line, file=sys.stderr)

    json.dump(payload, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
