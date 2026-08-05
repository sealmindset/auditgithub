#!/usr/bin/env python3
"""
Load AuditGithub's own credentials into the encrypted store.

Reads a JSON payload on stdin so that no secret ever appears in a command line, a
shell history, or the output of `ps`. Prints only names, lengths, fingerprints and
verification verdicts.

Payload shape:

    {
      "organizations": [
        {"name": "sleepnumber", "github_org": "sleepnumber", "display_name": "Sleep Number"}
      ],
      "github": [
        {"organization": "sleepnumber", "token": "ghp_...", "name": "default",
         "description": "..."}
      ],
      "graph": {
        "client_id": "...", "client_secret": "...", "tenant_id": "...",
        "app_roles": ["ThreatHunting.Read.All"], "description": "..."
      }
    }

Usage (from the repository root, so the host .env is not copied into the container):

    python3 scripts/collect_credentials.py | docker exec -i auditgh_api \
        python /app/scripts/bootstrap_credentials.py --verify

--verify authenticates each GitHub token against github.com to record its real scopes,
organization role and access gaps. That produces a genuine audit-log entry under each
token's owner. It is opt-in for exactly that reason.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, "/app")
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.api import credentials as cred_service  # noqa: E402
from src.api import models, secrets_store  # noqa: E402
from src.api.database import SessionLocal  # noqa: E402


def ensure_organizations(db, orgs):
    """Create any missing Organization rows. Returns a list of status strings."""
    out = []
    for spec in orgs:
        name = spec["name"]
        existing = (
            db.query(models.Organization)
            .filter(
                (models.Organization.name == name)
                | (models.Organization.github_org == spec.get("github_org", name))
            )
            .first()
        )
        if existing:
            out.append(f"  exists   {existing.name} -> {existing.github_org} ({existing.id})")
            continue
        row = models.Organization(
            name=name,
            github_org=spec.get("github_org", name),
            display_name=spec.get("display_name"),
            database_name=spec.get("database_name"),
            is_default=False,
            is_active=True,
        )
        db.add(row)
        db.commit()
        db.refresh(row)
        out.append(f"  CREATED  {row.name} -> {row.github_org} ({row.id})")
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--verify", action="store_true",
                    help="Authenticate each GitHub token to record real privilege. "
                         "Generates audit-log entries at GitHub.")
    args = ap.parse_args()

    if not secrets_store.is_configured():
        print("SECRETS_MASTER_KEY is not set in this process. Refusing to store "
              "credentials in plaintext.", file=sys.stderr)
        return 2

    payload = json.load(sys.stdin)
    db = SessionLocal()
    try:
        print(f"Master key fingerprint: {secrets_store.master_key_fingerprint()}")

        if payload.get("organizations"):
            print("\nOrganizations:")
            for line in ensure_organizations(db, payload["organizations"]):
                print(line)

        for entry in payload.get("github", []):
            org = entry.get("organization")
            token = entry["token"]
            summary = cred_service.store_github_token(
                db,
                org=org,
                token=token,
                privilege_level=entry.get("privilege_level", "unknown"),
                name=entry.get("name", "default"),
                description=entry.get("description"),
            )
            print(f"\ngithub_pat / {summary['name']} for org={org or '<tenant-wide>'}")
            print(f"  stored     length {summary['value_length']}, "
                  f"suffix …{summary['value_suffix']}, key {summary['key_fingerprint']}")

            if args.verify:
                org_row = cred_service._resolve_org(db, org) if org else None
                verdict = cred_service.verify_github_token(
                    token, github_org=org_row.github_org if org_row else None
                )
                cred_service.record_verification(
                    db, summary["id"], verdict["status"],
                    detail=f"login={verdict.get('login')} "
                           f"token_type={verdict.get('token_type')}",
                    scopes=verdict.get("scopes"),
                    privilege_level=verdict.get("privilege_level") or None,
                )
                for gap in verdict.get("gaps", []):
                    cred_service.record_gap(db, summary["id"], gap)
                print(f"  verified   status={verdict['status']} "
                      f"login={verdict.get('login')} "
                      f"privilege={verdict.get('privilege_level')} "
                      f"type={verdict.get('token_type')}")
                print(f"  scopes     {verdict.get('scopes') or '(none reported)'}")
                runners = verdict.get("runner_enumeration")
                if runners:
                    print(f"  runners    {runners}")
                for gap in verdict.get("gaps", []):
                    print(f"  GAP        {gap}")

        graph = payload.get("graph")
        if graph:
            summary = cred_service.store_graph_credentials(
                db,
                client_id=graph["client_id"],
                client_secret=graph["client_secret"],
                tenant_id=graph["tenant_id"],
                app_roles=graph.get("app_roles", []),
                name=graph.get("name", "default"),
                description=graph.get("description"),
            )
            print(f"\ngraph_app / {summary['name']} (tenant-wide)")
            print(f"  stored     length {summary['value_length']}, "
                  f"suffix …{summary['value_suffix']}, key {summary['key_fingerprint']}")
            print(f"  client_id  {summary['client_id']}")
            print(f"  tenant     {summary['tenant_id']}")
            print(f"  app_roles  {summary['scopes'] or '(none recorded)'}")

        # Final resolution report: which organizations now run on a credential the tool
        # owns, and which still borrow from the environment.
        print("\nResolution after bootstrap:")
        for org in db.query(models.Organization).order_by(models.Organization.name).all():
            r = cred_service.resolve_github_token(db, org)
            owned = "owned" if r.is_owned else "BORROWED"
            print(f"  {org.github_org:<20} {owned:<9} source={r.source:<12} "
                  f"privilege={r.privilege_level}")
        g = cred_service.resolve_graph_credentials(db)
        print(f"  {'graph':<20} {'owned' if g.is_owned else 'BORROWED':<9} "
              f"source={g.source}")
    finally:
        db.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
