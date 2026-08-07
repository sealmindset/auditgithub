#!/usr/bin/env python3
"""Repair repository rows whose ``url`` and ``organization_id`` name different organizations.

483 of 2,540 rows disagree with themselves, in both directions - 445 with
``url=SleepNumberInc, fk=sleepnumberlabs`` and 38 the reverse. The clone path took the URL
from one column and the credential from the other, so it presented one organization's token
to another organization's path and failed with ``remote: Repository not found.``
``src/api/utils/repo_origin.resolve_clone_target`` repairs a row the first time anything
touches it; this script repairs them all up front.

**Why an inventory rather than 483 lookups.** The obvious implementation asks
``GET /repos/{org}/{name}`` for each candidate, which is 483 to 966 requests against a
shared 5000/hr budget with many consumers. Listing each organization once costs about 27
paginated requests for the whole estate - 2,069 + 462 + 9 repositories at 100 per page,
plus one ``GET /orgs/{org}`` each - and answers for every row rather than only the broken
ones. Same authority, two percent of the cost.

**The coverage control comes first (doctrine §0.1).** Absence from the inventory is only
evidence of absence if the inventory is complete. Each organization's listing is checked
against the count GitHub reports for that organization, and an organization whose listing
is short, throttled, or refused is marked incomplete. Rows are then never repaired *away
from* an incomplete organization, because "not in the list" there means "not seen", not
"not there". Without this control the script would confidently move rows to the wrong
organization the moment a listing was truncated.

Three outcomes are reported separately and only the first is written:

* **resolved** - the name appears in exactly one organization. The row is corrected.
* **ambiguous** - the name appears in more than one. Only a per-repository probe
  distinguishes these, so they are left for ``resolve_clone_target`` on first touch.
* **unresolved** - the name appears in no complete inventory. Left alone: a repository
  absent from every organization we can see is either gone or invisible to the credentials
  we hold, and those two need ``repo`` scope on the owning organization to tell apart.

Dry run is the default. ``--apply`` writes.

    python scripts/maintenance/repair_repo_origins.py                 # dry run
    python scripts/maintenance/repair_repo_origins.py --apply
    python scripts/maintenance/repair_repo_origins.py --all --apply   # not just mismatches
"""
from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from src.api.database import SessionLocal  # noqa: E402
from src.api import models  # noqa: E402
from src.api.utils.github_reader import RATE_LIMITED, GitHubReader  # noqa: E402
from src.api.utils.repo_origin import get_token_for_org  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("repair_repo_origins")

PER_PAGE = 100
MAX_PAGES = 60          # 6,000 repositories per organization; a runaway-loop backstop.


@dataclass
class OrgInventory:
    """One organization's repository names, and whether the list can be trusted."""

    org: str
    names: Set[str] = field(default_factory=set)
    token_source: str = "none"
    requests_made: int = 0
    reported_total: Optional[int] = None
    complete: bool = False
    reason: str = ""

    @property
    def control(self) -> str:
        if self.complete:
            return f"complete ({len(self.names)} repositories)"
        return f"INCOMPLETE - {self.reason}"


def _org_url(url: Optional[str]) -> Optional[str]:
    if not url or "github.com/" not in url:
        return None
    segments = url.split("github.com/", 1)[1].strip("/").split("/")
    return segments[0] if len(segments) >= 2 else None


def _bare_name(name: Optional[str]) -> str:
    """Repository name without an owner prefix, for rows that stored a full name."""
    return (name or "").strip().rstrip("/").split("/")[-1]


async def collect_inventory(db, org_names: List[str]) -> Dict[str, OrgInventory]:
    """List every repository in every organization, with a completeness control each."""
    inventories: Dict[str, OrgInventory] = {}

    for org in org_names:
        inv = OrgInventory(org=org)
        inventories[org] = inv

        token, source = await get_token_for_org(db, org)
        inv.token_source = source
        if not token:
            inv.reason = "no credential available for this organization"
            logger.warning("%s: %s", org, inv.reason)
            continue

        reader = GitHubReader(token)

        # The control, before the data: GitHub's own count of what should come back.
        # `total_private_repos` is only present for a credential that can see private
        # repositories, which is precisely the credential this repair needs.
        profile, status = reader._get(f"/orgs/{org}")
        if status == 200 and profile:
            public = profile.get("public_repos")
            private = profile.get("total_private_repos")
            if public is not None and private is not None:
                inv.reported_total = int(public) + int(private)
            elif public is not None:
                inv.reported_total = int(public)
        else:
            logger.warning("%s: GET /orgs/%s -> HTTP %s, no count to check against",
                           org, org, status)

        page = 1
        while page <= MAX_PAGES:
            payload, status = reader._get(
                f"/orgs/{org}/repos",
                params={"per_page": PER_PAGE, "page": page, "type": "all"},
            )
            if status == RATE_LIMITED:
                inv.reason = (f"rate limited after {len(inv.names)} repositories "
                              f"(page {page})")
                break
            if status != 200 or payload is None:
                inv.reason = (f"GET /orgs/{org}/repos page {page} -> HTTP {status}; "
                              f"a credential with `repo` scope on {org} is required to "
                              f"list private repositories")
                break

            for entry in payload:
                name = entry.get("name")
                if name:
                    inv.names.add(name.lower())

            if len(payload) < PER_PAGE:
                inv.complete = True
                break
            page += 1
        else:
            inv.reason = f"stopped at the {MAX_PAGES}-page cap"

        inv.requests_made = reader.request_count

        # A listing that ran to the end but returned fewer repositories than GitHub says
        # exist is not complete, whatever the loop thought. Most often that is a
        # credential that cannot see the private ones.
        if inv.complete and inv.reported_total is not None and len(inv.names) < inv.reported_total:
            inv.complete = False
            inv.reason = (f"listed {len(inv.names)} of {inv.reported_total} repositories "
                          f"GitHub reports for {org}; the credential "
                          f"({inv.token_source}) cannot see all of them")

        logger.info("%s: %s | %s requests | token: %s",
                    org, inv.control, inv.requests_made, inv.token_source)

    return inventories


def owners_of(name: str, inventories: Dict[str, OrgInventory]) -> List[str]:
    """Organizations whose *complete* inventory contains this name."""
    return sorted(inv.org for inv in inventories.values()
                  if inv.complete and name.lower() in inv.names)


async def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--apply", action="store_true",
                        help="write the corrections; omitted, the run is a dry run")
    parser.add_argument("--all", action="store_true",
                        help="examine every row, not only rows whose two columns disagree")
    parser.add_argument("--limit", type=int, default=0,
                        help="stop after this many rows (0 = no limit)")
    parser.add_argument("--json", dest="json_out",
                        help="write the full per-row outcome to this file")
    args = parser.parse_args()

    db = SessionLocal()
    try:
        orgs = db.query(models.Organization).all()
        by_id = {o.id: o.name for o in orgs if o.name}
        by_name = {o.name.lower(): o.id for o in orgs if o.name}
        org_names = [o.name for o in orgs if o.name]
        logger.info("Organizations: %s", ", ".join(org_names))

        inventories = await collect_inventory(db, org_names)
        total_requests = sum(i.requests_made for i in inventories.values())
        usable = [i.org for i in inventories.values() if i.complete]
        if not usable:
            logger.error("No organization produced a complete listing. Nothing can be "
                         "repaired from an inventory that was not observed - rerun when "
                         "the budget resets or with a credential that can list private "
                         "repositories.")
            return 2
        logger.info("Inventory cost %s requests; usable organizations: %s",
                    total_requests, ", ".join(usable))

        repos = db.query(models.Repository).all()
        rows: List[dict] = []
        for repo in repos:
            name = _bare_name(repo.name)
            if not name:
                continue
            url_org = _org_url(repo.url)
            fk_org = by_id.get(repo.organization_id) if repo.organization_id else None
            mismatch = bool(url_org and fk_org and url_org.lower() != fk_org.lower())
            if not mismatch and not args.all:
                continue
            rows.append({"id": str(repo.id), "name": name, "url_org": url_org,
                         "fk_org": fk_org, "mismatch": mismatch, "_row": repo})
            if args.limit and len(rows) >= args.limit:
                break

        logger.info("Examining %s rows (%s of them self-contradictory)",
                    len(rows), sum(1 for r in rows if r["mismatch"]))

        resolved, ambiguous, unresolved, unchanged = [], [], [], []
        for row in rows:
            repo = row.pop("_row")
            owners = owners_of(row["name"], inventories)
            row["owners"] = owners

            if len(owners) > 1:
                row["outcome"] = "ambiguous"
                ambiguous.append(row)
                continue
            if not owners:
                row["outcome"] = "unresolved"
                unresolved.append(row)
                continue

            owner = owners[0]
            new_url = f"https://github.com/{owner}/{row['name']}"
            new_fk = by_name.get(owner.lower())
            url_wrong = (repo.url or "") != new_url
            fk_wrong = new_fk is not None and repo.organization_id != new_fk
            if not url_wrong and not fk_wrong:
                row["outcome"] = "unchanged"
                unchanged.append(row)
                continue

            row.update(outcome="resolved", new_url=new_url,
                       url_changed=url_wrong, fk_changed=fk_wrong)
            resolved.append(row)
            if args.apply:
                repo.url = new_url
                if new_fk is not None:
                    repo.organization_id = new_fk

        if args.apply and resolved:
            try:
                db.commit()
                logger.info("Committed %s corrections", len(resolved))
            except Exception as exc:
                db.rollback()
                logger.error("Could not commit corrections, rolled back: %s", exc)
                return 1
        elif resolved:
            db.rollback()

        by_owner: Dict[str, int] = defaultdict(int)
        for row in resolved:
            by_owner[row["owners"][0]] += 1

        print()
        print("=" * 78)
        print(f"{'APPLIED' if args.apply else 'DRY RUN - nothing written'}")
        print("=" * 78)
        for inv in inventories.values():
            print(f"  {inv.org:<20} {inv.control}")
        print(f"  inventory cost: {total_requests} GitHub requests")
        print()
        print(f"  examined:   {len(rows)}")
        print(f"  resolved:   {len(resolved)}"
              + (f"  ({', '.join(f'{k} {v}' for k, v in sorted(by_owner.items()))})"
                 if by_owner else ""))
        print(f"  unchanged:  {len(unchanged)}")
        print(f"  ambiguous:  {len(ambiguous)}   (name in more than one organization; left "
              f"for resolve_clone_target)")
        print(f"  unresolved: {len(unresolved)}   (name in no complete inventory; left alone)")
        if ambiguous:
            print("\n  ambiguous names:")
            for row in ambiguous[:20]:
                print(f"    {row['name']} -> {', '.join(row['owners'])}")
            if len(ambiguous) > 20:
                print(f"    ... and {len(ambiguous) - 20} more (use --json for all)")
        if unresolved:
            print("\n  unresolved names:")
            for row in unresolved[:20]:
                print(f"    {row['name']} (url: {row['url_org']}, fk: {row['fk_org']})")
            if len(unresolved) > 20:
                print(f"    ... and {len(unresolved) - 20} more (use --json for all)")
        print("=" * 78)

        if args.json_out:
            Path(args.json_out).write_text(json.dumps({
                "applied": args.apply,
                "inventory": {i.org: {"complete": i.complete, "reason": i.reason,
                                      "listed": len(i.names),
                                      "reported_total": i.reported_total,
                                      "requests": i.requests_made,
                                      "token_source": i.token_source}
                              for i in inventories.values()},
                "inventory_requests": total_requests,
                "resolved": resolved, "unchanged": unchanged,
                "ambiguous": ambiguous, "unresolved": unresolved,
            }, indent=2, default=str))
            logger.info("Wrote %s", args.json_out)

        return 0
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
