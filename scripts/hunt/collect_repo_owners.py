#!/usr/bin/env python3
"""Attribute hunt findings to an owning team, and to a blast radius.

A finding with no owner is a finding nobody will fix. The manager section of the daily
hunt report is only actionable if each line lands on someone, so this resolves two
independent questions per repository and keeps them separate:

  WHO  - CODEOWNERS on the default branch. Checked at the three locations GitHub honours
         (.github/, root, docs/), in that precedence order, because a repository with a
         root CODEOWNERS and an empty .github/CODEOWNERS is owned by the root one.
  WHAT - repo_deployment_coverage.reaches_production, dumped from the topology tables.
         Whether the repository can push to production is what turns "workflow leaks all
         secrets" from a hygiene item into an incident.

Deliberately NOT merged into one score. A repository can be well owned and reach
production, or unowned and reach nothing; collapsing those into a single number hides
exactly the case that matters - unowned AND production-reaching.

Absence is recorded, never inferred. A repository whose CODEOWNERS lookup errored is
`owner_lookup_error`, not `unowned`: the first is a gap in this script, the second is a
finding about the estate, and reporting one as the other is how a coverage lie starts.

Scope is the finding set, not the estate. Resolving owners for 2810 repositories would
spend the shared GitHub budget on repositories that have nothing to report.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_declared_ranges import (  # noqa: E402
    GITHUB_API,
    ORG_TOKEN_VARS,
    REPO_ROOT,
    Throttle,
    load_env,
)

# GitHub honours CODEOWNERS at exactly these three paths, in this precedence order.
CODEOWNERS_PATHS = (".github/CODEOWNERS", "CODEOWNERS", "docs/CODEOWNERS")

# An owner token is @user, @org/team, or a bare email. Anything else on the line is a
# path pattern and is not an owner.
OWNER_RE = re.compile(r"(@[A-Za-z0-9][A-Za-z0-9-]*(?:/[A-Za-z0-9._-]+)?|[^\s@]+@[^\s@]+\.[^\s@]+)")


def get_raw(url: str, token: str, throttle: Throttle) -> Tuple[Optional[str], Optional[str]]:
    throttle.wait()
    request = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github.raw",
        "Authorization": f"Bearer {token}",
        "User-Agent": "auditgh-hunt-owners",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            throttle.observe(response.headers)
            return response.read().decode("utf-8", errors="replace"), None
    except urllib.error.HTTPError as exc:
        throttle.observe(exc.headers)
        # 404 is the common, meaningful answer: no CODEOWNERS at this path. It is
        # returned as a status rather than an error so the caller can tell it apart
        # from a 403 (which means this script could not see, not that nobody owns).
        return None, f"HTTP {exc.code}"
    except Exception as exc:  # noqa: BLE001 - network shape varies; the string is the record
        return None, f"{type(exc).__name__}: {exc}"


def parse_codeowners(text: str) -> Dict[str, object]:
    """Return the owner set and, separately, the catch-all owners for `*`.

    The catch-all is what a reader wants when they ask "who owns this repo?". The full
    set matters because a workflow finding under .github/workflows/ may have a more
    specific owner than the repository default.
    """
    all_owners: List[str] = []
    default_owners: List[str] = []
    workflow_owners: List[str] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        pattern, owners = parts[0], OWNER_RE.findall(" ".join(parts[1:]))
        if not owners:
            continue
        all_owners.extend(owners)
        if pattern in ("*", "/*", "**"):
            default_owners.extend(owners)
        if "workflow" in pattern or pattern.rstrip("/*").endswith(".github"):
            workflow_owners.extend(owners)
    dedupe = lambda seq: sorted(dict.fromkeys(seq))  # noqa: E731 - order-stable dedupe
    return {
        "owners": dedupe(all_owners),
        "default_owners": dedupe(default_owners),
        "workflow_owners": dedupe(workflow_owners),
    }


def resolve_repo(full_name: str, ref: Optional[str], token: str,
                 throttle: Throttle) -> Dict[str, object]:
    org, repo = full_name.split("/", 1)
    out: Dict[str, object] = {
        "repo": full_name, "codeowners_path": None, "owners": [],
        "default_owners": [], "workflow_owners": [], "owner_state": None,
        "owner_lookup_error": None, "paths_checked": list(CODEOWNERS_PATHS),
    }
    errors: List[str] = []
    for path in CODEOWNERS_PATHS:
        url = (f"{GITHUB_API}/repos/{org}/{repo}/contents/{urllib.parse.quote(path)}"
               + (f"?ref={urllib.parse.quote(ref)}" if ref else ""))
        text, error = get_raw(url, token, throttle)
        if text is not None:
            parsed = parse_codeowners(text)
            out.update(parsed)
            out["codeowners_path"] = path
            out["owner_state"] = "owned" if parsed["owners"] else "codeowners_empty"
            return out
        if error and not error.endswith("404"):
            errors.append(f"{path}: {error}")
    # Every path 404'd, or every path failed for another reason. Those are different
    # answers and are never collapsed: one is an estate finding, the other is a blind spot.
    if errors:
        out["owner_state"] = "owner_lookup_error"
        out["owner_lookup_error"] = "; ".join(errors)
    else:
        out["owner_state"] = "unowned"
    return out


def load_topology(path: Path) -> Dict[str, dict]:
    """Index the topology dump by bare repository name.

    repo_deployment_coverage stores the repository name without the org, so the join is
    on the bare name. Where two orgs hold a repository of the same name the row is
    ambiguous; that is recorded on the row rather than silently resolved.
    """
    if not path.exists():
        return {}
    payload = json.loads(path.read_text())
    index: Dict[str, dict] = {}
    collisions: set = set()
    for row in payload.get("rows", []):
        name = str(row.get("repo", ""))
        if name in index:
            collisions.add(name)
        index[name] = row
    for name in collisions:
        index[name] = dict(index[name], name_ambiguous_across_orgs=True)
    return index


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--posture", type=Path,
                        default=REPO_ROOT / "exports/hunt/actions_posture_r3_coverage.json")
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees_r3.jsonl")
    parser.add_argument("--topology", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_deployment_coverage.json")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_owners.json")
    parser.add_argument("--extra-repos", nargs="*", default=[],
                        help="Additional full_name repositories to resolve.")
    parser.add_argument("--min-interval", type=float, default=0.32)
    args = parser.parse_args()

    env = load_env(REPO_ROOT / ".env")

    # The finding set. Every list here is a list this report will name repositories from;
    # if a new finding list is added to the posture sweep it must be added here too, or
    # the report will name a repository it cannot attribute.
    targets: set = set(args.extra_repos)
    if args.posture.exists():
        posture = json.loads(args.posture.read_text())
        for key in ("serialises_whole_secrets_context", "remote_code_piped_to_shell",
                    "self_hosted_runner_workflows", "secrets_interpolated_into_run",
                    "critical_privileged_trigger_with_pr_head_checkout",
                    "bun_fetch_workflows"):
            for entry in posture.get(key, []) or []:
                if isinstance(entry, dict) and entry.get("repo"):
                    targets.add(entry["repo"])
    else:
        print(f"[owners] posture coverage absent at {args.posture}", file=sys.stderr)

    # Default branch per repo, so CODEOWNERS is read from the ref the estate actually uses.
    refs: Dict[str, str] = {}
    if args.trees.exists():
        for line in args.trees.read_text(errors="replace").splitlines():
            if not line.strip():
                continue
            record = json.loads(line)
            ref = record.get("branch_inspected") or record.get("default_branch")
            if record.get("full_name") and ref:
                refs[record["full_name"]] = ref

    topology = load_topology(args.topology)
    if not topology:
        print(f"[owners] topology absent at {args.topology}; blast radius will read "
              f"'unknown' for every repository", file=sys.stderr)

    throttle = Throttle(args.min_interval)
    resolved: List[dict] = []
    for index, full_name in enumerate(sorted(targets), 1):
        org = full_name.split("/", 1)[0]
        token = next((env[v] for v in ORG_TOKEN_VARS.get(org, ["GITHUB_TOKEN"])
                      if env.get(v)), env.get("GITHUB_TOKEN"))
        if not token:
            resolved.append({"repo": full_name, "owner_state": "owner_lookup_error",
                             "owner_lookup_error": f"no token for org {org}"})
            continue
        row = resolve_repo(full_name, refs.get(full_name), token, throttle)
        topo = topology.get(full_name.split("/", 1)[1], {})
        row["reaches_production"] = topo.get("reaches_production")
        row["resolved_environments"] = topo.get("resolved_environments")
        row["deployment_coverage_state"] = topo.get("coverage_state", "not_in_topology")
        row["name_ambiguous_across_orgs"] = bool(topo.get("name_ambiguous_across_orgs"))
        resolved.append(row)
        if index % 25 == 0:
            print(f"  {index}/{len(targets)}", file=sys.stderr)

    states = {}
    for row in resolved:
        states[row["owner_state"]] = states.get(row["owner_state"], 0) + 1
    unowned_prod = [r["repo"] for r in resolved
                    if r.get("owner_state") == "unowned" and r.get("reaches_production")]

    payload = {
        "repos_resolved": len(resolved),
        "owner_states": states,
        # Called out on its own because it is the intersection that matters: nobody is
        # accountable and the repository can reach production.
        "unowned_and_reaches_production": sorted(unowned_prod),
        "topology_rows_available": len(topology),
        "repos": {r["repo"]: r for r in resolved},
        "limits": [
            "CODEOWNERS is read from the default branch only. A CODEOWNERS added on a "
            "release branch is not seen.",
            "Owner tokens are not validated against GitHub team membership. A CODEOWNERS "
            "naming a team that no longer exists reads as owned here and is not.",
            "reaches_production comes from deployment CAPABILITY inference, not from "
            "observed deployments. Absence of a topology row is reported as unknown.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, default=str))
    print(f"[owners] {len(resolved)} repos -> {args.out}", file=sys.stderr)
    for state, count in sorted(states.items()):
        print(f"  {state}: {count}", file=sys.stderr)
    print(f"  unowned AND reaches production: {len(unowned_prod)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
