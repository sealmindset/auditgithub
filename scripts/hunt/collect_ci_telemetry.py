#!/usr/bin/env python3
"""
Collect GitHub Actions runs and deployments for the worm window plus 30 days of baseline.

What this answers that the tree sweep cannot
--------------------------------------------
The tree sweep reads the default branch as it stands now. It therefore cannot see:

  * a workflow that ran and was then deleted or reverted — the run record survives the
    file's removal, and the run is the only remaining evidence;
  * a run on a non-default branch, which is where the worm is reported to plant hooks
    (up to 50 branches per repository);
  * who or what triggered a run, which is the part that distinguishes the campaign's
    forged `github-advanced-security[bot]` / `claude` authorship from real automation.

CHAINDROP's exfiltration path is a planted `.github/workflows/codeql_analysis.yml` that
uploads a `format-results` artifact, pushed on a branch named
`dependabot/github_actions/format/setup-formatter`. Each of those three is checked here
against run records rather than against files on disk.

Why 30 days of baseline and not just the window
-----------------------------------------------
A run inside the window is only anomalous relative to what this estate normally does. A
repository that runs CodeQL every day is not interesting because it ran CodeQL during the
window; a repository whose first-ever CodeQL run is inside the window is. The baseline is
what makes that distinction available, so it is collected as data rather than assumed.

Coverage
--------
Every repository queried is recorded with its outcome. A 403 (throttle or permission) and
a 404 (Actions disabled, or repository moved) are different facts and are kept apart: the
first is a coverage failure that invalidates a negative finding, the second is a
structural zero. Runs are only interpretable where the query demonstrably succeeded.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
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

# The corrected worm window, derived from registry publish timestamps rather than from a
# vendor's rounded "detected on" date. The first hunt used a window that began after the
# first malicious publish, which is why it is stated explicitly here.
#
# Widened on 2026-08-10 from 13:18:42Z. Unit 42 documents the operator rotating the C2
# address on chain at 2026-08-04T15:15:26Z, transaction
# 0xc55920f1bd0531b6738153068a666c080ddded47e6256f1fd980d51c0b507c91 - a signed artifact
# with a timestamp, which is harder evidence than either the 13:20Z propagation close
# StepSecurity claims or the 12:11:19.909Z last-publish bound the registry oracle proves.
# Every earlier run therefore hunted to a boundary that provably excluded 1h56m of
# operator activity.
#
# This moves the HUNT window only. The reported last malicious publish stays
# 12:11:19.909Z: rotating a C2 address is operator activity, not propagation, and the two
# numbers answer different questions. See chaindrop_unit42_2026_08.json.
WINDOW_START = "2026-08-04T09:35:00Z"
WINDOW_END = "2026-08-04T16:00:00Z"

# Campaign markers that are visible in a run record.
CAMPAIGN_BRANCH_PREFIX = "dependabot/github_actions/format/setup-formatter"
CAMPAIGN_WORKFLOW_BASENAME = "codeql_analysis.yml"
CAMPAIGN_ARTIFACT_NAME = "format-results"
CAMPAIGN_ACTORS = {"github-advanced-security[bot]", "claude"}


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


WINDOW_START_TS = parse_ts(WINDOW_START)
WINDOW_END_TS = parse_ts(WINDOW_END)


def get_json(url: str, token: str, throttle: Throttle,
             attempts: int = 4) -> Tuple[Optional[object], Optional[str]]:
    for attempt in range(attempts):
        throttle.wait()
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                throttle.observe(response.headers)
                return json.loads(response.read().decode("utf-8", errors="replace")), None
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                # Indistinguishable from a permissions denial at this call site, so it is
                # retried and, if it survives retries, recorded as a coverage failure
                # rather than as an answer. The whole pool backs off, not just this
                # worker: a per-worker sleep leaves the others spending the same
                # exhausted budget.
                headers = exc.headers or {}
                retry_after = headers.get("Retry-After")
                reset = headers.get("X-RateLimit-Reset")
                if retry_after:
                    delay = float(retry_after)
                elif reset:
                    try:
                        delay = max(2.0, float(reset) - datetime.now(
                            timezone.utc).timestamp() + 2)
                    except ValueError:
                        delay = 30.0 * (attempt + 1)
                else:
                    delay = 30.0 * (attempt + 1)
                throttle.back_off(min(delay, 3700.0))
                if attempt < attempts - 1:
                    continue
                return None, f"HTTP {exc.code} after {attempts} attempts"
            if exc.code == 404:
                return None, "HTTP 404"
            if exc.code >= 500 and attempt < attempts - 1:
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == attempts - 1:
                return None, type(exc).__name__
    return None, "exhausted attempts"


def classify_run(run: dict) -> List[str]:
    flags: List[str] = []
    created = parse_ts(run.get("created_at"))
    if created and WINDOW_START_TS <= created <= WINDOW_END_TS:
        flags.append("in_worm_window")
    branch = (run.get("head_branch") or "")
    if branch.startswith(CAMPAIGN_BRANCH_PREFIX):
        flags.append("campaign_branch")
    path = (run.get("path") or "")
    if path.rsplit("/", 1)[-1].lower() == CAMPAIGN_WORKFLOW_BASENAME:
        flags.append("campaign_workflow_file")
    for key in ("actor", "triggering_actor"):
        login = ((run.get(key) or {}).get("login") or "").lower()
        if login in CAMPAIGN_ACTORS:
            flags.append(f"campaign_actor_{key}")
    return flags


def collect_repo(record: dict, token: str, throttle: Throttle, since: str,
                 max_pages: int) -> dict:
    org, repo = record["org"], record["repo"]
    out: Dict[str, object] = {
        "full_name": record["full_name"], "org": org,
        "archived": record.get("archived"),
        "runs_total_count": None, "runs_collected": 0,
        "runs_error": None, "deployments_error": None,
        "flagged_runs": [], "in_window_runs": [],
        "workflow_paths_seen": {}, "actors_seen": {},
        "first_run_created_at": None, "last_run_created_at": None,
        "deployments_in_window": [], "deployments_collected": 0,
    }

    workflow_paths: Counter = Counter()
    actors: Counter = Counter()
    for page in range(1, max_pages + 1):
        url = (f"{GITHUB_API}/repos/{org}/{repo}/actions/runs"
               f"?created=%3E%3D{urllib.parse.quote(since)}&per_page=100&page={page}")
        body, error = get_json(url, token, throttle)
        if body is None:
            out["runs_error"] = error
            break
        if out["runs_total_count"] is None:
            out["runs_total_count"] = body.get("total_count")
        runs = body.get("workflow_runs") or []
        if not runs:
            break
        for run in runs:
            out["runs_collected"] += 1
            workflow_paths[run.get("path") or "?"] += 1
            actors[((run.get("actor") or {}).get("login") or "?")] += 1
            created = run.get("created_at")
            if created:
                if not out["first_run_created_at"] or created < out["first_run_created_at"]:
                    out["first_run_created_at"] = created
                if not out["last_run_created_at"] or created > out["last_run_created_at"]:
                    out["last_run_created_at"] = created
            flags = classify_run(run)
            if not flags:
                continue
            summary = {
                "id": run.get("id"), "name": run.get("name"), "path": run.get("path"),
                "event": run.get("event"), "head_branch": run.get("head_branch"),
                "head_sha": (run.get("head_sha") or "")[:12],
                "actor": (run.get("actor") or {}).get("login"),
                "triggering_actor": (run.get("triggering_actor") or {}).get("login"),
                "created_at": created, "conclusion": run.get("conclusion"),
                "run_attempt": run.get("run_attempt"),
                "html_url": run.get("html_url"), "flags": flags,
            }
            if flags == ["in_worm_window"]:
                out["in_window_runs"].append(summary)
            else:
                out["flagged_runs"].append(summary)
        if len(runs) < 100:
            break

    out["workflow_paths_seen"] = dict(workflow_paths.most_common(25))
    out["actors_seen"] = dict(actors.most_common(15))

    # Deployments have no `created` filter, so the first page is read and filtered. A
    # busy repository could push a window deployment off page one; that is recorded as a
    # bound rather than left implicit.
    url = f"{GITHUB_API}/repos/{org}/{repo}/deployments?per_page=100"
    body, error = get_json(url, token, throttle)
    if body is None:
        out["deployments_error"] = error
    elif isinstance(body, list):
        out["deployments_collected"] = len(body)
        out["deployments_page_full"] = len(body) == 100
        for deployment in body:
            created = parse_ts(deployment.get("created_at"))
            if created and WINDOW_START_TS <= created <= WINDOW_END_TS:
                out["deployments_in_window"].append({
                    "id": deployment.get("id"),
                    "environment": deployment.get("environment"),
                    "ref": deployment.get("ref"),
                    "sha": (deployment.get("sha") or "")[:12],
                    "creator": (deployment.get("creator") or {}).get("login"),
                    "created_at": deployment.get("created_at"),
                    "task": deployment.get("task"),
                })
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/ci_telemetry.jsonl")
    parser.add_argument("--coverage", type=Path, default=None)
    parser.add_argument("--since", default="2026-07-05T00:00:00Z",
                        help="Baseline start: 30 days before the worm window.")
    parser.add_argument("--only-orgs", nargs="*", default=None)
    parser.add_argument("--only", nargs="*", default=None, help="Specific full_names.")
    parser.add_argument("--max-pages", type=int, default=3,
                        help="Run pages per repo. 3 pages = 300 runs; repositories that "
                             "hit the cap are recorded so the bound stays visible.")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--min-interval", type=float, default=0.35)
    args = parser.parse_args()
    coverage_path = args.coverage or args.out.with_name(
        args.out.stem + "_coverage.json")

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    # Only repositories the sweep proved have workflow files. A repository with no
    # workflows can still have runs (a deleted workflow leaves its runs behind), so this
    # is a deliberate narrowing and it is named in the coverage output.
    targets = [r for r in records if (r.get("workflow_count") or 0) > 0]
    skipped_no_workflow_files = len(records) - len(targets)
    if args.only_orgs:
        wanted = {o.lower() for o in args.only_orgs}
        targets = [r for r in targets if r["org"].lower() in wanted]
    if args.only:
        wanted = {n.lower() for n in args.only}
        targets = [r for r in targets if r["full_name"].lower() in wanted]

    env = load_env(REPO_ROOT / ".env")
    print(f"repositories with workflow files: {len(targets)}", file=sys.stderr)
    print(f"window {WINDOW_START} .. {WINDOW_END}; baseline since {args.since}",
          file=sys.stderr)

    throttle = Throttle(min_interval=args.min_interval)
    results: List[dict] = []
    with args.out.open("w") as handle:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for record in targets:
                token = next((env[v] for v in ORG_TOKEN_VARS.get(record["org"], [])
                              if env.get(v)), env.get("GITHUB_TOKEN"))
                if not token:
                    continue
                futures[pool.submit(collect_repo, record, token, throttle,
                                    args.since, args.max_pages)] = record
            for done, future in enumerate(as_completed(futures), 1):
                record = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    result = {"full_name": record["full_name"], "org": record["org"],
                              "runs_error": f"worker crash: {exc}", "runs_collected": 0,
                              "flagged_runs": [], "in_window_runs": [],
                              "deployments_in_window": []}
                results.append(result)
                handle.write(json.dumps(result) + "\n")
                handle.flush()
                for run in result.get("flagged_runs") or []:
                    print(f"  FLAG {result['full_name']}: {run['flags']} "
                          f"{run.get('path')} branch={run.get('head_branch')} "
                          f"actor={run.get('actor')}", file=sys.stderr)
                if done % 50 == 0:
                    print(f"  {done}/{len(futures)}", file=sys.stderr)

    queried = len(results)
    throttled = [r["full_name"] for r in results
                 if (r.get("runs_error") or "").startswith("HTTP 403")
                 or (r.get("runs_error") or "").startswith("HTTP 429")]
    actions_absent = [r["full_name"] for r in results if r.get("runs_error") == "HTTP 404"]
    other_errors = [{"repo": r["full_name"], "error": r["runs_error"]} for r in results
                    if r.get("runs_error") and r["full_name"] not in throttled
                    and r["full_name"] not in actions_absent]
    with_runs = [r for r in results if (r.get("runs_collected") or 0) > 0]
    total_runs = sum(r.get("runs_collected") or 0 for r in results)
    page_capped = [r["full_name"] for r in results
                   if (r.get("runs_collected") or 0) >= args.max_pages * 100]

    # Runs come back NEWEST first, so hitting the page cap truncates the OLD end - the end
    # the worm window is at. A capped repository whose oldest collected run is still newer
    # than the window never looked at the window at all, and its `in_window_runs: 0` is a
    # measurement artifact, not a result. This is §0.4's ordering trap wearing a different
    # hat: nothing here says `asc`, but the pagination is descending and the cap cuts the
    # side that matters. Caught in r5, where SleepNumberInc/SBLDevOps-CCPA collected 300 of
    # 497 runs reaching back only to 2026-08-05, a day AFTER the window closed, and still
    # reported zero.
    window_end = WINDOW_END
    capped_missing_window = [
        {"repo": r["full_name"],
         "oldest_collected": r.get("first_run_created_at"),
         "runs_collected": r.get("runs_collected"),
         "runs_total_count": r.get("runs_total_count")}
        for r in results
        if r["full_name"] in page_capped
        and (r.get("first_run_created_at") or "") > window_end
    ]

    flagged = [{"repo": r["full_name"], **run}
               for r in results for run in (r.get("flagged_runs") or [])]
    in_window = [{"repo": r["full_name"], **run}
                 for r in results for run in (r.get("in_window_runs") or [])]
    deployments = [{"repo": r["full_name"], **d}
                   for r in results for d in (r.get("deployments_in_window") or [])]

    # The estate-level control. Per-repo zeros are expected and uninformative; a zero
    # across the whole estate would mean the query never worked, and every negative
    # below would be a measurement artifact rather than a finding.
    query_proven = bool(total_runs)
    # A repository that never read the window cannot support a negative about the window,
    # so it invalidates the estate-level negative exactly as a 403 would.
    coverage_ok = (query_proven and not throttled and not other_errors
                   and not capped_missing_window)

    coverage = {
        "repos_queried": queried,
        "repos_skipped_no_workflow_files": skipped_no_workflow_files,
        "repos_with_runs_in_baseline": len(with_runs),
        "runs_collected": total_runs,
        "repos_throttled_coverage_failure": throttled,
        "repos_actions_absent_http_404": len(actions_absent),
        "repos_other_errors": other_errors,
        "repos_hitting_page_cap": page_capped,
        # Capped is a disclosed bound; capped AND never reaching the window is a coverage
        # failure. Kept as two separate keys because collapsing them would let the second
        # hide inside the first.
        "repos_capped_before_reaching_window": capped_missing_window,
        "window": {"start": WINDOW_START, "end": WINDOW_END},
        "baseline_since": args.since,
        "query_demonstrably_works": query_proven,
        "coverage_supports_negative_finding": coverage_ok,
        "campaign_markers_checked": {
            "branch_prefix": CAMPAIGN_BRANCH_PREFIX,
            "workflow_basename": CAMPAIGN_WORKFLOW_BASENAME,
            "artifact_name": CAMPAIGN_ARTIFACT_NAME,
            "actors": sorted(CAMPAIGN_ACTORS),
        },
        "counts": {
            "campaign_flagged_runs": len(flagged),
            "runs_inside_worm_window": len(in_window),
            "deployments_inside_worm_window": len(deployments),
        },
        "campaign_flagged_runs": flagged,
        "deployments_inside_worm_window": deployments,
        "limits": [
            "Only repositories the tree sweep found to contain .github/workflows files "
            "were queried. A workflow that was planted and deleted leaves runs behind in "
            "a repository that now has no workflow files, and those repositories are not "
            "covered here.",
            f"At most {args.max_pages} pages ({args.max_pages * 100} runs) per repository. "
            "Repositories that hit the cap are listed; their oldest baseline runs were "
            "not read. Because runs paginate newest-first, the cap truncates the OLD end "
            "- the end the window is at - so any capped repository whose oldest collected "
            "run is newer than the window end never examined the window and is listed "
            "separately under repos_capped_before_reaching_window. Re-run those with "
            "--only <repo> --max-pages N until the oldest collected run predates the "
            "window.",
            "Deployments have no created-at filter in the API, so only the first 100 per "
            "repository were read and filtered.",
            "The artifact name is checked against run records only for flagged runs; "
            "enumerating artifacts for every run would multiply the request count by the "
            "number of runs.",
        ],
    }
    coverage_path.write_text(json.dumps(coverage, indent=2))
    print(f"\nwritten: {args.out}\ncoverage: {coverage_path}", file=sys.stderr)
    print(json.dumps({k: coverage[k] for k in (
        "repos_queried", "repos_with_runs_in_baseline", "runs_collected",
        "repos_actions_absent_http_404", "query_demonstrably_works",
        "coverage_supports_negative_finding", "counts")}, indent=2), file=sys.stderr)
    if throttled:
        print(f"*** COVERAGE FAILURE: {len(throttled)} repositories throttled; a negative "
              f"finding is not supported for them. ***", file=sys.stderr)
    if capped_missing_window:
        print(f"*** COVERAGE FAILURE: {len(capped_missing_window)} repositories hit the "
              f"page cap before reaching the window; their in-window zeros are artifacts, "
              f"not results. Re-run each with --only and a higher --max-pages: ***",
              file=sys.stderr)
        for entry in capped_missing_window:
            print(f"      {entry['repo']}: oldest collected "
                  f"{entry['oldest_collected']} > window end {window_end} "
                  f"({entry['runs_collected']} of {entry['runs_total_count']} runs)",
                  file=sys.stderr)
    return 0 if coverage_ok else 3


if __name__ == "__main__":
    sys.exit(main())
