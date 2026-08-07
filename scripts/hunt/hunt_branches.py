#!/usr/bin/env python3
"""
Close the non-default-branch gap: hunt branches, pushes and commit authorship.

The gap this closes
-------------------
Every hunt run so far reads the default branch. The worm is reported to commit its hooks
to up to 50 branches per accessible repository, so a repository can be compromised on a
side branch and read as clean on `main`. That limitation is written into the tree sweep's
own coverage output; this script is what removes it.

Why it does not have to look at all 2,810 repositories
-----------------------------------------------------
A push to ANY branch updates a repository's `pushed_at`. So a repository whose
`pushed_at` is earlier than the start of the worm window has received no push to any
branch since before the window, and cannot be holding a branch the worm created. That is
a property of the data already collected, not an assumption, and it reduces the
population from 2,810 to the repositories pushed since the window opened.

The narrowing is exact for pushes, and it is stated as such: it clears repositories of
having RECEIVED a worm push. It does not clear a repository whose compromise predates the
window, which is a different claim this campaign's timeline does not support.

What is checked per repository
------------------------------
  * every branch name, against the campaign's branch prefix;
  * the repository activity log, which records pushes and branch creations across all
    refs with their actor — one request covers every branch;
  * for each push inside the window, the commit's author, committer and message, against
    the forged-authorship markers (`claude@users.noreply.github.com`,
    `github-advanced-security[bot]`, "chore: update config", "Add CodeQL Analysis").

Coverage
--------
The activity API requires push access; a 403 there is a coverage failure, not an absence,
and is recorded as one. Branch listing is paginated to completion rather than sampled,
because "the first 100 branches are clean" is not an answer for a worm that creates 50.
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
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
from collect_ci_telemetry import WINDOW_END, WINDOW_START, parse_ts  # noqa: E402

CAMPAIGN_BRANCH_PREFIX = "dependabot/github_actions/format/setup-formatter"
# Matched as a substring of the branch name too: the prefix is what the reporting names,
# but a worm that appends a counter or a shortened ref would still contain "setup-formatter".
CAMPAIGN_BRANCH_TOKEN = "setup-formatter"
FORGED_EMAILS = {"claude@users.noreply.github.com"}
FORGED_LOGINS = {"github-advanced-security[bot]", "claude"}
CAMPAIGN_COMMIT_MESSAGES = ("chore: update config", "add codeql analysis")

# The decisive signal for an in-window push: what it changed. A campaign push writes the
# loader, the payload or an autostart hook; no legitimate feature branch does.
CAMPAIGN_FILE_BASENAMES = {"setup.mjs", "math_init.js", "math_symbol.js",
                           "codeql_analysis.yml", "format-results.txt"}
CAMPAIGN_FILE_PATHS = {".claude/settings.json", ".claude/settings.local.json",
                       ".vscode/tasks.json", ".github/workflows/codeql_analysis.yml",
                       ".claude/setup.mjs", ".claude/math_init.js", ".vscode/setup.mjs"}

# Deliberately a SECOND tier, not folded into the set above. A commit that adds a Bun
# runtime binary is a provenance question; a commit that adds math_init.js is a finding.
# Merging them would make "campaign_file_written" fire on any repository that vendors a
# toolchain, and that flag is the one a responder acts on.
#
# bun.exe is here because the Windows half of the bootstrap was never modelled: the
# documented staging path is mkdtemp('/tmp/bun-dl-') with a chmod 755, but the same
# source lists bun-windows-x64-baseline.zip and bun-windows-aarch64.zip among the fetched
# assets, and neither /tmp nor chmod appears anywhere on that path.
BUN_ARTIFACT_BASENAMES = {"bun.exe", "bunx.exe",
                          "bun-windows-x64-baseline.zip", "bun-windows-aarch64.zip",
                          "bun-linux-x64-baseline.zip", "bun-linux-x64-musl-baseline.zip",
                          "bun-linux-aarch64.zip", "bun-darwin-aarch64.zip",
                          "bun-darwin-x64.zip"}

# "Co-authored-by: Claude" is NOT an indicator on this estate and is deliberately not
# treated as one. Claude Code is in normal use here, so every legitimate agent-assisted
# commit carries the trailer: the first labs run flagged five commits on it, and all five
# were named engineers with corporate email addresses on ticket branches changing Java
# source. The campaign's marker is the trailer forged onto a commit it also AUTHORED as
# claude@users.noreply.github.com, with its own commit message, touching hook files. The
# trailer alone is recorded as context and only becomes a flag in that company.

WINDOW_START_TS = parse_ts(WINDOW_START)
WINDOW_END_TS = parse_ts(WINDOW_END)


def get_json(url: str, token: str, throttle: Throttle,
             attempts: int = 4) -> Tuple[Optional[object], Optional[str], Optional[str]]:
    """Returns (body, error, link_header)."""
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
                body = json.loads(response.read().decode("utf-8", errors="replace"))
                return body, None, response.headers.get("Link")
        except urllib.error.HTTPError as exc:
            headers = exc.headers or {}
            if exc.code in (403, 429):
                retry_after = headers.get("Retry-After")
                reset = headers.get("X-RateLimit-Reset")
                if retry_after:
                    delay = float(retry_after)
                elif reset:
                    try:
                        delay = max(2.0, float(reset)
                                    - datetime.now(timezone.utc).timestamp() + 2)
                    except ValueError:
                        delay = 30.0 * (attempt + 1)
                else:
                    delay = 30.0 * (attempt + 1)
                throttle.back_off(min(delay, 3700.0))
                if attempt < attempts - 1:
                    continue
                return None, f"HTTP {exc.code} after {attempts} attempts", None
            if exc.code >= 500 and attempt < attempts - 1:
                continue
            return None, f"HTTP {exc.code}", None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == attempts - 1:
                return None, type(exc).__name__, None
    return None, "exhausted attempts", None


def list_all_branches(org: str, repo: str, token: str,
                      throttle: Throttle, max_pages: int) -> Tuple[List[dict], Optional[str], bool]:
    branches: List[dict] = []
    for page in range(1, max_pages + 1):
        url = (f"{GITHUB_API}/repos/{org}/{repo}/branches"
               f"?per_page=100&page={page}")
        body, error, _ = get_json(url, token, throttle)
        if body is None:
            return branches, error, False
        if not isinstance(body, list):
            return branches, "unexpected body", False
        branches.extend(body)
        if len(body) < 100:
            return branches, None, True
    return branches, None, False  # cap hit: enumeration incomplete


def inspect_commit(org: str, repo: str, sha: str, token: str,
                   throttle: Throttle) -> Optional[dict]:
    url = f"{GITHUB_API}/repos/{org}/{repo}/commits/{urllib.parse.quote(sha)}"
    body, error, _ = get_json(url, token, throttle)
    if body is None or not isinstance(body, dict):
        return {"sha": sha, "error": error}
    commit = body.get("commit") or {}
    author = commit.get("author") or {}
    committer = commit.get("committer") or {}
    message = commit.get("message") or ""
    flags: List[str] = []
    for field, value in (("author_email", author.get("email")),
                         ("committer_email", committer.get("email"))):
        if (value or "").lower() in FORGED_EMAILS:
            flags.append(f"forged_{field}")
    for field in ("author", "committer"):
        login = ((body.get(field) or {}).get("login") or "").lower()
        if login in FORGED_LOGINS:
            flags.append(f"forged_{field}_login")
    lowered = message.lower()
    for marker in CAMPAIGN_COMMIT_MESSAGES:
        if marker in lowered:
            flags.append(f"campaign_message:{marker}")

    changed = [f.get("filename") or "" for f in (body.get("files") or [])]
    campaign_files = sorted({
        path for path in changed
        if path.rsplit("/", 1)[-1].lower() in CAMPAIGN_FILE_BASENAMES
        or path.lower() in CAMPAIGN_FILE_PATHS
    })
    if campaign_files:
        flags.append("campaign_file_written")

    bun_files = sorted({
        path for path in changed
        if path.rsplit("/", 1)[-1].lower() in BUN_ARTIFACT_BASENAMES
        or "bun-dl-" in path.lower()
    })
    if bun_files:
        # Separate flag name so a triager can filter it out in one pass, and so it never
        # silently promotes a Bun-vendoring commit into the campaign_file set.
        flags.append("bun_artifact_written")

    # Context, not a flag on its own. See CAMPAIGN_FILE_BASENAMES above for why.
    has_trailer = "co-authored-by: claude" in lowered
    if has_trailer and flags:
        flags.append("forged_coauthor_trailer_with_campaign_signal")

    return {
        "agent_coauthor_trailer": has_trailer,
        "campaign_files_changed": campaign_files,
        "bun_artifacts_changed": bun_files,
        "sha": sha[:12],
        "author_name": author.get("name"), "author_email": author.get("email"),
        "committer_name": committer.get("name"), "committer_email": committer.get("email"),
        "author_login": (body.get("author") or {}).get("login"),
        "committer_login": (body.get("committer") or {}).get("login"),
        "authored_at": author.get("date"), "committed_at": committer.get("date"),
        "message_first_line": message.splitlines()[0][:160] if message else "",
        "files_changed": [f.get("filename") for f in (body.get("files") or [])][:50],
        "verified": ((body.get("commit") or {}).get("verification") or {}).get("verified"),
        "flags": flags,
    }


def collect_repo(record: dict, token: str, throttle: Throttle,
                 max_branch_pages: int, max_commits: int) -> dict:
    org, repo = record["org"], record["repo"]
    out: Dict[str, object] = {
        "full_name": record["full_name"], "org": org,
        "pushed_at": record.get("pushed_at"), "default_branch": record.get("default_branch"),
        "branches_error": None, "activity_error": None,
        "branch_count": 0, "branch_enumeration_complete": False,
        "campaign_branches": [], "branches_touched_in_window": [],
        "activity_in_window": [], "commits_inspected": [], "flagged_commits": [],
    }

    branches, error, complete = list_all_branches(org, repo, token, throttle,
                                                  max_branch_pages)
    out["branches_error"] = error
    out["branch_count"] = len(branches)
    out["branch_enumeration_complete"] = complete
    out["campaign_branches"] = [
        b["name"] for b in branches
        if b.get("name", "").startswith(CAMPAIGN_BRANCH_PREFIX)
        or CAMPAIGN_BRANCH_TOKEN in b.get("name", "").lower()
    ]

    # One request covers pushes and branch creations across every ref, with the actor.
    url = f"{GITHUB_API}/repos/{org}/{repo}/activity?per_page=100"
    body, error, _ = get_json(url, token, throttle)
    out["activity_error"] = error
    window_shas: List[Tuple[str, str]] = []
    if isinstance(body, list):
        for event in body:
            stamp = parse_ts(event.get("timestamp"))
            if not stamp or not (WINDOW_START_TS <= stamp <= WINDOW_END_TS):
                continue
            entry = {
                "activity_type": event.get("activity_type"),
                "ref": event.get("ref"),
                "actor": (event.get("actor") or {}).get("login"),
                "timestamp": event.get("timestamp"),
                "before": (event.get("before") or "")[:12],
                "after": (event.get("after") or "")[:12],
            }
            out["activity_in_window"].append(entry)
            ref = (event.get("ref") or "")
            if ref:
                out["branches_touched_in_window"].append(ref.split("refs/heads/")[-1])
            if event.get("after"):
                window_shas.append((event["after"], ref))

    seen: set = set()
    for sha, ref in window_shas[:max_commits]:
        if sha in seen:
            continue
        seen.add(sha)
        detail = inspect_commit(org, repo, sha, token, throttle)
        if detail:
            detail["ref"] = ref
            out["commits_inspected"].append(detail)
            if detail.get("flags"):
                out["flagged_commits"].append(detail)
    out["branches_touched_in_window"] = sorted(set(out["branches_touched_in_window"]))
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/branch_hunt.jsonl")
    parser.add_argument("--since", default=WINDOW_START,
                        help="Only repositories pushed at or after this instant are "
                             "candidates; a push to any branch updates pushed_at.")
    parser.add_argument("--all-repos", action="store_true",
                        help="Ignore the pushed_at narrowing and inspect every repository. "
                             "Costs roughly 2 requests per repository.")
    parser.add_argument("--only-orgs", nargs="*", default=None,
                        help="Restrict to these orgs. sleepnumberlabs authenticates with "
                             "a different identity than the other two, so its quota is "
                             "independent and it can be run while they are rate limited.")
    parser.add_argument("--max-branch-pages", type=int, default=10)
    parser.add_argument("--max-commits", type=int, default=25)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--min-interval", type=float, default=0.32)
    args = parser.parse_args()
    coverage_path = args.out.with_name(args.out.stem + "_coverage.json")

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    if args.all_repos:
        targets = records
        excluded_reason = None
    else:
        targets = [r for r in records if (r.get("pushed_at") or "") >= args.since]
        excluded_reason = (
            f"{len(records) - len(targets)} repositories have pushed_at earlier than "
            f"{args.since}. A push to any branch updates pushed_at, so they have received "
            f"no push to any ref since before the worm window and cannot hold a branch "
            f"the worm created during it."
        )

    if args.only_orgs:
        wanted = {o.lower() for o in args.only_orgs}
        targets = [r for r in targets if r["org"].lower() in wanted]

    env = load_env(REPO_ROOT / ".env")
    print(f"candidate repositories: {len(targets)} of {len(records)}", file=sys.stderr)
    if excluded_reason:
        print(f"  {excluded_reason}", file=sys.stderr)

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
                                    args.max_branch_pages, args.max_commits)] = record
            for done, future in enumerate(as_completed(futures), 1):
                record = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    result = {"full_name": record["full_name"], "org": record["org"],
                              "branches_error": f"worker crash: {exc}",
                              "campaign_branches": [], "flagged_commits": [],
                              "activity_in_window": [], "branch_count": 0,
                              "branch_enumeration_complete": False}
                results.append(result)
                handle.write(json.dumps(result) + "\n")
                handle.flush()
                if result.get("campaign_branches"):
                    print(f"  CAMPAIGN BRANCH {result['full_name']}: "
                          f"{result['campaign_branches']}", file=sys.stderr)
                for commit in result.get("flagged_commits") or []:
                    print(f"  FLAGGED COMMIT {result['full_name']} {commit['sha']} "
                          f"{commit['flags']} {commit.get('message_first_line')}",
                          file=sys.stderr)
                if done % 20 == 0:
                    print(f"  {done}/{len(futures)}", file=sys.stderr)

    branch_errors = [{"repo": r["full_name"], "error": r["branches_error"]}
                     for r in results if r.get("branches_error")]
    activity_errors = [{"repo": r["full_name"], "error": r["activity_error"]}
                       for r in results if r.get("activity_error")]
    incomplete = [r["full_name"] for r in results
                  if not r.get("branch_enumeration_complete")]
    total_branches = sum(r.get("branch_count") or 0 for r in results)
    campaign = [{"repo": r["full_name"], "branches": r["campaign_branches"]}
                for r in results if r.get("campaign_branches")]
    flagged = [{"repo": r["full_name"], **c}
               for r in results for c in (r.get("flagged_commits") or [])]
    activity = [{"repo": r["full_name"], **a}
                for r in results for a in (r.get("activity_in_window") or [])]
    commits_inspected = sum(len(r.get("commits_inspected") or []) for r in results)
    # Recorded, not hidden. Demoting the trailer is a judgement call about this estate,
    # so the size of what it demotes is stated rather than left to be inferred.
    trailer_only = [
        {"repo": r["full_name"], "sha": c["sha"], "author_email": c.get("author_email"),
         "ref": c.get("ref"), "message_first_line": c.get("message_first_line")}
        for r in results for c in (r.get("commits_inspected") or [])
        if c.get("agent_coauthor_trailer") and not c.get("flags")
    ]

    # Controls. Branch enumeration is proven by having listed branches at all; commit
    # inspection is proven by having read commits and extracted authorship from them.
    branches_proven = total_branches > 0
    commits_proven = commits_inspected > 0 or not activity
    coverage_ok = (branches_proven and not branch_errors and not incomplete)

    coverage = {
        "repos_inspected": len(results),
        "repos_in_estate": len(records),
        "narrowing": excluded_reason,
        "narrowing_basis": (
            "pushed_at is updated by a push to any ref, not only the default branch. "
            "This is what makes the exclusion exact for pushes rather than a sample."
        ),
        "branches_enumerated": total_branches,
        "branch_enumeration_incomplete_for": incomplete,
        "branch_errors": branch_errors,
        "activity_errors": activity_errors,
        "activity_events_in_window": len(activity),
        "commits_inspected": commits_inspected,
        "campaign_branches_found": campaign,
        "flagged_commits": flagged,
        "agent_trailer_only_commits_not_flagged": {
            "count": len(trailer_only),
            "why_not_flagged": (
                "Claude Code is in normal use on this estate, so 'Co-authored-by: Claude' "
                "appears on legitimate commits. The first labs run flagged five on this "
                "trailer alone and all five were named engineers with corporate email "
                "addresses on ticket branches changing Java source. The trailer is a flag "
                "only alongside a campaign message, forged authorship or a campaign file."
            ),
            "commits": trailer_only,
        },
        "window": {"start": WINDOW_START, "end": WINDOW_END},
        "markers_checked": {
            "branch_prefix": CAMPAIGN_BRANCH_PREFIX,
            "branch_token": CAMPAIGN_BRANCH_TOKEN,
            "forged_emails": sorted(FORGED_EMAILS),
            "forged_logins": sorted(FORGED_LOGINS),
            "commit_messages": list(CAMPAIGN_COMMIT_MESSAGES),
        },
        "branch_enumeration_query_proven": branches_proven,
        "commit_inspection_query_proven": commits_proven,
        "coverage_supports_negative_finding": coverage_ok,
        "limits": [
            "Clears repositories of having RECEIVED a push during the window. It does not "
            "address a compromise that predates the window.",
            "The activity log is read to 100 entries per repository; a repository with "
            "more than 100 activity events since the window would have its oldest "
            "in-window events pushed off the page.",
            "Commit inspection covers the head commit of each in-window push, not every "
            "commit in the pushed range.",
        ],
        "activity_in_window": activity,
    }
    coverage_path.write_text(json.dumps(coverage, indent=2))
    print(f"\nwritten: {args.out}\ncoverage: {coverage_path}", file=sys.stderr)
    print(json.dumps({k: coverage[k] for k in (
        "repos_inspected", "branches_enumerated", "activity_events_in_window",
        "commits_inspected", "branch_enumeration_query_proven",
        "coverage_supports_negative_finding")}, indent=2), file=sys.stderr)
    print(f"campaign branches: {len(campaign)}   flagged commits: {len(flagged)}",
          file=sys.stderr)
    return 0 if coverage_ok else 3


if __name__ == "__main__":
    sys.exit(main())
