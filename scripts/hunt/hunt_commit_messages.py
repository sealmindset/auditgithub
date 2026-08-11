#!/usr/bin/env python3
"""Sweep commit MESSAGES across all three organizations for the campaign's own text.

The indicator this exists for
----------------------------
Unit 42 published the string the campaign leaves in the commit it pushes:

    IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOfAllThirdPartyClients

It is not an exfiltration marker or a payload hash. It is coercion aimed at the responder -
a claim that revoking the credential will take down third-party production - and it belongs
to the same step of the chain as the `gh-token-monitor` watchdog: make us hesitate before
rotating. No round of this hunt has ever queried it.

Why not just re-run the branch collector
---------------------------------------
`hunt_branches.py` reads commit messages, but only for the head commit of each in-window
push, capped at 25 per repository, and it costs two or more core-quota requests per
repository across 2,811 of them. The marker is added there for the next full run, and this
collector answers the question now: `GET /search/commits` draws on the search bucket, takes an
`org:` qualifier, and answers for an entire organization in one request.

The limit that comes with that, MEASURED and not asserted
-------------------------------------------------------
Commit search does not necessarily index commits that exist only on a non-default branch -
and this campaign commits to up to 50 side branches per repository, so that limit decides
whether this collector can support a clean finding at all. Rather than cite documentation, the
limit is measured:

  1. take candidate commits from `branches_r5.json` that were pushed to a NON-default ref;
  2. establish which of them are genuinely off the default branch, using
     `GET /repos/{org}/{repo}/compare/{default}...{sha}` - a status of `diverged` or `ahead`
     means the commit is not an ancestor of the default branch;
  3. ask commit search for each one by `hash:`;
  4. do the same for a commit that IS an ancestor of the default branch.

If the on-default commits are found and the off-default ones are not, the index's branch
coverage is a measured fact in this artifact, the negative result is correctly bounded, and
the compensating control - the marker now in `hunt_branches.py`, which enumerates every ref -
is named rather than implied.

Budget
------
`/search/commits` and `/search/code` use the search buckets, not the shared 5,000/hour core
quota. The compare calls are core, and there are at most `--control-candidates` * 2 of them.
A full run is well under fifty requests.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hunt_code_search import GITHUB_API, ORG_TOKEN_VARS, load_env  # noqa: E402

CLEAR = "CLEAR"
INCOMPLETE = "INCOMPLETE"
FINDINGS = "FINDINGS"

# The extortion string, from github_conf/ioc/chaindrop_unit42_2026_08.json
# (`github_markers.commit_message_prefix`). Searched as a prefix substring as well as whole,
# because a message that truncates or wraps it still contains the head of it.
EXTORTION_STRING = ("IfYouBlockThisAPIKeyItWillCrashTheLiveProductionServersOf"
                    "AllThirdPartyClients")
EXTORTION_PREFIX = "IfYouBlockThisAPIKey"
FORGED_AUTHOR_EMAIL = "claude@users.noreply.github.com"

QUERIES: List[Dict[str, str]] = [
    {"key": "extortion_string_full", "q": f'"{EXTORTION_STRING}"',
     "means": "the campaign's coercion message, verbatim. A hit is a compromised repository, "
              "not a lead: no legitimate commit carries this sentence"},
    {"key": "extortion_prefix", "q": f'"{EXTORTION_PREFIX}"',
     "means": "the head of the same string, for a message that truncated or re-wrapped it"},
    # Authorship, not text. This is the half hunt_branches.py can only see on the 25 head
    # commits it reads per repository; here it is answered for the whole organization.
    {"key": "forged_author_email", "q": f"author-email:{FORGED_AUTHOR_EMAIL}",
     "means": "commits authored as the identity the worm forges. Recorded as leads, because "
              "Claude Code is in normal use on this estate - the flag is this authorship "
              "TOGETHER with a campaign message or a hook file, per hunt_branches.py"},
    {"key": "campaign_message_and_forged_author",
     "q": f'"chore: update config" author-email:{FORGED_AUTHOR_EMAIL}',
     "means": "the campaign's own combination: its commit message under its forged author. "
              "This one is a finding, not a lead"},
    {"key": "campaign_selfname", "q": '"Shai-Hulud"',
     "means": "campaign self-identifier in a commit message"},
    {"key": "dead_drop_marker", "q": '"thebeautifulmarchoftime"',
     "means": "fallback-exfiltration marker; in a commit message it means the payload's "
              "strings were committed"},
]

# This hunt's own repositories hold the indicator files, so a commit that ADDS an indicator to
# them matches every query above. Same exclusion list and same reason as hunt_code_search.py:
# the match is correct behavior and a useless finding.
SELF_REPOS = ["sleepnumberinc/auditgithub", "sleepnumberlabs/auditgh",
              "sleepnumberinc/sec-diligence"]


def get_json(url: str, token: str, accept: str = "application/vnd.github+json",
             attempts: int = 4, pause: float = 0.0) -> Tuple[Optional[Any], Optional[str]]:
    """One request. A 403/429 is slept through rather than recorded.

    Recording throttling as a result turns it into a zero, and a zero is the finding this
    collector has to be able to defend.
    """
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
            if pause:
                time.sleep(pause)
            return body, None
        except urllib.error.HTTPError as exc:
            headers = exc.headers or {}
            if exc.code in (403, 429):
                retry_after = headers.get("Retry-After")
                reset = headers.get("X-RateLimit-Reset")
                if retry_after:
                    delay = float(retry_after)
                elif reset:
                    delay = max(2.0, float(reset) - time.time() + 2)
                else:
                    delay = 20.0 * (attempt + 1)
                if attempt == attempts - 1:
                    return None, f"HTTP {exc.code} after {attempts} attempts"
                print(f"    throttled, sleeping {int(delay)}s", file=sys.stderr)
                time.sleep(min(delay, 3700.0))
                continue
            if exc.code == 422:
                return None, "HTTP 422 (query rejected)"
            if exc.code >= 500 and attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            if attempt == attempts - 1:
                return None, type(exc).__name__
            time.sleep(2 ** attempt)
    return None, "exhausted attempts"


def search_commits(query: str, token: str, pause: float) -> Tuple[Optional[dict], Optional[str]]:
    url = f"{GITHUB_API}/search/commits?q={urllib.parse.quote(query)}&per_page=100"
    return get_json(url, token, pause=pause)


def pick_branch_coverage_candidates(branches_path: Path,
                                    limit: int) -> List[Dict[str, str]]:
    """Candidate commits for the control: some pushed to a non-default ref, some to the default.

    Both halves are needed. Off-default commits measure whether the index reaches side branches;
    on-default commits are the positive half that proves a zero from the first group means
    "not indexed" rather than "this query form does not work".

    The ref recorded here only selects candidates. Whether a commit is genuinely off the default
    branch is established by the compare call - a push to a side branch that was later merged is
    ON the default branch, and using it here would prove the opposite of what the control is for.
    """
    off: List[Dict[str, str]] = []
    on: List[Dict[str, str]] = []
    seen_repos: set = set()
    with branches_path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            default = record.get("default_branch")
            full = record.get("full_name")
            if not default or not full or full.lower() in SELF_REPOS or full in seen_repos:
                continue
            for commit in (record.get("commits_inspected") or []):
                sha = commit.get("sha") or ""
                ref = (commit.get("ref") or "").split("refs/heads/")[-1]
                # HTTP 422 placeholders carry an all-zero sha and no commit data.
                if commit.get("error") or not ref or set(sha) == {"0"} or len(sha) < 7:
                    continue
                bucket = on if ref == default else off
                if len(bucket) >= limit:
                    continue
                seen_repos.add(full)
                bucket.append({"full_name": full, "org": record["org"], "default": default,
                               "pushed_to_ref": ref, "sha_abbrev": sha,
                               "message_first_line": commit.get("message_first_line") or ""})
                break
            if len(off) >= limit and len(on) >= limit:
                break
    # The on-default half only has to establish that the query form works.
    return off + on[:max(2, limit // 3)]


def resolve_and_locate(candidate: Dict[str, str],
                       token: str) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Full sha and `on_default`/`off_default`, or a reason neither could be established.

    The full sha comes first because commit search's `hash:` qualifier is matched against the
    full 40-character sha, and the branch collector records 12. Then compare: `identical` and
    `behind` mean the commit is an ancestor of the default branch; `ahead` and `diverged` mean
    it is not, which is what makes it usable as a branch-coverage control.
    """
    org, repo = candidate["full_name"].split("/", 1)
    base = f"{GITHUB_API}/repos/{urllib.parse.quote(org)}/{urllib.parse.quote(repo)}"
    body, error = get_json(f"{base}/commits/{urllib.parse.quote(candidate['sha_abbrev'])}", token)
    if body is None or not isinstance(body, dict) or not body.get("sha"):
        return None, None, f"could not resolve full sha: {error}"
    full_sha = body["sha"]

    body, error = get_json(
        f"{base}/compare/{urllib.parse.quote(candidate['default'])}...{full_sha}", token)
    if body is None or not isinstance(body, dict):
        return full_sha, None, f"compare failed: {error}"
    status = body.get("status")
    if status in ("identical", "behind"):
        return full_sha, "on_default", None
    if status in ("ahead", "diverged"):
        return full_sha, "off_default", None
    return full_sha, None, f"unexpected compare status {status!r}"


def run_branch_coverage_control(candidates: List[Dict[str, str]], env: Dict[str, str],
                                pause: float) -> Dict[str, Any]:
    """Measure whether commit search returns a commit that exists only off the default branch."""
    checked: List[Dict[str, Any]] = []
    for candidate in candidates:
        token = next((env[v] for v in ORG_TOKEN_VARS.get(candidate["org"], []) if env.get(v)),
                     env.get("GITHUB_TOKEN"))
        if not token:
            continue
        full_sha, where, error = resolve_and_locate(candidate, token)
        entry = {**candidate, "sha": full_sha, "ancestry": where, "ancestry_error": error,
                 "found_by_commit_search": None, "search_error": None}
        if where and full_sha:
            body, search_error = search_commits(
                f"hash:{full_sha} org:{candidate['org']}", token, pause)
            entry["search_error"] = search_error
            if body is not None:
                entry["found_by_commit_search"] = bool(body.get("total_count"))
        checked.append(entry)
        print(f"  coverage control {candidate['full_name']} {candidate['sha_abbrev']} "
              f"{where or error} -> found={entry['found_by_commit_search']}", file=sys.stderr)

    off = [c for c in checked if c["ancestry"] == "off_default"
           and c["found_by_commit_search"] is not None]
    on = [c for c in checked if c["ancestry"] == "on_default"
          and c["found_by_commit_search"] is not None]
    off_found = [c for c in off if c["found_by_commit_search"]]
    on_found = [c for c in on if c["found_by_commit_search"]]
    return {
        "method": (
            "For each candidate: `GET /repos/{org}/{repo}/compare/{default}...{sha}` "
            "establishes whether the commit is an ancestor of the default branch, then "
            "`GET /search/commits?q=hash:{sha}` asks whether the index holds it. Two "
            "populations, one query form, and the difference between them is the measurement."),
        "commits_checked": checked,
        "off_default_checked": len(off),
        "off_default_found_by_search": len(off_found),
        "on_default_checked": len(on),
        "on_default_found_by_search": len(on_found),
        "index_covers_non_default_branches": (
            None if not off else bool(off_found)),
        "index_returns_default_branch_commits": (
            None if not on else bool(on_found)),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--branches", type=Path,
                        default=REPO_ROOT / "exports/hunt/branches_r5.json",
                        help="Source of candidate commits for the branch-coverage control.")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/commit_messages_r1.json")
    parser.add_argument("--orgs", nargs="*",
                        default=["SleepNumberInc", "sleepnumberlabs", "sleepnumber"])
    parser.add_argument("--pause", type=float, default=2.5,
                        help="Seconds between searches. The commit-search bucket is 30/minute, "
                             "so the default deliberately undershoots it.")
    parser.add_argument("--control-candidates", type=int, default=6)
    args = parser.parse_args()

    env = load_env(REPO_ROOT / ".env")

    print("=== branch-coverage control ===", file=sys.stderr)
    candidates = pick_branch_coverage_candidates(args.branches, args.control_candidates)
    coverage_control = run_branch_coverage_control(candidates, env, args.pause)

    results: Dict[str, Any] = {}
    for org in args.orgs:
        token = next((env[v] for v in ORG_TOKEN_VARS.get(org, ["GITHUB_TOKEN"])
                      if env.get(v)), None)
        if not token:
            results[org] = {"error": "no token for org"}
            print(f"{org}: no token", file=sys.stderr)
            continue

        print(f"\n=== {org} ===", file=sys.stderr)
        # Positive control: a query on the same endpoint that MUST return rows. Without it a
        # zero from an org whose commits are not indexed reads exactly like a clean estate.
        body, control_error = search_commits(f"fix org:{org}", token, args.pause)
        control_total = (body or {}).get("total_count") if body else None
        control_ok = bool(control_total)
        print(f"  positive control: total={control_total} -> usable={control_ok}",
              file=sys.stderr)

        findings: List[dict] = []
        for spec in QUERIES:
            query = f"{spec['q']} org:{org}"
            body, error = search_commits(query, token, args.pause)
            total = (body or {}).get("total_count") if body else None
            raw = [{"repo": ((it.get("repository") or {}).get("full_name")),
                    "sha": (it.get("sha") or "")[:12],
                    "author_email": (((it.get("commit") or {}).get("author")) or {}).get("email"),
                    "author_login": ((it.get("author") or {}) or {}).get("login"),
                    "committed_at": (((it.get("commit") or {}).get("committer")) or {}).get("date"),
                    "message_first_line": ((it.get("commit") or {}).get("message")
                                           or "").splitlines()[0][:200] if
                    ((it.get("commit") or {}).get("message")) else "",
                    "html_url": it.get("html_url")}
                   for it in ((body or {}).get("items") or [])]
            self_hits = [r for r in raw if str(r["repo"]).lower() in SELF_REPOS]
            matches = [r for r in raw if str(r["repo"]).lower() not in SELF_REPOS]
            findings.append({
                "key": spec["key"], "query": query, "means": spec["means"],
                "total_count": total, "error": error,
                "matches": matches, "excluded_self_matches": self_hits,
                # One page is requested. If the index holds more than it returned, the rows
                # below are a sample and the artifact has to say so - a truncated population
                # reported as a complete one is the exact failure this collector must not have.
                "rows_returned": len(raw),
                "returned_rows_are_a_sample": bool(total and total > len(raw)),
                "verdict": ("ERROR" if error else
                            "HIT" if matches else
                            "clean" if control_ok else
                            "UNKNOWN_index_unusable"),
            })
            print(f"  {spec['key']:34s} total={str(total):>6s} "
                  f"{findings[-1]['verdict']}", file=sys.stderr)

        results[org] = {
            "positive_control": {"query": f"fix org:{org}", "total_count": control_total,
                                 "error": control_error, "index_usable": control_ok,
                                 "note": ("A commit-message zero from this org is only clean "
                                          "if this control returned rows. Commit search "
                                          "answers total_count 0 with no error for an org it "
                                          "has not indexed.")},
            "findings": findings,
        }

    hits = [{"org": org, **f} for org, data in results.items()
            for f in (data.get("findings") or []) if f["verdict"] == "HIT"]
    unknown = [{"org": org, "key": f["key"]} for org, data in results.items()
               for f in (data.get("findings") or [])
               if f["verdict"] == "UNKNOWN_index_unusable"]
    errors = [{"org": org, "key": f["key"], "error": f["error"]}
              for org, data in results.items()
              for f in (data.get("findings") or []) if f["error"]]
    sampled = [{"org": org, "key": f["key"], "total_count": f["total_count"],
                "rows_returned": f["rows_returned"]}
               for org, data in results.items()
               for f in (data.get("findings") or []) if f.get("returned_rows_are_a_sample")]
    self_excluded = sum(len(f["excluded_self_matches"]) for data in results.values()
                        for f in (data.get("findings") or []))

    # Only the two unambiguous keys are compromise evidence. Forged authorship alone is not:
    # Claude Code is in normal use here, and hunt_branches.py already measured that flagging
    # the trailer alone produced five commits by named engineers on ticket branches.
    decisive = {"extortion_string_full", "extortion_prefix",
                "campaign_message_and_forged_author", "dead_drop_marker"}
    decisive_hits = [h for h in hits if h["key"] in decisive]
    lead_hits = [h for h in hits if h["key"] not in decisive]

    covers_side_branches = coverage_control["index_covers_non_default_branches"]
    unresolved: List[str] = []
    if covers_side_branches is False:
        unresolved.append(
            f"Commit search did not return any of the "
            f"{coverage_control['off_default_checked']} commit(s) this run PROVED are not "
            f"ancestors of their repository's default branch, while returning "
            f"{coverage_control['on_default_found_by_search']} of "
            f"{coverage_control['on_default_checked']} that are. So every clean result above "
            f"is clean FOR DEFAULT BRANCHES. This campaign commits to up to 50 side branches "
            f"per repository, so the compensating control is the extortion string now in the "
            f"marker set of scripts/hunt/hunt_branches.py, which enumerates every ref - and it "
            f"has not been re-run since the marker was added. Until it is, the commit-message "
            f"answer covers default branches only.")
    elif covers_side_branches is None:
        unresolved.append(
            "The branch-coverage control could not be established: no candidate commit was "
            "confirmed to be off its default branch. The commit-search results cannot be "
            "bounded, so they are reported as untested for non-default branches rather than "
            "as clean.")
    for item in errors:
        unresolved.append(
            f"Query `{item['key']}` against {item['org']} did not execute: {item['error']}. "
            f"That indicator is untested for that organization, not absent from it.")
    for item in sampled:
        unresolved.append(
            f"`{item['key']}` against {item['org']} reported {item['total_count']} matching "
            f"commits and returned {item['rows_returned']}. The rows in this artifact are a "
            f"sample of that population, not all of it; re-run with pagination before treating "
            f"the listed commits as the full set.")
    for item in unknown:
        unresolved.append(
            f"`{item['key']}` returned zero from {item['org']} while the positive control "
            f"also returned zero, so the organization's commits are not demonstrably indexed. "
            f"Reported as UNKNOWN rather than clean.")

    # The coverage axis, which is what makes each zero above readable. Strings, one claim each,
    # every number taken from the run rather than restated.
    coverage: List[str] = []
    for org, data in results.items():
        control = data.get("positive_control") or {}
        if control.get("total_count") is None:
            coverage.append(f"{org}: the positive control did not execute "
                            f"({control.get('error')}), so nothing below is a measured zero "
                            f"for this organization.")
        else:
            coverage.append(
                f"{org} positive control: the same endpoint and query form returned "
                f"{control['total_count']:,} commits for a benign term. Every zero below for "
                f"this organization is therefore a measured absence, not an unindexed org.")
    if coverage_control["on_default_checked"]:
        coverage.append(
            f"Branch coverage, measured not assumed: "
            f"{coverage_control['on_default_found_by_search']} of "
            f"{coverage_control['on_default_checked']} commit(s) proved by "
            f"`GET /repos/../compare` to be ancestors of their default branch were returned by "
            f"`hash:` search, against "
            f"{coverage_control['off_default_found_by_search']} of "
            f"{coverage_control['off_default_checked']} proved NOT to be. That difference is "
            f"the index's branch coverage, and it bounds every result in this artifact.")
    if self_excluded:
        coverage.append(
            f"{self_excluded} match(es) were in this hunt's own repositories "
            f"({', '.join(SELF_REPOS)}) - commits that ADD the indicator to the IOC corpus. "
            f"Excluded from findings and written out verbatim under "
            f"`excluded_self_matches`, because a rule that deleted them silently would "
            f"eventually delete a real hit in a repository whose name happens to match.")

    coverage_gaps: List[Dict[str, str]] = []
    if covers_side_branches is False:
        coverage_gaps.append({
            "gap": "Commits that exist only on a non-default branch are not in the index this "
                   "vector queries.",
            "population": (f"Every commit in all {len(args.orgs)} organizations that is not an "
                           f"ancestor of its repository's default branch. Bounded, not "
                           f"estimated: {coverage_control['off_default_checked']} such commits "
                           f"were tested and {coverage_control['off_default_found_by_search']} "
                           f"were returned."),
            "named_by": ("exports/hunt/branches_r5.json - `commits_inspected[].ref`, which "
                         "records the ref each inspected commit was pushed to, and "
                         "`branch_count` per repository"),
            "cannot_confirm_or_deny": ("whether the extortion string or the campaign's commit "
                                       "message appears on a side branch, which is exactly "
                                       "where this campaign pushes"),
            "closed_by": ("re-running scripts/hunt/hunt_branches.py, which enumerates every ref "
                          "and now carries the extortion string in CAMPAIGN_COMMIT_MESSAGES"),
            "owner": "Security Engineering",
        })

    status = FINDINGS if decisive_hits else (INCOMPLETE if unresolved else CLEAR)
    artifact = {
        "name": "Commit-message sweep - the campaign's extortion string and forged authorship",
        "status": status,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scope": (f"All commits indexed by GitHub commit search across "
                  f"{', '.join(args.orgs)}, {len(QUERIES)} indicators. Bounded by the measured "
                  f"branch coverage below."),
        "counts": {
            "Organizations queried": len(args.orgs),
            "Indicators queried per organization": len(QUERIES),
            "Decisive hits (a hit is a compromised repository)": len(decisive_hits),
            "Leads requiring corroboration": len(lead_hits),
            "Queries that failed to execute": len(errors),
            "Zeros that cannot support a clean finding": len(unknown),
            "Results that returned a sample rather than the whole population": len(sampled),
            "Matches in this hunt's own repositories, excluded as correct behavior":
                self_excluded,
            "Commits used for the branch-coverage control":
                len(coverage_control["commits_checked"]),
            "Of those, proved to be off the default branch":
                coverage_control["off_default_checked"],
            "Of those, returned by commit search":
                coverage_control["off_default_found_by_search"],
        },
        "coverage": coverage,
        "coverage_gaps": coverage_gaps,
        "branch_coverage_control": coverage_control,
        "indicators": {"extortion_string": EXTORTION_STRING,
                       "extortion_prefix": EXTORTION_PREFIX,
                       "forged_author_email": FORGED_AUTHOR_EMAIL,
                       "source": "github_conf/ioc/chaindrop_unit42_2026_08.json, "
                                 "github_markers.commit_message_prefix"},
        "unresolved_items": unresolved,
        "findings": [
            {"id": f"commit-{h['org']}-{h['key']}",
             "what": (f"{h['key']} matched {len(h['matches'])} commit(s) in {h['org']}: "
                      f"{h['means']}"),
             "severity": "critical", "evidence": h["matches"][:20]}
            for h in decisive_hits
        ],
        "leads": lead_hits,
        "excluded_repos": SELF_REPOS,
        "orgs": results,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, default=str) + "\n")

    print(f"\n[commit-messages] {status} -> {args.out}", file=sys.stderr)
    for key, value in artifact["counts"].items():
        print(f"  {key}: {value}")
    for item in unresolved:
        print(f"  UNREAD: {item[:200]}")
    for finding in artifact["findings"]:
        print(f"  FINDING: {finding['what']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
