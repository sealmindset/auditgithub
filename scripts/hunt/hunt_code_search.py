#!/usr/bin/env python3
"""
Hunt CHAINDROP file and content indicators via GitHub code search.

Why code search rather than another tree sweep
---------------------------------------------
The tree sweep (collect_repo_trees.py) reads one recursive tree per repository — 2,810
requests against the core quota, which this hunt has already exhausted once. Code search
draws on a separate bucket (`code_search`, 10 requests/minute) and answers a filename or
content question across an entire organization in a single request. For the indicators
learned late from the Elastic and JFrog write-ups, that is the difference between a
30-request hunt and a full re-sweep.

It also reaches indicators a tree sweep cannot. `thebeautifulmarchoftime`, the Ethereum
C2 address and the campaign's domains live *inside* files; a tree only lists paths.

The coverage control is mandatory, not optional
----------------------------------------------
GitHub's code search index is not guaranteed to cover every repository — archived repos,
forks, very large files and recently-created repositories can all be missing or stale,
and a query against an unindexed org returns `total_count: 0` with no error. That is
indistinguishable from "the indicator is absent", which is the exact failure this hunt
keeps having to design against.

So every org is first asked a question that MUST have answers (a filename known from the
tree sweep to exist in that org, with the count the sweep found). If the control returns
zero, every other zero for that org is reported as UNKNOWN rather than as clean. The
control's count is also compared against the sweep's count to show how complete the index
is, because an index that finds 3 of 300 known files is technically working and still
cannot support a negative finding.

Note on `filename:` and paths
----------------------------
Code search matches `filename:` on the basename. A path-qualified indicator such as
`.github/workflows/codeql_analysis.yml` is therefore searched by basename and the returned
paths are checked, rather than trusting the query to have been path-precise.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")

ORG_TOKEN_VARS = {
    "SleepNumberInc": ["ORG_SLEEPNUMBERINC_TOKEN", "GITHUB_TOKEN"],
    "sleepnumberlabs": ["ORG_SLEEPNUMBERLABS_TOKEN"],
    "sleepnumber": ["ORG_SLEEPNUMBER_TOKEN", "GITHUB_TOKEN"],
}

# Indicators, each tagged with what a hit would mean. Sourced from the Elastic CHAINDROP
# analysis and JFrog's write-up; the campaign's own loader/payload names plus the Actions
# exfiltration workflow and the in-file markers.
QUERIES: List[Dict[str, str]] = [
    # --- dropped files -------------------------------------------------------
    {"key": "setup.mjs", "q": "filename:setup.mjs",
     "means": "npm preinstall dropper, or the IDE-autostart copy"},
    {"key": "math_init.js", "q": "filename:math_init.js",
     "means": "worm payload (727,680 B at the known hash)"},
    {"key": "Math_Symbol.js", "q": "filename:Math_Symbol.js",
     "means": "payload variant shipped in keyv-monorepo packages"},
    {"key": "codeql_analysis.yml", "q": "filename:codeql_analysis.yml",
     "means": "GitHub Actions exfiltration workflow planted by the worm",
     "expect_path": ".github/workflows/codeql_analysis.yml"},
    # Unit 42, 2026-08-10. A third dropped file, named with no hash published, so this is
    # the only way to look for it short of reading every tree. A hit is a lead: the file
    # has to be read before it is called anything else.
    {"key": "router_runtime.js", "q": "filename:router_runtime.js",
     "means": "third dropped payload file named by Unit 42; no published hash, so a hit "
              "is a lead until the contents are read"},
    # --- dependency-injection marker -----------------------------------------
    # Cycode calls @opensearch/setup a malicious optionalDependencies entry added before
    # the patch-bump republish; Unit 42 calls it a typosquat of the @opensearch-project
    # scope injected on the OIDC trusted-publishing path. Both agree it is malicious when
    # present, which is all a search needs. The authoritative answer comes from the
    # dependency inventory, not from here - code search is corroborating only (§0.3).
    {"key": "opensearch_setup_dep", "q": "\"@opensearch/setup\"",
     "means": "worm dependency-injection marker; no legitimate package declares it"},
    {"key": "node_runtime_init", "q": "\"_NODE_RUNTIME_INIT\"",
     "means": "the payload's recursion guard, set in the process environment. Present in "
              "a repository only if the payload or a copy of it was committed"},
    # --- in-file markers -----------------------------------------------------
    {"key": "marker_march", "q": "\"thebeautifulmarchoftime\"",
     "means": "signed GitHub fallback-exfiltration marker"},
    {"key": "marker_snads", "q": "\"thebeautifulsnadsoftime\"",
     "means": "second fallback marker variant (JFrog)"},
    {"key": "eth_c2", "q": "\"0xE1f2395ee43e45A1556EC6438a88c31B83493103\"",
     "means": "Ethereum smart-contract C2 resolver address"},
    {"key": "domain_npm_cache", "q": "\"npm-cache.com\"",
     "means": "campaign C2 / lure domain"},
    {"key": "domain_icu", "q": "\"awqhnjewqjkl.icu\"",
     "means": "campaign C2 domain"},
    {"key": "shai_hulud_str", "q": "\"Shai-Hulud\"",
     "means": "campaign self-identifier, used in repo descriptions and commit text"},
    {"key": "bypass_2fa", "q": "\"bypass_2fa\"",
     "means": "npm token setting the worm requires to republish"},
    # --- hook wiring ---------------------------------------------------------
    {"key": "sessionstart_node", "q": "\"SessionStart\" \"setup.mjs\"",
     "means": "Claude SessionStart hook wired to the dropper"},
    {"key": "folderopen_node", "q": "\"folderOpen\" \"setup.mjs\"",
     "means": "VS Code folderOpen task wired to the dropper"},
    # --- Bun bootstrap, including the Windows binary -------------------------
    # These are text queries on purpose. `filename:bun.exe` is deliberately NOT here:
    # GitHub's code-search index excludes binaries, so a committed bun.exe returns
    # total_count 0 from this API and the zero would be an artifact of the index, not a
    # fact about the estate. Binary presence is answered authoritatively by the tree
    # sweep (collect_repo_trees.py, bun_artifact_hits), which reads the git tree itself.
    #
    # A hit here is a lead about *provenance*, not a detection. Bun is a legitimate
    # runtime; the question a hit raises is which build step fetches it, from where, and
    # whether that step is pinned.
    {"key": "bun_exe_string", "q": "\"bun.exe\"",
     "means": "Windows Bun binary referenced in a script, workflow or task file. The "
              "campaign's bun-windows-*.zip assets unpack to this name into %TEMP%, "
              "which is the Windows form of the /tmp/bun-dl- bootstrap"},
    {"key": "bun_release_cdn", "q": "\"oven-sh/bun/releases/download\"",
     "means": "direct fetch of a Bun release binary — the dropper's first hop, and the "
              "one origin an egress allowlist would have to cover"},
    {"key": "bun_windows_asset", "q": "\"bun-windows-x64-baseline\"",
     "means": "the exact Windows release asset named in the StepSecurity fetch list"},
    {"key": "bun_staging_stem", "q": "\"bun-dl-\"",
     "means": "the dropper's mkdtemp staging stem, which is platform-independent even "
              "though the documented path (/tmp/bun-dl-) is not"},
]


def load_env(path: Path) -> Dict[str, str]:
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def search(query: str, token: str, pause: float,
           attempts: int = 4) -> Tuple[Optional[dict], Optional[str]]:
    """
    One code-search request, paced to stay inside the 10/minute bucket.

    A 403 here is retried rather than recorded: throttling that is recorded as a result
    becomes a zero, and a zero is the finding this whole script exists to make trustworthy.
    """
    url = (f"{GITHUB_API}/search/code?q={urllib.parse.quote(query)}"
           f"&per_page=100")
    for attempt in range(attempts):
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                body = json.loads(response.read().decode("utf-8", errors="replace"))
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
                    delay = 30.0 * (attempt + 1)
                print(f"    throttled, sleeping {int(delay)}s", file=sys.stderr)
                time.sleep(delay)
                continue
            if exc.code == 422:
                # Unprocessable: the query itself is rejected (unsupported syntax).
                return None, "HTTP 422 (query rejected)"
            if exc.code >= 500 and attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts - 1:
                return None, f"{type(exc).__name__}"
            time.sleep(2 ** attempt)
    return None, "rate limited beyond retries"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/code_search_hunt.json")
    parser.add_argument("--orgs", nargs="*",
                        default=["SleepNumberInc", "sleepnumberlabs", "sleepnumber"])
    parser.add_argument("--pause", type=float, default=7.0,
                        help="Seconds between searches. The bucket is 10/minute, so the "
                             "default deliberately undershoots it.")
    parser.add_argument("--exclude-repos", nargs="*",
                        default=["SleepNumberInc/auditgithub", "sleepnumberlabs/auditgh",
                                 "SleepNumberInc/sec-diligence"],
                        help="Repositories whose matches are the hunt's own reference "
                             "material rather than findings.")
    args = parser.parse_args()
    # An IOC hunt run from inside the estate it is hunting will find its own IOC database.
    # The first run reported 7 hits; every content hit was this repository's
    # github_conf/ioc/*.json and docs/playbooks/*.md, plus a sibling audit tool's
    # CHANGELOG. Those are the files that define the indicators, so matching them is
    # correct behavior and a useless finding. Excluded by name, and the exclusions are
    # recorded in the output so the omission is visible rather than silent.
    excluded = {name.lower() for name in args.exclude_repos}

    env = load_env(REPO_ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith(("GITHUB_", "ORG_"))})

    # Build each org's control from the sweep: a basename the sweep proved is present,
    # and how many repositories it appeared in.
    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    control_counts: Counter = Counter()
    for record in records:
        if not record.get("tree_ok"):
            continue
        if any(p.rsplit("/", 1)[-1] == "package-lock.json"
               for p in (record.get("npm_manifests") or [])):
            control_counts[record["org"]] += 1

    results: Dict[str, dict] = {}
    for org in args.orgs:
        token = next((env[v] for v in ORG_TOKEN_VARS.get(org, ["GITHUB_TOKEN"])
                      if env.get(v)), None)
        if not token:
            results[org] = {"error": "no token for org"}
            print(f"{org}: no token", file=sys.stderr)
            continue

        print(f"\n=== {org} ===", file=sys.stderr)
        org_out: Dict[str, object] = {}

        # Control first. Everything after it is interpreted through its outcome.
        expected = control_counts.get(org, 0)
        body, error = search(f"filename:package-lock.json org:{org}", token, args.pause)
        found = (body or {}).get("total_count") if body else None
        index_works = bool(found)
        # A repository containing package-lock.json contains at least one such FILE, so a
        # working index must return at least as many files as the sweep found repositories.
        # Measured on this estate: SleepNumberInc 103 files against 295 repositories, so
        # the index covers roughly a third of the org. That is enough to prove a hit and
        # nowhere near enough to prove an absence, which is why the ratio is carried
        # through to every verdict instead of being reduced to a usable/unusable boolean.
        ratio = (found / expected) if (expected and found is not None) else None
        index_complete = bool(ratio is not None and ratio >= 1.0)
        org_out["control"] = {
            "query": f"filename:package-lock.json org:{org}",
            "repos_with_file_per_tree_sweep": expected,
            "code_search_total_count": found,
            "error": error,
            "index_usable": index_works,
            "index_files_per_known_repo": round(ratio, 3) if ratio is not None else None,
            "index_complete_enough_for_negative_findings": index_complete,
            "note": (
                "Every repository holding package-lock.json holds at least one such file, "
                "so files >= repos is the floor for a complete index. A ratio below 1.0 "
                "is a lower bound on how much of the org is missing from the index, and "
                "any zero from this org is correspondingly weak."
            ),
        }
        print(f"  control: sweep says {expected} repos have package-lock.json; "
              f"code search files={found}; ratio={ratio if ratio is None else round(ratio,2)} "
              f"-> usable={index_works} complete={index_complete}", file=sys.stderr)

        findings: List[dict] = []
        for spec in QUERIES:
            query = f"{spec['q']} org:{org}"
            body, error = search(query, token, args.pause)
            total = (body or {}).get("total_count") if body else None
            raw_items = [
                {"repo": it["repository"]["full_name"], "path": it.get("path")}
                for it in ((body or {}).get("items") or [])
            ]
            self_hits = [i for i in raw_items if i["repo"].lower() in excluded]
            items = [i for i in raw_items if i["repo"].lower() not in excluded]

            if spec.get("expect_path"):
                exact = [i for i in items
                         if (i["path"] or "").lower() == spec["expect_path"].lower()]
            elif spec["q"].startswith("filename:"):
                # `filename:` matches tokenized names, not exact basenames:
                # "filename:setup.mjs" returned scripts/gh-session-setup.mjs. Requiring
                # the basename to match exactly keeps a legitimately-named file from
                # being reported as the campaign's dropper.
                wanted = spec["q"].split(":", 1)[1].strip('"').lower()
                exact = [i for i in items
                         if (i["path"] or "").rsplit("/", 1)[-1].lower() == wanted]
            else:
                exact = items
            near_misses = [i for i in items if i not in exact]
            entry = {
                "key": spec["key"], "query": query, "means": spec["means"],
                "total_count": total, "error": error,
                "matches": exact[:100],
                "near_misses_same_token_different_basename": near_misses[:20],
                "excluded_self_matches": self_hits[:20],
                # A zero is only a clean result if the index demonstrably covers the org.
                # index_usable proves it returns something; index_ratio says how much.
                "verdict": (
                    "ERROR" if error else
                    "HIT" if exact else
                    "clean" if index_complete else
                    "weak_zero_partial_index" if index_works else
                    "UNKNOWN_index_unusable"
                ),
            }
            findings.append(entry)
            flag = "  <-- HIT" if entry["verdict"] == "HIT" else ""
            print(f"  {spec['key']:22s} total={str(total):>6s} "
                  f"{entry['verdict']}{flag}", file=sys.stderr)
        org_out["findings"] = findings
        results[org] = org_out

    hits = [
        {"org": org, **f}
        for org, data in results.items()
        for f in (data.get("findings") or [])
        if f["verdict"] == "HIT"
    ]
    unknown = [
        {"org": org, "key": f["key"], "verdict": f["verdict"]}
        for org, data in results.items()
        for f in (data.get("findings") or [])
        if f["verdict"] in ("UNKNOWN_index_unusable", "weak_zero_partial_index")
    ]
    payload = {
        "orgs": results,
        "hits": hits,
        "excluded_repos": sorted(excluded),
        "zeros_not_supporting_a_clean_finding": unknown,
        "interpretation": [
            "A zero is 'clean' only where the control proved the index returns at least as "
            "many files as the sweep found repositories. Below that it is "
            "weak_zero_partial_index, and with no control results at all it is "
            "UNKNOWN_index_unusable — code search returns total_count 0 for an unindexed "
            "org with no error, which is indistinguishable from absence.",
            "Matches inside this hunt's own repositories are excluded by name. They are "
            "the files that define the indicators; matching them is correct and useless. "
            "The first run reported 7 hits and every content hit was of this kind.",
            "filename: matches on basename. For path-qualified indicators the returned "
            "paths are re-checked, and basename-only matches are listed separately as "
            "leads rather than counted as hits.",
            "Code search does not replace the tree sweep: coverage of archived repos, "
            "forks and very large files is not guaranteed. It complements it, and reaches "
            "in-file content that a tree listing cannot.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"\nwritten: {args.out}", file=sys.stderr)
    print(f"HITS: {len(hits)}   zeros that cannot support a clean finding: {len(unknown)}",
          file=sys.stderr)
    for hit in hits:
        print(f"  HIT {hit['org']} {hit['key']}: {hit['means']}", file=sys.stderr)
        for match in hit["matches"][:10]:
            print(f"      {match['repo']}  {match['path']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
