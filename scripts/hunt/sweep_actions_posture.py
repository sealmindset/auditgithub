#!/usr/bin/env python3
"""
Threat-agnostic GitHub Actions supply-chain posture sweep.

Why this is separate from the CHAINDROP hunt
--------------------------------------------
Everything else in scripts/hunt/ asks "did THIS campaign touch us". That question has a
short shelf life: it is answered by indicators that a specific actor happened to leave
behind, and a clean answer says nothing about the next campaign. This sweep asks the
durable question instead — what would let a supply-chain attacker succeed here regardless
of which package or which worm.

CHAINDROP's own exfiltration step was a planted workflow using the repository's Actions
token. That step succeeds or fails on posture, not on indicators: whether workflows pin
what they run, whether the default token is write-scoped, and whether untrusted code can
reach a privileged context.

What is measured
----------------
  * Unpinned third-party actions. `uses: some/action@v4` resolves a mutable tag; the tag
    owner can repoint it at any commit. Same-org actions are counted separately because
    the trust boundary is different, not because mutability is.
  * `pull_request_target` and `workflow_run` combined with a checkout of the pull
    request's head. That pair runs untrusted code with the base repository's secrets and
    is the highest-severity Actions misconfiguration there is.
  * Absent `permissions:` blocks. Without one the workflow gets the repository default,
    which on many organisations is still read-write on contents.
  * Self-hosted runners, where a compromised job can persist on the host between jobs.
  * Piped remote code (`curl ... | sh`) in run steps.
  * Secrets interpolated directly into `run:` script bodies, where they land in process
    arguments rather than the environment.

Each is reported as a count with the evidence attached, not as a pass or fail. Which of
these are acceptable is an organisational decision; the sweep's job is to make the
current state legible.

Coverage
--------
Workflow files found versus read is reported per organisation, and a run whose read rate
falls below the threshold is marked as not supporting any statement about prevalence.
"""

from __future__ import annotations

import argparse
import json
import re
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

# `uses:` values. A 40-hex ref is a commit pin; anything else is a mutable ref.
USES_RE = re.compile(r"^\s*-?\s*uses\s*:\s*['\"]?([^'\"\s#]+)", re.MULTILINE)
SHA_RE = re.compile(r"^[0-9a-f]{40}$")
PERMISSIONS_RE = re.compile(r"^\s*permissions\s*:", re.MULTILINE)
RUNS_ON_RE = re.compile(r"^\s*runs-on\s*:\s*(.+)$", re.MULTILINE)
ON_BLOCK_RE = re.compile(r"^(?:on|\"on\"|'on')\s*:", re.MULTILINE)
# A checkout that takes the pull request's head rather than the merge commit.
PR_HEAD_CHECKOUT_RE = re.compile(
    r"ref\s*:\s*\$\{\{\s*github\.event\.pull_request\.head\.(?:sha|ref)\s*\}\}")
CURL_PIPE_RE = re.compile(r"(?:curl|wget)[^\n|]{0,200}\|\s*(?:sudo\s+)?(?:ba)?sh")
SECRET_IN_RUN_RE = re.compile(r"\$\{\{\s*secrets\.[A-Za-z0-9_]+\s*\}\}")
# The exfil primitive itself, not the two filenames it has been seen under. Both
# documented variants -- `codeql_analysis.yml` on a dependabot branch, and a workflow
# named `Run Copilot` on push -- do one thing: serialise the whole secrets context and
# upload it. Keying on either filename misses the other, and misses the next one.
TOJSON_SECRETS_RE = re.compile(r"toJSON\s*\(\s*secrets\s*\)", re.IGNORECASE)
# Bun bootstrap in CI, including the Windows binary. `bun.exe` is listed explicitly
# because the Windows release assets unpack to that name and every earlier pass modelled
# the bootstrap as POSIX (mkdtemp('/tmp/bun-dl-') + chmod 755), which cannot match on a
# windows-latest runner. A hit is a provenance question, not a finding: setup-bun and a
# pinned Bun install are both legitimate and common.
BUN_FETCH_RE = re.compile(
    r"oven-sh/bun/releases/download|bun-windows-[a-z0-9-]+\.zip|bun-dl-|bun\.exe",
    re.IGNORECASE)

# Actions published by GitHub itself. Still mutable, but the tag owner is the platform,
# so they are separated from arbitrary third parties rather than being excused.
FIRST_PARTY_OWNERS = {"actions", "github"}


def get(url: str, token: str, throttle: Throttle, raw: bool = False,
        attempts: int = 4) -> Tuple[Optional[object], Optional[str]]:
    accept = ("application/vnd.github.raw" if raw else "application/vnd.github+json")
    for attempt in range(attempts):
        throttle.wait()
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                throttle.observe(response.headers)
                body = response.read()
                if raw:
                    return body.decode("utf-8", errors="replace"), None
                return json.loads(body.decode("utf-8", errors="replace")), None
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


def analyse_workflow(path: str, text: str) -> dict:
    out: Dict[str, object] = {"path": path, "bytes": len(text)}

    unpinned_third_party: List[str] = []
    unpinned_first_party: List[str] = []
    unpinned_same_repo_org: List[str] = []
    pinned = 0
    for raw_use in USES_RE.findall(text):
        use = raw_use.strip()
        if use.startswith("./") or use.startswith("docker://"):
            continue  # local composite action or an image reference, not a tag pin
        action, _, ref = use.partition("@")
        if not ref:
            continue
        if SHA_RE.match(ref):
            pinned += 1
            continue
        owner = action.split("/", 1)[0].lower()
        if owner in FIRST_PARTY_OWNERS:
            unpinned_first_party.append(use)
        elif owner in ("sleepnumberinc", "sleepnumberlabs", "sleepnumber"):
            unpinned_same_repo_org.append(use)
        else:
            unpinned_third_party.append(use)

    triggers: List[str] = []
    for trigger in ("pull_request_target", "workflow_run", "issue_comment",
                    "workflow_call", "repository_dispatch", "schedule"):
        if re.search(rf"^\s*{trigger}\s*:", text, re.MULTILINE):
            triggers.append(trigger)

    runners = [r.strip() for r in RUNS_ON_RE.findall(text)]
    self_hosted = [r for r in runners if "self-hosted" in r.lower()]

    pr_head_checkout = bool(PR_HEAD_CHECKOUT_RE.search(text))
    privileged_trigger = any(t in triggers for t in ("pull_request_target", "workflow_run"))

    out.update({
        "actions_pinned_to_sha": pinned,
        "unpinned_third_party": sorted(set(unpinned_third_party)),
        "unpinned_first_party_github": sorted(set(unpinned_first_party)),
        "unpinned_same_org": sorted(set(unpinned_same_repo_org)),
        "triggers": triggers,
        "self_hosted_runners": sorted(set(self_hosted)),
        "declares_permissions": bool(PERMISSIONS_RE.search(text)),
        "checks_out_pr_head": pr_head_checkout,
        # The critical pair: untrusted code checked out into a context that holds the base
        # repository's secrets.
        "privileged_trigger_with_pr_head_checkout": bool(
            privileged_trigger and pr_head_checkout),
        "pipes_remote_code_to_shell": len(CURL_PIPE_RE.findall(text)),
        "secrets_interpolated_in_run": len(set(SECRET_IN_RUN_RE.findall(text))),
        "serialises_whole_secrets_context": bool(TOJSON_SECRETS_RE.search(text)),
        "bun_fetch_markers": sorted({m.lower() for m in BUN_FETCH_RE.findall(text)}),
        "references_bun_exe": bool(re.search(r"bun\.exe", text, re.IGNORECASE)),
        "has_on_block": bool(ON_BLOCK_RE.search(text)),
    })
    return out


def sweep_repo(record: dict, token: str, throttle: Throttle,
               max_files: int) -> dict:
    org, repo = record["org"], record["repo"]
    ref = record.get("branch_inspected") or record.get("default_branch")
    out: Dict[str, object] = {
        "full_name": record["full_name"], "org": org, "ref": ref,
        "archived": record.get("archived"), "pushed_at": record.get("pushed_at"),
        "listing_error": None, "workflows_found": 0, "workflows_read": 0,
        "read_errors": [], "workflows": [],
    }

    url = (f"{GITHUB_API}/repos/{org}/{repo}/contents/"
           f".github/workflows?ref={urllib.parse.quote(str(ref))}")
    body, error = get(url, token, throttle)
    if body is None:
        out["listing_error"] = error
        return out
    if not isinstance(body, list):
        out["listing_error"] = "not a directory"
        return out

    files = [entry for entry in body
             if entry.get("type") == "file"
             and str(entry.get("name", "")).lower().endswith((".yml", ".yaml"))]
    out["workflows_found"] = len(files)
    for entry in files[:max_files]:
        raw_url = (f"{GITHUB_API}/repos/{org}/{repo}/contents/"
                   f"{urllib.parse.quote(entry['path'])}?ref={urllib.parse.quote(str(ref))}")
        text, error = get(raw_url, token, throttle, raw=True)
        if text is None:
            out["read_errors"].append({"path": entry["path"], "error": error})
            continue
        out["workflows_read"] += 1
        out["workflows"].append(analyse_workflow(entry["path"], text))
    if len(files) > max_files:
        out["workflows_truncated_at"] = max_files
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/actions_posture.jsonl")
    parser.add_argument("--only-orgs", nargs="*", default=None)
    parser.add_argument("--max-files", type=int, default=30,
                        help="Workflow files per repository. Repositories exceeding this "
                             "are recorded as truncated.")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--min-interval", type=float, default=0.32)
    parser.add_argument("--min-read-rate", type=float, default=0.95)
    args = parser.parse_args()
    coverage_path = args.out.with_name(args.out.stem + "_coverage.json")

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    targets = [r for r in records if (r.get("workflow_count") or 0) > 0]
    if args.only_orgs:
        wanted = {o.lower() for o in args.only_orgs}
        targets = [r for r in targets if r["org"].lower() in wanted]

    env = load_env(REPO_ROOT / ".env")
    print(f"repositories with workflow files: {len(targets)}", file=sys.stderr)

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
                futures[pool.submit(sweep_repo, record, token, throttle,
                                    args.max_files)] = record
            for done, future in enumerate(as_completed(futures), 1):
                record = futures[future]
                try:
                    result = future.result()
                except Exception as exc:  # noqa: BLE001
                    result = {"full_name": record["full_name"], "org": record["org"],
                              "listing_error": f"worker crash: {exc}",
                              "workflows_found": 0, "workflows_read": 0,
                              "read_errors": [], "workflows": []}
                results.append(result)
                handle.write(json.dumps(result) + "\n")
                handle.flush()
                for workflow in result.get("workflows") or []:
                    if workflow.get("privileged_trigger_with_pr_head_checkout"):
                        print(f"  CRITICAL {result['full_name']} {workflow['path']}: "
                              f"{workflow['triggers']} + PR head checkout",
                              file=sys.stderr)
                if done % 50 == 0:
                    print(f"  {done}/{len(futures)}", file=sys.stderr)

    workflows = [(r["full_name"], w) for r in results for w in (r.get("workflows") or [])]
    found = sum(r.get("workflows_found") or 0 for r in results)
    read = sum(r.get("workflows_read") or 0 for r in results)
    read_rate = (read / found) if found else 0.0

    critical = [{"repo": name, "path": w["path"], "triggers": w["triggers"]}
                for name, w in workflows
                if w.get("privileged_trigger_with_pr_head_checkout")]
    self_hosted = [{"repo": name, "path": w["path"], "runners": w["self_hosted_runners"]}
                   for name, w in workflows if w.get("self_hosted_runners")]
    curl_pipe = [{"repo": name, "path": w["path"],
                  "occurrences": w["pipes_remote_code_to_shell"]}
                 for name, w in workflows if w.get("pipes_remote_code_to_shell")]
    no_permissions = [f"{name}:{w['path']}" for name, w in workflows
                      if not w.get("declares_permissions")]
    secrets_in_run = [{"repo": name, "path": w["path"],
                       "distinct_secrets": w["secrets_interpolated_in_run"]}
                      for name, w in workflows if w.get("secrets_interpolated_in_run")]
    # §6 check 8 of the hunt TTP, added 2026-08-06 and never executed until now.
    tojson_secrets = [{"repo": name, "path": w["path"]}
                      for name, w in workflows
                      if w.get("serialises_whole_secrets_context")]
    bun_fetch = [{"repo": name, "path": w["path"],
                  "markers": w["bun_fetch_markers"],
                  "references_bun_exe": w.get("references_bun_exe")}
                 for name, w in workflows if w.get("bun_fetch_markers")]

    third_party = Counter()
    for _, workflow in workflows:
        for use in workflow.get("unpinned_third_party") or []:
            third_party[use] += 1
    unpinned_first_party = Counter()
    for _, workflow in workflows:
        for use in workflow.get("unpinned_first_party_github") or []:
            unpinned_first_party[use] += 1

    pinned_total = sum(w.get("actions_pinned_to_sha") or 0 for _, w in workflows)
    unpinned_total = sum(
        len(w.get("unpinned_third_party") or []) + len(w.get("unpinned_first_party_github") or [])
        + len(w.get("unpinned_same_org") or [])
        for _, w in workflows)

    coverage_ok = read_rate >= args.min_read_rate and read > 0
    coverage = {
        "repos_swept": len(results),
        "workflow_files_found": found,
        "workflow_files_read": read,
        "read_rate": round(read_rate, 4),
        "coverage_supports_prevalence_claims": coverage_ok,
        "listing_errors": [{"repo": r["full_name"], "error": r["listing_error"]}
                           for r in results if r.get("listing_error")],
        "read_errors": [{"repo": r["full_name"], **e}
                        for r in results for e in (r.get("read_errors") or [])],
        "repos_truncated": [r["full_name"] for r in results
                            if r.get("workflows_truncated_at")],
        "counts": {
            "workflows_analysed": len(workflows),
            "action_refs_pinned_to_sha": pinned_total,
            "action_refs_on_mutable_refs": unpinned_total,
            "workflows_without_permissions_block": len(no_permissions),
            "workflows_with_self_hosted_runners": len(self_hosted),
            "workflows_piping_remote_code_to_shell": len(curl_pipe),
            "workflows_interpolating_secrets_into_run": len(secrets_in_run),
            "workflows_serialising_whole_secrets_context": len(tojson_secrets),
            "workflows_fetching_bun": len(bun_fetch),
            "workflows_referencing_bun_exe": sum(
                1 for b in bun_fetch if b["references_bun_exe"]),
            "CRITICAL_privileged_trigger_with_pr_head_checkout": len(critical),
        },
        "critical_privileged_trigger_with_pr_head_checkout": critical,
        "serialises_whole_secrets_context": tojson_secrets,
        "bun_fetch_workflows": bun_fetch,
        "self_hosted_runner_workflows": self_hosted,
        "remote_code_piped_to_shell": curl_pipe,
        "secrets_interpolated_into_run": secrets_in_run[:200],
        "most_common_unpinned_third_party_actions": third_party.most_common(40),
        "most_common_unpinned_github_actions": unpinned_first_party.most_common(20),
        "interpretation": [
            "An action on a mutable ref is a standing write primitive for whoever controls "
            "that ref. This is the same class of exposure the npm dependency hunt measured, "
            "in a different ecosystem, and it is not addressed by anything in the CHAINDROP "
            "indicator set.",
            "pull_request_target or workflow_run combined with a checkout of the pull "
            "request head runs untrusted code with the base repository's secrets. Any hit "
            "here is a standalone critical finding independent of any campaign.",
            "A workflow with no permissions block inherits the organisation default. Where "
            "that default is read-write, a planted step can commit — which is exactly the "
            "capability CHAINDROP's exfiltration workflow used.",
            "Counts are only interpretable as prevalence where read_rate meets the "
            "threshold; below it, the numbers are a floor and not a rate.",
            "toJSON(secrets) is the exfiltration primitive both documented CHAINDROP "
            "workflow variants use. A legitimate hit is possible — some matrix and "
            "reusable-workflow patterns pass the whole context deliberately — so each "
            "one needs an author and a commit date, not a verdict from this count.",
            "A Bun fetch marker is a provenance question, not a finding. What matters is "
            "whether the fetch is pinned and mirrored: the release CDN is the dropper's "
            "first hop and one egress origin, versus 75 RPC endpoints downstream. "
            "bun.exe is matched explicitly because the Windows bootstrap writes that "
            "name and never touches /tmp or chmod, so the POSIX-shaped checks in this "
            "corpus could not have seen it.",
        ],
        "limits": [
            "Default branch only, and only repositories the tree sweep found to have "
            ".github/workflows files.",
            "Static text analysis. A composite action referenced by a pinned SHA can "
            "itself use mutable refs internally, which is not visible here.",
            "Reusable workflows called with workflow_call are analysed where they live in "
            "this estate and not where they are external.",
        ],
    }
    coverage_path.write_text(json.dumps(coverage, indent=2))
    print(f"\nwritten: {args.out}\ncoverage: {coverage_path}", file=sys.stderr)
    print(json.dumps({"repos_swept": coverage["repos_swept"],
                      "workflow_files_read": read, "read_rate": coverage["read_rate"],
                      "counts": coverage["counts"]}, indent=2), file=sys.stderr)
    return 0 if coverage_ok else 3


if __name__ == "__main__":
    sys.exit(main())
