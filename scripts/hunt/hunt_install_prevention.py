#!/usr/bin/env python3
"""T03's control half: is a package's install-time script ALLOWED to run here?

The question, and why no earlier round asked it
----------------------------------------------
`install_activity_r2.json` measured that lifecycle scripts fire in the thousands inside the hunt
window - 2,670 executions on 101 devices - and that none of them is attributable to a package.
That is an ARRIVAL measurement. It says the primitive the campaign needs is firing constantly,
and it says nothing whatsoever about whether anything stands in the way, which is why T03 sits
at UNMEASURED on the control axis with evidence on the observation axis.

The control has a name. npm, yarn, pnpm and bun all honor `ignore-scripts`, and the campaign's
entire entry point is a `preinstall` script. So the control question is answerable from files:

  * `.npmrc` anywhere in the repository, and whether it sets `ignore-scripts`;
  * every workflow that installs dependencies, and whether that install refuses scripts -
    `--ignore-scripts` on the command, or `NPM_CONFIG_IGNORE_SCRIPTS` in the environment.

What this collector deliberately does NOT claim
-----------------------------------------------
It measures CI and repository configuration. It cannot see a developer's `~/.npmrc`, and the
101 devices in the install-activity artifact are workstations, not runners. So a repository that
refuses scripts in CI is still installing with scripts enabled on somebody's laptop, and that
gap is emitted as a coverage gap with the device population named rather than left implied.
A clean CI answer here is not an estate answer, and the artifact says so twice.

Why one tree request per repository instead of guessing paths
------------------------------------------------------------
`.npmrc` is per-directory: a monorepo can hold one at the root and one per package, and the one
that wins is the closest to the install. Guessing `.npmrc` beside every manifest costs a request
per manifest and still misses the ones that sit somewhere else. A recursive tree costs ONE
request per repository and returns every `.npmrc` path and every workflow path exactly, so the
sweep reads only files that exist. Cheaper and complete instead of cheaper and partial.

Population
----------
The 364 npm-relevant repositories from the tree sweep, not all 2,811. A repository with no npm
manifest cannot run an npm lifecycle script, so it is out of the denominator by a property of
the data rather than by sampling. That narrowing is exact and it is stated in the scope.

Budget
------
One tree request per repository, then one content request per `.npmrc` and per workflow found:
roughly 364 + 1,900 core requests against the shared 5,000/hour budget. Pacing is the shared
Throttle from check_declared_ranges, driven by real response headers - `GET /rate_limit` is not
consulted, because on these tokens it reports a different bucket than the one real requests
spend.
"""

from __future__ import annotations

import argparse
import base64
import json
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_declared_ranges import (  # noqa: E402
    GITHUB_API, ORG_TOKEN_VARS, REPO_ROOT, THROTTLE, load_env,
)

CLEAR = "CLEAR"
FINDINGS = "FINDINGS"
INCOMPLETE = "INCOMPLETE"

# Install commands, per package manager. Matched on the command line inside a `run:` block.
# `npm i` is included because it is the form people type; `npm install` and `npm ci` are the
# forms CI uses, and only `npm ci` respects a lockfile - which is a different control (T02).
INSTALL_PATTERNS: List[Tuple[str, re.Pattern]] = [
    ("npm ci", re.compile(r"\bnpm\s+ci\b")),
    ("npm install", re.compile(r"\bnpm\s+(?:install|i)\b(?!\s*-g)")),
    ("yarn install", re.compile(r"\byarn\s+(?:install\b|--frozen-lockfile|$)", re.M)),
    ("pnpm install", re.compile(r"\bpnpm\s+(?:install|i)\b")),
    ("bun install", re.compile(r"\bbun\s+(?:install|i)\b")),
]

# The control, in every spelling that actually takes effect.
IGNORE_ON_COMMAND = re.compile(r"--ignore-scripts\b")
IGNORE_IN_ENV = re.compile(r"(?i)\bNPM_CONFIG_IGNORE_SCRIPTS\s*:\s*(?:'|\")?(?:true|1)\b")
IGNORE_VIA_CONFIG_SET = re.compile(r"npm\s+config\s+set\s+ignore-scripts\s+true")
# pnpm and yarn Berry read their own keys; a repo that sets these is refusing scripts too.
IGNORE_PNPM = re.compile(r"(?m)^\s*ignore-scripts\s*[:=]\s*true\s*$")
IGNORE_YARN_BERRY = re.compile(r"(?m)^\s*enableScripts\s*:\s*false\s*$")

# `.npmrc` is ini-ish: `key=value`, comments with `;` or `#`. Only the last assignment wins,
# so the file is scanned in order and the final value is the one recorded.
NPMRC_IGNORE = re.compile(r"(?im)^\s*ignore-scripts\s*=\s*(true|false)\s*(?:[;#].*)?$")

WORKFLOW_DIR = ".github/workflows/"


def request_json(url: str, token: str, accept: str = "application/vnd.github+json",
                 attempts: int = 5) -> Tuple[Optional[Any], Optional[str]]:
    """One paced request through the shared Throttle.

    A 403 is retried and, if it survives retries, recorded as a coverage failure rather than
    as an answer - it is indistinguishable from a permissions denial at the call site, and the
    first run of a sibling collector reported zero reachable manifests entirely because of this.
    """
    for attempt in range(attempts):
        THROTTLE.wait()
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": accept,
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                THROTTLE.observe(response.headers)
                raw = response.read()
        except urllib.error.HTTPError as exc:
            THROTTLE.observe(exc.headers)
            if exc.code == 404:
                return None, "HTTP 404"
            if exc.code in (403, 429):
                headers = exc.headers or {}
                retry_after = headers.get("Retry-After")
                if retry_after:
                    THROTTLE.back_off(float(retry_after))
                elif headers.get("X-RateLimit-Remaining") == "0":
                    reset = headers.get("X-RateLimit-Reset")
                    THROTTLE.back_off(
                        max(1.0, float(reset) - time.time() + 2) if reset else 60.0)
                else:
                    THROTTLE.back_off(min(60.0 * (attempt + 1), 300.0))
                continue
            if exc.code >= 500 and attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts - 1:
                return None, type(exc).__name__
            time.sleep(2 ** attempt)
            continue
        try:
            return json.loads(raw.decode("utf-8", errors="replace")), None
        except json.JSONDecodeError as exc:
            return None, f"JSONDecodeError: {exc}"
    return None, "rate limited beyond retries"


def read_text_file(org: str, repo: str, ref: str, path: str,
                   token: str) -> Tuple[Optional[str], Optional[str]]:
    """File content as text, via the contents API's base64 payload.

    Not `Accept: raw`: a raw response cannot be distinguished from a JSON error body by the
    shared helper, and `.npmrc` is not JSON. The base64 form is one request either way.
    """
    url = (f"{GITHUB_API}/repos/{urllib.parse.quote(org)}/{urllib.parse.quote(repo)}"
           f"/contents/{urllib.parse.quote(path)}?ref={urllib.parse.quote(ref)}")
    body, error = request_json(url, token)
    if body is None:
        return None, error
    if isinstance(body, dict) and body.get("encoding") == "base64":
        try:
            return base64.b64decode(body.get("content") or "").decode(
                "utf-8", errors="replace"), None
        except (ValueError, TypeError) as exc:
            return None, f"decode failed: {type(exc).__name__}"
    if isinstance(body, dict) and body.get("size") == 0:
        return "", None
    return None, "unexpected contents payload"


def classify_npmrc(text: str) -> Optional[bool]:
    """Last `ignore-scripts` assignment wins, or None if the file does not mention it."""
    matches = NPMRC_IGNORE.findall(text)
    if not matches:
        return None
    return matches[-1].lower() == "true"


def logical_lines(text: str) -> List[Tuple[int, str]]:
    r"""Shell continuations joined, so `npm ci \` + `  --ignore-scripts` reads as one command.

    Without this, a multi-line install command looks like a bare `npm ci` on one line and an
    orphaned flag on the next, and the flag is credited to nothing.
    """
    out: List[Tuple[int, str]] = []
    buffer, start = "", 0
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.rstrip()
        if not buffer:
            start = number
        if stripped.endswith("\\"):
            buffer += stripped[:-1] + " "
            continue
        out.append((start, buffer + stripped))
        buffer = ""
    if buffer:
        out.append((start, buffer))
    return out


def classify_workflow(text: str) -> Dict[str, Any]:
    """What this workflow does about installs, and about scripts during them.

    Matched per command line, not per file. A workflow that runs `npm ci --ignore-scripts` in one
    job and a bare `npm ci` in another is NOT protected, and a file-wide search for the flag would
    have called it protected - the generous reading turns one hardened step into a clean
    repository. So each install command is its own site with its own answer, and the workflow
    counts as protected only when every site is.

    Two controls legitimately apply file-wide and are credited that way, with the reason:
    `NPM_CONFIG_IGNORE_SCRIPTS` in an `env:` block and `npm config set ignore-scripts true` both
    change the runner's npm configuration rather than one command, so an install later in the same
    job inherits them. That credit is recorded under its own key so a reader can tell which
    repositories are protected per-command and which by ambient configuration.

    A workflow that never installs anything is not protected and not exposed - it is out of the
    denominator, because folding it into either column is how a percentage stops meaning anything.
    """
    sites: List[Dict[str, Any]] = []
    for number, line in logical_lines(text):
        commands = [name for name, pattern in INSTALL_PATTERNS if pattern.search(line)]
        if not commands:
            continue
        sites.append({"line": number, "commands": commands,
                      "refuses_scripts": bool(IGNORE_ON_COMMAND.search(line)),
                      "text": line.strip()[:200]})
    env_refuses = bool(IGNORE_IN_ENV.search(text))
    config_set_refuses = bool(IGNORE_VIA_CONFIG_SET.search(text))
    return {
        "installs": sorted({c for site in sites for c in site["commands"]}),
        "install_sites": sites,
        "install_sites_refusing_scripts": sum(1 for s in sites if s["refuses_scripts"]),
        "ignore_scripts_in_env": env_refuses,
        "ignore_scripts_via_config_set": config_set_refuses,
        "protected": bool(sites) and (env_refuses or config_set_refuses
                                      or all(s["refuses_scripts"] for s in sites)),
        # A workflow with no install command of its own that calls an action may still install:
        # the command lives in the action, not here. Recorded so the gap can be counted.
        "calls_actions": bool(re.search(r"(?m)^\s*-?\s*uses:\s*\S+", text)),
    }


def sweep_repo(record: dict, token: str) -> dict:
    org, repo = record["org"], record["repo"]
    ref = record.get("branch_inspected") or record.get("default_branch")
    out: Dict[str, Any] = {
        "full_name": record["full_name"], "org": org, "ref": ref,
        "archived": record.get("archived"), "pushed_at": record.get("pushed_at"),
        "npm_manifest_count": record.get("npm_manifest_count"),
        "tree_error": None, "tree_truncated": None,
        "npmrc_files": [], "workflows": [], "read_errors": [],
        "workflows_found": 0, "workflows_read": 0,
    }
    if not ref:
        out["tree_error"] = "no ref recorded by the tree sweep"
        return out

    tree, error = request_json(
        f"{GITHUB_API}/repos/{urllib.parse.quote(org)}/{urllib.parse.quote(repo)}"
        f"/git/trees/{urllib.parse.quote(ref)}?recursive=1", token)
    if tree is None or not isinstance(tree, dict):
        out["tree_error"] = error or "unexpected tree payload"
        return out
    out["tree_truncated"] = bool(tree.get("truncated"))

    npmrc_paths, workflow_paths, yarnrc_paths = [], [], []
    for entry in (tree.get("tree") or []):
        if entry.get("type") != "blob":
            continue
        path = entry.get("path") or ""
        base = path.rsplit("/", 1)[-1]
        if "node_modules/" in path:
            continue
        if base == ".npmrc":
            npmrc_paths.append(path)
        elif base in (".yarnrc.yml", ".yarnrc.yaml", ".pnpmrc"):
            yarnrc_paths.append(path)
        elif path.startswith(WORKFLOW_DIR) and base.endswith((".yml", ".yaml")):
            workflow_paths.append(path)
    out["workflows_found"] = len(workflow_paths)

    for path in npmrc_paths + yarnrc_paths:
        text, error = read_text_file(org, repo, ref, path, token)
        if text is None:
            out["read_errors"].append({"path": path, "error": error})
            continue
        if path.rsplit("/", 1)[-1] == ".npmrc":
            setting = classify_npmrc(text)
        else:
            setting = True if (IGNORE_PNPM.search(text)
                               or IGNORE_YARN_BERRY.search(text)) else None
        out["npmrc_files"].append({"path": path, "ignore_scripts": setting,
                                   "at_repo_root": "/" not in path})

    for path in workflow_paths:
        text, error = read_text_file(org, repo, ref, path, token)
        if text is None:
            out["read_errors"].append({"path": path, "error": error})
            continue
        out["workflows_read"] += 1
        detail = classify_workflow(text)
        if detail["installs"] or detail["ignore_scripts_in_env"]:
            out["workflows"].append({"path": path, **detail})
        elif detail["calls_actions"]:
            out["workflows"].append({"path": path, **detail})
    return out


def repo_verdict(row: dict) -> str:
    """One repository's control state on this vector.

    Five outcomes, and the two that are not about the repository are named as such: a tree we
    could not read is a coverage failure, and a repository that installs nothing in CI is out of
    the denominator rather than protected.
    """
    if row.get("tree_error"):
        return "unreadable"
    npmrc_true = any(f["ignore_scripts"] is True for f in row["npmrc_files"])
    npmrc_false = any(f["ignore_scripts"] is False for f in row["npmrc_files"])
    installing = [w for w in row["workflows"] if w["installs"]]
    protected = [w for w in installing if w["protected"]]
    if npmrc_true and not npmrc_false:
        return "prevented_by_npmrc"
    if installing and len(protected) == len(installing):
        return "prevented_in_every_installing_workflow"
    if installing and protected:
        return "prevented_in_some_installing_workflows"
    if installing:
        return "installs_with_scripts_enabled"
    return "no_ci_install_observed"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees_r5.jsonl")
    parser.add_argument("--install-activity", type=Path,
                        default=REPO_ROOT / "exports/hunt/install_activity_r2.json",
                        help="Source of the workstation population this vector cannot answer "
                             "for. Absent, the gap is still emitted, without a device count.")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/install_prevention_r1.json")
    parser.add_argument("--rows-out", type=Path,
                        default=REPO_ROOT / "exports/hunt/install_prevention_r1_rows.jsonl")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--limit", type=int, default=0,
                        help="Sweep only the first N repositories. For smoke-testing the "
                             "collector; a limited run is stamped as such in the artifact so it "
                             "can never be read as an estate answer.")
    args = parser.parse_args()

    env = load_env(REPO_ROOT / ".env")
    records = []
    with args.trees.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            if record.get("npm_relevant"):
                records.append(record)
    if args.limit:
        records = records[:args.limit]
    print(f"[install-prevention] {len(records)} npm-relevant repositories", file=sys.stderr)

    rows: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for record in records:
            token = next((env[v] for v in ORG_TOKEN_VARS.get(record["org"], ["GITHUB_TOKEN"])
                          if env.get(v)), None)
            if not token:
                rows.append({"full_name": record["full_name"], "org": record["org"],
                             "tree_error": "no token for org", "npmrc_files": [],
                             "workflows": [], "read_errors": [], "workflows_found": 0,
                             "workflows_read": 0})
                continue
            futures[pool.submit(sweep_repo, record, token)] = record["full_name"]
        for index, future in enumerate(as_completed(futures), 1):
            rows.append(future.result())
            if index % 25 == 0:
                print(f"  {index}/{len(futures)} swept "
                      f"(budget remaining {THROTTLE.remaining})", file=sys.stderr)

    for row in rows:
        row["verdict"] = repo_verdict(row)

    by_verdict: Dict[str, List[str]] = {}
    for row in rows:
        by_verdict.setdefault(row["verdict"], []).append(row["full_name"])

    unreadable = by_verdict.get("unreadable", [])
    exposed = sorted(by_verdict.get("installs_with_scripts_enabled", []))
    partial = sorted(by_verdict.get("prevented_in_some_installing_workflows", []))
    by_npmrc = sorted(by_verdict.get("prevented_by_npmrc", []))
    by_workflow = sorted(by_verdict.get("prevented_in_every_installing_workflow", []))
    no_install = by_verdict.get("no_ci_install_observed", [])

    installing_workflows = [w for row in rows for w in row["workflows"] if w["installs"]]
    protected_workflows = [w for w in installing_workflows if w["protected"]]
    install_sites = [s for w in installing_workflows for s in w["install_sites"]]
    sites_refusing = [s for s in install_sites if s["refuses_scripts"]]
    # Credited file-wide because they change the runner's npm config, not one command. Counted
    # apart from the per-command number so neither figure quietly absorbs the other.
    ambient_only = [w for w in protected_workflows
                    if not all(s["refuses_scripts"] for s in w["install_sites"])]
    npmrc_total = [f for row in rows for f in row["npmrc_files"]]
    npmrc_setting_it = [f for f in npmrc_total if f["ignore_scripts"] is True]
    npmrc_disabling_it = [f for f in npmrc_total if f["ignore_scripts"] is False]
    truncated = [r["full_name"] for r in rows if r.get("tree_truncated")]
    read_errors = [{"full_name": r["full_name"], **e}
                   for r in rows for e in (r.get("read_errors") or [])]
    workflows_found = sum(r.get("workflows_found") or 0 for r in rows)
    workflows_read = sum(r.get("workflows_read") or 0 for r in rows)
    # A workflow that installs nothing itself but calls an action might install inside it. That
    # is the population this vector cannot see into, and it is counted rather than described.
    no_workflows = sorted({r["full_name"] for r in rows
                           if not r.get("tree_error") and not (r.get("workflows_found") or 0)})
    action_only = sorted({r["full_name"] for r in rows
                          if not [w for w in r["workflows"] if w["installs"]]
                          and [w for w in r["workflows"] if w["calls_actions"]]})

    # The positive control. Without it, a run where every content read failed reports the same
    # numbers as an estate that installs nothing - zero installing workflows, zero exposure.
    control_ok = bool(installing_workflows)

    coverage: List[str] = [
        f"Population control: {len(rows)} npm-relevant repositories out of 2,811 enumerated. A "
        f"repository with no npm manifest cannot run an npm lifecycle script, so the narrowing "
        f"is a property of the tree sweep's data rather than a sample.",
        f"Read control: {workflows_read} of {workflows_found} workflow file(s) were read across "
        f"the population, and {len(installing_workflows)} of them run a dependency install. "
        + ("A non-zero install count is what makes the exposure numbers below readable: the "
           "content read demonstrably works."
           if control_ok else
           "ZERO installing workflows were found, which is not credible for this population - "
           "treat every number below as a broken read, not as an absence."),
        f"The control is matched per install command, not per file: {len(sites_refusing)} of "
        f"{len(install_sites)} individual install command(s) carry `--ignore-scripts` on the "
        f"command itself. A file-wide match would have credited one hardened step to every other "
        f"install in the same file, and {len(ambient_only)} workflow(s) are counted as protected "
        f"only because an `env:` var or `npm config set` changes the runner's configuration for "
        f"all of them.",
        f"`.npmrc` discovery is exact rather than guessed: one recursive tree per repository "
        f"returned every path, so the {len(npmrc_total)} config file(s) read are all of them "
        f"that exist on the swept ref, at any depth, not only at the repository root.",
    ]
    if unreadable:
        coverage.append(
            f"{len(unreadable)} repository tree(s) could not be read, so those repositories are "
            f"neither protected nor exposed in the counts below - they are unanswered, and "
            f"named in `repositories.unreadable`.")

    devices = None
    if args.install_activity.exists():
        activity = json.loads(args.install_activity.read_text())
        rows_ = (((activity.get("evidence") or {}).get("lifecycle_hook_control") or {})
                 .get("rows") or [])
        devices = (rows_[0].get("Devices") if rows_ else None)

    coverage_gaps: List[Dict[str, str]] = [
        {
            "gap": "Developer workstations are not covered. This vector reads repository and CI "
                   "configuration; `~/.npmrc` on a laptop is in neither.",
            "population": ((f"The {devices} device(s) on which lifecycle scripts were observed "
                            f"executing inside the hunt window"
                            if devices else
                            "The devices on which lifecycle scripts were observed executing "
                            "inside the hunt window")
                           + f", and the {len(no_workflows)} swept repository(ies) with no "
                             f"workflow file at all, whose dependencies are therefore only ever "
                             f"installed on a machine this sweep cannot read"),
            "named_by": ("exports/hunt/install_activity_r2.json - "
                         "`evidence.lifecycle_hook_control.rows`, which returns the device "
                         "count, and the per-device rows in the same artifact"),
            "cannot_confirm_or_deny": ("whether a developer installing a dependency on their own "
                                       "machine has scripts enabled - which is the surface the "
                                       "campaign's `preinstall` actually landed on for most "
                                       "victims"),
            "closed_by": ("a managed `~/.npmrc` with `ignore-scripts=true` delivered by MDM, or "
                          "a Defender query that reads npm config state per device - the first "
                          "is a control, the second is only a measurement"),
            "owner": "IT Endpoint Engineering, with Security Engineering for the measurement",
        },
        {
            "gap": "An install that happens inside a called action is invisible here: the "
                   "command lives in the action's own definition, not in the workflow text this "
                   "sweep read.",
            "population": (f"{len(action_only)} repository(ies) whose workflows call an action "
                           f"and contain no install command of their own"),
            "named_by": ("`repositories.install_may_be_inside_a_called_action` in this artifact, "
                         "which lists them by identifier"),
            "cannot_confirm_or_deny": ("whether those repositories install dependencies at all, "
                                       "and if they do, whether that install refuses scripts"),
            "closed_by": ("resolving each `uses:` reference to its action definition and reading "
                          "its steps - a second pass over a bounded list, roughly one request "
                          "per distinct action reference rather than per repository"),
            "owner": "Security Engineering",
        },
        {
            "gap": "Read on one ref per repository - the default branch. A workflow or `.npmrc` "
                   "that exists only on another branch is not in these counts.",
            "population": f"All {len(rows)} swept repositories, each on the single ref recorded "
                          f"in its row as `ref`",
            "named_by": "the `ref` field on every row in install_prevention_r1_rows.jsonl",
            "cannot_confirm_or_deny": ("whether a side branch installs differently from the "
                                       "default branch. It bounds the CONTROL claim, not the "
                                       "compromise claim - branch compromise is "
                                       "hunt_branches.py's question"),
            "closed_by": ("re-running this sweep per branch, which multiplies its cost by the "
                          "branch count and is not worth it as a control measurement - the "
                          "default branch is what CI runs on merge"),
            "owner": "Security Engineering",
        },
    ]
    if truncated:
        coverage_gaps.append({
            "gap": "The git tree came back truncated for some repositories, so a `.npmrc` or "
                   "workflow below the truncation point was never seen.",
            "population": f"{len(truncated)} repository(ies), listed in "
                          f"`repositories.tree_truncated`",
            "named_by": "`repositories.tree_truncated` in this artifact",
            "cannot_confirm_or_deny": ("whether those repositories carry an `ignore-scripts` "
                                       "setting the sweep did not reach"),
            "closed_by": ("walking those trees directory by directory, the same fallback the r5 "
                          "tree sweep records as `truncation_resolved_by`"),
            "owner": "Security Engineering",
        })

    unresolved: List[str] = []
    if not control_ok:
        unresolved.append(
            "The read control failed: zero workflows in the whole population run a dependency "
            "install, which is not a credible result for 364 npm-relevant repositories. Every "
            "count in this artifact is therefore untrustworthy and no control state should be "
            "derived from it until the content read is fixed.")
    if read_errors:
        unresolved.append(
            f"{len(read_errors)} file read(s) failed and are listed verbatim in `read_errors`. "
            f"Each is a file whose setting is unknown, not a file with no setting - a repository "
            f"whose only `.npmrc` failed to read may be protected and is counted as exposed.")
    if npmrc_disabling_it:
        unresolved.append(
            f"{len(npmrc_disabling_it)} `.npmrc` file(s) set `ignore-scripts=false` explicitly, "
            f"which turns the control OFF where a parent or user config might otherwise have "
            f"turned it on. First "
            + str(min(10, len(npmrc_disabling_it)))
            + " of them, with the full list in `config_files` in this artifact: "
            + ", ".join(f["path"] for f in npmrc_disabling_it[:10])
            + ". Each needs an owner to say whether that is deliberate.")

    if not control_ok:
        status = INCOMPLETE
    elif exposed or partial:
        status = FINDINGS
    elif unresolved:
        status = INCOMPLETE
    else:
        status = CLEAR

    artifact = {
        "name": "Install-time script prevention (`ignore-scripts`) across npm-relevant repos",
        "status": status,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scope": (f"{len(rows)} npm-relevant repositories of 2,811 enumerated, each on its "
                  f"default branch: every `.npmrc` at any depth plus every workflow file, read "
                  f"for whether a dependency install refuses lifecycle scripts."
                  + (" LIMITED RUN - --limit was passed, so this is not an estate answer."
                     if args.limit else "")),
        "counts": {
            "npm-relevant repositories swept": len(rows),
            "Repositories whose tree could not be read": len(unreadable),
            "Workflow files found": workflows_found,
            "Workflow files read": workflows_read,
            "Workflows that install dependencies": len(installing_workflows),
            "Of those, refusing lifecycle scripts at every install": len(protected_workflows),
            "Of those, protected only by an env var or `npm config set`": len(ambient_only),
            "Individual install commands": len(install_sites),
            "Of those, carrying --ignore-scripts on the command": len(sites_refusing),
            "Config files read (.npmrc, .yarnrc.yml, .pnpmrc)": len(npmrc_total),
            "Config files setting ignore-scripts=true": len(npmrc_setting_it),
            "Config files setting ignore-scripts=false": len(npmrc_disabling_it),
            "Repositories preventing scripts by config": len(by_npmrc),
            "Repositories preventing scripts in every installing workflow": len(by_workflow),
            "Repositories preventing scripts in only some installing workflows": len(partial),
            "Repositories that install with scripts enabled": len(exposed),
            "Repositories with no CI install observed": len(no_install),
            # Not a control and not an exposure in CI - it means every install of this
            # repository's dependencies happens on somebody's machine, which is the surface
            # this vector cannot read at all. It belongs next to the workstation gap.
            "Of those, with no workflow file at all": len(no_workflows),
            "Repositories where the install may be inside a called action": len(action_only),
            "File reads that failed": len(read_errors),
        },
        "coverage": coverage,
        "coverage_gaps": coverage_gaps,
        "unresolved_items": unresolved,
        # Exposure, not compromise. A repository installing with scripts enabled is how this
        # campaign would run, and it is not evidence that it did - so it goes in the
        # status-evidence channel and never in `findings`.
        "findings": [],
        "evidence_for_status": [
            {"what": (f"{len(exposed)} repository(ies) run a dependency install in CI with "
                      f"lifecycle scripts enabled and no `ignore-scripts` anywhere - the exact "
                      f"primitive this campaign's `preinstall` entry point needs"),
             "resources": exposed},
            {"what": (f"{len(partial)} repository(ies) refuse scripts in some installing "
                      f"workflows and not others, which is the hole rather than the control"),
             "resources": partial},
        ] if (exposed or partial) else [],
        "repositories": {
            "installs_with_scripts_enabled": exposed,
            "prevented_in_some_installing_workflows": partial,
            "prevented_by_config": by_npmrc,
            "prevented_in_every_installing_workflow": by_workflow,
            "no_ci_install_observed": sorted(no_install),
            "no_workflow_file_at_all": no_workflows,
            "install_may_be_inside_a_called_action": action_only,
            "tree_truncated": sorted(truncated),
            "unreadable": sorted(unreadable),
        },
        "config_files": npmrc_total,
        "read_errors": read_errors,
        "limited_run": bool(args.limit),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, default=str) + "\n")
    with args.rows_out.open("w") as handle:
        for row in rows:
            handle.write(json.dumps(row, default=str) + "\n")

    print(f"\n[install-prevention] {status} -> {args.out}", file=sys.stderr)
    for key, value in artifact["counts"].items():
        print(f"  {key}: {value}")
    for gap in coverage_gaps:
        print(f"  GAP: {gap['gap'][:150]}")
    for item in unresolved:
        print(f"  UNREAD: {item[:150]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
