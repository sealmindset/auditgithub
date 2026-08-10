#!/usr/bin/env python3
"""
Collect the full file listing of every repository in scope, one API call per repo.

Why this exists
---------------
The platform's existing dependency data comes from cloning a repository and running
Syft over it. That is accurate but expensive, and it had only ever been run against a
fraction of the estate: at the time this script was written, 2,531 repositories were
inventoried but only 144 of them had a single npm dependency row. Every "no affected
package found" answer the previous hunt produced was computed over those 144, which is
not a clean result — it is an unmeasured one.

GitHub's recursive tree API returns the entire file list of a ref in a single request.
That is enough to answer two questions at once:

  1. Which repositories are npm-relevant at all (a package.json or a JS lockfile
     anywhere in the tree, including monorepo subdirectories)? This bounds the
     dependency-collection work to the repositories where an npm worm could land,
     which is the scope decision this hunt is operating under.

  2. Does any repository carry a CHAINDROP file indicator on disk (setup.mjs,
     Math_Symbol.js, .claude/settings.json, .vscode/tasks.json, codeql_analysis.yml)?
     No previous pass had looked for these in repository contents at all.

Deliberate limits, recorded rather than hidden
----------------------------------------------
* Default branch only. Elastic reports the worm writes hooks to up to 50 branches per
  accessible repository, so a repository can be compromised on a non-default branch and
  read clean here. This script records the branch it inspected; widening to other
  branches is a separate, targeted pass over the repositories that matter.
* The trees API truncates very large trees. When it does, it says so, and that
  repository's file list is incomplete. A negative result on a truncated tree is not
  evidence of absence, so `truncated` is carried through to the output and counted in
  the coverage block.
* A filename is a lead, not a detection. regenerate-unicode-properties legitimately
  ships General_Category/Math_Symbol.js, and this workstation has a legitimate
  .vscode/tasks.json folderOpen task that launches Claude Code. Hits from this script
  are inputs to a hash check, never verdicts.

Output is JSON Lines under exports/hunt/, which is gitignored: it names private
repositories and their internal file layout.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Dict, Iterable, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_OUT = REPO_ROOT / "exports" / "hunt" / "repo_trees.jsonl"
IOC_DIR = REPO_ROOT / "github_conf" / "ioc"
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")

# Git's constant hash of the empty tree. A commit pointing here has no files, and the
# GitHub trees API returns 404 for it rather than an empty list.
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

# Organizations in scope, with the environment variable holding the token that can
# actually reach each one. This mapping is not cosmetic: the tenant-wide GITHUB_TOKEN
# returns 404 for sleepnumberlabs, which is indistinguishable from "no such org" unless
# the right token is used. A hunt that used one token everywhere would silently report
# an entire organization as empty.
ORG_TOKENS: List[Tuple[str, List[str]]] = [
    ("SleepNumberInc", ["ORG_SLEEPNUMBERINC_TOKEN", "GITHUB_TOKEN"]),
    ("sleepnumberlabs", ["ORG_SLEEPNUMBERLABS_TOKEN"]),
    ("sleepnumber", ["ORG_SLEEPNUMBER_TOKEN", "GITHUB_TOKEN"]),
]

# npm relevance. Basenames are matched case-insensitively against every path in the
# tree, so a manifest in packages/foo/package.json counts.
NPM_MANIFESTS = {
    "package.json",
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    ".npmrc",
}

# Other ecosystems, recorded so that "not npm-relevant" can be stated as a positive
# fact about a repository rather than as an absence of information about it.
OTHER_MANIFESTS = {
    "requirements.txt": "python",
    "pyproject.toml": "python",
    "poetry.lock": "python",
    "pipfile.lock": "python",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "build.gradle.kts": "gradle",
    "gemfile": "rubygems",
    "gemfile.lock": "rubygems",
    "cargo.toml": "cargo",
    "cargo.lock": "cargo",
    "composer.json": "composer",
    "gopkg.toml": "go",
    "dockerfile": "container",
    "main.tf": "terraform",
    "pubspec.yaml": "dart",
    "podfile": "cocoapods",
}


def load_env(path: Path) -> Dict[str, str]:
    """Parse a .env file. Values are never logged, only used."""
    env: Dict[str, str] = {}
    if not path.exists():
        return env
    for line in path.read_text(errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def load_indicator_basenames() -> Dict[str, List[str]]:
    """
    Read the file indicators out of the IOC files rather than hardcoding them here.

    The IOC files are the artifact under version control that reviewers read; a
    hardcoded copy in a script drifts from them silently, and the drift is invisible
    precisely because both look correct in isolation.
    """
    basenames: set[str] = set()
    exact_paths: set[str] = set()
    # chaindrop_stepsecurity_2026_08.json was ingested on 2026-08-06 and was NOT read
    # here until 2026-08-07. Its .claude/setup.mjs and .vscode/setup.mjs persistence
    # paths were therefore absent from every tree sweep run against it: the file existed
    # under version control and looked like coverage. It uses a different schema from
    # the other two (persistence.repository_scoped rather than dropped_files), which is
    # why a loader that only understood one shape skipped it silently.
    #
    # That was the second half of the same bug. The first half was this loop naming its
    # files, so adding a source to github_conf/ioc/ left the sweep unchanged and nothing
    # failed to say so. It recurred on 2026-08-10 with two new sources (Cycode, Unit 42),
    # one of which carries the only known name for a third dropped file. Enumerating the
    # directory means a new source file reaches the sweep by existing, which is the same
    # property the docstring above claims for reading the IOC files at all.
    for path in sorted(IOC_DIR.glob("*.json")):
        data = json.loads(path.read_text())
        persistence = data.get("persistence", {}) or {}
        repo_scoped = persistence.get("repository_scoped", []) or []
        for entry in list(data.get("dropped_files", []) or []) + list(repo_scoped):
            if entry.startswith("/"):
                continue  # absolute host paths (e.g. /tmp locks) cannot appear in a repo tree
            if "/" in entry:
                # Path-qualified indicators match as exact paths only. Reducing them to
                # a basename destroys the precision that made them worth listing:
                # ".claude/settings.json" becomes "settings.json", which matches
                # .vscode/settings.json and .air/settings.json on ordinary repositories.
                # It fired on two of the first nine repositories tested.
                exact_paths.add(entry.lower())
            else:
                basenames.add(entry.lower())
        components = data.get("components", {}) or {}
        for component in components.values():
            raw = (component or {}).get("file", "")
            for piece in re.split(r"\s*/\s*", raw):
                piece = piece.strip()
                if piece:
                    basenames.add(piece.lower())
        marker = (data.get("github_markers", {}) or {}).get("workflow_file")
        if marker:
            basenames.add(marker.lower())
        # StepSecurity records the stage-2 collector as one hash under two filenames.
        # Both names are already known from the other sources, but reading them from
        # here too means a future rename in this file propagates without a code change.
        for meta in (data.get("hashes", {}) or {}).values():
            for filename in (meta or {}).get("filenames", []) or []:
                basenames.add(str(filename).lower())
    # Persistence directories are checked as path prefixes, not basenames.
    return {
        "basenames": sorted(basenames),
        "exact_paths": sorted(exact_paths),
    }


def load_bun_artifacts() -> Dict[str, List[str]]:
    """
    Build the Bun-runtime artifact set, including the Windows binary.

    Why this is separate from the indicator set above: a Bun artifact is not evidence of
    compromise the way math_init.js is. Bun is a legitimate runtime and some repositories
    vendor or reference it deliberately. These are *leads with a provenance question* —
    "why is a runtime binary in a git tree, and which build wrote it" — and they are kept
    in their own bucket so a hit does not inflate the indicator count.

    The Windows case is the reason this exists at all. Every prior pass modelled the Bun
    bootstrap as POSIX: the StepSecurity assertion is mkdtemp('/tmp/bun-dl-'), chmod 755,
    execute. But the same file lists bun-windows-x64-baseline.zip and
    bun-windows-aarch64.zip among the fetched release assets, and those unpack to
    **bun.exe**, into %TEMP%\\bun-dl-*, with no chmod and no /tmp path anywhere. On an
    estate whose endpoint population is overwhelmingly Windows, a hunt that only knew the
    POSIX shape could read a bootstrapped host as clean.

    bun.lock and bun.lockb are deliberately NOT included. They are ordinary Bun project
    files and would turn this into a "does anyone use Bun" census, which is a different
    question with a much larger answer.
    """
    # Exact basenames only. "bun" as a bare name is excluded: it collides with source
    # directories called bun/ and with shell wrappers, and the executable form is what
    # the bootstrap actually writes.
    binaries = {"bun.exe", "bunx.exe"}
    assets: set[str] = set()
    staging_prefixes = {"bun-dl-"}

    path = IOC_DIR / "chaindrop_stepsecurity_2026_08.json"
    if path.exists():
        bootstrap = (json.loads(path.read_text()).get("bun_bootstrap", {}) or {})
        for asset in bootstrap.get("assets", []) or []:
            assets.add(str(asset).lower())
        # "mkdtemp('/tmp/bun-dl-')" -> the "bun-dl-" stem, so the Windows %TEMP% form of
        # the same staging directory matches on the stem rather than on the POSIX path.
        staging = str(bootstrap.get("staging_dir", ""))
        stem = re.search(r"([A-Za-z0-9_.-]*bun-dl-)", staging)
        if stem:
            staging_prefixes.add(stem.group(1).lower().lstrip("/").split("/")[-1])
    else:
        # Recorded rather than silently degraded: without the source file the asset list
        # is unknown and only the binary names are checked.
        assets.add("_ioc_file_missing_")

    return {
        "binaries": sorted(binaries),
        "release_assets": sorted(a for a in assets if a != "_ioc_file_missing_"),
        "staging_prefixes": sorted(staging_prefixes),
        "source_file_present": path.exists(),
    }


class RateLimiter:
    """
    Serialize the decision to pause on rate limiting.

    Without the lock, every worker independently reads a near-zero remaining count and
    they all sleep for the full reset interval one after another, turning a single
    30-second pause into a 30-second-per-worker pause.
    """

    def __init__(self) -> None:
        self._lock = Lock()
        self._resume_at = 0.0

    def wait(self) -> None:
        while True:
            with self._lock:
                delay = self._resume_at - time.time()
            if delay <= 0:
                return
            time.sleep(min(delay, 5.0))

    def note_headers(self, headers) -> None:
        try:
            remaining = int(headers.get("X-RateLimit-Remaining", "1"))
            reset = int(headers.get("X-RateLimit-Reset", "0"))
        except (TypeError, ValueError):
            return
        if remaining <= 2 and reset:
            with self._lock:
                self._resume_at = max(self._resume_at, reset + 1)

    def back_off(self, seconds: float) -> None:
        with self._lock:
            self._resume_at = max(self._resume_at, time.time() + seconds)


LIMITER = RateLimiter()


def api_get(url: str, token: str, accept: str = "application/vnd.github+json",
            attempts: int = 4) -> Tuple[int, object, dict]:
    """
    GET a GitHub API URL. Returns (status, parsed body or None, headers).

    HTTP errors are returned rather than raised: a 404 on one repository is data about
    that repository, not a reason to abandon the sweep.
    """
    last: Tuple[int, object, dict] = (0, None, {})
    for attempt in range(attempts):
        LIMITER.wait()
        request = urllib.request.Request(
            url,
            headers={
                "Authorization": f"token {token}",
                "Accept": accept,
                "X-GitHub-Api-Version": "2022-11-28",
                "User-Agent": "auditgithub-hunt/1.0",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=60) as response:
                LIMITER.note_headers(response.headers)
                body = response.read()
                parsed = json.loads(body) if body else None
                return response.status, parsed, dict(response.headers)
        except urllib.error.HTTPError as exc:
            headers = dict(exc.headers or {})
            LIMITER.note_headers(exc.headers or {})
            try:
                parsed = json.loads(exc.read() or b"null")
            except Exception:
                parsed = None
            last = (exc.code, parsed, headers)
            # 403/429 with a rate-limit signal is transient; 404/409/451 are terminal.
            if exc.code in (403, 429):
                retry_after = headers.get("Retry-After")
                LIMITER.back_off(float(retry_after) if retry_after else 60.0)
                continue
            if exc.code >= 500:
                time.sleep(2 ** attempt)
                continue
            return last
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            last = (0, {"message": str(exc)}, {})
            time.sleep(2 ** attempt)
    return last


def list_org_repos(org: str, token: str) -> Tuple[List[dict], Optional[str]]:
    """
    Page through every repository in an organization.

    Pagination is followed to exhaustion and the final empty page is what proves the
    enumeration is complete. Organization metadata counters are not used: for
    sleepnumber they report roughly 12 repositories where exhaustive pagination returns
    9, and an inflated denominator makes a complete import look like a partial one.
    """
    repos: List[dict] = []
    page = 1
    while True:
        status, body, _ = api_get(
            f"{GITHUB_API}/orgs/{org}/repos?per_page=100&type=all&page={page}", token
        )
        if status != 200 or not isinstance(body, list):
            message = (body or {}).get("message") if isinstance(body, dict) else None
            return repos, f"HTTP {status}: {message or 'unexpected body'}"
        if not body:
            return repos, None
        repos.extend(body)
        if len(body) < 100:
            return repos, None
        page += 1
        if page > 100:  # 10,000 repositories; a runaway guard, not an expected bound
            return repos, "pagination guard hit at page 100"


def classify_tree(paths: Iterable[str], indicators: Dict[str, List[str]],
                  bun: Optional[Dict[str, List[str]]] = None) -> dict:
    """Turn a flat path list into the facts the hunt needs."""
    npm_hits: List[str] = []
    ecosystems: set[str] = set()
    indicator_hits: List[str] = []
    mjs_files: List[str] = []
    bun_hits: List[dict] = []
    workflow_count = 0

    basenames = set(indicators["basenames"])
    exact_paths = set(indicators["exact_paths"])
    bun = bun or {"binaries": [], "release_assets": [], "staging_prefixes": []}
    bun_binaries = set(bun.get("binaries", []))
    bun_assets = set(bun.get("release_assets", []))
    bun_prefixes = tuple(bun.get("staging_prefixes", []))

    for path in paths:
        lower = path.lower()
        base = lower.rsplit("/", 1)[-1]

        # Bun artifacts are classified by *why* they are interesting, not lumped into
        # one flag: a committed bun.exe is a different conversation from a workflow that
        # downloads the Windows zip, and a bun-dl-* directory in a git tree is a third
        # thing again (staging that was supposed to be deleted and got committed).
        if base in bun_binaries:
            bun_hits.append({"path": path, "kind": "binary", "why":
                             "Bun runtime executable committed to the tree. The Windows "
                             "bootstrap unpacks exactly this name; verify provenance by hash."})
        elif base in bun_assets:
            bun_hits.append({"path": path, "kind": "release_asset", "why":
                             "A Bun release archive named in the campaign's fetch list."})
        elif any(seg.startswith(bun_prefixes) for seg in lower.split("/") if bun_prefixes):
            bun_hits.append({"path": path, "kind": "staging_dir", "why":
                             "Path segment matches the dropper's mkdtemp staging stem."})

        if base in NPM_MANIFESTS:
            npm_hits.append(path)
            ecosystems.add("npm")
        eco = OTHER_MANIFESTS.get(base)
        if eco:
            ecosystems.add(eco)

        if base in basenames or lower in exact_paths:
            indicator_hits.append(path)
        if lower.endswith(".mjs"):
            mjs_files.append(path)
        if lower.startswith(".github/workflows/"):
            workflow_count += 1

    return {
        "npm_relevant": bool(npm_hits),
        "npm_manifests": sorted(npm_hits)[:200],
        "npm_manifest_count": len(npm_hits),
        "ecosystems": sorted(ecosystems),
        "indicator_hits": sorted(indicator_hits),
        "mjs_files": sorted(mjs_files)[:100],
        "mjs_count": len(mjs_files),
        "bun_artifact_hits": bun_hits,
        "bun_artifact_count": len(bun_hits),
        "workflow_count": workflow_count,
    }


# Hook-bearing files. Their presence is normal; what they run is the question. The worm
# uses the IDE autostart chain as a second execution path that needs no npm install at
# all, so on npm >= 12 (which does not run preinstall hooks) this is the only path.
HOOK_FILES = (".claude/settings.json", ".claude/settings.local.json", ".vscode/tasks.json")

# Tokens that make a hook interesting. Matched independently, not as a fixed string:
# Elastic's own hunting query uses "node  setup.mjs" with two spaces, so anything
# matching the single-space form as a literal misses their documented variant.
HOOK_SUSPICIOUS = ("setup.mjs", "math_init.js", "math_symbol.js", "bun", ".mjs")


def strip_jsonc(text: str) -> str:
    """
    Remove comments and trailing commas so a VS Code config parses as JSON.

    .vscode/tasks.json is JSONC by convention — VS Code's own generated file opens with
    a `//` comment linking to its documentation. Without this, json.loads fails on the
    common case, the code falls back to scanning raw text for suspicious tokens, and
    "bun" matches inside "bundle generation complete". That is exactly what happened on
    sleepnumberlabs/web-data-sharing-consent, an ordinary Angular task file.

    String literals are tracked so a `//` inside a URL is not mistaken for a comment.
    """
    out: List[str] = []
    i, n = 0, len(text)
    in_string = False
    escaped = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            while i < n and text[i] != "\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    # Trailing commas before } or ] are legal in JSONC and fatal in JSON.
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def inspect_hook_file(org: str, repo_name: str, ref: str, path: str, token: str) -> dict:
    """
    Fetch a hook file and record what it actually executes.

    Returns the content hash and the specific tokens matched, so a reviewer can tell a
    legitimate hook from a malicious one. This workstation has a legitimate
    .vscode/tasks.json folderOpen task that launches Claude Code; the indicator is a
    hook invoking node or bun against a .mjs, not the existence of a hook.
    """
    import base64
    import hashlib

    result = {"path": path, "fetched": False, "error": None}
    status, body, _ = api_get(
        f"{GITHUB_API}/repos/{org}/{repo_name}/contents/{path}?ref={ref}", token
    )
    if status != 200 or not isinstance(body, dict):
        message = (body or {}).get("message") if isinstance(body, dict) else None
        result["error"] = f"HTTP {status}: {message or 'unexpected body'}"
        return result
    try:
        raw = base64.b64decode(body.get("content", "") or "")
    except Exception as exc:
        result["error"] = f"decode failed: {exc}"
        return result

    text = raw.decode("utf-8", errors="replace")
    lowered = text.lower()
    result.update({
        "fetched": True,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "size": len(raw),
        # Word-boundary matched: a substring test reports "bun" inside "bundle".
        "matched_tokens": sorted({
            t for t in HOOK_SUSPICIOUS
            if re.search(r"(?<![a-z0-9])" + re.escape(t) + r"(?![a-z0-9])", lowered)
        }),
        "has_session_start": "sessionstart" in lowered,
        "has_folder_open": "folderopen" in lowered,
    })

    # Extract the commands that actually autostart, rather than scanning the whole file
    # for suspicious words. A .claude/settings.json permissions allowlist routinely
    # contains "Edit(/**.mjs)" and "Bash(npm run *)": a token scan flags it, and on the
    # first repository tested it did exactly that on a file with no hooks key at all.
    # At estate scale that noise is what buries a real hit.
    commands: List[str] = []
    parse_error = None
    try:
        config = json.loads(text)
    except json.JSONDecodeError:
        try:
            config = json.loads(strip_jsonc(text))
        except json.JSONDecodeError as exc:
            config, parse_error = None, str(exc)

    if isinstance(config, dict):
        hooks = config.get("hooks")
        if isinstance(hooks, dict):
            # Claude Code: hooks -> {event: [ {hooks: [ {type, command} ]} ]}
            for event, matchers in hooks.items():
                for matcher in matchers if isinstance(matchers, list) else []:
                    entries = (matcher or {}).get("hooks", []) if isinstance(matcher, dict) else []
                    for entry in entries if isinstance(entries, list) else []:
                        cmd = (entry or {}).get("command")
                        if cmd:
                            commands.append(f"{event}: {cmd}")
        elif isinstance(hooks, list):
            for entry in hooks:
                cmd = (entry or {}).get("command") if isinstance(entry, dict) else None
                if cmd:
                    commands.append(str(cmd))

        for task in config.get("tasks", []) if isinstance(config.get("tasks"), list) else []:
            if not isinstance(task, dict):
                continue
            run_on = ((task.get("runOptions") or {}).get("runOn")
                      if isinstance(task.get("runOptions"), dict) else None)
            if run_on != "folderOpen":
                continue  # a task the developer runs by hand is not autostart persistence
            parts = [str(task.get("command", ""))]
            args = task.get("args")
            if isinstance(args, list):
                parts.extend(str(a) for a in args)
            commands.append(f"folderOpen: {' '.join(p for p in parts if p)}".strip())

    result["autostart_commands"] = commands
    result["config_parse_error"] = parse_error
    result["has_hooks_key"] = bool(commands)
    # An autostart command is the indicator only when it executes a script. This
    # workstation has a legitimate folderOpen task that launches Claude Code, so the
    # discriminator is node/bun against a .mjs, not the existence of autostart.
    joined = " ".join(commands).lower()
    result["runs_node_or_bun"] = bool(re.search(r"\b(node|bun|npx|bunx)\b", joined))
    result["autostart_runs_script"] = bool(
        re.search(r"\b(node|bun|npx|bunx)\b", joined)
        and re.search(r"\.(mjs|cjs|js)\b", joined)
    )
    # If the file could not be parsed, a negative structured result proves nothing, so
    # fall back to the token scan and say so.
    result["unparsed_fallback_tokens"] = (
        result["matched_tokens"] if parse_error else []
    )
    # Kept short: enough to judge, not enough to paste a whole config into a report.
    result["excerpt"] = text[:1200]
    return result


def walk_tree_completely(org: str, name: str, ref: str, token: str,
                         max_requests: int = 400):
    """Read a truncated tree in full by descending into it one subtree at a time.

    GitHub truncates a `?recursive=1` response against a size cap on that single
    response, not against a limit on what it will serve. Asking for a subtree asks for a
    smaller response, so the same content comes back complete. Descend only into subtrees
    that themselves truncate; everything else is captured by its parent's recursive read.

    Returns (blob_paths, unresolved_subtree_paths, requests_used). A non-empty second
    element is the honest residue: those directories were not read, and any statement
    about their contents would be a guess. `max_requests` bounds a pathological repository
    so one outlier cannot drain the shared budget - hitting it is reported as residue,
    never as completion.
    """
    paths: list = []
    unresolved: list = []
    # (tree_ref, path_prefix). The root is re-read here rather than reusing the caller's
    # truncated body: mixing a partial root with complete subtrees would produce a file
    # list that is neither, and no counter would show it.
    queue = [(ref, "")]
    requests = 0
    while queue:
        tree_ref, prefix = queue.pop()
        if requests >= max_requests:
            unresolved.append(prefix or "/")
            continue
        status, body, _ = api_get(
            f"{GITHUB_API}/repos/{org}/{name}/git/trees/{tree_ref}?recursive=1", token
        )
        requests += 1
        if status != 200 or not isinstance(body, dict):
            unresolved.append(prefix or "/")
            continue
        entries = body.get("tree") or []
        if body.get("truncated"):
            # This response is partial, so nothing in it can be trusted as a complete
            # listing. Discard it and queue its immediate children instead; a
            # non-recursive read of the same ref reliably fits.
            nr_status, nr_body, _ = api_get(
                f"{GITHUB_API}/repos/{org}/{name}/git/trees/{tree_ref}", token
            )
            requests += 1
            if nr_status != 200 or not isinstance(nr_body, dict) or nr_body.get("truncated"):
                unresolved.append(prefix or "/")
                continue
            for entry in nr_body.get("tree") or []:
                child = f"{prefix}{entry.get('path', '')}"
                if entry.get("type") == "blob":
                    paths.append(child)
                elif entry.get("type") == "tree" and entry.get("sha"):
                    queue.append((entry["sha"], child + "/"))
            continue
        for entry in entries:
            if entry.get("type") == "blob":
                paths.append(f"{prefix}{entry.get('path', '')}")
    return paths, unresolved, requests


def collect_repo(org: str, repo: dict, token: str, indicators: Dict[str, List[str]],
                 bun: Optional[Dict[str, List[str]]] = None) -> dict:
    name = repo["name"]
    branch = repo.get("default_branch")
    record = {
        "org": org,
        "repo": name,
        "full_name": repo.get("full_name") or f"{org}/{name}",
        "private": repo.get("private"),
        "archived": repo.get("archived"),
        "fork": repo.get("fork"),
        "pushed_at": repo.get("pushed_at"),
        "default_branch": branch,
        "description": repo.get("description"),
        "branch_inspected": branch,
        "tree_ok": False,
        "truncated": None,
        "file_count": None,
        "error": None,
    }
    if not branch:
        record["error"] = "no default branch (empty repository)"
        record["resolution"] = "no_files"
        record["file_count"] = 0
        return record

    status, body, _ = api_get(
        f"{GITHUB_API}/repos/{org}/{name}/git/trees/{branch}?recursive=1", token
    )

    # A 404 on the default branch is usually not an access problem: the repository's
    # default_branch pointer is stale and the branch it names no longer exists. Eight
    # repositories on this estate are in that state — SN_COGNITO advertises `main` while
    # its only branch is SFSTRY0002143 — and the repository, its branch list and its
    # contents all return 200. Any tool that inspects "the default branch" reads those
    # repositories as empty, which is a blind spot produced by bookkeeping rather than
    # by permissions. Fall back to a branch that exists and record the substitution.
    if status == 404:
        br_status, branches, _ = api_get(
            f"{GITHUB_API}/repos/{org}/{name}/branches?per_page=100", token
        )
        names = [b.get("name") for b in branches] if isinstance(branches, list) else []
        record["default_branch_stale"] = bool(names)
        record["branches_available"] = names[:100]
        for candidate in names:
            status, body, _ = api_get(
                f"{GITHUB_API}/repos/{org}/{name}/git/trees/{candidate}?recursive=1", token
            )
            if status == 200:
                record["branch_inspected"] = candidate
                break

    # A 404 that survives the branch fallback still has one innocent explanation left:
    # the branch's commit points at git's empty tree, and GitHub's trees API 404s on it.
    # sleepnumberlabs/asrd-bas-breatheiq-accuracy-assessment-study is that case — repo,
    # branch list and commit list all 200, contents returns [], tree 404. It is as empty
    # as the 409 "Git Repository is empty" repositories, but it has a commit, so it does
    # not report itself that way. Left unclassified it reads as an access gap, which is
    # the one reading that would be wrong.
    if status == 404:
        c_status, commit, _ = api_get(
            f"{GITHUB_API}/repos/{org}/{name}/commits/{branch}", token
        )
        tree_sha = None
        if c_status == 200 and isinstance(commit, dict):
            tree_sha = ((commit.get("commit") or {}).get("tree") or {}).get("sha")
        if tree_sha == EMPTY_TREE_SHA:
            record["error"] = "empty tree (single commit with no files)"
            record["empty_tree"] = True
            record["file_count"] = 0
            record["resolution"] = "no_files"
            return record

    if status != 200 or not isinstance(body, dict):
        message = (body or {}).get("message") if isinstance(body, dict) else None
        record["error"] = f"HTTP {status}: {message or 'unexpected body'}"
        # A repository with no commits has no files, so no file-based indicator can be
        # hiding in it. That is a determination, not a failure to look, and counting it
        # as a failure understates coverage - which is how a sweep ends up describing
        # itself as weak when it is complete.
        record["resolution"] = ("no_files" if status == 409 and "empty" in (message or "").lower()
                                else "unresolved")
        return record
    branch = record["branch_inspected"] or branch

    entries = body.get("tree") or []
    paths = [e.get("path", "") for e in entries if e.get("type") == "blob"]
    record["tree_ok"] = True
    record["truncated"] = bool(body.get("truncated"))
    record["file_count"] = len(paths)

    # A truncated tree is the one case where this sweep holds a partial file list and
    # could report "no bun.exe" about a repository it never finished reading. Rather than
    # carry that forward as a caveat, walk the tree per-subtree until it is complete: the
    # byte cap that truncated the root applies per response, so smaller subtree requests
    # return in full. Cost is bounded and paid only by the handful of repositories that
    # actually truncate.
    if record["truncated"]:
        walked, unresolved, requests_used = walk_tree_completely(org, name, branch, token)
        record["truncation_walk_requests"] = requests_used
        if not unresolved:
            paths = walked
            record["file_count"] = len(paths)
            record["truncated"] = False
            record["truncation_resolved_by"] = "per-subtree walk"
        else:
            # Still incomplete. Name the subtrees that were not read, so the residue is a
            # finite work item rather than a repository-level shrug.
            record["truncation_unresolved_subtrees"] = unresolved
    record["resolution"] = "unresolved" if record["truncated"] else "read"
    record.update(classify_tree(paths, indicators, bun))

    # Resolve every hook-file lead into a determination while the token and ref are in
    # hand. Leaving them as filename hits would push the judgment into the report,
    # where the evidence needed to make it is no longer available.
    hook_paths = [p for p in paths if p.lower() in HOOK_FILES]
    record["hook_files"] = [
        inspect_hook_file(org, name, branch, p, token) for p in sorted(hook_paths)
    ]
    # Two tiers, kept apart on purpose. `hooks_present` is context for a reviewer;
    # `hooks_running_code` is the set that warrants a hash check. Collapsing them was
    # what produced the first false positive.
    record["hooks_present"] = sorted(
        h["path"] for h in record["hook_files"] if h.get("has_hooks_key")
    )
    record["hooks_running_code"] = sorted(
        h["path"] for h in record["hook_files"]
        if h.get("autostart_runs_script") or h.get("unparsed_fallback_tokens")
    )
    return record


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--org", action="append", dest="orgs",
                        help="Restrict to one organization (repeatable).")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0,
                        help="Stop after N repositories per org (smoke testing only).")
    args = parser.parse_args()

    env = load_env(REPO_ROOT / ".env")
    env = {**env, **{k: v for k, v in os.environ.items() if k.startswith(("GITHUB_", "ORG_"))}}
    indicators = load_indicator_basenames()
    if not indicators["basenames"]:
        print("refusing to run: no file indicators loaded from github_conf/ioc/",
              file=sys.stderr)
        return 2
    print(f"file indicators loaded: {len(indicators['basenames'])} basenames, "
          f"{len(indicators['exact_paths'])} exact paths", file=sys.stderr)
    bun = load_bun_artifacts()
    if not bun["source_file_present"]:
        # Not fatal — the binary names are known independently — but it is the difference
        # between "no Bun release archive in any tree" and "the archive list was empty",
        # and those must not read the same in the coverage block.
        print("WARNING: chaindrop_stepsecurity_2026_08.json absent; Bun release-asset "
              "names unavailable, checking binaries only", file=sys.stderr)
    print(f"bun artifacts loaded: {len(bun['binaries'])} binaries "
          f"({', '.join(bun['binaries'])}), {len(bun['release_assets'])} release assets, "
          f"staging prefixes {bun['staging_prefixes']}", file=sys.stderr)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    # Named, not just counted. "2 repositories unresolved" is a caveat a reader must take
    # on trust; naming them turns it into a work item someone can close, and closing it is
    # what makes the next run's zero unqualified.
    unresolved_repos: List[dict] = []
    coverage = {
        "orgs": {},
        "totals": Counter(),
        "indicator_basenames": indicators["basenames"],
        "bun_artifacts": bun,
        "limits": [
            "default branch only; the worm is reported to write hooks to up to 50 "
            "branches per repository, so a clean result here does not clear other branches",
            "trees API truncates very large trees; a truncated tree is re-read per-subtree "
            "and only counted unresolved if that walk also fails to complete",
            "filename matches are leads requiring a hash or a second indicator",
            "bun.exe / bunx.exe / bun-*.zip hits are provenance questions, not "
            "indicators: Bun is a legitimate runtime and this counts them separately",
        ],
    }

    with args.out.open("w") as handle:
        for org, token_vars in ORG_TOKENS:
            if args.orgs and org not in args.orgs:
                continue
            token = next((env[v] for v in token_vars if env.get(v)), None)
            org_cov = {"token_var": next((v for v in token_vars if env.get(v)), None)}
            if not token:
                org_cov["error"] = f"no token: none of {token_vars} set"
                coverage["orgs"][org] = org_cov
                print(f"{org}: SKIPPED — {org_cov['error']}", file=sys.stderr)
                continue

            repos, list_error = list_org_repos(org, token)
            if args.limit:
                repos = repos[: args.limit]
            org_cov["repos_enumerated"] = len(repos)
            org_cov["enumeration_error"] = list_error
            org_cov["enumeration_complete"] = list_error is None
            print(f"{org}: {len(repos)} repositories enumerated"
                  f"{' (INCOMPLETE: ' + list_error + ')' if list_error else ''}",
                  file=sys.stderr)

            counts = Counter()
            with ThreadPoolExecutor(max_workers=args.workers) as pool:
                futures = {
                    pool.submit(collect_repo, org, repo, token, indicators, bun): repo["name"]
                    for repo in repos
                }
                for done, future in enumerate(as_completed(futures), 1):
                    try:
                        record = future.result()
                    except Exception as exc:  # a worker crash must not lose the sweep
                        record = {"org": org, "repo": futures[future],
                                  "tree_ok": False, "error": f"worker crash: {exc}"}
                    handle.write(json.dumps(record) + "\n")
                    handle.flush()
                    counts["repos"] += 1
                    counts["tree_ok" if record.get("tree_ok") else "tree_failed"] += 1
                    # Resolution is the accounting that decides whether a zero from this
                    # sweep is a clean finding. Every repository lands in exactly one
                    # bucket, and the buckets sum to `repos`, so the report can state
                    # coverage as a number instead of as an adjective.
                    resolution = record.get("resolution") or "unresolved"
                    counts[f"resolution_{resolution}"] += 1
                    if resolution == "unresolved":
                        unresolved_repos.append({
                            "repo": record.get("full_name") or f"{org}/{record.get('repo')}",
                            "why": record.get("error") or ("truncated tree: "
                                   + ", ".join(record.get("truncation_unresolved_subtrees") or [])),
                        })
                    if record.get("truncated"):
                        counts["truncated"] += 1
                    if record.get("truncation_resolved_by"):
                        counts["truncation_resolved_by_walk"] += 1
                    if record.get("npm_relevant"):
                        counts["npm_relevant"] += 1
                    if record.get("indicator_hits"):
                        counts["repos_with_indicator_hits"] += 1
                        for hit in record["indicator_hits"]:
                            print(f"  INDICATOR {org}/{record['repo']}: {hit}",
                                  file=sys.stderr)
                    if record.get("bun_artifact_hits"):
                        counts["repos_with_bun_artifacts"] += 1
                        for hit in record["bun_artifact_hits"]:
                            counts[f"bun_{hit['kind']}"] += 1
                            print(f"  BUN {org}/{record['repo']}: "
                                  f"{hit['kind']} {hit['path']}", file=sys.stderr)
                    if record.get("hooks_running_code"):
                        counts["repos_with_hooks_running_code"] += 1
                        for hook in record["hook_files"]:
                            if hook.get("runs_node_or_bun") or hook.get("matched_tokens"):
                                print(f"  HOOK {org}/{record['repo']}: {hook['path']} "
                                      f"tokens={hook.get('matched_tokens')} "
                                      f"sha256={hook.get('sha256', '')[:16]}",
                                      file=sys.stderr)
                    if done % 100 == 0:
                        print(f"  {org}: {done}/{len(repos)}", file=sys.stderr)

            org_cov.update(counts)
            coverage["orgs"][org] = org_cov
            coverage["totals"].update(counts)
            print(f"{org}: done — {dict(counts)}", file=sys.stderr)

    coverage["totals"] = dict(coverage["totals"])
    totals = coverage["totals"]
    # The one number that decides whether this sweep's zero is a clean finding. Asserted
    # here rather than inferred in the report, so the two can never disagree.
    totals["repos_unresolved"] = len(unresolved_repos)
    totals["coverage_complete"] = not unresolved_repos
    coverage["unresolved_repos"] = unresolved_repos
    coverage["resolution_accounting"] = {
        "read": totals.get("resolution_read", 0),
        "no_files": totals.get("resolution_no_files", 0),
        "unresolved": totals.get("resolution_unresolved", 0),
        "sums_to_repos": (totals.get("resolution_read", 0)
                          + totals.get("resolution_no_files", 0)
                          + totals.get("resolution_unresolved", 0)) == totals.get("repos", 0),
        "note": "no_files repositories have no commits or an empty tree. They cannot "
                "contain a file-based indicator, so they are resolved, not failed.",
    }
    coverage_path = args.out.with_name(args.out.stem + "_coverage.json")
    coverage_path.write_text(json.dumps(coverage, indent=2))
    print(f"\nrecords: {args.out}\ncoverage: {coverage_path}", file=sys.stderr)
    print(json.dumps(coverage["totals"], indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
