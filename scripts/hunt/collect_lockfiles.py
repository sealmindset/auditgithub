#!/usr/bin/env python3
"""
Extract resolved npm name@version pairs from lockfiles, straight from GitHub.

Why this exists
---------------
The estate had 2,810 repositories, 364 of them npm-relevant, and dependency data for
only 144 — so 222 npm-relevant repositories had never been examined at all. The previous
hunt's "no affected package found" was computed over the 144 and reported as a clean
result for the estate. It was not clean; it was 39% measured.

The existing collection path clones each repository and runs Syft. That is thorough and
far too slow to close a 222-repository gap during an incident. A lockfile already
contains exactly what the hunt needs and nothing it does not: the *resolved* versions
actually installed. Manifest ranges cannot answer the question — "^4.5.4" tells you what
was permitted, not what was locked — and a name without a version is unactionable here,
because keyv, flat-cache and cacheable-request are ordinary dependencies at safe
versions on this estate.

Reads lockfile paths from the tree sweep (scripts/hunt/collect_repo_trees.py) so it
fetches only files known to exist.

Formats handled, and how each states a resolved version
------------------------------------------------------
* package-lock.json v2/v3 — "packages" keyed by path, version per entry
* package-lock.json v1   — nested "dependencies", version per entry
* yarn.lock v1           — "name@range:" blocks with an indented "version" line
* yarn.lock berry (v2+)  — YAML-ish, same shape, quoted keys
* pnpm-lock.yaml         — "packages:" keys of the form /name/version or name@version

A format this does not understand is recorded as a parse failure, not skipped silently:
an unparsed lockfile is a repository the hunt did not actually cover, and it has to be
counted that way or the coverage number is a lie.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")

LOCKFILE_BASENAMES = {
    "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
}

ORG_TOKEN_VARS = {
    "SleepNumberInc": ["ORG_SLEEPNUMBERINC_TOKEN", "GITHUB_TOKEN"],
    "sleepnumberlabs": ["ORG_SLEEPNUMBERLABS_TOKEN"],
    "sleepnumber": ["ORG_SLEEPNUMBER_TOKEN", "GITHUB_TOKEN"],
}


def load_env(path: Path) -> Dict[str, str]:
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


class Throttle:
    """
    Shared pause on rate limiting, plus a minimum gap between requests.

    The pacing matters as much as the backoff. GitHub's *secondary* rate limit on the
    contents endpoint is independent of the core quota: with 4,990 of 5,000 core requests
    still available, a sustained 8-worker read returned HTTP 403 in 0.26s on every call.
    Backing off after the fact only recovers; spacing requests is what avoids tripping it.
    A 403 here is not a permissions problem and must never be recorded as one.
    """

    def __init__(self, min_interval: float = 0.0) -> None:
        self._lock = Lock()
        self._resume_at = 0.0
        self._next_slot = 0.0
        self._min_interval = min_interval

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.time()
                delay = max(self._resume_at - now, self._next_slot - now)
                if delay <= 0:
                    # Claim this slot before releasing the lock, so two workers cannot
                    # both decide the gap has elapsed and fire simultaneously.
                    self._next_slot = max(now, self._next_slot) + self._min_interval
                    return
            time.sleep(min(delay, 5.0))

    def back_off(self, seconds: float) -> None:
        with self._lock:
            self._resume_at = max(self._resume_at, time.time() + seconds)


THROTTLE = Throttle()


def fetch_raw(org: str, repo: str, ref: str, path: str, token: str,
              attempts: int = 4) -> Tuple[Optional[bytes], Optional[str]]:
    """
    Fetch a file's raw bytes.

    The raw media type is used rather than the default JSON-with-base64 response because
    the latter refuses files over 1 MB, and a package-lock.json for a real application is
    routinely larger than that. Falling back to base64 would silently skip the biggest
    repositories — exactly the ones with the most dependencies.
    """
    url = f"{GITHUB_API}/repos/{org}/{repo}/contents/{urllib.parse.quote(path)}?ref={ref}"
    for attempt in range(attempts):
        THROTTLE.wait()
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.raw",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=120) as response:
                return response.read(), None
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429):
                retry_after = (exc.headers or {}).get("Retry-After")
                THROTTLE.back_off(float(retry_after) if retry_after else 60.0)
                continue
            if exc.code >= 500 and attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts - 1:
                return None, f"{type(exc).__name__}: {exc}"
            time.sleep(2 ** attempt)
    return None, "exhausted attempts"


_CONFLICT_START = re.compile(r"^<{7}[ \t]")
_CONFLICT_MID = re.compile(r"^={7}\s*$")
_CONFLICT_END = re.compile(r"^>{7}[ \t]")


def split_merge_conflicts(text: str) -> List[str]:
    """
    Turn a lockfile containing unresolved conflict markers into parseable variants.

    Two repositories on this estate committed package-lock.json files with live
    <<<<<<< / ======= / >>>>>>> markers (product-exchange-backend line 5164,
    snint-fn-test-sftp-onpremise-dev line 8162). Those files are not valid JSON, so
    `npm ci` cannot install them at all — but they were the only dependency record those
    repositories had, and dropping them would have left two repositories unexamined.

    Simply deleting the marker lines does not work: the two sides become sibling entries
    with no comma between them, which is still invalid. Instead each side is extracted
    into its own complete document, and the caller unions the results. The union is the
    conservative reading — if either side of an unresolved merge names a malicious
    version, the repository is in scope regardless of which side would eventually win.
    """
    if not any(_CONFLICT_START.match(line) for line in text.splitlines()):
        return [text]
    ours: List[str] = []
    theirs: List[str] = []
    side = "both"
    for line in text.splitlines(keepends=True):
        if _CONFLICT_START.match(line):
            side = "ours"
            continue
        if _CONFLICT_MID.match(line) and side == "ours":
            side = "theirs"
            continue
        if _CONFLICT_END.match(line):
            side = "both"
            continue
        if side in ("both", "ours"):
            ours.append(line)
        if side in ("both", "theirs"):
            theirs.append(line)
    return ["".join(ours), "".join(theirs)]


def parse_package_lock(text: str) -> Set[str]:
    """package-lock.json / npm-shrinkwrap.json, both layouts."""
    pairs: Set[str] = set()
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        variants = split_merge_conflicts(text)
        if len(variants) < 2:
            raise
        recovered: Set[str] = set()
        errors: List[str] = []
        for variant in variants:
            try:
                recovered |= parse_package_lock(variant)
            except json.JSONDecodeError as exc:
                errors.append(str(exc))
        if not recovered:
            raise json.JSONDecodeError(
                f"unresolved merge conflict, neither side parsed: {errors}", text, 0
            )
        return recovered

    # v2/v3: flat "packages" map keyed by install path.
    for path, entry in (data.get("packages") or {}).items():
        if not isinstance(entry, dict):
            continue
        version = entry.get("version")
        name = entry.get("name")
        if not name and path:
            # "node_modules/@scope/pkg/node_modules/dep" -> "dep"; the last
            # node_modules segment is the package's own name, scope included.
            marker = "node_modules/"
            idx = path.rfind(marker)
            if idx >= 0:
                name = path[idx + len(marker):]
        if name and version:
            pairs.add(f"{name}@{version}")

    # v1: recursive "dependencies".
    def walk(node: dict) -> None:
        for name, entry in (node.get("dependencies") or {}).items():
            if not isinstance(entry, dict):
                continue
            version = entry.get("version")
            if version:
                pairs.add(f"{name}@{version}")
            walk(entry)

    walk(data)
    return pairs


_YARN_ENTRY = re.compile(r'^(?P<keys>(?:"[^"]+"|[^\s#][^:\n]*?))\s*:\s*$')
_YARN_VERSION = re.compile(r'^\s+version:?\s+"?(?P<version>[^"\s]+)"?\s*$')


def parse_yarn_lock(text: str) -> Set[str]:
    """
    yarn.lock, both the v1 custom format and the berry YAML-ish one.

    An entry's key lists every range that resolved to the same version
    ("keyv@^4.5.4, keyv@^4.5.0:"), and the version line follows in the block. The name is
    everything before the LAST '@', because scoped names begin with one.
    """
    pairs: Set[str] = set()
    current_names: List[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            match = _YARN_ENTRY.match(line.rstrip())
            current_names = []
            if match:
                for key in match.group("keys").split(","):
                    key = key.strip().strip('"')
                    if not key or key in ("__metadata",):
                        continue
                    name = key.rsplit("@", 1)[0] if key.count("@") >= 1 else key
                    # A berry descriptor may be "name@npm:range"; the rsplit above already
                    # removed it. A bare "name" with no '@' keeps its own value.
                    if name:
                        current_names.append(name)
            continue
        version_match = _YARN_VERSION.match(line)
        if version_match and current_names:
            version = version_match.group("version")
            for name in current_names:
                pairs.add(f"{name}@{version}")
    return pairs


def parse_pnpm_lock(text: str) -> Set[str]:
    """
    pnpm-lock.yaml, without a YAML dependency.

    Three key layouts exist across versions, and the leading slash does not tell you which
    separator is in use:

        /keyv/4.5.4:        v5      leading slash, slash separator
        /keyv@6.0.0:        v6      leading slash, AT separator
        keyv@6.0.0:         v9      no slash, at separator

    So the separator is chosen by which one yields a version, not by the slash. Splitting
    v6 keys on "/" finds no separator and silently produced zero pairs — a parser that
    returns nothing reads as a clean repository, which is the worst possible failure here.

    A peer-dependency suffix in parentheses — "react-dom@18.2.0(react@18.2.0)" — is not
    part of the version and is removed first, before any '@' splitting, or the trailing
    peer spec would be mistaken for the version.

    Entries are identified by indentation rather than by a trailing colon. v9 writes
    "keyv@6.0.0: {}" with the value inline, so a trailing-colon test misses the whole
    snapshots block; and matching any "key:" line at any depth would harvest the nested
    "resolution:" and "dependencies:" properties as though they were packages. The first
    line inside the block establishes the entry indent, and only that depth is read.
    """
    pairs: Set[str] = set()
    in_packages = False
    entry_indent: Optional[int] = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent == 0:
            in_packages = stripped.rstrip(":") in ("packages", "snapshots")
            entry_indent = None
            continue
        if not in_packages:
            continue
        if entry_indent is None:
            entry_indent = indent
        if indent != entry_indent:
            continue
        # Split on the LAST ": " so a key containing a colon still resolves; a bare
        # trailing colon means the value is nested on following lines.
        key = stripped[:-1] if stripped.endswith(":") else stripped.rsplit(": ", 1)[0]
        key = key.strip().strip("'\"")
        key = key.split("(", 1)[0].lstrip("/")
        name, version = "", ""
        for separator in ("@", "/"):
            candidate_name, _, candidate_version = key.rpartition(separator)
            if candidate_name and re.match(r"^\d", candidate_version):
                name, version = candidate_name, candidate_version
                break
        if name and version:
            pairs.add(f"{name}@{version}")
    return pairs


PARSERS = {
    "package-lock.json": parse_package_lock,
    "npm-shrinkwrap.json": parse_package_lock,
    "yarn.lock": parse_yarn_lock,
    "pnpm-lock.yaml": parse_pnpm_lock,
}


def collect_repo(record: dict, token: str, scope: Set[str]) -> dict:
    org, repo = record["org"], record["repo"]
    ref = record.get("branch_inspected") or record.get("default_branch")
    lockfiles = [p for p in (record.get("npm_manifests") or [])
                 if p.rsplit("/", 1)[-1] in LOCKFILE_BASENAMES]
    out = {
        "org": org, "repo": repo, "full_name": record["full_name"],
        "ref": ref, "archived": record.get("archived"),
        "pushed_at": record.get("pushed_at"),
        "lockfiles_found": lockfiles,
        "lockfiles_parsed": [], "parse_failures": [],
        "pair_count": 0, "matches": [],
        "has_manifest_only": bool(record.get("npm_relevant")) and not lockfiles,
    }
    all_pairs: Set[str] = set()
    for path in lockfiles:
        basename = path.rsplit("/", 1)[-1]
        blob, error = fetch_raw(org, repo, ref, path, token)
        if blob is None:
            out["parse_failures"].append({"path": path, "error": f"fetch: {error}"})
            continue
        try:
            text = blob.decode("utf-8", errors="replace")
            pairs = PARSERS[basename](text)
        except Exception as exc:
            out["parse_failures"].append({"path": path,
                                          "error": f"{type(exc).__name__}: {exc}"})
            continue
        out["lockfiles_parsed"].append({"path": path, "pairs": len(pairs),
                                        "bytes": len(blob)})
        all_pairs |= pairs

    out["pair_count"] = len(all_pairs)
    hits = sorted(all_pairs & scope)
    out["matches"] = hits
    # Name-level context: which affected package names appear at all, at what versions.
    scope_names = {s.rpartition("@")[0] for s in scope}
    present = {}
    for pair in all_pairs:
        name, _, version = pair.rpartition("@")
        if name in scope_names:
            present.setdefault(name, []).append(version)
    out["affected_names_present"] = {k: sorted(set(v)) for k, v in sorted(present.items())}
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--scope", type=Path,
                        default=REPO_ROOT / "exports/hunt/registry_truth_v2.json")
    parser.add_argument("--confirmed-live", type=Path,
                        default=REPO_ROOT / "exports/hunt/live_tarball_verdicts.json")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/lockfile_exposure.jsonl")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--limit", type=int, default=0)
    parser.add_argument("--only", nargs="*", default=None,
                        help="Restrict to these org/repo full names. Use when re-reading a "
                             "handful of repositories instead of resweeping all 364.")
    parser.add_argument("--min-interval", type=float, default=0.0,
                        help="Minimum seconds between requests across all workers. Set "
                             "this above 0 if the contents endpoint starts returning 403 "
                             "while the core quota is still healthy.")
    args = parser.parse_args()

    global THROTTLE
    THROTTLE = Throttle(min_interval=args.min_interval)

    env = load_env(REPO_ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith(("GITHUB_", "ORG_"))})

    truth = json.loads(args.scope.read_text())
    # Scope is the strict malicious set plus the cleanup misses that hashing confirmed
    # are live malware. Unconfirmed cleanup misses are deliberately excluded: 112 of the
    # 115 candidates were shown clean by tarball hash, and carrying them would inflate
    # the match count with versions that are not the attacker's.
    scope: Set[str] = set(truth.get("malicious_specs") or [])
    confirmed_live: List[str] = []
    if args.confirmed_live.exists():
        verdicts = json.loads(args.confirmed_live.read_text())
        confirmed_live = list(
            (verdicts.get("by_verdict") or {}).get("MALICIOUS_CONFIRMED_BY_HASH") or []
        )
        scope |= set(confirmed_live)
    print(f"hunt scope: {len(scope)} specs "
          f"({len(truth.get('malicious_specs') or [])} registry-confirmed + "
          f"{len(confirmed_live)} hash-confirmed still-live)", file=sys.stderr)

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    targets = [r for r in records if r.get("npm_relevant")]
    if args.only:
        wanted = {name.lower() for name in args.only}
        targets = [r for r in targets if r["full_name"].lower() in wanted]
        missing = wanted - {r["full_name"].lower() for r in targets}
        if missing:
            print(f"not found or not npm-relevant: {sorted(missing)}", file=sys.stderr)
    if args.limit:
        targets = targets[: args.limit]
    print(f"npm-relevant repositories to examine: {len(targets)}", file=sys.stderr)

    counts: Counter = Counter()
    findings: List[dict] = []
    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w") as handle:
        with ThreadPoolExecutor(max_workers=args.workers) as pool:
            futures = {}
            for record in targets:
                token_vars = ORG_TOKEN_VARS.get(record["org"], ["GITHUB_TOKEN"])
                token = next((env[v] for v in token_vars if env.get(v)), None)
                if not token:
                    counts["no_token"] += 1
                    handle.write(json.dumps({**{k: record.get(k) for k in
                                                ("org", "repo", "full_name")},
                                             "error": "no token for org"}) + "\n")
                    continue
                futures[pool.submit(collect_repo, record, token, scope)] = record

            for done, future in enumerate(as_completed(futures), 1):
                record = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = {"org": record["org"], "repo": record["repo"],
                              "full_name": record["full_name"],
                              "error": f"worker crash: {exc}"}
                handle.write(json.dumps(result) + "\n")
                handle.flush()
                counts["repos"] += 1
                if result.get("lockfiles_parsed"):
                    counts["repos_with_parsed_lockfile"] += 1
                if result.get("parse_failures"):
                    counts["repos_with_parse_failure"] += 1
                if result.get("has_manifest_only"):
                    counts["manifest_but_no_lockfile"] += 1
                counts["pairs"] += result.get("pair_count") or 0
                if result.get("matches"):
                    counts["REPOS_WITH_MATCH"] += 1
                    findings.append(result)
                    print(f"  MATCH {result['full_name']}: {result['matches']}",
                          file=sys.stderr)
                if result.get("affected_names_present"):
                    counts["repos_with_affected_name_present"] += 1
                if done % 50 == 0:
                    print(f"  {done}/{len(futures)}", file=sys.stderr)

    coverage = {
        "scope_specs": len(scope),
        "confirmed_live_included": confirmed_live,
        "counts": dict(counts),
        "findings": findings,
        "interpretation": [
            "REPOS_WITH_MATCH is the only positive result. Zero is meaningful only "
            "alongside repos_with_affected_name_present: if affected package NAMES appear "
            "at other versions, the query provably can return rows, which makes the "
            "absence of the malicious versions evidence rather than silence.",
            "manifest_but_no_lockfile counts repositories with a package.json and no "
            "lockfile. Their installed versions are not recorded anywhere in the "
            "repository, so this method cannot clear them; they are unmeasured, not clean.",
            "repos_with_parse_failure is an explicit coverage hole. Those repositories "
            "were fetched but not understood.",
        ],
    }
    coverage_path = args.out.with_name(args.out.stem + "_coverage.json")
    coverage_path.write_text(json.dumps(coverage, indent=2))
    print(f"\nwritten: {args.out}\ncoverage: {coverage_path}", file=sys.stderr)
    print(json.dumps(coverage["counts"], indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
