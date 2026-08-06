#!/usr/bin/env python3
"""
Evaluate declared dependency ranges against the malicious version set.

The question this answers, and why the lockfile hunt does not
-------------------------------------------------------------
collect_lockfiles.py establishes what is *installed today*. It returned zero matches.
That is the right answer to "are we compromised now", and the wrong answer to "could a
build pull the malicious version". Two populations make the second question live:

  * 37 npm-relevant repositories have a package.json and no lockfile at all. Nothing
    pins them. What they install is decided entirely by the declared range at install
    time, so the lockfile hunt could never clear them — it had nothing to read.
  * Repositories that ARE pinned are pinned only until someone regenerates the lockfile.
    A range that admits a malicious version is a latent exposure in a repository whose
    current lockfile is clean.

Concretely, cacheable-request on this estate reaches 13.0.17 while the malicious version
is 13.0.20 — the same minor line. Both "^13.0.17" and "~13.0.17" admit 13.0.20. The other
three affected names sit a major boundary away (keyv 5.5.5 vs 6.0.0, file-entry-cache
8.0.0 vs 11.1.6, flat-cache 4.0.1 vs 6.1.24), and no caret or tilde range crosses a major.

Why the malicious versions are nonetheless not installable from npm today
------------------------------------------------------------------------
Every version in the malicious set satisfies "published in window AND withdrawn", so the
public registry no longer serves it. A reachable range is therefore a *conditional*
finding: it matters if a copy survives somewhere the range can still resolve against —
a private feed with an npmjs upstream that cached the tarball during the window, or a
build image with a warm npm cache. The two exceptions are the versions npm's sweep
missed, which remain live and are included in the scope for exactly that reason.

Range evaluation
----------------
Uses the semver implementation bundled with the installed npm rather than a
reimplementation, because the failure mode of a hand-rolled range parser is a range it
silently reads as non-matching, which reports as safe. Anything semver cannot parse is
reported as "unknown", never as safe.

Direct dependencies only. A transitive range lives in some dependency's own manifest,
which is not in this repository, so transitive reachability is not established here and
is not claimed.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from threading import Lock
from typing import Dict, List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_API = os.environ.get("GITHUB_API", "https://api.github.com")

DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies",
                "peerDependencies")

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
        if line and not line.startswith("#") and "=" in line:
            key, value = line.split("=", 1)
            env[key.strip()] = value.strip().strip('"').strip("'")
    return env


def locate_semver() -> str:
    """Find the semver module npm ships with, so nothing has to be installed."""
    try:
        root = subprocess.run(["npm", "root", "-g"], capture_output=True, text=True,
                              timeout=60).stdout.strip()
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemExit(f"cannot locate npm: {exc}")
    candidate = Path(root) / "npm" / "node_modules" / "semver"
    if not candidate.exists():
        raise SystemExit(f"semver not found at {candidate}; cannot evaluate ranges")
    return str(candidate)


def evaluate_ranges(pairs: List[Tuple[str, str]], semver_path: str) -> Dict[str, str]:
    """
    Evaluate (range, version) pairs in one node process.

    Returns "true" / "false" / "unknown" keyed by "range\\x00version". A range semver
    cannot parse yields "unknown" so it surfaces as a coverage gap rather than a pass.
    """
    script = """
const semver = require(process.argv[1]);
const pairs = JSON.parse(require('fs').readFileSync(0, 'utf8'));
const out = {};
for (const [range, version] of pairs) {
  const key = range + '\\u0000' + version;
  try {
    const r = semver.validRange(range);
    out[key] = (r === null) ? 'unknown' : (semver.satisfies(version, range) ? 'true' : 'false');
  } catch (e) { out[key] = 'unknown'; }
}
process.stdout.write(JSON.stringify(out));
"""
    result = subprocess.run(
        ["node", "-e", script, semver_path],
        input=json.dumps(pairs), capture_output=True, text=True, timeout=300,
    )
    if result.returncode != 0:
        raise SystemExit(f"semver evaluation failed: {result.stderr[:500]}")
    return json.loads(result.stdout)


class Throttle:
    """
    Shared pacing and backoff across workers, driven by real response headers.

    Two failures motivated every part of this.

    The first run of this script took 541 HTTP 403s out of 583 manifest reads and
    reported zero reachable ranges — a clean-looking result produced entirely by rate
    limiting. A 403 is indistinguishable from a permissions denial at the call site, so
    it has to be retried and, if it survives retries, recorded as a coverage failure
    rather than as an answer.

    More importantly, GET /rate_limit cannot be trusted as a pre-flight check for these
    tokens. Asked at the same moment about the same token, /rate_limit reported
    remaining=4990 used=10 reset-in-2266s while an actual repository request returned
    remaining=0 used=5000 reset-in-1566s. Different buckets, different resets, and the
    optimistic one is the one that costs nothing to ask. Only headers returned by a real
    request describe the budget that real requests spend, so pacing is driven from those.
    """

    def __init__(self, min_interval: float = 0.0, floor: int = 50) -> None:
        self._lock = Lock()
        self._resume_at = 0.0
        self._next_slot = 0.0
        self._min_interval = min_interval
        self._floor = floor
        self.remaining: Optional[int] = None

    def wait(self) -> None:
        while True:
            with self._lock:
                now = time.time()
                delay = max(self._resume_at - now, self._next_slot - now)
                if delay <= 0:
                    self._next_slot = max(now, self._next_slot) + self._min_interval
                    return
            time.sleep(min(delay, 5.0))

    def back_off(self, seconds: float) -> None:
        with self._lock:
            self._resume_at = max(self._resume_at, time.time() + seconds)

    def observe(self, headers) -> None:
        """Pause the whole pool before the quota runs out, not after."""
        if not headers:
            return
        raw_remaining = headers.get("X-RateLimit-Remaining")
        raw_reset = headers.get("X-RateLimit-Reset")
        if raw_remaining is None:
            return
        try:
            remaining = int(raw_remaining)
        except ValueError:
            return
        self.remaining = remaining
        if remaining <= self._floor and raw_reset:
            try:
                sleep_for = max(1.0, float(raw_reset) - time.time() + 2)
            except ValueError:
                return
            print(f"  quota nearly spent (remaining={remaining}); pausing "
                  f"{int(sleep_for)}s for reset", file=sys.stderr)
            self.back_off(sleep_for)


THROTTLE = Throttle()


def fetch_json(org: str, repo: str, ref: str, path: str, token: str,
               attempts: int = 5) -> Tuple[Optional[dict], Optional[str]]:
    url = f"{GITHUB_API}/repos/{org}/{repo}/contents/{urllib.parse.quote(path)}?ref={ref}"
    for attempt in range(attempts):
        THROTTLE.wait()
        request = urllib.request.Request(url, headers={
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.raw",
            "User-Agent": "auditgithub-hunt/1.0",
        })
        try:
            with urllib.request.urlopen(request, timeout=90) as response:
                THROTTLE.observe(response.headers)
                raw = response.read()
        except urllib.error.HTTPError as exc:
            THROTTLE.observe(exc.headers)
            if exc.code in (403, 429):
                headers = exc.headers or {}
                retry_after = headers.get("Retry-After")
                if retry_after:
                    THROTTLE.back_off(float(retry_after))
                elif headers.get("X-RateLimit-Remaining") == "0":
                    reset = headers.get("X-RateLimit-Reset")
                    THROTTLE.back_off(
                        max(1.0, float(reset) - time.time() + 2) if reset else 60.0
                    )
                else:
                    THROTTLE.back_off(min(60.0 * (attempt + 1), 300.0))
                continue
            if exc.code >= 500 and attempt < attempts - 1:
                time.sleep(2 ** attempt)
                continue
            return None, f"HTTP {exc.code}"
        except (urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts - 1:
                return None, f"{type(exc).__name__}"
            time.sleep(2 ** attempt)
            continue
        try:
            return json.loads(raw.decode("utf-8", errors="replace")), None
        except json.JSONDecodeError as exc:
            return None, f"JSONDecodeError: {exc}"
    return None, "rate limited beyond retries"


def collect_manifests(record: dict, token: str, affected_names: Set[str]) -> dict:
    org, repo = record["org"], record["repo"]
    ref = record.get("branch_inspected") or record.get("default_branch")
    manifests = [p for p in (record.get("npm_manifests") or [])
                 if p.rsplit("/", 1)[-1] == "package.json"
                 and "node_modules/" not in p]
    out = {
        "org": org, "repo": repo, "full_name": record["full_name"], "ref": ref,
        "archived": record.get("archived"), "pushed_at": record.get("pushed_at"),
        "manifests_found": len(manifests), "manifests_read": 0,
        "read_errors": [], "declared": [],
    }
    for path in manifests:
        data, error = fetch_json(org, repo, ref, path, token)
        if data is None:
            out["read_errors"].append({"path": path, "error": error})
            continue
        out["manifests_read"] += 1
        for section in DEP_SECTIONS:
            for name, spec in (data.get(section) or {}).items():
                if name in affected_names and isinstance(spec, str):
                    out["declared"].append({"path": path, "section": section,
                                            "name": name, "range": spec})
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
                        default=REPO_ROOT / "exports/hunt/declared_range_exposure.json")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--min-interval", type=float, default=0.0,
                        help="Minimum seconds between requests across all workers.")
    parser.add_argument("--only-orgs", nargs="*", default=None,
                        help="Restrict to these orgs. Useful when one token's quota is "
                             "exhausted but another org's token is a separate identity.")
    args = parser.parse_args()

    global THROTTLE
    THROTTLE = Throttle(min_interval=args.min_interval)

    semver_path = locate_semver()
    print(f"semver: {semver_path}", file=sys.stderr)

    env = load_env(REPO_ROOT / ".env")
    env.update({k: v for k, v in os.environ.items() if k.startswith(("GITHUB_", "ORG_"))})

    truth = json.loads(args.scope.read_text())
    scope: Set[str] = set(truth.get("malicious_specs") or [])
    still_live: Set[str] = set()
    if args.confirmed_live.exists():
        verdicts = json.loads(args.confirmed_live.read_text())
        still_live = set((verdicts.get("by_verdict") or {})
                         .get("MALICIOUS_CONFIRMED_BY_HASH") or [])
        scope |= still_live

    # name -> the malicious versions of that name
    versions_by_name: Dict[str, List[str]] = defaultdict(list)
    for spec in scope:
        name, _, version = spec.rpartition("@")
        versions_by_name[name].append(version)
    affected_names = set(versions_by_name)
    print(f"scope: {len(scope)} specs across {len(affected_names)} package names "
          f"({len(still_live)} still installable from npm)", file=sys.stderr)

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    targets = [r for r in records if r.get("npm_relevant")]
    if args.only_orgs:
        wanted = {o.lower() for o in args.only_orgs}
        targets = [r for r in targets if r["org"].lower() in wanted]
    print(f"npm-relevant repositories: {len(targets)}", file=sys.stderr)

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for record in targets:
            token = next((env[v] for v in ORG_TOKEN_VARS.get(record["org"], ["GITHUB_TOKEN"])
                          if env.get(v)), None)
            if not token:
                results.append({"full_name": record["full_name"], "error": "no token"})
                continue
            futures[pool.submit(collect_manifests, record, token, affected_names)] = record
        for done, future in enumerate(as_completed(futures), 1):
            record = futures[future]
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"full_name": record["full_name"],
                                "error": f"worker crash: {exc}"})
            if done % 50 == 0:
                print(f"  {done}/{len(futures)}", file=sys.stderr)

    # One node call for every distinct (range, malicious version) pair.
    to_check: Set[Tuple[str, str]] = set()
    for result in results:
        for declaration in result.get("declared") or []:
            for version in versions_by_name[declaration["name"]]:
                to_check.add((declaration["range"], version))
    print(f"range/version pairs to evaluate: {len(to_check)}", file=sys.stderr)
    verdicts = evaluate_ranges(sorted(to_check), semver_path) if to_check else {}

    reachable: List[dict] = []
    unknown: List[dict] = []
    counts: Counter = Counter()
    lock_state = {}
    for record in records:
        if record.get("npm_relevant"):
            has_lock = any(p.rsplit("/", 1)[-1] in ("package-lock.json", "yarn.lock",
                                                    "pnpm-lock.yaml", "npm-shrinkwrap.json")
                           for p in (record.get("npm_manifests") or []))
            lock_state[record["full_name"]] = has_lock

    for result in results:
        counts["repos"] += 1
        if result.get("error"):
            counts["errors"] += 1
            continue
        if result.get("read_errors"):
            counts["repos_with_read_error"] += 1
        if result.get("declared"):
            counts["repos_declaring_affected_name"] += 1
        for declaration in result["declared"]:
            for version in versions_by_name[declaration["name"]]:
                verdict = verdicts.get(f"{declaration['range']}\x00{version}", "unknown")
                entry = {
                    "repo": result["full_name"], "path": declaration["path"],
                    "section": declaration["section"], "name": declaration["name"],
                    "declared_range": declaration["range"],
                    "malicious_version": version,
                    "pinned_by_lockfile": lock_state.get(result["full_name"]),
                    "still_installable_from_npm": f"{declaration['name']}@{version}" in still_live,
                }
                if verdict == "true":
                    reachable.append(entry)
                    counts["REACHABLE_DECLARATIONS"] += 1
                elif verdict == "unknown":
                    unknown.append(entry)
                    counts["unparseable_ranges"] += 1

    # Coverage gate. A run that could not read its inputs has no verdict to give, and the
    # shape of that failure is a zero — which is why it is asserted here rather than left
    # for a reader to notice in the counts.
    manifests_found = sum(r.get("manifests_found") or 0 for r in results)
    manifests_read = sum(r.get("manifests_read") or 0 for r in results)
    read_rate = (manifests_read / manifests_found) if manifests_found else 0.0
    coverage_valid = read_rate >= 0.98
    if not coverage_valid:
        print(f"\n*** COVERAGE FAILURE: read {manifests_read}/{manifests_found} manifests "
              f"({read_rate:.1%}). This run cannot support a negative finding. ***",
              file=sys.stderr)

    payload = {
        "scope_specs": len(scope),
        "coverage_valid": coverage_valid,
        "manifests_found": manifests_found,
        "manifests_read": manifests_read,
        "manifest_read_rate": round(read_rate, 4),
        "still_installable_from_npm": sorted(still_live),
        "counts": dict(counts),
        "reachable": sorted(reachable, key=lambda e: (e["repo"], e["name"])),
        "unknown_ranges": unknown,
        "repos_without_lockfile": sorted(
            name for name, has_lock in lock_state.items() if not has_lock
        ),
        "per_repo": results,
        "interpretation": [
            "REACHABLE_DECLARATIONS counts direct declarations whose range admits a "
            "malicious version. It is a latent finding, not an active compromise: all but "
            "the still_installable_from_npm versions were withdrawn from the public "
            "registry, so the range can only resolve against a surviving copy — a private "
            "feed that cached the tarball during the window, or a warm npm cache in a "
            "build image.",
            "pinned_by_lockfile=false is the urgent subset. Those repositories have no "
            "lockfile, so the declared range decides every install, and the lockfile hunt "
            "had nothing to read for them.",
            "Direct dependencies only. Transitive ranges live in other packages' "
            "manifests and are not evaluated; a zero here does not clear transitive paths.",
            "unparseable_ranges are ranges semver could not validate (git URLs, file: "
            "paths, aliases). They are reported as unknown, never as safe.",
        ],
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"\nwritten: {args.out}", file=sys.stderr)
    print(f"coverage_valid={coverage_valid} "
          f"({manifests_read}/{manifests_found} manifests read)", file=sys.stderr)
    print(json.dumps(payload["counts"], indent=2), file=sys.stderr)
    return 0 if coverage_valid else 3


if __name__ == "__main__":
    sys.exit(main())
