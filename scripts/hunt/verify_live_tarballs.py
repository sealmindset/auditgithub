#!/usr/bin/env python3
"""
Resolve cleanup-miss candidates by hashing the tarball npm is actually serving.

Why hash instead of reason about timestamps
-------------------------------------------
`suspected_uncleaned` finds versions published inside the attack window that are still
installable while sibling in-window versions were withdrawn. That is a lead, and the
population is mixed. Three different things produce the same shape:

  * live malware npm's unpublish sweep missed — confirmed to exist on this campaign;
  * a maintainer's legitimate recovery release, republished after the incident;
  * npm's own tombstone, published as `0.0.1-security` when npm security removes a
    package (@servicetitan/suppress-warnings@0.0.1-security is one).

Timestamps cannot separate these reliably, and the attack window is itself derived from
the malicious set that excluded these very versions — so filtering by it would be
circular. The tarball is the ground truth: either it contains the campaign's loader and
payload at their known hashes, or it does not.

Safety
------
Tarballs are downloaded and read. Nothing is installed and nothing is executed: the
archive is opened for listing and member extraction to memory only. This matters
because every one of these packages carries "preinstall": "node setup.mjs", so an
`npm install` to inspect them would execute the payload being investigated.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
import tarfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
IOC_DIR = REPO_ROOT / "github_conf" / "ioc"

# Members worth hashing. The dropper and payload are the decisive artifacts; other
# members are recorded by name only so a repacked variant is still visible.
INTERESTING_MEMBERS = (
    "package/setup.mjs",
    "package/math_init.js",
    "package/Math_Symbol.js",
    "package/.vscode/setup.mjs",
    "package/.claude/setup.mjs",
    "package/.claude/math_init.js",
    # Unit 42 names router_runtime.js as a third dropped file and gives no hash for it,
    # so it is hashed here rather than trusted by name: a member at this path in a live
    # tarball is what would produce the first hash for it.
    "package/router_runtime.js",
)


def load_known_hashes() -> Dict[str, str]:
    """Known campaign hashes, read from the IOC files so this cannot drift from them."""
    known: Dict[str, str] = {}
    # Enumerated rather than named, for the reason recorded in collect_repo_trees.py:
    # a named list means a newly ingested source is silently absent from the check.
    # StepSecurity, Cycode and Unit 42 all state hashes under a `hashes` mapping rather
    # than `file_hashes_sha256`, so both shapes are read here; Unit 42 is the only source
    # for the second dropper variant.
    for path in sorted(IOC_DIR.glob("*.json")):
        name = path.name
        data = json.loads(path.read_text())
        for meta in (data.get("hashes") or {}).values():
            if not isinstance(meta, dict):
                continue
            digest = meta.get("sha256")
            if digest:
                filenames = meta.get("filenames") or []
                label = f"{name}: {'/'.join(filenames) or 'unnamed member'}"
                known.setdefault(digest.lower(), label)
        for entry in data.get("file_hashes_sha256") or []:
            if isinstance(entry, dict):
                digest = entry.get("sha256") or entry.get("hash")
                label = entry.get("file") or entry.get("role") or name
            else:
                digest, label = entry, name
            if digest:
                known[digest.lower()] = label
        # Elastic states its confirmations in prose rather than a hash list.
        rel = data.get("_relationship_to_shai_hulud_2026_08", {}) or {}
        for claim in rel.get("confirms", []) or []:
            for token in claim.split():
                token = token.strip(".,").lower()
                if len(token) == 64 and all(c in "0123456789abcdef" for c in token):
                    known.setdefault(token, f"{name}: {claim[:60]}")
    return known


def http_get(url: str, attempts: int = 3, timeout: int = 90) -> Optional[bytes]:
    for attempt in range(attempts):
        try:
            request = urllib.request.Request(
                url, headers={"User-Agent": "auditgithub-hunt/1.0"}
            )
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return response.read()
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as exc:
            if attempt == attempts - 1:
                raise
            _ = exc
    return None


def verify_spec(spec: str, known: Dict[str, str]) -> dict:
    package, _, version = spec.rpartition("@")
    result = {
        "spec": spec, "package": package, "version": version,
        "verdict": "unresolved", "error": None,
        "members_hashed": {}, "known_hash_matches": [],
        "lifecycle_scripts": {}, "member_names": [],
    }
    try:
        packument = json.loads(http_get(f"https://registry.npmjs.org/{package}") or b"{}")
        entry = (packument.get("versions") or {}).get(version)
        if not entry:
            result["verdict"] = "absent_from_registry"
            result["error"] = "version no longer published (unpublished since arbitration)"
            return result
        tarball_url = ((entry.get("dist") or {}).get("tarball"))
        if not tarball_url:
            result["error"] = "no tarball URL in packument"
            return result

        blob = http_get(tarball_url)
        result["tarball_sha256"] = hashlib.sha256(blob).hexdigest()
        result["tarball_bytes"] = len(blob)

        # Listing and in-memory extraction only. Never extracted to disk, never installed.
        with tarfile.open(fileobj=io.BytesIO(blob), mode="r:gz") as archive:
            names = archive.getnames()
            result["member_names"] = [n for n in names if not n.endswith("/")][:400]
            for member in INTERESTING_MEMBERS:
                if member not in names:
                    continue
                handle = archive.extractfile(member)
                if handle is None:
                    continue
                data = handle.read()
                digest = hashlib.sha256(data).hexdigest()
                result["members_hashed"][member] = {"sha256": digest, "size": len(data)}
                if digest in known:
                    result["known_hash_matches"].append(
                        {"member": member, "sha256": digest, "known_as": known[digest]}
                    )
            if "package/package.json" in names:
                handle = archive.extractfile("package/package.json")
                if handle is not None:
                    try:
                        manifest = json.loads(handle.read())
                        scripts = manifest.get("scripts") or {}
                        result["lifecycle_scripts"] = {
                            k: v for k, v in scripts.items()
                            if k in ("preinstall", "install", "postinstall",
                                     "prepare", "prepublish")
                        }
                    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                        result["lifecycle_scripts"] = {"_parse_error": str(exc)}
    except Exception as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result

    # Verdicts, most decisive first. A known hash match is conclusive; a dropper filename
    # plus a lifecycle hook is strong but wants the hash recorded; a bare `-security`
    # version with neither is npm's tombstone, not malware.
    if result["known_hash_matches"]:
        result["verdict"] = "MALICIOUS_CONFIRMED_BY_HASH"
    elif result["members_hashed"] and result["lifecycle_scripts"]:
        result["verdict"] = "MALICIOUS_LIKELY_UNKNOWN_HASH"
    elif result["members_hashed"]:
        result["verdict"] = "dropper_file_present_no_lifecycle_hook"
    elif version.endswith("-security"):
        result["verdict"] = "npm_security_tombstone"
    else:
        result["verdict"] = "clean_no_dropper_artifacts"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--input", type=Path,
                        default=REPO_ROOT / "exports/hunt/registry_truth_v2.json")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/live_tarball_verdicts.json")
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--specs", nargs="*", help="Verify these specs instead of the file.")
    args = parser.parse_args()

    known = load_known_hashes()
    print(f"known campaign hashes loaded: {len(known)}", file=sys.stderr)
    if not known:
        print("refusing to run: no known hashes in github_conf/ioc/", file=sys.stderr)
        return 2

    if args.specs:
        specs = list(args.specs)
    else:
        data = json.loads(args.input.read_text())
        specs = list(data.get("suspected_uncleaned_specs") or [])
    print(f"specs to verify: {len(specs)}", file=sys.stderr)

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {pool.submit(verify_spec, s, known): s for s in specs}
        for done, future in enumerate(as_completed(futures), 1):
            try:
                record = future.result()
            except Exception as exc:
                record = {"spec": futures[future], "verdict": "unresolved",
                          "error": f"worker crash: {exc}"}
            results.append(record)
            if record["verdict"].startswith("MALICIOUS"):
                print(f"  {record['verdict']}  {record['spec']}  "
                      f"scripts={record.get('lifecycle_scripts')}", file=sys.stderr)
            if done % 20 == 0:
                print(f"  {done}/{len(specs)}", file=sys.stderr)

    by_verdict: Dict[str, List[str]] = {}
    for record in results:
        by_verdict.setdefault(record["verdict"], []).append(record["spec"])

    payload = {
        "specs_verified": len(results),
        "summary": {k: len(v) for k, v in sorted(by_verdict.items())},
        "by_verdict": {k: sorted(v) for k, v in sorted(by_verdict.items())},
        "results": sorted(results, key=lambda r: r["spec"]),
        "method": (
            "Downloaded the tarball npm is currently serving for each version, listed it "
            "and hashed package/setup.mjs and package/math_init.js in memory. Nothing was "
            "installed or executed — every one of these versions declares "
            "'preinstall': 'node setup.mjs', so an install to inspect them would run the "
            "payload under investigation."
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"\nwritten: {args.out}", file=sys.stderr)
    print(json.dumps(payload["summary"], indent=2), file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
