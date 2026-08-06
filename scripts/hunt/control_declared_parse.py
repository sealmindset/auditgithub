#!/usr/bin/env python3
"""
Control for check_declared_ranges.py: prove the declaration reader can return rows.

Why this exists
---------------
check_declared_ranges.py read 542 manifests across 331 repositories and reported zero
declared ranges in scope. That number is either the answer or a broken parser, and the
output is identical either way — the script only records declarations whose name is in
the malicious set, so a manifest reader that returns nothing at all produces the same
clean-looking zero as a manifest reader that works perfectly.

This control re-reads a sample of the same manifests with the same fetch path and the
same DEP_SECTIONS, and counts EVERY declaration rather than only in-scope ones. Three
outcomes:

  * total declarations 0            -> the reader is broken; the zero is meaningless.
  * total > 0, in-scope 0           -> the reader works; the zero is a real finding.
  * in-scope > 0                    -> check_declared_ranges.py has a filter bug.

The sample is deliberately biased toward repositories the lockfile hunt showed contain
affected package NAMES (at other versions). Those are where a direct declaration is most
likely to exist, so a zero there is the strongest available negative. A random sample
would mostly draw repositories with no relationship to these packages, where finding
nothing proves nothing.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Dict, List, Set

sys.path.insert(0, str(Path(__file__).resolve().parent))

from check_declared_ranges import (  # noqa: E402
    DEP_SECTIONS,
    Throttle,
    fetch_json,
    load_env,
    ORG_TOKEN_VARS,
    REPO_ROOT,
)


def read_all_declarations(record: dict, token: str) -> dict:
    org, repo = record["org"], record["repo"]
    ref = record.get("branch_inspected") or record.get("default_branch")
    manifests = [p for p in (record.get("npm_manifests") or [])
                 if p.rsplit("/", 1)[-1] == "package.json"
                 and "node_modules/" not in p]
    out = {
        "full_name": record["full_name"], "manifests_found": len(manifests),
        "manifests_read": 0, "total_declarations": 0, "read_errors": [],
        "by_section": Counter(), "declared_names": set(),
    }
    for path in manifests:
        data, error = fetch_json(org, repo, ref, path, token)
        if data is None:
            out["read_errors"].append({"path": path, "error": error})
            continue
        out["manifests_read"] += 1
        for section in DEP_SECTIONS:
            entries = data.get(section) or {}
            if not isinstance(entries, dict):
                continue
            for name, spec in entries.items():
                if isinstance(spec, str):
                    out["total_declarations"] += 1
                    out["by_section"][section] += 1
                    out["declared_names"].add(name)
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path,
                        default=REPO_ROOT / "exports/hunt/repo_trees.jsonl")
    parser.add_argument("--lockfiles", type=Path,
                        default=REPO_ROOT / "exports/hunt/lockfile_exposure.jsonl")
    parser.add_argument("--scope", type=Path,
                        default=REPO_ROOT / "exports/hunt/registry_truth_v2.json")
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/control_declared_parse.json")
    parser.add_argument("--sample", type=int, default=60)
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--min-interval", type=float, default=0.35)
    args = parser.parse_args()

    truth = json.loads(args.scope.read_text())
    affected: Set[str] = {spec.rpartition("@")[0]
                          for spec in (truth.get("malicious_specs") or [])}

    # Rank by how many affected names the lockfile hunt saw in each repository. Those
    # repositories provably relate to these packages; if a direct declaration exists
    # anywhere on the estate, it is most likely to be in one of them.
    weight: Dict[str, int] = {}
    for line in args.lockfiles.read_text().splitlines():
        if not line:
            continue
        row = json.loads(line)
        weight[row["full_name"]] = len(row.get("affected_names_present") or [])

    records = [json.loads(line) for line in args.trees.read_text().splitlines() if line]
    targets = [r for r in records if r.get("npm_relevant")]
    targets.sort(key=lambda r: (-weight.get(r["full_name"], 0),
                                -(r.get("npm_manifest_count") or 0)))
    targets = targets[:args.sample]

    env = load_env(REPO_ROOT / ".env")
    throttle = Throttle(min_interval=args.min_interval)

    results: List[dict] = []
    with ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = {}
        for record in targets:
            token = next((env[v] for v in ORG_TOKEN_VARS.get(record["org"], [])
                          if env.get(v)), env.get("GITHUB_TOKEN"))
            if not token:
                continue
            futures[pool.submit(read_all_declarations, record, token)] = record
        for done, future in enumerate(as_completed(futures), 1):
            try:
                results.append(future.result())
            except Exception as exc:  # noqa: BLE001
                results.append({"full_name": futures[future]["full_name"],
                                "error": f"{type(exc).__name__}: {exc}",
                                "total_declarations": 0, "manifests_read": 0,
                                "manifests_found": 0, "read_errors": [],
                                "by_section": Counter(), "declared_names": set()})
            if done % 20 == 0:
                print(f"  {done}/{len(futures)}", file=sys.stderr)
    _ = throttle

    total_declarations = sum(r["total_declarations"] for r in results)
    manifests_read = sum(r["manifests_read"] for r in results)
    all_names: Set[str] = set()
    for record in results:
        all_names |= set(record.get("declared_names") or ())
    in_scope = sorted(all_names & affected)

    if total_declarations == 0:
        verdict = "CONTROL_FAILED_reader_returns_nothing"
    elif in_scope:
        verdict = "FILTER_BUG_in_scope_names_declared_but_not_reported"
    else:
        verdict = "control_passed_reader_works_and_no_in_scope_declarations"

    payload = {
        "repos_sampled": len(results),
        "manifests_read": manifests_read,
        "total_declarations_all_names": total_declarations,
        "distinct_names_declared": len(all_names),
        "declared_names_in_malicious_scope": in_scope,
        "affected_names_in_scope": len(affected),
        "by_section": dict(sum((r["by_section"] for r in results), Counter())),
        "verdict": verdict,
        "sample_selection": (
            "The 60 npm-relevant repositories with the most affected package names "
            "present in their lockfiles, then by manifest count. Biased on purpose: a "
            "zero is only worth reporting where a non-zero was plausible."
        ),
        "repos": sorted(
            ({k: (sorted(v) if isinstance(v, set) else dict(v) if isinstance(v, Counter) else v)
              for k, v in r.items() if k != "declared_names"}
             for r in results),
            key=lambda r: -r["total_declarations"],
        ),
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2))
    print(f"\nwritten: {args.out}", file=sys.stderr)
    print(f"{verdict}: {total_declarations} declarations across {manifests_read} manifests, "
          f"{len(all_names)} distinct names, {len(in_scope)} in malicious scope",
          file=sys.stderr)
    return 0 if verdict.startswith("control_passed") else 3


if __name__ == "__main__":
    sys.exit(main())
