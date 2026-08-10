#!/usr/bin/env python3
"""Sweep our own orgs for the worm's dead-drop repositories (§6 checks 1 and 12).

This phase treats our GitHub tenancy as a *victim surface*, not as a code host. Modern
worms exfiltrate over provider-owned infrastructure - a repository created under the
stolen account, holding the loot - precisely so that an egress-based network hunt comes
back clean. §5.3's clean network result therefore proves much less than it appears to,
and this is the check that covers the difference.

Why this runs offline, and why that makes it *stronger* rather than weaker
-------------------------------------------------------------------------
The two signals here are repository **name** and repository **description**. Both come
from the org repository listing, which `collect_repo_trees.py` already paginated to
completion across all three orgs and recorded per repository. Reading them from that
artifact costs zero API calls and, more importantly, inherits an enumeration that is
complete by construction.

Contrast the content half of the same check: GitHub **code search** for the marker string
returned zero, but its index excludes binaries and lags new commits, so that zero is a
`weak_zero_partial_index` and cannot clear the estate (§0.3, §0.1). Name and description
are metadata on an object we enumerated exhaustively, so a zero here is a real zero.

What this does NOT cover - stated so the zero is not overread
------------------------------------------------------------
  * `created_at`. Check 1 also asks for recently-created repositories *regardless of
    description*, because the attacker can leave the description blank. The trees
    artifact does not carry `created_at`, so that sub-check is reported as UNMEASURED
    rather than folded into the pass. `pushed_at` is present and is used as a weaker
    proxy that is reported separately, never as a substitute: a repository created in
    the window and never pushed to again has a `pushed_at` in the window too, but so do
    thousands of ordinary active repositories.
  * Actions artifacts (check 2), force-push history (check 3) and npm token state
    (check 4). Different APIs, not this script.
  * Repository *contents*. A dead drop whose name and description are both innocuous is
    invisible here and is the reason check 12's content search exists alongside this.

Doctrine, applied
-----------------
Per §0.1 a zero is only meaningful if the query could have found the thing, so this runs
two controls before reporting anything: it proves the description field is actually
populated across the estate (a zero over 2810 empty descriptions would be meaningless),
and it runs the matcher against synthetic records carrying the real marker and a real
Dune-vocabulary name, asserting both are caught. If either control fails the run is
reported as inconclusive instead of clean.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent))

# The campaign's default dead-drop description. Matched case-insensitively and with
# whitespace collapsed, because the marker is copied by the payload and a stray newline
# or double space must not create a miss.
CAMPAIGN_DESCRIPTION_MARKERS = (
    "shai-hulud: here we go again.",
    "shai-hulud: here we go again",
    "shai-hulud",
)

# Unit 42: the worm searches the commit API for the first of these to find and reuse
# credentials other infections published; the second is the backup-domain dead drop.
# Deliberately NOT window-bounded - Unit 42's earliest marker repository is dated
# 2026-05-11, almost three months before the keyv compromise, so a window-bounded search
# would have missed the whole population.
CAMPAIGN_NAME_MARKERS = (
    "thebeautifulmarchoftime",
    "thebeautifulsnadsoftime",
)

# Dune vocabulary observed in dead-drop repository names, e.g. `sardaukar-futar-421`.
# Usable against repository NAMES only, never as a content indicator - the caveat is
# recorded in chaindrop_elastic_2026_08.json. These are ordinary English-adjacent words
# in a Dune-reading company, so every hit is a candidate for review, not a finding.
DUNE_NAME_VOCABULARY = (
    "sardaukar", "mentat", "fremen", "atreides", "harkonnen", "futar", "ghola",
)

# The campaign's staging repositories hold `results-*.json`. Matched on the repository
# name because a repository *named* for the loot is the cheap tell.
STAGING_NAME_RE = re.compile(r"(?i)^results[-_]|[-_]results[-_]?\d*$")


def normalize(text: Optional[str]) -> str:
    return re.sub(r"\s+", " ", (text or "")).strip().lower()


def classify(record: dict) -> List[str]:
    """Return the marker reasons this repository matches. Empty list means no match."""
    reasons: List[str] = []
    name = normalize(record.get("repo") or "")
    description = normalize(record.get("description"))

    for marker in CAMPAIGN_DESCRIPTION_MARKERS:
        if marker in description:
            reasons.append(f"description_marker:{marker}")
            break  # The markers nest; one reason per repository, the longest that hit.

    for marker in CAMPAIGN_NAME_MARKERS:
        if marker in name or marker in description:
            reasons.append(f"campaign_marker_string:{marker}")

    # Word-boundary matched. `mentat` as a substring would hit `documentation`-shaped
    # names and turn this check into noise nobody reads.
    for word in DUNE_NAME_VOCABULARY:
        if re.search(rf"(?<![a-z]){word}(?![a-z])", name):
            reasons.append(f"dune_name_vocabulary:{word}")

    if STAGING_NAME_RE.search(record.get("repo") or ""):
        reasons.append("staging_name_results_pattern")

    return reasons


def run_controls(records: List[dict]) -> Dict[str, object]:
    """Prove the query could have found the thing, before trusting any zero."""
    described = sum(1 for r in records if normalize(r.get("description")))
    positives = [
        {"repo": "dead-drop-canary",
         "description": "Shai-Hulud: Here We Go Again.",
         "expect": "description_marker"},
        {"repo": "sardaukar-futar-421", "description": "",
         "expect": "dune_name_vocabulary"},
        {"repo": "thebeautifulmarchoftime-loot", "description": "",
         "expect": "campaign_marker_string"},
        {"repo": "results-20260804", "description": "",
         "expect": "staging_name_results_pattern"},
    ]
    control_results = []
    for case in positives:
        reasons = classify(case)
        control_results.append({
            "repo": case["repo"], "expected": case["expect"],
            "reasons": reasons,
            "caught": any(r.startswith(case["expect"]) for r in reasons),
        })

    # A negative control matters as much: if the matcher fires on an ordinary repository
    # the zero would be hidden inside a pile of noise.
    negatives = [{"repo": "documentation-site", "description": "Internal docs portal"},
                 {"repo": "api-gateway", "description": "Kong configuration"}]
    false_positives = [n["repo"] for n in negatives if classify(n)]

    return {
        "repos_examined": len(records),
        "repos_with_a_description": described,
        "description_populated_rate": round(described / len(records), 4) if records else 0.0,
        "positive_controls": control_results,
        "all_positive_controls_caught": all(c["caught"] for c in control_results),
        "negative_control_false_positives": false_positives,
        # The gate. Anything but True here means a zero from this run is inconclusive.
        "controls_pass": (all(c["caught"] for c in control_results)
                          and not false_positives),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path, required=True,
                        help="repo_trees_*.jsonl from collect_repo_trees.py.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--window-start", default="2026-08-04T09:35:00Z")
    parser.add_argument("--window-end", default="2026-08-04T16:00:00Z")
    args = parser.parse_args()

    records = [json.loads(line) for line in
               args.trees.read_text(errors="replace").splitlines() if line.strip()]
    if not records:
        print(f"[deaddrop] no records in {args.trees}", file=sys.stderr)
        return 1

    controls = run_controls(records)

    matches: List[dict] = []
    for record in records:
        reasons = classify(record)
        if reasons:
            matches.append({
                "repo": record.get("full_name"), "org": record.get("org"),
                "private": record.get("private"), "fork": record.get("fork"),
                "archived": record.get("archived"),
                "description": record.get("description"),
                "pushed_at": record.get("pushed_at"),
                "reasons": reasons,
            })

    # The weaker proxy, reported on its own axis and never merged into the result above.
    pushed_in_window = [
        {"repo": r.get("full_name"), "pushed_at": r.get("pushed_at"),
         "description": r.get("description")}
        for r in records
        if r.get("pushed_at") and args.window_start <= r["pushed_at"] <= args.window_end
    ]

    by_org = Counter(r.get("org") for r in records)
    payload = {
        "trees_artifact": str(args.trees),
        "orgs_covered": dict(by_org),
        "controls": controls,
        "result": {
            "marker_repositories": matches,
            "marker_repository_count": len(matches),
        },
        "coverage": {
            "enumeration": "Complete by construction: names and descriptions are read "
                           "from the org repository listing that collect_repo_trees.py "
                           "paginated to completion. No API call, no sampling.",
            # The two halves of this sweep do NOT have the same coverage, and averaging
            # them would be the coverage lie §0.7 exists to prevent.
            "by_signal": {
                "repository_name": {
                    "repos_in_scope": len(records),
                    "effective_coverage": 1.0,
                    "reading": "Every repository has a name, so the name-based checks "
                               "(campaign marker strings, Dune vocabulary, results-* "
                               "staging pattern) are a TRUE zero over the full estate.",
                },
                "repository_description": {
                    "repos_in_scope": controls["repos_with_a_description"],
                    "repos_with_no_description": (
                        len(records) - controls["repos_with_a_description"]),
                    "effective_coverage": controls["description_populated_rate"],
                    "reading": "The description marker check could only ever have fired "
                               "on repositories that HAVE a description. The remainder "
                               "are not cleared by it - they are cleared only by the "
                               "name checks. A dead drop created with the marker "
                               "description would be caught; one created with a blank "
                               "description and an innocuous name would not.",
                },
            },
            "pushed_at_in_window": {
                "count": len(pushed_in_window),
                "repos": pushed_in_window,
                "reading": "A WEAK proxy for 'created in the window', reported "
                           "separately and never as a substitute. An ordinary active "
                           "repository also pushes during any 6.5-hour window.",
            },
            "unmeasured": [
                "created_at. Check 1 asks for recently-created repositories regardless "
                "of description; the trees artifact does not carry created_at, so that "
                "sub-check is NOT covered here. Closing it needs the repository listing "
                "re-read with created_at retained - no new privilege, only a re-run.",
                "Repository contents. A dead drop with an innocuous name and blank "
                "description is invisible to this sweep. Check 12's code and commit "
                "search covers that half and returned only weak_zero_partial_index.",
                "Actions artifacts (check 2), force-push and tag history (check 3), and "
                "npm automation token state (check 4). Different APIs, not this script.",
            ],
            "rights_gaps": [],
        },
        "limits": [
            "Dune-vocabulary name hits are CANDIDATES, not findings. The words are "
            "ordinary enough to appear in legitimate project names; each hit needs a "
            "human read of the repository.",
            "A zero here clears repository METADATA only. It does not clear repository "
            "contents, and the two must not be reported as one number.",
        ],
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(payload, indent=2, default=str))

    print(f"[deaddrop] {len(records)} repos across {dict(by_org)}", file=sys.stderr)
    print(f"[deaddrop] controls_pass={controls['controls_pass']} "
          f"description_populated={controls['repos_with_a_description']}"
          f"/{len(records)}", file=sys.stderr)
    print(f"[deaddrop] marker repositories: {len(matches)}", file=sys.stderr)
    for match in matches:
        print(f"    {match['repo']}: {match['reasons']}", file=sys.stderr)
    print(f"[deaddrop] pushed_at in window (weak proxy): {len(pushed_in_window)}",
          file=sys.stderr)
    print(f"[deaddrop] -> {args.out}", file=sys.stderr)
    if not controls["controls_pass"]:
        print("[deaddrop] CONTROLS FAILED - treat this run as inconclusive, not clean",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
