#!/usr/bin/env python3
"""
Re-derive the authoritative malicious name@version set from the registry.

Why this exists as a file rather than as a throwaway one-liner: the window bound this
produces is the number the report states, and the open Tier 0 escalation is an argument
about that bound. An argument about a number needs a rerunnable command, not a shell
history entry.

The registry is the Tier 0 oracle here - it holds publish timestamps and unpublish state
for every version - so this queries npm directly and does not touch the GitHub budget.

Two facts about the previous derivation (exports/hunt/rederive_window_14z.json) motivate
the wider bracket:

  * its latest confirmed malicious publish is @umacloud/cli-linux-musl-x64@1.0.74 at
    2026-08-04T13:18:41.376Z, which is later than the 12:11:19.909Z bound the corpus
    still reports, and within two seconds of StepSecurity's 13:20Z propagation close;
  * its latest suspected-uncleaned publish is @adminide-stack/yantra-mobile@12.0.33-alpha.3
    at 2026-08-04T13:30:46.398Z, which is past that close.

A bracket that ends at 14:00Z cannot tell the difference between "propagation stopped"
and "the bracket stopped". Unit 42 then put operator activity at 15:15:26Z. So the
default end here runs to 18:00Z: far enough past every claimed close that an empty tail
is evidence rather than an artifact of the bound.
"""

import argparse
import csv
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT))

from src.threat_intel.registry_oracle import RegistryOracle  # noqa: E402

DEFAULT_CSV = REPO_ROOT / "github_conf" / "ioc" / "keyv-packages-wiz.csv"
DEFAULT_OUT = REPO_ROOT / "exports" / "hunt" / "rederive_window_18z.json"


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_candidates(path: Path) -> list:
    """
    Read candidate package names from the vendor CSV.

    The CSV is the candidate list, not the answer: the registry decides which versions
    are malicious. Names are deduplicated in first-seen order so the run is reproducible.
    """
    names: list = []
    seen = set()
    with path.open() as handle:
        for row in csv.DictReader(handle):
            name = (row.get("Package") or "").strip()
            if name and name not in seen:
                seen.add(name)
                names.append(name)
    return names


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--packages-csv", type=Path, default=DEFAULT_CSV)
    parser.add_argument("--window-start", default="2026-08-04T09:00:00Z")
    parser.add_argument("--window-end", default="2026-08-04T18:00:00Z")
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--ecosystem", default="npm")
    parser.add_argument("--limit", type=int, default=0,
                        help="Query only the first N candidates. For smoke tests; a "
                             "limited run must not be reported as a derivation.")
    args = parser.parse_args()

    if not args.packages_csv.exists():
        print(f"candidate list not found: {args.packages_csv}", file=sys.stderr)
        return 2

    candidates = load_candidates(args.packages_csv)
    if args.limit:
        candidates = candidates[:args.limit]

    start, end = parse_ts(args.window_start), parse_ts(args.window_end)
    print(f"candidates: {len(candidates)}  window: {start.isoformat()} .. {end.isoformat()}",
          flush=True)

    oracle = RegistryOracle()
    result = oracle.derive_malicious_set(candidates, start, end, args.ecosystem)

    # The tail is the whole point of the wider bracket, so state it in the artifact
    # rather than leaving every reader to re-sort malicious_detail to find it.
    def latest(rows):
        stamps = [row.get("published") for row in rows if row.get("published")]
        return max(stamps) if stamps else None

    result["_bound_summary"] = {
        "latest_malicious_publish": latest(result.get("malicious_detail") or []),
        "latest_suspected_uncleaned_publish": latest(
            result.get("suspected_uncleaned_detail") or []),
        "bracket_end": end.isoformat(),
        "_how_to_read_this": (
            "If the latest publish sits well inside the bracket, the bracket is not the "
            "thing bounding it and the close time is a registry fact. If it sits at the "
            "bracket edge, widen the bracket again before reporting a close."
        ),
        "limited_run": bool(args.limit),
    }

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str))
    print(f"malicious specs: {result['malicious_count']}  "
          f"suspected uncleaned: {len(result.get('suspected_uncleaned_specs') or [])}  "
          f"unreachable: {len(result.get('unreachable') or [])}")
    print(f"latest malicious publish: {result['_bound_summary']['latest_malicious_publish']}")
    print(f"latest suspected uncleaned: "
          f"{result['_bound_summary']['latest_suspected_uncleaned_publish']}")
    print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
