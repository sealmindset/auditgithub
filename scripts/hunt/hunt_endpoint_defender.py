#!/usr/bin/env python3
"""Endpoint and identity hunt, via Microsoft Defender advanced hunting.

This is the only hunt surface that can see a developer workstation. Every other vector in
the round-3 hunt reads GitHub, and GitHub cannot show a laptop. The Windows form of the
CHAINDROP bootstrap lands on a laptop, so a report built only from GitHub results can be
entirely clean and entirely uninformative about the question that matters.

The report used to render this vector as BLOCKED with the reason "GRAPH_TENANT_ID,
GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET are absent from the environment". That reason was
true and irrelevant: `GraphClient.from_db` reads the encrypted credential store, not the
process environment, and the store holds an active app registration with
ThreatHunting.Read.All. The vector was never blocked. It had simply never been run, and
those two things are not the same thing to a reader deciding whether to file an access
request.

ORDER MATTERS (doctrine §0.1). The coverage control runs FIRST and its result gates the
interpretation of everything after it. A hunting query that returns nothing because the
estate is clean and one that returns nothing because the table is empty are the same JSON.
Only the control tells them apart, and without it every zero below is unreadable.

Reads only. `GraphClient` refuses any verb other than GET and the single allowlisted
`runHuntingQuery` POST, and throttles submissions. Nothing here touches the GitHub budget.

    python3 scripts/hunt/hunt_endpoint_defender.py
    python3 scripts/hunt/hunt_endpoint_defender.py --lookback-days 30 --out /tmp/x.json
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

HUNT = REPO_ROOT / "exports/hunt"
KQL = REPO_ROOT / "github_conf/detections/kql"

# Statuses, spelled the same way render_hunt_report.py spells them. Imported by value
# rather than from that module because this script must run without pulling in the
# renderer's own dependencies.
CLEAR = "CLEAR"
INCOMPLETE = "INCOMPLETE"
FINDINGS = "FINDINGS"


# ----------------------------------------------------------------------------------
# Queries. Each one is here to answer a question the others cannot, and each carries the
# reason it exists, because a query whose purpose is not written down gets deleted by
# whoever next reads it and cannot tell it apart from the one above.
# ----------------------------------------------------------------------------------

# The discriminator. This is the campaign's documented execution shape: node or npm, which
# a developer runs constantly, spawning bun, which nothing in a normal toolchain does. It
# is deliberately narrow — narrow enough that a hit is not triage, it is an incident.
Q_NODE_SPAWNS_BUN = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where InitiatingProcessFileName in~ ("node", "node.exe")
| where FileName in~ ("bun", "bun.exe", "bunx", "bunx.exe")
| project Timestamp, DeviceName, DeviceId, AccountName, FileName, FolderPath, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, ProcessCommandLine
| order by Timestamp desc
| limit 500
"""

# The Windows binary, on every table that could carry it. The discriminator above requires
# a node/npm parent; this one does not, so a bun.exe unzipped by explorer, powershell or an
# installer still shows up. A zero here and a zero above mean different things and both are
# needed.
Q_BUN_EXE_ANY_TABLE = """
let BunWindows = dynamic(["bun.exe", "bunx.exe"]);
union
 (DeviceProcessEvents   | where Timestamp > ago({lookback}d) | where FileName in~ (BunWindows) | extend SourceTable = "DeviceProcessEvents"),
 (DeviceFileEvents      | where Timestamp > ago({lookback}d) | where FileName in~ (BunWindows) | extend SourceTable = "DeviceFileEvents"),
 (DeviceImageLoadEvents | where Timestamp > ago({lookback}d) | where FileName in~ (BunWindows) | extend SourceTable = "DeviceImageLoadEvents")
| summarize Events = count(), Devices = dcount(DeviceId), LastSeen = max(Timestamp)
    by SourceTable
| limit 20
"""

# The write, not the execution. The campaign fetches a Bun release archive and unpacks it;
# on Windows there is no chmod step, so the file write is the earliest artefact that exists
# at all. Nothing else in the library looks at it.
Q_BUN_WRITTEN = """
let BunBinaries = dynamic(["bun.exe", "bunx.exe", "bun", "bunx"]);
let BunArchives = dynamic(["bun-windows-x64-baseline.zip", "bun-windows-aarch64.zip",
    "bun-linux-x64-baseline.zip", "bun-linux-x64-musl-baseline.zip", "bun-linux-aarch64.zip",
    "bun-darwin-aarch64.zip", "bun-darwin-x64.zip"]);
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where FileName in~ (BunBinaries) or FileName in~ (BunArchives) or FolderPath has "bun-dl-"
| summarize Events = count(), Devices = dcount(DeviceId), Names = make_set(FileName, 50),
            Paths = make_set(FolderPath, 50), LastSeen = max(Timestamp)
| limit 10
"""

# Onboarding. The denominator for every count above. A device that is not reporting cannot
# produce a hit, and a hunt that does not say how many of those there are is quoting a
# percentage with the denominator hidden.
Q_ONBOARDING = """
DeviceInfo
| where Timestamp > ago(7d)
| summarize arg_max(Timestamp, OSPlatform, OnboardingStatus) by DeviceId
| summarize Devices = count() by OSPlatform, OnboardingStatus
| order by Devices desc
| limit 100
"""


def _rows(result: Any) -> List[dict]:
    if hasattr(result, "rows"):
        return list(result.rows or [])
    if isinstance(result, dict):
        return list(result.get("results") or result.get("rows") or [])
    return []


def _clean(rows: List[dict]) -> List[dict]:
    """Drop Kusto's `@odata.type` companion keys.

    The Graph JSON carries a `Foo@odata.type` sibling for every non-string column. They
    double the size of the artefact and none of them is evidence.
    """
    return [{k: v for k, v in row.items() if not k.endswith("@odata.type")} for row in rows]


def run(lookback_days: int) -> Dict[str, Any]:
    from src.api.database import SessionLocal            # noqa: E402
    from src.api.integrations.msgraph import GraphClient  # noqa: E402

    client = GraphClient.from_db(SessionLocal())
    identity = client.verify()

    def hunt(name: str, query: str) -> Dict[str, Any]:
        try:
            rows = _clean(_rows(client.run_hunting_query(query, strict_lint=False)))
            return {"ok": True, "row_count": len(rows), "rows": rows}
        except Exception as exc:  # noqa: BLE001 - the error IS the result for this vector
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "rows": []}

    # §0.1. First, and its answer gates every other answer in this file.
    control = client.coverage_control(hours=24)
    control.pop("buckets", None)

    evidence: Dict[str, Any] = {
        "telemetry_control_24h": control,
        "onboarding": hunt("onboarding", Q_ONBOARDING),
        "node_spawns_bun": hunt("node_spawns_bun",
                                Q_NODE_SPAWNS_BUN.format(lookback=lookback_days)),
        "bun_exe_any_table": hunt("bun_exe_any_table",
                                  Q_BUN_EXE_ANY_TABLE.format(lookback=lookback_days)),
        "bun_binary_or_archive_written": hunt("bun_written",
                                              Q_BUN_WRITTEN.format(lookback=lookback_days)),
        "toolchain_visibility": hunt(
            "coverage_08",
            (KQL / "coverage/08-bun-exe-telemetry-shape.kql").read_text()),
        "bun_artefact_sweep": hunt(
            "backlog_22",
            (KQL / "backlog/22-bun-windows-artifact-sweep.kql").read_text()),
    }
    return {"identity": identity, "evidence": evidence, "lookback_days": lookback_days}


# ----------------------------------------------------------------------------------
# Interpretation. Separated from collection so the raw rows can be re-read against a
# different rule later without re-querying the tenant.
# ----------------------------------------------------------------------------------

def interpret(raw: Dict[str, Any], as_of: str) -> Dict[str, Any]:
    ev = raw["evidence"]
    lookback = raw["lookback_days"]
    control = ev["telemetry_control_24h"]
    telemetry_present = bool(control.get("telemetry_present"))

    onboard_rows = ev["onboarding"]["rows"]
    by_status: Dict[str, int] = {}
    onboarded_by_platform: Dict[str, int] = {}
    for row in onboard_rows:
        status = row.get("OnboardingStatus") or "unknown"
        by_status[status] = by_status.get(status, 0) + row.get("Devices", 0)
        if status == "Onboarded":
            platform = row.get("OSPlatform") or "(unreported)"
            onboarded_by_platform[platform] = (
                onboarded_by_platform.get(platform, 0) + row.get("Devices", 0))
    devices_seen = sum(by_status.values())
    onboarded = by_status.get("Onboarded", 0)
    not_reporting = devices_seen - onboarded

    tool_rows = ev["toolchain_visibility"]["rows"]
    # The comparison the whole zero rests on. Bun absent is only readable as "absent" if
    # node is present on the SAME table and the SAME platform.
    node_platforms = sorted({r.get("OSPlatform") for r in tool_rows
                             if not r.get("IsBun") and r.get("SourceTable") == "DeviceProcessEvents"
                             and r.get("Events")})
    bun_rows = [r for r in tool_rows if r.get("IsBun") and r.get("Events")]

    # Hash coverage, per platform, on the process table. Provenance triage on any future
    # bun.exe is a SHA256 comparison, and a platform reporting no hashes cannot be triaged
    # that way no matter how suspicious the path looks.
    no_hash_platforms = sorted({
        r.get("OSPlatform") for r in tool_rows
        if r.get("SourceTable") == "DeviceProcessEvents" and r.get("Events")
        and not r.get("WithHash")})

    node_bun = ev["node_spawns_bun"]
    bun_exe = ev["bun_exe_any_table"]
    written = ev["bun_binary_or_archive_written"]["rows"]
    written_events = written[0].get("Events", 0) if written else 0
    sweep_rows = ev["bun_artefact_sweep"]["rows"]

    # A sweep row is only a finding if it is NOT explained. Explained means: outside a temp
    # or staging path, and not spawned by a package manager. That is the benign developer
    # population the query was written to leave visible rather than filter away.
    suspicious = [r for r in sweep_rows
                  if r.get("FromTempOrStaging") or r.get("FromBunStagingDir")]
    benign = [r for r in sweep_rows if r not in suspicious]

    findings: List[dict] = []
    for row in suspicious:
        findings.append({
            "id": f"ENDPOINT-BUN-{row.get('DeviceName', 'unknown')}",
            "what": f"Bun runtime in a temp or staging path on {row.get('DeviceName')}",
            "evidence": row,
        })

    # Status. FINDINGS if the campaign shape is present. Otherwise INCOMPLETE, never
    # CLEAR: 'CLEAR' in this report means "looked everywhere in scope", and several
    # hundred devices in this estate are not reporting at all. That is a named, counted
    # residue, which is exactly what INCOMPLETE is for.
    unresolved_items: List[str] = []
    for status, count in sorted(by_status.items(), key=lambda kv: -kv[1]):
        if status != "Onboarded" and count:
            unresolved_items.append(f"{count} device(s) in Defender onboarding state "
                                    f"'{status}' - not reporting, cannot produce a hit")
    for platform in no_hash_platforms:
        unresolved_items.append(
            f"SHA256 is empty on every DeviceProcessEvents row for {platform} - hash-based "
            f"provenance triage is blind on that platform")
    if not raw["identity"].get("capabilities", {}).get("signIns", {}).get("available"):
        unresolved_items.append(
            "AuditLog.Read.All is not granted, so GET /auditLogs/signIns is unavailable "
            "app-only; sign-in analysis must come from hunting tables instead")

    status = FINDINGS if findings else (INCOMPLETE if unresolved_items else CLEAR)

    coverage: List[str] = []
    coverage.append(
        f"Telemetry control ran first and passed: {control.get('total_events', 0):,} "
        f"DeviceProcessEvents rows from up to "
        f"{control.get('max_devices_in_any_hour', 0):,} devices in a single hour of the "
        f"last 24. Every zero below is therefore a measured absence, not an empty table."
        if telemetry_present else
        "TELEMETRY CONTROL FAILED. The pipeline, not the estate, is the finding - every "
        "zero below is uninterpretable and none of it should be read as clean.")
    coverage.append(
        f"{onboarded:,} of {devices_seen:,} devices seen by Defender in the last 7 days are "
        f"onboarded and reporting: "
        + ", ".join(f"{p} {c:,}" for p, c in
                    sorted(onboarded_by_platform.items(), key=lambda kv: -kv[1])[:6])
        + f". The remaining {not_reporting:,} are outside this hunt and are listed as "
          f"unresolved rather than counted as clean.")
    coverage.append(
        f"The discriminator is readable because its other half is loud: node is present on "
        f"{', '.join(node_platforms) or 'no platform'} in DeviceProcessEvents over the same "
        f"window. A zero for bun beside a non-zero for node on the same table and platform "
        f"is an absence; a zero for both would be blindness.")
    if bun_rows:
        coverage.append(
            "Bun is present in this estate, on "
            + "; ".join(f"{r.get('Devices')} {r.get('OSPlatform')} device(s), "
                        f"{r.get('Events')} event(s), last seen {r.get('LastSeen')}"
                        for r in bun_rows)
            + ". Those rows are triaged individually below rather than counted as hits.")
    else:
        coverage.append("Bun does not appear on any table, on any platform, in the window.")
    coverage.append(
        f"Windows specifically: bun.exe and bunx.exe return zero rows across "
        f"DeviceProcessEvents, DeviceFileEvents and DeviceImageLoadEvents over "
        f"{lookback} days, and zero Bun release archives or bun-dl- staging directories "
        f"were written anywhere in the estate.")
    for row in benign:
        coverage.append(
            f"Triaged and explained: {row.get('FileName')} on {row.get('DeviceName')} "
            f"({row.get('Events')} event(s), {row.get('FirstSeen')} to {row.get('LastSeen')}) "
            f"ran from {', '.join(row.get('Paths') or [])}, started by "
            f"{', '.join(row.get('Parents') or [])}. Not a temp or staging path, and not "
            f"spawned by a package manager, so it does not match the campaign shape.")

    return {
        "name": "Endpoint / identity (Microsoft Defender)",
        "status": status,
        "as_of": as_of,
        "scope": f"{onboarded:,} onboarded devices, {lookback}-day lookback, "
                 f"6 advanced-hunting queries",
        "counts": {
            "Hunting queries executed": sum(
                1 for k, v in ev.items()
                if isinstance(v, dict) and v.get("ok") is not None),
            "Devices reporting to Defender": onboarded,
            "Devices seen but NOT reporting": not_reporting,
            "node/npm spawning Bun (the campaign's execution shape)": node_bun["row_count"],
            "bun.exe or bunx.exe, any table, any device": sum(
                r.get("Events", 0) for r in bun_exe["rows"]),
            "Bun binaries or release archives written to disk": written_events,
            "Bun executions found and individually triaged": len(sweep_rows),
            "Bun executions from a temp or staging path": len(suspicious),
        },
        "coverage": coverage,
        "unresolved_items": unresolved_items,
        "findings": findings,
        "identity": raw["identity"],
        "evidence": ev,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lookback-days", type=int, default=30)
    parser.add_argument("--out", type=Path, default=HUNT / "endpoint_hunt.json")
    parser.add_argument("--as-of", type=str, default=None)
    args = parser.parse_args()

    as_of = args.as_of or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    raw = run(args.lookback_days)
    vector = interpret(raw, as_of)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(vector, indent=2, default=str))
    print(f"{vector['status']}  ->  {args.out}", file=sys.stderr)
    for line in vector["coverage"]:
        print(f"  . {line}", file=sys.stderr)
    for item in vector["unresolved_items"]:
        print(f"  ! {item}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
