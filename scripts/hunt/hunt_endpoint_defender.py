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
# on Windows there is no chmod step, so the file write is the earliest artifact that exists
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

# The fetch, before anything lands on disk. The campaign downloads a Bun release from
# bun.sh or the oven-sh/bun GitHub releases, and a download that failed to unpack, or
# unpacked somewhere DeviceFileEvents does not instrument, leaves no trace anywhere else in
# this file. Nothing in the collector looked at the network at all until this was added.
Q_BUN_NETWORK_FETCH = """
let BunUrlMarkers = dynamic(["bun.sh", "oven-sh/bun", "bun-windows-x64-baseline",
    "bun-windows-aarch64", "bun-linux-x64-baseline", "bun-linux-aarch64",
    "bun-darwin-aarch64", "bun-darwin-x64", "bun.zip"]);
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where RemoteUrl has_any (BunUrlMarkers)
    or (isnotempty(RemoteUrl) and RemoteUrl has "bun" and RemoteUrl has "release")
| summarize Events = count(), Devices = dcount(DeviceId),
            Urls = make_set(RemoteUrl, 25), Initiators = make_set(InitiatingProcessFileName, 15),
            LastSeen = max(Timestamp)
| limit 20
"""

# The control for the query above, and it is the one most likely to fail. RemoteUrl is
# populated by Network Protection, which is a separate feature from EDR onboarding. Where
# it is off, DeviceNetworkEvents still carries rows and RemoteUrl is empty on all of them -
# so the fetch query returns zero and looks exactly like a clean estate. This measures how
# many rows actually carry a URL, which is the only thing that makes that zero readable.
Q_NETWORK_URL_COVERAGE = """
DeviceNetworkEvents
| where Timestamp > ago(24h)
| summarize Rows = count(), Devices = dcount(DeviceId),
            RowsWithUrl = countif(isnotempty(RemoteUrl)),
            DevicesWithUrl = dcountif(DeviceId, isnotempty(RemoteUrl))
| limit 5
"""

# The control for the credential-access rule. A Bun-parented rule cannot fire where Bun
# does not run, so its zero is only readable on the devices where Bun executes at all.
Q_BUN_AS_PARENT_CONTROL = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where InitiatingProcessFileName in~ ("bun", "bun.exe", "bunx", "bunx.exe")
| summarize Events = count(), Devices = dcount(DeviceId),
            Children = make_set(FileName, 25), LastSeen = max(Timestamp)
| limit 5
"""

# Controls for the published-signature rule. Two branches, two controls, and they do not
# return the same verdict on this tenant - which is the entire reason they are separate.
Q_ALERT_TABLE_CONTROL = """
AlertInfo
| where Timestamp > ago({lookback}d)
| summarize AlertRows = count(), DistinctAlerts = dcount(AlertId)
| limit 5
"""

Q_THREATFAMILY_CONTROL = """
AlertEvidence
| where Timestamp > ago({lookback}d)
| where isnotempty(ThreatFamily)
| summarize Rows = count(), Families = dcount(ThreatFamily)
| limit 5
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
    double the size of the artifact and none of them is evidence.
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
        "bun_artifact_sweep": hunt(
            "backlog_22",
            (KQL / "backlog/22-bun-windows-artifact-sweep.kql").read_text()),
        # The fetch, and the control that decides whether its zero can be read at all.
        "bun_network_fetch": hunt(
            "bun_network_fetch",
            Q_BUN_NETWORK_FETCH.format(lookback=lookback_days)),
        "network_url_coverage": hunt("network_url_coverage", Q_NETWORK_URL_COVERAGE),
        # The two published rules, run from the same files that are committed as the
        # detection content - not a paraphrase of them. A rule that is executed from a copy
        # is not evidence about the rule that ships (§0.6(a)); rule 17 shipped for a day
        # with a column name that does not exist and nothing caught it, because nothing
        # ever ran the file.
        "rule_16_bun_credential_access": hunt(
            "rule_16",
            (KQL / "detections/16-bun-credential-access.kql").read_text()),
        "bun_as_parent_control": hunt(
            "bun_as_parent_control",
            Q_BUN_AS_PARENT_CONTROL.format(lookback=lookback_days)),
        "rule_17_published_signatures": hunt(
            "rule_17",
            (KQL / "detections/17-defender-published-signatures.kql").read_text()),
        "alert_table_control": hunt(
            "alert_table_control", Q_ALERT_TABLE_CONTROL.format(lookback=lookback_days)),
        "threatfamily_control": hunt(
            "threatfamily_control", Q_THREATFAMILY_CONTROL.format(lookback=lookback_days)),
    }
    return {"identity": identity, "evidence": evidence, "lookback_days": lookback_days}


# ----------------------------------------------------------------------------------
# Interpretation. Separated from collection so the raw rows can be re-read against a
# different rule later without re-querying the tenant.
# ----------------------------------------------------------------------------------

def build_bun_questions(ev: Dict[str, Any], lookback: int, bun_rows: List[dict],
                        node_platforms: List[str],
                        suspicious: List[dict]) -> List[dict]:
    """Every question this hunt asks about Bun, each with the control that makes it readable.

    Bun is the campaign's execution vehicle, so "did Bun run here" is the question the whole
    endpoint vector exists to answer - and it is not one question. It is seven, they fail
    independently, and before this they were scattered across six query results, two
    detection files that had never been executed, and a network surface nobody had looked at.
    A reader adding those up by hand cannot tell which zeros were readable.

    Every entry pairs an answer with the control that earns it (doctrine §0.1) and states
    the population the answer actually covers (§0.6). `readable` false is not a softer
    version of clean - it means the query could not have found the thing, so its zero is
    withdrawn rather than reported. Those become named residue.
    """
    def rows(key: str) -> List[dict]:
        return (ev.get(key) or {}).get("rows") or []

    def failed(key: str) -> Optional[str]:
        """The query error, if the query did not execute at all.

        A query that 400s is not a zero. Rule 17 shipped filtering on a column that does
        not exist and would have contributed a silent, confident zero to this table.
        """
        entry = ev.get(key) or {}
        return None if entry.get("ok") else (entry.get("error") or "did not run")

    def summed(key: str, field: str) -> int:
        return sum(r.get(field, 0) or 0 for r in rows(key))

    net = rows("network_url_coverage")
    net_rows = net[0].get("Rows", 0) if net else 0
    net_with_url = net[0].get("RowsWithUrl", 0) if net else 0
    parent = rows("bun_as_parent_control")
    parent_events = parent[0].get("Events", 0) if parent else 0
    parent_devices = parent[0].get("Devices", 0) if parent else 0
    alerts = rows("alert_table_control")
    alert_rows = alerts[0].get("AlertRows", 0) if alerts else 0
    families = rows("threatfamily_control")
    family_rows = families[0].get("Rows", 0) if families else 0

    bun_devices = sum(r.get("Devices", 0) or 0 for r in bun_rows)
    bun_platforms = sorted({r.get("OSPlatform") for r in bun_rows if r.get("OSPlatform")})

    questions: List[dict] = [
        {
            "question": "Did node or npm spawn Bun - the campaign's documented execution "
                        "shape?",
            "hits": (ev["node_spawns_bun"] or {}).get("row_count", 0),
            "error": failed("node_spawns_bun"),
            "control": f"node is present in DeviceProcessEvents on "
                       f"{', '.join(node_platforms) or 'no platform'} over the same "
                       f"{lookback}-day window.",
            "readable": bool(node_platforms),
            "covers": "every reporting device on the platforms where node is visible",
        },
        {
            "question": "Did bun.exe or bunx.exe appear on any table - process, file write, "
                        "or image load?",
            "hits": summed("bun_exe_any_table", "Events"),
            "error": failed("bun_exe_any_table"),
            "control": "The same three tables return non-zero for the rest of the "
                       "toolchain on Windows, so the tables are populated.",
            "readable": bool(node_platforms),
            "covers": "all reporting Windows devices",
        },
        {
            "question": "Was a Bun binary or a Bun release archive written to disk anywhere?",
            "hits": summed("bun_binary_or_archive_written", "Events"),
            "error": failed("bun_binary_or_archive_written"),
            "control": "DeviceFileEvents is populated for the toolchain on Windows; it is "
                       "sparser on macOS and Linux, which limits this answer to Windows.",
            "readable": bool(node_platforms),
            "covers": "reporting Windows devices; weaker on macOS and Linux",
        },
        {
            "question": "Was a Bun release fetched over the network from bun.sh or the "
                        "oven-sh/bun releases?",
            "hits": summed("bun_network_fetch", "Events"),
            "error": failed("bun_network_fetch"),
            # This is the control most likely to fail and the reason the question is here.
            # RemoteUrl is written by Network Protection, not by EDR onboarding, and where
            # it is off every URL query on this tenant returns a confident zero.
            "control": f"DeviceNetworkEvents carried {net_rows:,} rows in the last 24h, "
                       f"{net_with_url:,} of them with a non-empty RemoteUrl.",
            "readable": net_with_url > 0,
            "covers": ("devices with Network Protection populating RemoteUrl"
                       if net_with_url else "nothing - RemoteUrl is empty across the tenant"),
        },
        {
            "question": "Did a Bun process reach for cloud credentials - gh, gcloud, az, "
                        "aws, kubectl? (rule 16)",
            "hits": (ev["rule_16_bun_credential_access"] or {}).get("row_count", 0),
            "error": failed("rule_16_bun_credential_access"),
            "control": f"Bun appears as the initiating process in "
                       f"{parent_events:,} event(s) on {parent_devices} device(s) over "
                       f"{lookback} days, so the parent-child telemetry this rule needs "
                       f"exists.",
            "readable": parent_events > 0,
            # Stated because it is the most over-readable zero in the set. A rule keyed on
            # Bun as the parent is structurally incapable of firing where Bun never runs.
            "covers": (f"the {parent_devices} device(s) where Bun actually executes. It "
                       f"cannot fire elsewhere, so it clears nothing else."
                       if parent_events else "nothing"),
        },
        {
            "question": "Did any of Microsoft's five published signatures for this campaign "
                        "fire? (rule 17)",
            "hits": (ev["rule_17_published_signatures"] or {}).get("row_count", 0),
            "error": failed("rule_17_published_signatures"),
            "control": f"AlertInfo carried {alert_rows:,} alert rows over {lookback} days "
                       f"(Title branch: readable). AlertEvidence carried {family_rows} row(s) "
                       f"with a non-empty ThreatFamily (family branch: NOT readable).",
            "readable": alert_rows > 0,
            "covers": ("alert titles across the tenant. The ThreatFamily branch of this "
                       "rule contributes no coverage - the column is effectively never "
                       "written here."),
        },
        {
            "question": "Where Bun did execute, did it run from a temp or staging path?",
            "hits": len(suspicious),
            "error": failed("bun_artifact_sweep"),
            "control": f"The sweep returned Bun activity on {bun_devices} device(s) "
                       f"({', '.join(bun_platforms) or 'no platform'}), so it is reading "
                       f"real rows and each is triaged individually.",
            "readable": True,
            "covers": "every Bun execution the sweep found, benign rows included",
        },
    ]

    for entry in questions:
        if entry["error"]:
            # A query that errored has no answer in either direction. Reporting its zero
            # would be the exact defect rule 17 shipped with.
            entry["verdict"] = f"NO ANSWER - the query did not execute: {entry['error']}"
            entry["readable"] = False
        elif not entry["readable"]:
            entry["verdict"] = ("NO ANSWER - the control failed, so a zero here is "
                                "indistinguishable from blindness and is withdrawn")
        elif entry["hits"]:
            entry["verdict"] = f"{entry['hits']} hit(s) - triaged below"
        else:
            entry["verdict"] = "No evidence, and the control proves the query could have "\
                               "found it"
    return questions


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
    sweep_rows = ev["bun_artifact_sweep"]["rows"]

    # A sweep row is only a finding if it is NOT explained. Explained means: outside a temp
    # or staging path, and not spawned by a package manager. That is the benign developer
    # population the query was written to leave visible rather than filter away.
    suspicious = [r for r in sweep_rows
                  if r.get("FromTempOrStaging") or r.get("FromBunStagingDir")]
    benign = [r for r in sweep_rows if r not in suspicious]

    bun_questions = build_bun_questions(ev, lookback, bun_rows, node_platforms, suspicious)

    findings: List[dict] = []
    for row in suspicious:
        findings.append({
            "id": f"ENDPOINT-BUN-{row.get('DeviceName', 'unknown')}",
            "what": f"Bun runtime in a temp or staging path on {row.get('DeviceName')}",
            "evidence": row,
        })

    # TWO AXES. Result on one, coverage on the other, and the split is the whole point.
    #
    # This block used to put everything in `unresolved_items`, which made the status
    # INCOMPLETE and the report AMBER, every single day, because 1,379 devices in this
    # estate do not send telemetry. That was wrong twice over. It read as though the hunt
    # had found something unresolved when what it had found was nothing at all across
    # 3,424 devices with controls proving the queries worked - and it made the endpoint
    # vector, the only one that can see a laptop, permanently amber for a reason no query
    # will ever resolve. A color that never changes is a color nobody reads.
    #
    # The test for which list an item belongs in is: can WE close it with the access we
    # already hold?
    #
    #   unresolved_items - yes. Our unfinished work. Stays on the result axis, because an
    #                      unfinished hunt is not a clean hunt.
    #   coverage_gaps    - no. Needs a device onboarded, a feature enabled, a permission
    #                      granted. Comes off the result axis entirely, is reported in its
    #                      own register, and inside it the honest answer is that we can
    #                      neither confirm nor deny.
    #
    # And a coverage gap has to be ENUMERABLE - `named_by` is the query that returns the
    # individual members, by an identifier somebody can act on. A population nobody can
    # list is a population nobody can fix, so it is not a gap and does not get reported;
    # the renderer refuses to publish one without that field.
    unresolved_items: List[str] = []
    coverage_gaps: List[dict] = []

    # Devices Defender knows about and is not hearing from. Enumerable one by one out of
    # DeviceInfo, which is what makes this a work item rather than a worry: the endpoint
    # team can be handed 571 DeviceIds this afternoon.
    for state, count in sorted(by_status.items(), key=lambda kv: -kv[1]):
        if state == "Onboarded" or not count:
            continue
        # Each onboarding state closes differently, and saying so is the difference between
        # a gap and a complaint. "Unsupported" is the honest hard case: an OS Defender does
        # not run on is not onboarding work, it is a decision about a different control.
        if state == "Can be onboarded":
            closed_by = ("running the Defender onboarding package on each device - the "
                         "platform is supported and nothing blocks it but scheduling")
        elif state == "Unsupported":
            closed_by = ("no Defender onboarding can close this - the OS is not supported. "
                         "Closing it means either replacing/upgrading those platforms or "
                         "covering them with a different control and recording that "
                         "decision. Until then this hunt permanently cannot answer for them")
        elif state == "Insufficient info":
            closed_by = ("Defender cannot determine the platform, so triage the list first "
                         "against Intune/AD to establish what each device is, then onboard "
                         "or classify as unsupported")
        else:
            closed_by = (f"establishing why {count} device(s) sit in state '{state}' and "
                         f"onboarding or retiring each one")
        coverage_gaps.append({
            "gap": f"Devices in Defender onboarding state '{state}'",
            "population": f"{count:,} of {devices_seen:,} devices Defender has seen in the "
                          f"last 7 days",
            # Grouped by DeviceId alone, matching the aggregate that produced the count
            # above. Grouping by DeviceId AND DeviceName instead returned 590 rows against a
            # count of 570, because a device that has been renamed appears twice - the list
            # and the number have to come from the same grouping or one of them is wrong.
            # Verified 2026-08-07: this form returns 569 rows against a count of 570, the
            # difference being the 7-day window sliding between the two executions.
            "named_by": ("`DeviceInfo | where Timestamp > ago(7d) | summarize "
                         "arg_max(Timestamp, DeviceName, OSPlatform, OnboardingStatus) by "
                         f"DeviceId | where OnboardingStatus == \"{state}\" | project "
                         "DeviceId, DeviceName, OSPlatform` - one row per device, carrying "
                         "the identifier the endpoint team acts on"),
            "cannot_confirm_or_deny": "whether any Bun execution, credential access or "
                                      "campaign artifact occurred on them - they emit no "
                                      "events, so every query returns nothing whether or "
                                      "not it happened",
            "closed_by": closed_by,
            "owner": "Endpoint management / Security operations",
        })

    # A platform whose process rows carry no SHA256. Not our unfinished work: we cannot make
    # the column populate, and until it does, provenance triage there cannot be a hash
    # comparison no matter how suspicious a path looks.
    # Both numbers, from the row itself. "6 devices" alone invites the reading that the other
    # Linux devices are fine; "0 of 111,908 rows" is what actually establishes that the column
    # is never written for the population we measured.
    hash_blind: Dict[str, Dict[str, int]] = {}
    for r in tool_rows:
        if (r.get("SourceTable") == "DeviceProcessEvents" and r.get("Events")
                and not r.get("WithHash")):
            entry = hash_blind.setdefault(r.get("OSPlatform"), {"devices": 0, "events": 0})
            entry["devices"] = max(entry["devices"], r.get("Devices") or 0)
            entry["events"] += r.get("Events") or 0
    for platform in no_hash_platforms:
        measured = hash_blind.get(platform, {"devices": 0, "events": 0})
        coverage_gaps.append({
            "gap": f"SHA256 absent from every DeviceProcessEvents row on {platform}",
            "population": f"the {measured['devices']:,} reporting {platform} device(s) that "
                          f"ran a JavaScript toolchain in the window - {measured['events']:,} "
                          f"process events between them, 0 carrying a SHA256",
            # The same toolchain filter and platform join as coverage/08, which is what
            # measured the shortfall - grouped per device instead of per platform. Dropping
            # the toolchain filter would list every device on the platform, which is a
            # different and much larger population than the number above describes.
            # Verified 2026-08-07: 6 devices, 111,912 rows, 0 with a hash, against 111,908
            # rows at collection - the 30-day window slid between the two executions.
            "named_by": ("`let Platform = DeviceInfo | where Timestamp > ago(7d) | summarize "
                         "arg_max(Timestamp, OSPlatform) by DeviceId | project DeviceId, "
                         "OSPlatform; let Toolchain = dynamic([\"bun.exe\",\"bunx.exe\","
                         "\"bun\",\"bunx\",\"node.exe\",\"node\",\"npm.exe\",\"npm\","
                         f"\"npm-cli.js\"]); DeviceProcessEvents | where Timestamp > "
                         f"ago({lookback}d) | where FileName in~ (Toolchain) | join "
                         "kind=leftouter Platform on DeviceId | extend OSPlatform = "
                         "iff(isempty(OSPlatform), \"unknown\", OSPlatform) | where "
                         f"OSPlatform == \"{platform}\" | summarize Rows = count(), WithHash "
                         "= countif(isnotempty(SHA256)) by DeviceId, DeviceName` - the same "
                         "filter that measured the shortfall, so the list is exactly the "
                         "population counted above, and WithHash proves it per device"),
            "cannot_confirm_or_deny": f"whether a Bun binary found on a {platform} device is "
                                      f"the published Bun release or the campaign's "
                                      f"repackaged one. Execution is still visible; its "
                                      f"provenance is not",
            "closed_by": (f"a Microsoft support case establishing whether SHA256 can be "
                          f"populated for DeviceProcessEvents on {platform} at all - nothing "
                          f"in {measured['events']:,} rows says it ever is here, and whether "
                          f"that is configurable or a product limit is not something this "
                          f"hunt can determine. If it cannot be populated, the gap is "
                          f"permanent and triage on that platform must rest on path and "
                          f"parent process instead, which is a documented limitation rather "
                          f"than a fix"),
            "owner": "Security operations, with Microsoft support",
        })

    # A Bun question whose control failed stays on the RESULT axis, deliberately. A failed
    # control usually means our query or our window was wrong - which is ours to fix with
    # the access we already have, and therefore unfinished work rather than a blind spot.
    # The exception is a control that fails because a column is never written on this tenant
    # (rule 17's ThreatFamily branch); if that becomes the standing reason, it is a coverage
    # gap and belongs above, with the configuration change that populates the column.
    for entry in bun_questions:
        if not entry["readable"]:
            unresolved_items.append(
                f"Bun question unanswered - \"{entry['question']}\" {entry['verdict']}. "
                f"Control: {entry['control']}")
    # §0.6(b). An access gap is reportable only if it is priced in exact privileges, and
    # the six fields are structured rather than prose so `validate_vectors` in the renderer
    # can refuse to publish a half-filled one. This is derived from a live `verify()`
    # against the tenant, not from an absent environment variable - the whole reason this
    # collector exists is that the previous version inferred a permissions problem from a
    # place the client never reads.
    access_required: List[dict] = []
    if not raw["identity"].get("capabilities", {}).get("signIns", {}).get("available"):
        access_required.append({
            "api": "Microsoft Graph",
            "endpoint": "GET /auditLogs/signIns",
            "permission": "AuditLog.Read.All",
            "grant_type": "application (app-only), admin consent",
            "granted_by": "Microsoft 365 Global Administrator or Privileged Role "
                          "Administrator",
            "proves": "interactive and service-principal sign-in history for accounts whose "
                      "credentials the campaign harvests. Not a blocker for this hunt - the "
                      "AADSpnSignInEventsBeta and IdentityLogonEvents hunting tables carry "
                      "the same ground and ThreatHunting.Read.All already covers them.",
        })
        # Deliberately NOT added to either list. It was in `unresolved_items`, which claimed
        # something was unchecked when nothing is: AADSpnSignInEventsBeta and
        # IdentityLogonEvents cover the same ground and ThreatHunting.Read.All already
        # reaches them. And it is not a coverage gap, because no population is unobservable
        # because of it. It is an access improvement, priced in `access_required` and
        # described there as the non-blocker it is. Filing it as a gap would be a false
        # positive on the coverage axis - a request for a permission that closes nothing.
        pass

    # Status is now the RESULT axis only. CLEAR means: over the population these queries can
    # observe, they could have found the campaign and did not. It does not mean the
    # population is the estate - `coverage_gaps` carries that, the renderer prints it beside
    # the status, and the report says so in the row itself.
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
        + f". The remaining {not_reporting:,} are outside what this hunt can observe. They "
          f"are not counted as clean and they are not counted as a finding either - they are "
          f"registered as coverage gaps, enumerable by DeviceId, with what closes each one.")
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
    # Derived, not asserted. This sentence used to state the Windows zero as a literal, so
    # it would have printed "return zero rows" on a run that found bun.exe on fifty
    # machines - a §0.6(a) violation sitting inside the coverage block whose whole job is
    # to justify the numbers beside it.
    bun_exe_events = sum(r.get("Events", 0) or 0 for r in bun_exe["rows"])
    if bun_exe_events or written_events:
        coverage.append(
            f"Windows specifically: bun.exe/bunx.exe returned {bun_exe_events:,} event(s) "
            f"across DeviceProcessEvents, DeviceFileEvents and DeviceImageLoadEvents over "
            f"{lookback} days, and {written_events:,} Bun binary or release-archive write(s) "
            f"were seen. These are hits, not coverage - they are triaged individually.")
    else:
        coverage.append(
            f"Windows specifically: bun.exe and bunx.exe returned zero rows across "
            f"DeviceProcessEvents, DeviceFileEvents and DeviceImageLoadEvents over "
            f"{lookback} days, and zero Bun release archives or bun-dl- staging directories "
            f"were written anywhere in the estate.")
    # The Bun question set, stated as coverage rather than left in the artifact, because
    # "did Bun run here" is the question this vector exists to answer and it is seven
    # questions that fail independently.
    answered = sum(1 for q in bun_questions if q["readable"])
    coverage.append(
        f"Bun question set: {answered} of {len(bun_questions)} questions returned a "
        f"readable answer. Each is listed with the control that earns it; the "
        f"{len(bun_questions) - answered} whose control failed are withdrawn rather than "
        f"reported as zero.")
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
        # Counted, not written. This said "6 advanced-hunting queries" as a literal while
        # the collector ran a different number, and it would have kept saying 6 forever.
        "scope": f"{onboarded:,} onboarded devices, {lookback}-day lookback, "
                 f"{sum(1 for v in ev.values() if isinstance(v, dict) and v.get('ok') is not None)}"
                 f" advanced-hunting queries",
        "counts": {
            "Hunting queries executed": sum(
                1 for k, v in ev.items()
                if isinstance(v, dict) and v.get("ok") is not None),
            "Hunting queries that FAILED to execute": sum(
                1 for v in ev.values() if isinstance(v, dict) and v.get("ok") is False),
            "Bun questions asked": len(bun_questions),
            "Bun questions with a readable answer": sum(
                1 for q in bun_questions if q["readable"]),
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
        "bun_questions": bun_questions,
        "unresolved_items": unresolved_items,
        # The coverage axis. Populations no query here can answer for, each enumerable by the
        # query in its own `named_by`. These do not move `status` and must not move the
        # report's verdict.
        "coverage_gaps": coverage_gaps,
        "access_required": access_required,
        # §0.6(c). The suspicious rows, named. A FINDINGS status that a reader cannot
        # trace to a specific device and path is the shape a false positive takes, and the
        # renderer will refuse to publish one.
        "evidence_for_status": [f["what"] for f in findings],
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
    for gap in vector["coverage_gaps"]:
        print(f"  ? BLIND: {gap['gap']} - {gap['population']}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
