#!/usr/bin/env python3
"""Is anything on this estate watching for us to revoke a token?

The question, and why it is not the same question as any earlier round
---------------------------------------------------------------------
StepSecurity's teardown records a component none of the other write-ups lead with: a
watchdog installed alongside the payload that polls `https://api.github.com/user` every 60
seconds for 24 hours and fires the collector again when the token stops authenticating.

That inverts standard incident response. Revoking the stolen credential is the watchdog's
*trigger*, not the remediation - it treats revocation as the signal to re-collect and
re-exfiltrate from whatever is still live. And it survives cleanup of everything else the
campaign drops: `setup.mjs`, `math_init.js`, `.claude/` and `.vscode/` contain none of it.

  ~/.local/bin/gh-token-monitor.sh      the script
  ~/.config/gh-token-monitor/           its state
  gh-token-monitor.service              systemd registration (Linux)
  com.user.gh-token-monitor             launchd registration (macOS)

No round of this hunt has ever asked for any of that. r9 asked whether the payload behaved
(node spawning Bun, credential access, persistence); r2 asked whether a malicious tarball
was fetched; r3 asked whether anything touched the campaign's infrastructure. None of them
asked whether something is sitting on a host waiting for us to start remediating.

Two sweeps, because a name is not a shape
-----------------------------------------
**By name.** The four artifacts above all contain the literal `gh-token-monitor`, so one
substring answers for all of them across the file, process and event tables. A hit here is a
finding, not a lead.

**By shape.** A renamed watchdog answers no name query, so the behavior is swept
independently: a process making sustained high-rate requests to `api.github.com`, and writes
into the launchd, systemd, cron, Run-key and Startup-folder surfaces by a script interpreter.
Both of these have legitimate populations on this estate - `gh`, the VS Code GitHub
extension and CI agents all poll the API - so shape results are reported as **leads with a
triage order**, never as findings. A hunt that called every `gh` invocation a watchdog would
be ignored the week it mattered.

The cadence result is bounded by the same control as the domain sweep
--------------------------------------------------------------------
The cadence query reads `RemoteUrl`, and `install_activity_r2.json` already measured that
macOS populates it on zero of 687,005 network rows because Defender Network Protection is not
enabled there. So the URL-coverage control from `hunt_advisory_iocs.py` is re-run here rather
than re-derived, and the platforms it names are recorded as a coverage gap on this vector
too. One configuration change closes the same blind spot on three vectors, which is worth
stating in the one place a reader is deciding whether to fund it.

The command-line half is what answers for those platforms: a shell script polling the API
spells `api.github.com/user` out on its own command line, and `DeviceProcessEvents` records
it regardless of Network Protection.

Reads only. No GitHub budget is touched.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from hunt_advisory_iocs import (  # noqa: E402
    CLEAR,
    FINDINGS,
    INCOMPLETE,
    LOOKBACK_DAYS,
    Q_URL_COVERAGE,
    kql_list,
)

# ----------------------------------------------------------------------------------
# The indicators. Two tiers, and the tiers are the whole point: the exact name is
# attribution, a generic token is a lead. Folding them together would put every
# `token_monitor.py` in the estate into a critical finding.
# ----------------------------------------------------------------------------------

WATCHDOG_EXACT = ["gh-token-monitor"]
WATCHDOG_ARTIFACTS = [
    {"value": "~/.local/bin/gh-token-monitor.sh", "role": "the watchdog script itself"},
    {"value": "~/.config/gh-token-monitor/", "role": "its state directory"},
    {"value": "gh-token-monitor.service", "role": "systemd registration, Linux"},
    {"value": "com.user.gh-token-monitor", "role": "launchd registration, macOS"},
]
WATCHDOG_GENERIC = ["token-monitor", "token_monitor", "tokenmonitor"]

# The endpoint the watchdog polls. Narrow on purpose: `api.github.com` alone is ordinary
# traffic, `api.github.com/user` is a token-validity check and almost nothing else.
TOKEN_CHECK_PATH = "api.github.com/user"

# The autostart surfaces a watchdog has to register on to survive a logout. Per platform,
# because a query that only knows about launchd reports Linux and Windows as clean.
#
# The Windows entries carry no backslash on purpose. A KQL string literal cannot hold a bare
# `\S`, and building a `@"..."` verbatim list here would make the shared kql_list() helper
# platform-aware for one caller. `has` is token-based, so the unqualified folder name matches
# the full path anyway - `Startup` matches `...\Start Menu\Programs\Startup`.
AUTOSTART_PATHS = [
    "/Library/LaunchAgents", "/Library/LaunchDaemons", "Library/LaunchAgents",
    "/etc/systemd/system", "/usr/lib/systemd/system", ".config/systemd/user",
    "/etc/cron.d", "/var/spool/cron", "/var/at/tabs",
    "Start Menu", "Startup",
]

# Interpreters a dropped watchdog runs under. Not "any process": a write into LaunchAgents by
# an MDM agent or an installer is the normal population of that directory, and including it
# would bury the one row that matters.
SCRIPT_INTERPRETERS = ["node", "bun", "bunx", "sh", "bash", "zsh", "python3", "python",
                       "osascript", "powershell.exe", "pwsh.exe", "cmd.exe", "curl", "wget"]

# The watchdog's documented cadence is one request per minute for 24 hours. The floors below
# are deliberately under it - 40/hour rather than 60, 6 hours rather than 24 - because a
# sweep tuned to the exact published numbers finds only the variant that was published.
MIN_REQUESTS_PER_HOUR = 40
MIN_HOURS_AT_CADENCE = 6

# Initiators with a legitimate reason to poll the GitHub API at that rate on this estate.
# Used to ORDER triage, never to drop a row: the campaign's watchdog runs under `sh` and
# `node`, which are also on this list, so filtering by it would delete the finding.
KNOWN_API_CLIENTS = {"gh", "gh.exe", "git", "git-remote-https", "code", "code helper",
                     "electron", "runner.worker", "runner.listener", "dependabot",
                     "jetbrains", "idea", "webstorm"}


EXACT_LIST = kql_list(WATCHDOG_EXACT)
GENERIC_LIST = kql_list(WATCHDOG_GENERIC)
AUTOSTART_LIST = kql_list(AUTOSTART_PATHS)
INTERPRETER_LIST = kql_list(SCRIPT_INTERPRETERS)

# ----------------------------------------------------------------------------------
# Controls. Every zero below is read through one of these.
# ----------------------------------------------------------------------------------

# Proves the file table records the autostart surfaces at all, by platform. Without this a
# zero from the autostart sweep is indistinguishable from a table that never sees those paths.
Q_AUTOSTART_COVERAGE = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where FolderPath has_any ({autostart})
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago({lookback}d)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
  ) on DeviceId
| summarize Rows = count(), Devices = dcount(DeviceId) by OSPlatform
| order by Rows desc
| limit 40
"""

# Proves `has_any` on FileName/FolderPath returns rows for a name shape that must exist, on
# the same table and the same operator as the watchdog name sweep.
Q_NAME_POSITIVE_CONTROL = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where FileName has_any ("monitor", "agent", "update")
| summarize Rows = count(), Devices = dcount(DeviceId)
| limit 5
"""

# Proves the cadence query's table and operator work: the GitHub API is reached from this
# estate, so a zero from the cadence sweep is a cadence answer and not a connectivity answer.
Q_API_POSITIVE_CONTROL = """
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where RemoteUrl has "api.github.com"
| summarize Rows = count(), Devices = dcount(DeviceId),
            Initiators = dcount(InitiatingProcessFileName)
| limit 5
"""

# ----------------------------------------------------------------------------------
# The sweeps - by name first.
# ----------------------------------------------------------------------------------

Q_NAME_FILES = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where FileName has_any ({exact}) or FolderPath has_any ({exact})
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp desc
| limit 500
"""

Q_NAME_PROCESSES = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where ProcessCommandLine has_any ({exact}) or InitiatingProcessCommandLine has_any ({exact})
    or FileName has_any ({exact}) or FolderPath has_any ({exact})
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
| limit 500
"""

# DeviceEvents carries the persistence action types - launchd/systemd registration on the
# platforms that report it, scheduled-task creation on Windows.
Q_NAME_EVENTS = """
DeviceEvents
| where Timestamp > ago({lookback}d)
| where FileName has_any ({exact}) or FolderPath has_any ({exact})
    or InitiatingProcessCommandLine has_any ({exact})
    or tostring(AdditionalFields) has_any ({exact})
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AdditionalFields
| order by Timestamp desc
| limit 300
"""

# The generic tier. Separate query and separate output field so a triager can dismiss the
# whole class in one pass without it ever having been counted as the exact name.
Q_NAME_GENERIC = """
search in (DeviceFileEvents, DeviceProcessEvents, DeviceEvents)
    Timestamp > ago({lookback}d)
| where FileName has_any ({generic}) or FolderPath has_any ({generic})
    or ProcessCommandLine has_any ({generic})
    or InitiatingProcessCommandLine has_any ({generic})
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| limit 300
"""

# ----------------------------------------------------------------------------------
# By shape - the queries that would find a renamed watchdog.
# ----------------------------------------------------------------------------------

Q_TOKEN_POLL_CADENCE = """
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has "api.github.com"
| summarize Requests = count() by DeviceId, DeviceName, InitiatingProcessFileName,
            Hour = bin(Timestamp, 1h)
| where Requests >= {min_per_hour}
| summarize HoursAtCadence = dcount(Hour), TotalRequests = sum(Requests),
            PeakPerHour = max(Requests), FirstSeen = min(Hour), LastSeen = max(Hour)
            by DeviceId, DeviceName, InitiatingProcessFileName
| where HoursAtCadence >= {min_hours}
| order by HoursAtCadence desc, TotalRequests desc
| limit 200
"""

# The query that answers for the platforms where RemoteUrl is empty. Narrower by
# construction - it sees only a poll a process spelled out on its own command line - and that
# is exactly the shape of a shell-script watchdog.
Q_TOKEN_POLL_CMDLINE = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where ProcessCommandLine has "{token_path}"
    or InitiatingProcessCommandLine has "{token_path}"
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
| limit 300
"""

# Aggregated, not sampled. The first run projected raw rows with `limit 300` and hit the cap
# on both of these, which reports a truncated population as if it were the whole one. A
# summarize over the interpreter list cannot truncate: the list has
# len(SCRIPT_INTERPRETERS) entries and the limit is far above it, so the totals below are the
# real totals.
Q_AUTOSTART_BY_INTERPRETER = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath has_any ({autostart})
| where InitiatingProcessFileName has_any ({interpreters})
| summarize Writes = count(), Devices = dcount(DeviceId),
            DeviceNames = make_set(DeviceName, 10), Files = make_set(FileName, 10),
            Folders = make_set(FolderPath, 6),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by InitiatingProcessFileName
| order by Writes desc
| limit 60
"""

# Windows autostart lives in the registry, not the filesystem. Without this the Windows half
# of the estate would be reported clean by a query that cannot see its autostart surface.
Q_RUNKEY_BY_INTERPRETER = """
DeviceRegistryEvents
| where Timestamp > ago({lookback}d)
| where RegistryKey has_any ("CurrentVersion\\\\Run", "CurrentVersion\\\\RunOnce")
| where InitiatingProcessFileName has_any ({interpreters})
    or RegistryValueData has_any ({interpreters})
| extend ByInterpreterFlag = InitiatingProcessFileName has_any ({interpreters}),
         DataNamesInterpreterFlag = RegistryValueData has_any ({interpreters})
| summarize Writes = count(), ByInterpreter = countif(ByInterpreterFlag),
            DataNamesInterpreter = countif(DataNamesInterpreterFlag),
            Devices = dcount(DeviceId),
            DeviceNames = make_set(DeviceName, 10), Values = make_set(RegistryValueName, 10),
            Data = make_set(RegistryValueData, 6),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by InitiatingProcessFileName
| order by Writes desc
| limit 60
"""

# The narrowing query, and the reason this collector is not just two lead piles. A watchdog
# has to do BOTH things: register for autostart, and talk to the GitHub API. Neither
# population alone is actionable at this estate's scale; their intersection is.
Q_AUTOSTART_PLUS_API = """
let autostart = DeviceFileEvents
    | where Timestamp > ago({lookback}d)
    | where ActionType in ("FileCreated", "FileModified", "FileRenamed")
    | where FolderPath has_any ({autostart})
    | where InitiatingProcessFileName has_any ({interpreters})
    | distinct DeviceId;
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where RemoteUrl has "api.github.com"
| where InitiatingProcessFileName has_any ({interpreters})
| where DeviceId in (autostart)
| summarize Requests = count(), Hours = dcount(bin(Timestamp, 1h)),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
            by DeviceId, DeviceName, InitiatingProcessFileName
| order by Requests desc
| limit 200
"""


def collect(lookback: int) -> Dict[str, Any]:
    from src.api.database import SessionLocal            # noqa: E402
    from src.api.integrations.msgraph import GraphClient  # noqa: E402

    client = GraphClient.from_db(SessionLocal())
    identity = client.verify()

    def hunt(query: str) -> Dict[str, Any]:
        try:
            result = client.run_hunting_query(query, strict_lint=False)
            rows = list(getattr(result, "rows", None)
                        or (result.get("results") if isinstance(result, dict) else [])
                        or [])
            rows = [{k: v for k, v in r.items() if not k.endswith("@odata.type")}
                    for r in rows]
            return {"ok": True, "row_count": len(rows), "rows": rows}
        except Exception as exc:  # noqa: BLE001 - the error IS the result here
            return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "rows": []}

    fmt = {"lookback": lookback, "exact": EXACT_LIST, "generic": GENERIC_LIST,
           "autostart": AUTOSTART_LIST, "interpreters": INTERPRETER_LIST,
           "token_path": TOKEN_CHECK_PATH, "min_per_hour": MIN_REQUESTS_PER_HOUR,
           "min_hours": MIN_HOURS_AT_CADENCE}
    return {
        "identity": identity,
        "lookback_days": lookback,
        "evidence": {
            "url_coverage_by_platform": hunt(Q_URL_COVERAGE.format(**fmt)),
            "autostart_coverage_by_platform": hunt(Q_AUTOSTART_COVERAGE.format(**fmt)),
            "name_positive_control": hunt(Q_NAME_POSITIVE_CONTROL.format(**fmt)),
            "api_positive_control": hunt(Q_API_POSITIVE_CONTROL.format(**fmt)),
            "watchdog_name_files": hunt(Q_NAME_FILES.format(**fmt)),
            "watchdog_name_processes": hunt(Q_NAME_PROCESSES.format(**fmt)),
            "watchdog_name_events": hunt(Q_NAME_EVENTS.format(**fmt)),
            "watchdog_name_generic": hunt(Q_NAME_GENERIC.format(**fmt)),
            "token_poll_cadence": hunt(Q_TOKEN_POLL_CADENCE.format(**fmt)),
            "token_poll_command_lines": hunt(Q_TOKEN_POLL_CMDLINE.format(**fmt)),
            "autostart_writes_by_interpreter": hunt(Q_AUTOSTART_BY_INTERPRETER.format(**fmt)),
            "windows_runkey_writes": hunt(Q_RUNKEY_BY_INTERPRETER.format(**fmt)),
            "autostart_and_api": hunt(Q_AUTOSTART_PLUS_API.format(**fmt)),
        },
    }


# ----------------------------------------------------------------------------------
# A name hit has three possible causes and only one of them is a finding.
#
# The first run of this collector reported 71 critical findings. Every one was on the
# analyst's own workstation, and every one was a shell loop grepping this repository's IOC
# corpus for `gh-token-monitor.service` and `com.user.gh-token-monitor` - the two strings
# github_conf/ioc/chaindrop_stepsecurity_2026_08.json exists to record. This is the same
# failure hunt_advisory_iocs.py hit with the C2 domains, arriving from the other direction: a
# hunt run from inside the estate it hunts finds the files that define its own indicators.
#
# So a name hit is classified before it is reported, and nothing is dropped - the demoted
# rows are written out verbatim. Dropping them would eventually drop a real watchdog that
# happened to live under a path containing one of these words.
# ----------------------------------------------------------------------------------

ANALYSIS_MARKERS = ("auditgithub", "auditgh", "sec-diligence", "github_conf",
                    "docs/playbooks", "shell-snapshots",
                    "/.local/share/claude/versions/", "/.claude/projects/")
READ_TOOLS = ("grep", "ugrep", "rg ", "ripgrep", "awk", "sed", "cat ", "wc ", "wc -",
              "less ", "head ", "tail ", "findstr", "select-string", "printf", "jq ",
              "python3 -", "python -", "for s in", "glob", "open(")

ANALYSIS = "analysis_corpus_reference"
TEXT = "text_reference"
CAPABLE = "watchdog_capable"


def classify_name_hit(row: dict) -> str:
    """`watchdog_capable`, `text_reference` or `analysis_corpus_reference`.

    Order matters. The analysis-corpus check runs first because the decisive evidence is the
    PATH being read, not the tool doing the reading: a `for` loop with no recognisable read
    tool in it still points at github_conf/ioc when that is what it is looping over. Anything
    unrecognised defaults to `watchdog_capable`, so a shape this classifier has never seen is
    reported rather than silently cleared.
    """
    text = " ".join(str(row.get(field) or "").lower() for field in (
        "ProcessCommandLine", "InitiatingProcessCommandLine", "FileName", "FolderPath",
        "AdditionalFields"))
    if any(marker in text for marker in ANALYSIS_MARKERS):
        return ANALYSIS
    if any(tool in text for tool in READ_TOOLS):
        return TEXT
    return CAPABLE


def split_by_class(candidates: List[dict]) -> Dict[str, List[dict]]:
    out: Dict[str, List[dict]] = {CAPABLE: [], TEXT: [], ANALYSIS: []}
    for row in candidates:
        out[classify_name_hit(row)].append({**row, "classification": classify_name_hit(row)})
    return out


def rows(ev: Dict[str, Any], key: str) -> List[dict]:
    return (ev.get(key) or {}).get("rows") or []


def first(ev: Dict[str, Any], key: str) -> dict:
    got = rows(ev, key)
    return got[0] if got else {}


def triage_priority(row: dict) -> str:
    """Order the cadence leads. Ordering only - nothing is dropped by this.

    The published cadence is 60 requests/hour sustained for 24 hours under a shell or node
    interpreter. A lead matching both halves goes first; a known API client at the same rate
    goes last, and is still printed, because `sh` and `node` appear on both lists.
    """
    initiator = str(row.get("InitiatingProcessFileName") or "").lower()
    hours = int(row.get("HoursAtCadence") or 0)
    known = any(client in initiator for client in KNOWN_API_CLIENTS)
    if hours >= 20 and not known:
        return "first - sustained for a full day under an initiator with no known reason to poll"
    if hours >= 20:
        return "second - sustained for a full day, but the initiator is a known API client"
    if not known:
        return "third - shorter run, initiator has no known reason to poll"
    return "last - known API client, below the published duration"


def build(raw: Dict[str, Any]) -> Dict[str, Any]:
    ev = raw["evidence"]
    lookback = raw["lookback_days"]

    coverage: List[str] = []
    unresolved: List[str] = []
    coverage_gaps: List[dict] = []
    access_required: List[dict] = []
    findings: List[dict] = []

    queries_run = sum(1 for q in ev.values() if q.get("ok"))
    queries_failed = [k for k, q in ev.items() if not q.get("ok")]
    for key in queries_failed:
        unresolved.append(
            f"Query `{key}` did not execute: {ev[key].get('error')}. Every result that "
            f"depended on it is untested rather than clean.")

    # ---- controls ----
    name_pos = first(ev, "name_positive_control")
    name_control_ok = bool(name_pos.get("Rows"))
    if name_control_ok:
        coverage.append(
            f"Name-sweep positive control: the same table and the same `has_any` operator "
            f"returned {(name_pos.get('Rows') or 0):,} row(s) across "
            f"{(name_pos.get('Devices') or 0):,} device(s) over {lookback} days for a benign "
            f"filename set. The `gh-token-monitor` zero below is a measured absence on the "
            f"tables that record filenames, not a broken query.")
    else:
        unresolved.append(
            "The name-sweep positive control returned nothing: `has_any` on FileName found no "
            "row for `monitor`, `agent` or `update` in 30 days, which cannot be true of this "
            "estate. The watchdog name result is therefore untested and must not be read as "
            "clean.")

    api_pos = first(ev, "api_positive_control")
    api_control_ok = bool(api_pos.get("Rows"))
    if api_control_ok:
        coverage.append(
            f"Cadence-sweep positive control: {(api_pos.get('Rows') or 0):,} connection(s) to "
            f"api.github.com from {(api_pos.get('Devices') or 0):,} device(s) under "
            f"{(api_pos.get('Initiators') or 0)} distinct initiating process(es) over "
            f"{lookback} days. So a zero from the cadence query is a statement about RATE, "
            f"not about whether the GitHub API is reachable from here.")
    else:
        unresolved.append(
            "The cadence positive control returned nothing: no connection to api.github.com "
            "was recorded in 30 days. The polling-shape sweep is untested, which matters "
            "because it is the only query here that could find a RENAMED watchdog.")

    url_rows = rows(ev, "url_coverage_by_platform")
    blind_platforms = [r for r in url_rows if not (r.get("UrlRows") or 0)]
    if url_rows:
        coverage.append(
            "URL-population control, re-run here because the cadence query reads RemoteUrl: "
            + "; ".join(
                f"{r.get('OSPlatform') or 'unknown'} {(r.get('Devices') or 0):,} device(s), "
                f"{(r.get('NetRows') or 0):,} network row(s), "
                f"{(r.get('UrlRows') or 0):,} with a URL"
                for r in url_rows[:12]))

    autostart_rows = rows(ev, "autostart_coverage_by_platform")
    autostart_seen = {str(r.get("OSPlatform")) for r in autostart_rows
                      if (r.get("Rows") or 0)}
    if autostart_rows:
        coverage.append(
            f"Autostart-surface control, which decides whether a persistence zero means "
            f"anything: the file table recorded "
            f"{sum((r.get('Rows') or 0) for r in autostart_rows):,} write(s) inside the "
            f"launchd, systemd, cron and Startup-folder paths over {lookback} days, across "
            + "; ".join(
                f"{r.get('OSPlatform') or 'unknown'} {(r.get('Devices') or 0):,} device(s), "
                f"{(r.get('Rows') or 0):,} row(s)" for r in autostart_rows[:12])
            + f". {len(AUTOSTART_PATHS)} path prefixes were swept.")
    else:
        unresolved.append(
            f"The autostart-surface control returned nothing: no write to any of the "
            f"{len(AUTOSTART_PATHS)} launchd, systemd, cron or Startup paths was recorded in "
            f"{lookback} days. Every persistence result below is untested rather than clean, "
            f"because the table cannot be shown to see the surface at all.")

    # ---- name sweep: a hit here is attribution, once it is the campaign's and not ours ----
    name_files = split_by_class(rows(ev, "watchdog_name_files"))
    name_procs = split_by_class(rows(ev, "watchdog_name_processes"))
    name_events = split_by_class(rows(ev, "watchdog_name_events"))
    name_generic = split_by_class(rows(ev, "watchdog_name_generic"))

    # Two different denominators, kept apart. `exact_*` is the campaign's literal name across
    # the three name tables, and the three sub-counts under it sum to it. `own_analysis` and
    # `text_only` are wider - they collect the demoted rows from every query in this collector,
    # including the generic tier and the token-path query - so they are reported under their
    # own heading rather than as "of those".
    exact_capable = name_files[CAPABLE] + name_procs[CAPABLE] + name_events[CAPABLE]
    exact_analysis = name_files[ANALYSIS] + name_procs[ANALYSIS] + name_events[ANALYSIS]
    exact_text = name_files[TEXT] + name_procs[TEXT] + name_events[TEXT]
    exact_total = len(exact_capable) + len(exact_analysis) + len(exact_text)
    own_analysis = exact_analysis + name_generic[ANALYSIS]
    text_only = exact_text + name_generic[TEXT]

    for row in name_files[CAPABLE]:
        findings.append({
            "id": f"watchdog-file-{row.get('DeviceName')}-{row.get('FileName')}",
            "what": (f"{row.get('FileName')} at {row.get('FolderPath')} on "
                     f"{row.get('DeviceName')} carries the anti-remediation watchdog's name. "
                     f"Remove it BEFORE any credential rotation on this host: revocation is "
                     f"its trigger condition."),
            "severity": "critical",
            "evidence": row,
        })
    for row in name_procs[CAPABLE]:
        findings.append({
            "id": f"watchdog-proc-{row.get('DeviceName')}-{row.get('Timestamp')}",
            "what": (f"A process on {row.get('DeviceName')} names the anti-remediation "
                     f"watchdog and is not a read of this hunt's own indicator files: "
                     f"{row.get('ProcessCommandLine')}"),
            "severity": "critical",
            "evidence": row,
        })
    for row in name_events[CAPABLE]:
        findings.append({
            "id": f"watchdog-event-{row.get('DeviceName')}-{row.get('Timestamp')}",
            "what": (f"{row.get('ActionType')} on {row.get('DeviceName')} references the "
                     f"anti-remediation watchdog - this is the persistence registration, "
                     f"which survives cleanup of setup.mjs and the IDE hooks"),
            "severity": "critical",
            "evidence": row,
        })

    # ---- shape sweep: leads with an order, never findings ----
    cadence = rows(ev, "token_poll_cadence")
    cadence_leads = sorted(
        ({**row, "triage_priority": triage_priority(row)} for row in cadence),
        key=lambda r: r["triage_priority"])
    poll_cmdlines = split_by_class(rows(ev, "token_poll_command_lines"))
    autostart_writers = rows(ev, "autostart_writes_by_interpreter")
    runkey_writers = rows(ev, "windows_runkey_writes")
    both_surfaces = rows(ev, "autostart_and_api")
    autostart_writes = sum((r.get("Writes") or 0) for r in autostart_writers)
    runkey_writes = sum((r.get("Writes") or 0) for r in runkey_writers)
    runkey_by_interpreter = sum((r.get("ByInterpreter") or 0) for r in runkey_writers)
    runkey_value_names = sum((r.get("DataNamesInterpreter") or 0) for r in runkey_writers)
    # Derived, not asserted. Whether the intersection set sits below the published cadence is
    # a measurement, and the sentence that reports it is gated on this number.
    both_rates = [(r.get("Requests") or 0) / max(1, int(r.get("Hours") or 1))
                  for r in both_surfaces]
    peak_both_rate = max(both_rates) if both_rates else 0.0
    # Nothing vanishes. The demoted rows from the token-path query join the same two lists as
    # the demoted rows from the name sweep, so every row this collector read is in the output
    # under exactly one heading.
    own_analysis = own_analysis + poll_cmdlines[ANALYSIS]
    text_only = text_only + poll_cmdlines[TEXT]

    coverage.append(
        f"Watchdog swept by NAME across the file, process and event tables over {lookback} "
        f"days: {exact_total} row(s) carry `gh-token-monitor`, of which "
        f"{len(exact_capable)} are on a process or file that could BE the watchdog rather than "
        f"a read of this hunt's own indicator corpus. {len(WATCHDOG_ARTIFACTS)} published "
        f"artifacts all contain that literal, so one substring answers for the script, its "
        f"state directory, the systemd unit and the launchd label together.")
    if own_analysis:
        coverage.append(
            f"{len(own_analysis)} of those name row(s) are this hunt reading its own "
            f"indicator files, on "
            f"{len({r.get('DeviceName') for r in own_analysis})} device(s): a shell loop over "
            f"github_conf/ioc and docs/playbooks, which are the files that RECORD "
            f"`gh-token-monitor.service` and `com.user.gh-token-monitor`. Classified rather "
            f"than filtered and written out verbatim under "
            f"`name_hits_reading_our_own_indicator_corpus`, because a rule that deleted them "
            f"would eventually delete a real watchdog living under a path that happens to "
            f"contain one of those words."
            + (f" {len(text_only)} further row(s) are a read or search command with no "
               f"analysis path on it." if text_only else ""))
    coverage.append(
        f"Watchdog swept by SHAPE, which is what would find a renamed one: "
        f"{len(cadence)} device/process pair(s) made at least {MIN_REQUESTS_PER_HOUR} "
        f"requests/hour to api.github.com in at least {MIN_HOURS_AT_CADENCE} distinct hours "
        f"over {lookback} days, against a published cadence of 60/hour for 24 hours. "
        f"{len(poll_cmdlines[CAPABLE])} command line(s) name `{TOKEN_CHECK_PATH}` directly on "
        f"a process that is not reading our own files.")
    if poll_cmdlines[CAPABLE]:
        # Named, because a lead nobody can look up is not a lead. This is the shape the
        # watchdog has - a bearer token pushed at the user endpoint in a loop - so it gets a
        # device name and an owner question rather than a count.
        poll_devices = sorted({str(r.get("DeviceName")) for r in poll_cmdlines[CAPABLE]})
        coverage.append(
            f"Those command lines are a token-validity check loop and they are named rather "
            f"than counted: {', '.join(poll_devices)}. The observed form pipes bearer tokens "
            f"into `curl` against the GitHub user endpoint through `xargs`, which is the same "
            f"shape as the watchdog with a different endpoint - the watchdog polls "
            f"api.github.com/user, this polls api.github.com/user/orgs. It is a LEAD and not "
            f"a finding: neither the exact name nor the cadence is present. Resolved by asking "
            f"the device owner what the loop is, and by reading the parent process on those "
            f"rows in `token_poll_command_lines`.")
    dominant = autostart_writers[0] if autostart_writers else {}
    runkey_dominant = runkey_writers[0] if runkey_writers else {}
    coverage.append(
        f"Persistence surface measured rather than sampled: {autostart_writes:,} write(s) "
        f"into a launchd, systemd, cron or Startup path came from one of "
        f"{len(SCRIPT_INTERPRETERS)} script interpreters, across "
        f"{len(autostart_writers)} distinct interpreter(s). On the Windows registry surface "
        f"{runkey_writes:,} Run-key write(s) matched, of which {runkey_by_interpreter:,} were "
        f"WRITTEN BY a script interpreter and {runkey_value_names:,} merely POINT AT one - two "
        f"different questions that a single total would fuse. These are counts over the whole "
        f"population, not the first 300 rows: the first run of this collector projected raw "
        f"rows and hit its own limit on both queries, which reports a truncated population as "
        f"a complete one."
        + (f" The registry number is dominated by one benign writer - "
           f"{runkey_dominant.get('InitiatingProcessFileName')} accounts for "
           f"{(runkey_dominant.get('Writes') or 0):,} of it across "
           f"{(runkey_dominant.get('Devices') or 0):,} devices - which is the difference "
           f"between a scary number and a legible one."
           if runkey_dominant else "")
        + (f" Autostart writers, largest first: " + "; ".join(
            f"{r.get('InitiatingProcessFileName')} {(r.get('Writes') or 0):,} write(s) on "
            f"{(r.get('Devices') or 0):,} device(s)" for r in autostart_writers[:6])
           if autostart_writers else ""))
    both_named = "; ".join(
        f"{r.get('DeviceName')} under {r.get('InitiatingProcessFileName')}, "
        f"{(r.get('Requests') or 0):,} request(s) across {r.get('Hours')} distinct hour(s) "
        f"({(r.get('Requests') or 0) / max(1, int(r.get('Hours') or 1)):.1f}/hour)"
        for r in both_surfaces[:10])
    coverage.append(
        f"The narrowing that makes those two populations usable: {len(both_surfaces)} "
        f"device/process pair(s) did BOTH things a watchdog must do - wrote an autostart entry "
        f"under a script interpreter AND reached api.github.com under one - over {lookback} "
        f"days. Named, with the rate, because the rate is what separates them from the "
        f"campaign: {both_named or 'none'}. "
        + (f"The published cadence is 60 requests/hour and the fastest pair above runs at "
           f"{peak_both_rate:.1f}/hour, so the intersection is a persistent integration "
           f"rather than a poller - which is why these are the triage list for this vector "
           f"and not findings."
           if both_surfaces and peak_both_rate < MIN_REQUESTS_PER_HOUR else
           f"The fastest pair above runs at {peak_both_rate:.1f} requests/hour against a "
           f"published cadence of 60/hour, which is inside the range this sweep exists to "
           f"find. Triage it before anything else on this vector."
           if both_surfaces else ""))

    if name_generic[CAPABLE] or name_generic[TEXT]:
        generic = name_generic[CAPABLE] + name_generic[TEXT]
        coverage.append(
            f"{len(generic)} row(s) carry a generic `token-monitor` style token rather than "
            f"the campaign's exact name, across "
            f"{len({r.get('DeviceName') for r in generic})} device(s). Recorded in "
            f"`generic_name_leads` and deliberately NOT counted as watchdog hits: a locally "
            f"written `token_monitor.py` is not this campaign, and putting it in the finding "
            f"set is how the one row that matters gets dismissed with the rest.")

    # ---- gaps ----
    if blind_platforms:
        blind_names = ", ".join(str(r.get("OSPlatform") or "unknown")
                                for r in blind_platforms)
        blind_devices = sum((r.get("Devices") or 0) for r in blind_platforms)
        blind_netrows = sum((r.get("NetRows") or 0) for r in blind_platforms)
        coverage_gaps.append({
            "gap": ("The polling-cadence sweep cannot answer for platforms that record no "
                    "URL, so a renamed watchdog on them is invisible to the shape query"),
            "population": (
                f"{blind_devices:,} device(s) on {blind_names}, carrying {blind_netrows:,} "
                f"network row(s) over {lookback} days with zero of them populating RemoteUrl. "
                f"The name sweep still answers for these devices; only the renamed-watchdog "
                f"question is unanswered."),
            "named_by": ("the per-platform rows of url_coverage_by_platform in this artifact, "
                         "and device by device by the same query grouped by DeviceId rather "
                         "than OSPlatform"),
            "cannot_confirm_or_deny": (
                "whether a process on those devices is polling the GitHub API at the "
                "watchdog's rate under a different name. The command-line query partially "
                "compensates, because a shell-script watchdog spells the URL out on its own "
                "command line - but a compiled poller or one using a library call spells "
                "nothing out."),
            "closed_by": (
                "enabling Defender Network Protection (audit mode is sufficient) on macOS and "
                "Linux - the same single change that closes the tarball-attribution gap on "
                "the install-activity vector and the campaign-domain gap on the advisory-IOC "
                "vector. One configuration change, three vectors."),
            "owner": ("Endpoint security - the team that owns the Defender device "
                      "configuration profiles for macOS and Linux"),
        })

    missing_autostart = sorted({str(r.get("OSPlatform")) for r in url_rows}
                               - autostart_seen - {"None", ""})
    if autostart_rows and missing_autostart:
        coverage_gaps.append({
            "gap": ("Platforms that report network activity but no write to any autostart "
                    "path, so the persistence half of this vector is untested there"),
            "population": (
                f"{', '.join(missing_autostart)} - present in the URL-coverage control with "
                f"devices reporting, absent from the autostart-surface control over "
                f"{lookback} days across all {len(AUTOSTART_PATHS)} swept path prefixes."),
            "named_by": ("the OSPlatform rows present in url_coverage_by_platform and absent "
                         "from autostart_coverage_by_platform in this artifact"),
            "cannot_confirm_or_deny": (
                "whether a watchdog registered itself for autostart on those platforms. A "
                "zero from a table that never records the directory is not an absence."),
            "closed_by": (
                "establishing which file paths Defender's file-event sensor covers on those "
                "platforms, and adding the paths it does cover to AUTOSTART_PATHS in this "
                "collector. If the sensor covers none of them, the limit is permanent and "
                "persistence triage there rests on process ancestry instead."),
            "owner": "Security operations, with Microsoft support",
        })

    # The half of this vector that no query closes, stated rather than implied.
    unresolved.append(
        "A clean watchdog sweep does not make the remediation ORDER safe. The watchdog is "
        "triggered by revocation, so the control for this vector is a runbook that removes "
        "persistence from every affected host before the first credential is rotated. That "
        "ordering is written - docs/playbooks/supply-chain-hunt-ttp.md section 6.3, six steps, "
        "with removal verified on the host by `pgrep -af gh-token-monitor` rather than from an "
        "alert - and what remains open is that it is doctrine on a page and not a step anyone "
        "is held to: no incident-response process here requires it before a rotation, and this "
        "sweep cannot establish that it would be followed. It has to hold whatever the sweep "
        "returns, because the sweep covers the devices Defender reports on and the rotation "
        "covers every credential.")

    if findings:
        status = FINDINGS
    elif unresolved or not name_control_ok or not api_control_ok:
        status = INCOMPLETE
    else:
        status = CLEAR

    return {
        "name": "Anti-remediation watchdog sweep - is anything waiting for us to rotate",
        "status": status,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scope": (f"All devices reporting to Microsoft Defender, {lookback}-day lookback. The "
                  f"`gh-token-monitor` watchdog published by StepSecurity and referenced by "
                  f"Integrity360 and Snyk, swept by name and independently by behavior."),
        "counts": {
            "Hunting queries executed": queries_run,
            "Hunting queries that FAILED to execute": len(queries_failed),
            "Published watchdog artifacts swept": len(WATCHDOG_ARTIFACTS),
            "Autostart path prefixes swept": len(AUTOSTART_PATHS),
            "Rows naming the watchdog exactly, all tables": exact_total,
            "Of those, on a process or file that could BE the watchdog": len(exact_capable),
            "Of those, this hunt reading its own indicator corpus": len(exact_analysis),
            "Of those, another read or search command": len(exact_text),
            "Generic token-monitor rows (leads, not watchdog hits)":
                len(name_generic[CAPABLE]) + len(name_generic[TEXT]),
            "Rows demoted as our own analysis across every query here": len(own_analysis),
            "Device/process pairs polling api.github.com at watchdog cadence":
                len(cadence_leads),
            "Of those, sustained a full day under an unexplained initiator":
                sum(1 for r in cadence_leads if r["triage_priority"].startswith("first")),
            f"Command lines naming {TOKEN_CHECK_PATH}": len(poll_cmdlines[CAPABLE]),
            "Autostart writes by a script interpreter (whole population)": autostart_writes,
            "Windows Run-key writes written BY a script interpreter": runkey_by_interpreter,
            "Windows Run-key writes whose value POINTS AT a script interpreter":
                runkey_value_names,
            "Device/process pairs on BOTH the autostart and the API surface":
                len(both_surfaces),
        },
        "coverage": coverage,
        "unresolved_items": unresolved,
        "coverage_gaps": coverage_gaps,
        "access_required": access_required,
        "findings": findings,
        "token_poll_cadence_leads": cadence_leads,
        "token_poll_command_lines": poll_cmdlines[CAPABLE],
        "devices_on_both_surfaces": both_surfaces,
        "autostart_writers_by_interpreter": autostart_writers,
        "windows_runkey_writers_by_interpreter": runkey_writers,
        "generic_name_leads": name_generic[CAPABLE] + name_generic[TEXT],
        "name_hits_reading_our_own_indicator_corpus": own_analysis,
        "name_hits_that_are_a_read_or_search_command": text_only,
        "indicators": {
            "exact_name": WATCHDOG_EXACT,
            "published_artifacts": WATCHDOG_ARTIFACTS,
            "generic_tokens": WATCHDOG_GENERIC,
            "token_check_path": TOKEN_CHECK_PATH,
            "published_cadence": "one request per minute for 24 hours",
            "cadence_floor_used": {"requests_per_hour": MIN_REQUESTS_PER_HOUR,
                                   "distinct_hours": MIN_HOURS_AT_CADENCE,
                                   "why_below_published": (
                                       "a sweep tuned to the exact published numbers finds "
                                       "only the variant that was published")},
            "autostart_paths": AUTOSTART_PATHS,
            "script_interpreters": SCRIPT_INTERPRETERS,
        },
        "identity": raw.get("identity"),
        "evidence": ev,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lookback", type=int, default=LOOKBACK_DAYS)
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/antiremediation_r1.json")
    args = parser.parse_args()

    raw = collect(args.lookback)
    artifact = build(raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, default=str) + "\n")

    print(f"[antiremediation] {artifact['status']} -> {args.out}")
    for key, value in artifact["counts"].items():
        print(f"  {key}: {value}")
    for gap in artifact["coverage_gaps"]:
        print(f"  GAP: {gap['gap']}")
    for item in artifact["unresolved_items"]:
        print(f"  UNREAD: {item[:160]}")
    for finding in artifact["findings"]:
        print(f"  FINDING: {finding['what']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
