#!/usr/bin/env python3
"""Did any endpoint touch the campaign's own infrastructure, or hold one of its files?

Why this is a separate collector
--------------------------------
`hunt_endpoint_defender.py` asks whether the payload *behaved* here — node spawning Bun,
credential access, persistence. `hunt_install_activity.py` asks whether a malicious tarball
was *fetched*. Neither asks the two questions the published advisories actually make
answerable:

  1. **Did anything talk to the attacker's infrastructure?** The C2 domain, the three
     Ethereum RPC endpoints the loader uses to resolve its C2 out of a smart contract, and
     the two sibling registry-lookalike domains. r9 never queried a single campaign domain:
     its only network query was for Bun release URLs.
  2. **Does any device hold a file at a campaign hash?** r9 and r2 matched dropped files by
     NAME (`setup.mjs`, `Math_Symbol.js`), which is why both recorded the result as
     name-only. Integrity360 published three SHA-1 hashes and Snyk published two SHA-256
     hashes. A name match is a lead; a hash match is a verdict.

The SHA-1 half matters twice over. Defender's `stopAndQuarantineFiles` takes a SHA-1, and the
r9 report already carries the finding that SHA-1 is absent from a fraction of
DeviceFileEvents rows on every Windows platform. Until this run there was no campaign SHA-1
to give it.

Two design choices, both from doctrine §0.1
------------------------------------------
**A domain zero is worthless where RemoteUrl is empty.** `install_activity_r2.json` measured
it: macOS reports 83 devices, 687,005 network rows and **zero** with a URL, because Defender
Network Protection is not enabled there. So this collector runs the URL-coverage control
first and states, per platform, whether its domain result is readable at all.

**Hence the command-line sweep.** The same IOC hostnames are matched against process command
lines as well as against RemoteUrl. A `curl https://npm-cache.com/...` is visible in
DeviceProcessEvents on a device whose RemoteUrl column is empty, so this is the one query in
this collector that can answer for macOS. It is narrower than the network sweep — it only
sees egress a process spelled out on its own command line — and that limit is recorded rather
than papered over.

IOC provenance is carried per indicator, because the two advisories do not agree on
everything and a hunt that flattens them cannot say which source it is trusting.

Reads only. No GitHub budget is touched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CLEAR = "CLEAR"
INCOMPLETE = "INCOMPLETE"
FINDINGS = "FINDINGS"

LOOKBACK_DAYS = 30

# ----------------------------------------------------------------------------------
# The indicators, each with the advisory that published it. Provenance is not decoration:
# where two sources disagree the report has to be able to say which one it acted on, and a
# single-source indicator is a weaker basis for an alert than a corroborated one.
# ----------------------------------------------------------------------------------

IOC_DOMAINS = [
    {"value": "npm-cache.com", "role": "primary C2",
     "sources": ["Integrity360"]},
    {"value": "js-mirror.com", "role": "registry-lookalike, sibling infrastructure",
     "sources": ["Integrity360"]},
    {"value": "pypi-get.com", "role": "registry-lookalike, sibling infrastructure",
     "sources": ["Integrity360"]},
    {"value": "eth-mainnet.nodereal.io", "role": "Ethereum RPC - C2 address resolution",
     "sources": ["Integrity360"]},
    {"value": "go.getblock.io", "role": "Ethereum RPC - C2 address resolution",
     "sources": ["Integrity360"]},
    {"value": "eth.llamarpc.com", "role": "Ethereum RPC - C2 address resolution",
     "sources": ["Integrity360"]},
]

# Two of these four resolve to Cloudflare, which is shared anycast infrastructure. A hit on
# one is NOT attribution to this campaign and this collector says so rather than counting it
# as a finding - reporting a Cloudflare IP as a C2 hit is how a hunt loses its audience.
IOC_IPS = [
    {"value": "104.21.35.216", "role": "Cloudflare edge in front of npm-cache.com",
     "shared_infrastructure": True, "sources": ["Integrity360"]},
    {"value": "172.67.167.200", "role": "Cloudflare edge in front of eth.llamarpc.com",
     "shared_infrastructure": True, "sources": ["Integrity360"]},
    {"value": "185.44.207.215", "role": "go.getblock.io",
     "shared_infrastructure": False, "sources": ["Integrity360"]},
    {"value": "35.175.164.77", "role": "AWS host of eth-mainnet.nodereal.io",
     "shared_infrastructure": True, "sources": ["Integrity360"]},
]

IOC_HASHES = [
    {"algorithm": "SHA1", "value": "35a672cf34b996b91f3e1c28cbf3a05a37e036e4",
     "artifact": "Math_Symbol.js / math_init.js (stage 2 infostealer)",
     "sources": ["Integrity360"]},
    {"algorithm": "SHA1", "value": "686aa40d0fc22c8d569494543a0f891f359f2f99",
     "artifact": "setup.mjs dropped into .claude/", "sources": ["Integrity360"]},
    {"algorithm": "SHA1", "value": "f525d52ceb966516686b482d3dc0137028cc6a63",
     "artifact": "setup.mjs dropped into .vscode/", "sources": ["Integrity360"]},
    {"algorithm": "SHA256",
     "value": "54dc7ea54a1317cca0e890a2770630cf7fa6c97813e0cb9d2caa93012b350668",
     "artifact": "setup.mjs, 29,918 bytes (stage 1 dropper)", "sources": ["Snyk"]},
    {"algorithm": "SHA256",
     "value": "9fc2570b7cef51c1b8df116d144d11ff4096357be7d2c4c6367cfc2509cf1bcc",
     "artifact": "Math_Symbol.js, 727,680 bytes (stage 2 infostealer)",
     "sources": ["Snyk"]},
]

# The Bun build the loader pins. Advisories agree on 1.3.13, which makes the version string
# itself an indicator rather than only the binary name.
BUN_VERSION = "1.3.13"


def kql_list(values: List[str]) -> str:
    return ", ".join(f'"{v}"' for v in values)


DOMAIN_LIST = kql_list([d["value"] for d in IOC_DOMAINS])
IP_LIST = kql_list([i["value"] for i in IOC_IPS])
SHA1_LIST = kql_list([h["value"] for h in IOC_HASHES if h["algorithm"] == "SHA1"])
SHA256_LIST = kql_list([h["value"] for h in IOC_HASHES if h["algorithm"] == "SHA256"])

# ----------------------------------------------------------------------------------
# Controls first. Every zero below is read through one of these.
# ----------------------------------------------------------------------------------

# Whether a URL is recorded at all, by platform. This is the control that decides whether
# the domain sweep can answer for a given platform, and on this tenant it is already known
# to fail for macOS.
Q_URL_COVERAGE = """
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| summarize NetRows = count(), UrlRows = countif(isnotempty(RemoteUrl)) by DeviceId
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago({lookback}d)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
  ) on DeviceId
| summarize Devices = dcount(DeviceId), NetRows = sum(NetRows), UrlRows = sum(UrlRows),
            DevicesWithUrl = dcountif(DeviceId, UrlRows > 0) by OSPlatform
| order by NetRows desc
| limit 40
"""

# The positive control for the domain sweep: the same table, the same operator, a marker set
# that MUST return rows. If this is zero the sweep is broken, not the estate clean.
Q_DOMAIN_POSITIVE_CONTROL = """
DeviceNetworkEvents
| where Timestamp > ago(1d)
| where RemoteUrl has_any ("github.com", "microsoft.com", "google.com")
| summarize Rows = count(), Devices = dcount(DeviceId)
| limit 5
"""

# Whether the hash columns are populated, by platform and by table. A hash zero on a platform
# that never records a hash is untested, exactly as a domain zero is where RemoteUrl is empty.
Q_HASH_COVERAGE = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| summarize Rows = count(), Sha1Rows = countif(isnotempty(SHA1)),
            Sha256Rows = countif(isnotempty(SHA256)) by DeviceId
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago({lookback}d)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
  ) on DeviceId
| summarize Devices = dcount(DeviceId), Rows = sum(Rows), Sha1Rows = sum(Sha1Rows),
            Sha256Rows = sum(Sha256Rows) by OSPlatform
| extend Sha1Pct = round(100.0 * Sha1Rows / Rows, 1),
         Sha256Pct = round(100.0 * Sha256Rows / Rows, 1)
| order by Rows desc
| limit 40
"""

# ----------------------------------------------------------------------------------
# The sweeps.
# ----------------------------------------------------------------------------------

Q_IOC_DOMAINS = """
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where isnotempty(RemoteUrl)
| where RemoteUrl has_any ({domains})
| extend Host = tostring(split(tostring(split(RemoteUrl, "://")[-1]), "/")[0])
| summarize Rows = count(), Devices = dcount(DeviceId),
            DeviceNames = make_set(DeviceName, 25),
            Initiators = make_set(InitiatingProcessFileName, 15),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by Host
| order by Rows desc
| limit 100
"""

# The query that can answer for the platforms where RemoteUrl is empty. Narrower by
# construction: it only sees egress a process spelled out on its own command line.
Q_IOC_CMDLINE = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where ProcessCommandLine has_any ({domains})
    or InitiatingProcessCommandLine has_any ({domains})
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp desc
| limit 500
"""

# The positive control for the command-line sweep. Same table, same operator, a hostname that
# routinely appears on a command line.
Q_CMDLINE_POSITIVE_CONTROL = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where ProcessCommandLine has_any ("github.com", "registry.npmjs.org", "https://")
| summarize Rows = count(), Devices = dcount(DeviceId)
| limit 5
"""

Q_IOC_IPS = """
DeviceNetworkEvents
| where Timestamp > ago({lookback}d)
| where RemoteIP in ({ips})
| summarize Rows = count(), Devices = dcount(DeviceId),
            DeviceNames = make_set(DeviceName, 25),
            Urls = make_set(RemoteUrl, 25),
            Initiators = make_set(InitiatingProcessFileName, 15),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp) by RemoteIP
| order by Rows desc
| limit 50
"""

Q_HASH_FILES = """
DeviceFileEvents
| where Timestamp > ago({lookback}d)
| where tolower(SHA1) in ({sha1}) or tolower(SHA256) in ({sha256})
| project Timestamp, DeviceName, DeviceId, ActionType, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| limit 500
"""

Q_HASH_PROCESSES = """
DeviceProcessEvents
| where Timestamp > ago({lookback}d)
| where tolower(SHA1) in ({sha1}) or tolower(SHA256) in ({sha256})
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine, SHA1,
          SHA256, InitiatingProcessFileName
| order by Timestamp desc
| limit 500
"""

Q_HASH_IMAGES = """
DeviceImageLoadEvents
| where Timestamp > ago({lookback}d)
| where tolower(SHA1) in ({sha1}) or tolower(SHA256) in ({sha256})
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, SHA1, SHA256,
          InitiatingProcessFileName
| order by Timestamp desc
| limit 500
"""

# The pinned Bun build, as a string rather than as a binary name. A device that downloaded
# bun-1.3.13 specifically is a different question from a device that has Bun installed.
Q_BUN_VERSION = """
search in (DeviceProcessEvents, DeviceFileEvents, DeviceNetworkEvents)
    Timestamp > ago({lookback}d)
| where ProcessCommandLine has "bun-{version}" or FolderPath has "bun-{version}"
    or FileName has "bun-{version}" or RemoteUrl has "bun-v{version}"
    or RemoteUrl has "bun/releases/download/bun-v{version}"
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine, RemoteUrl
| order by Timestamp desc
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

    fmt = {"lookback": lookback, "domains": DOMAIN_LIST, "ips": IP_LIST,
           "sha1": SHA1_LIST.lower(), "sha256": SHA256_LIST.lower(),
           "version": BUN_VERSION}
    return {
        "identity": identity,
        "lookback_days": lookback,
        "evidence": {
            "url_coverage_by_platform": hunt(Q_URL_COVERAGE.format(**fmt)),
            "domain_positive_control": hunt(Q_DOMAIN_POSITIVE_CONTROL),
            "cmdline_positive_control": hunt(Q_CMDLINE_POSITIVE_CONTROL.format(**fmt)),
            "hash_coverage_by_platform": hunt(Q_HASH_COVERAGE.format(**fmt)),
            "ioc_domains": hunt(Q_IOC_DOMAINS.format(**fmt)),
            "ioc_domains_on_command_lines": hunt(Q_IOC_CMDLINE.format(**fmt)),
            "ioc_ips": hunt(Q_IOC_IPS.format(**fmt)),
            "hash_matches_files": hunt(Q_HASH_FILES.format(**fmt)),
            "hash_matches_processes": hunt(Q_HASH_PROCESSES.format(**fmt)),
            "hash_matches_images": hunt(Q_HASH_IMAGES.format(**fmt)),
            "pinned_bun_build": hunt(Q_BUN_VERSION.format(**fmt)),
        },
    }


# A command line can carry a campaign hostname for two entirely different reasons, and the
# first run of this collector proved it by flagging the analyst's own grep as a critical
# finding. So a match is classified before it is reported: a command that can make a network
# request is a lead worth waking somebody for, and a command that reads or searches text is
# this hunt looking at itself. Neither is dropped - dropping the second would eventually drop
# a real `curl` that happened to contain the word grep.
EGRESS_TOOLS = ("curl", "wget", "invoke-webrequest", "iwr", "node", "bun", "bunx", "npm",
                "npx", "pnpm", "yarn", "pip", "nc ", "ncat", "openssl s_client", "ssh",
                "start-bitstransfer", "certutil", "powershell -e")
SEARCH_TOOLS = ("grep", "rg ", "ripgrep", "awk", "sed", "cat ", "less ", "head ", "tail ",
                "findstr", "select-string", "python3 -", "python -", "glob", "open(")


# Two ways this classifier read a hostname as a tool invocation on the first attempt, both
# of them substring accidents:
#   - `npm-cache.com` was stripped, but the bare label `npm-cache` was not, so `npm` matched
#     the C2 hostname itself. So every indicator is stripped in both forms, longest first.
#   - `bun` matched inside the Defender detection name `suspbunactivity`, which is a string
#     that appears in a *query about* the campaign. So a tool name that is a bare word is
#     matched on its boundaries, not as a substring.
_INDICATOR_FORMS = sorted(
    {form
     for d in IOC_DOMAINS
     for form in (d["value"].lower(), d["value"].lower().rsplit(".", 1)[0])},
    key=len, reverse=True)


def _tool_matcher(tool: str):
    """Boundary-anchored for a bare word; literal for anything carrying punctuation."""
    if re.fullmatch(r"[a-z0-9]+", tool):
        return re.compile(r"(?<![a-z0-9])" + re.escape(tool) + r"(?![a-z0-9])").search
    return lambda text, _t=tool: _t in text


_EGRESS_MATCHERS = [_tool_matcher(t) for t in EGRESS_TOOLS]
_SEARCH_MATCHERS = [_tool_matcher(t) for t in SEARCH_TOOLS]


# Ported verbatim from `hunt_antiremediation.py`, where this problem was already solved and
# reviewed. Keeping two divergent copies of the same judgement is how one collector reports a
# finding the other correctly demotes - which is exactly what happened on 2026-08-11, when
# this collector reported FINDINGS on five rows that were this hunt's own test commands and
# `hunt_antiremediation.py` demoted 247 rows of the same kind on the same estate.
ANALYSIS_MARKERS = ("auditgithub", "auditgh", "sec-diligence", "github_conf",
                    "docs/playbooks", "shell-snapshots",
                    "/.local/share/claude/versions/", "/.claude/projects/")

EGRESS = "egress_capable"
TEXT = "text_reference"
ANALYSIS = "analysis_corpus_reference"


def classify_command_line(row: dict) -> str:
    """`egress_capable`, `text_reference` or `analysis_corpus_reference`.

    The indicator strings are removed from the text before the tool scan, because
    `npm-cache.com` contains `npm` and would otherwise classify every mention of the C2
    domain as an npm invocation - which is how a grep for the IOC becomes an IOC.

    ORDER MATTERS, and getting it wrong is what made this vector read FINDINGS on
    2026-08-11. The decisive evidence is the PATH the command is working in, not the tool
    doing the work: a `python3 - <<PY` heredoc that imports `scripts.hunt.hunt_advisory_iocs`
    to test this very classifier is a python invocation, and python is egress-capable, so a
    tool-first order reports the security team testing its own detection as a C2 contact.
    Five such rows on one analyst workstation drove this vector to FINDINGS with a critical
    severity, and every one of them was us.

    Why this is a demotion and not a suppression, which is the line that matters:
      * The class is NAMED, counted in `counts`, and every row is written to the artifact
        verbatim under `command_line_analysis_references`. Nothing is deleted. A reader who
        disagrees with the call can see exactly what was demoted and re-read it.
      * Anything unrecognised still defaults to `egress_capable`, so a shape this classifier
        has never seen is reported rather than silently cleared.
      * The markers are paths belonging to this repository and to the analyst tooling that
        reads it. They are not a device allowlist: the same command line on any device is
        demoted, and a genuine `curl https://npm-cache.com` on an analyst's laptop still
        classifies as egress, because no marker appears in it.

    The residual risk is stated rather than hidden: an attacker who ran their fetch from
    inside a path named `auditgithub` would be demoted too. That is accepted because the
    alternative - reporting the hunt's own instrumentation as critical findings every cycle -
    trains the reader to ignore this vector, and a vector nobody reads detects nothing.
    """
    text = " ".join(str(row.get(field) or "").lower()
                    for field in ("ProcessCommandLine", "InitiatingProcessCommandLine",
                                  "FileName", "FolderPath"))
    for indicator in _INDICATOR_FORMS:
        text = text.replace(indicator, " <indicator> ")
    if any(marker in text for marker in ANALYSIS_MARKERS):
        return ANALYSIS
    if any(match(text) for match in _EGRESS_MATCHERS):
        return EGRESS
    if any(match(text) for match in _SEARCH_MATCHERS):
        return TEXT
    return EGRESS


def rows(ev: Dict[str, Any], key: str) -> List[dict]:
    return (ev.get(key) or {}).get("rows") or []


def first(ev: Dict[str, Any], key: str) -> dict:
    got = rows(ev, key)
    return got[0] if got else {}


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

    # ---- control 1: is a URL recorded at all, and where is it not ----
    url_rows = rows(ev, "url_coverage_by_platform")
    blind_platforms = [r for r in url_rows if not (r.get("UrlRows") or 0)]
    seeing_platforms = [r for r in url_rows if (r.get("UrlRows") or 0)]
    if url_rows:
        coverage.append(
            "URL-population control, which decides whether the domain sweep can answer for a "
            "platform at all: " + "; ".join(
                f"{r.get('OSPlatform') or 'unknown'} {(r.get('Devices') or 0):,} device(s), "
                f"{(r.get('NetRows') or 0):,} network row(s), "
                f"{(r.get('UrlRows') or 0):,} with a URL"
                for r in url_rows[:12]))

    # ---- control 2: does the operator work at all ----
    pos = first(ev, "domain_positive_control")
    domain_control_ok = bool(pos.get("Rows"))
    if domain_control_ok:
        coverage.append(
            f"Domain-sweep positive control: the same table and the same `has_any` operator "
            f"returned {(pos.get('Rows') or 0):,} row(s) across "
            f"{(pos.get('Devices') or 0):,} device(s) in 24h for a benign marker set. The "
            f"campaign-domain zero below is therefore a measured absence on the platforms "
            f"that populate RemoteUrl, not a broken query.")
    else:
        unresolved.append(
            "The domain-sweep positive control returned nothing. `has_any` on RemoteUrl "
            "found no row for github.com, microsoft.com or google.com in 24 hours, which "
            "cannot be true of this estate - so the campaign-domain result is untested and "
            "must not be read as clean.")

    cmd_pos = first(ev, "cmdline_positive_control")
    cmdline_control_ok = bool(cmd_pos.get("Rows"))
    if cmdline_control_ok:
        coverage.append(
            f"Command-line sweep positive control: {(cmd_pos.get('Rows') or 0):,} process "
            f"row(s) across {(cmd_pos.get('Devices') or 0):,} device(s) carry a hostname on "
            f"the command line over {lookback} days. This is the query that can answer for "
            f"the platforms where RemoteUrl is empty.")
    else:
        unresolved.append(
            "The command-line positive control returned nothing, so the command-line IOC "
            "sweep is untested. That matters more than it looks: it is the only query here "
            "that can see egress on a platform whose RemoteUrl column is empty.")

    # ---- control 3: are hashes recorded ----
    hash_rows = rows(ev, "hash_coverage_by_platform")
    if hash_rows:
        coverage.append(
            "Hash-population control for the file sweep, by platform: " + "; ".join(
                f"{r.get('OSPlatform') or 'unknown'} {(r.get('Rows') or 0):,} file row(s), "
                f"SHA1 on {r.get('Sha1Pct')}%, SHA256 on {r.get('Sha256Pct')}%"
                for r in hash_rows[:12]))
    # 10%, not 0%. A platform recording a hash on 1.6% of its file rows is not "mostly
    # covered" - a hash match needs the row carrying the hash to be the row that matters, so
    # at 1.6% a zero says almost nothing. Naming the threshold beats implying there is none.
    HASH_FLOOR_PCT = 10.0
    hash_blind = [r for r in hash_rows
                  if (r.get("Sha1Pct") is not None
                      and float(r.get("Sha1Pct") or 0) < HASH_FLOOR_PCT
                      and float(r.get("Sha256Pct") or 0) < HASH_FLOOR_PCT)]

    # Which platform is blind to which sweep - and whether any platform is blind to both.
    # This is the question that decides whether the estate has a hole or two overlapping
    # partial views, and neither control answers it alone.
    url_blind_names = {str(r.get("OSPlatform")) for r in blind_platforms}
    hash_blind_names = {str(r.get("OSPlatform")) for r in hash_blind}
    both_blind = sorted(url_blind_names & hash_blind_names)
    if url_rows and hash_rows:
        coverage.append(
            "Cross-check of the two sweeps against each other, by platform. Domain sweep "
            f"blind on: {', '.join(sorted(url_blind_names)) or 'no platform'}. Hash sweep "
            f"blind (below {HASH_FLOOR_PCT:.0f}% hash population) on: "
            f"{', '.join(sorted(hash_blind_names)) or 'no platform'}. Blind to BOTH: "
            f"{', '.join(both_blind) or 'no platform'}. "
            + ("Where a platform is blind to one sweep it is covered by the other, so the "
               "campaign has no platform on which both its infrastructure and its files are "
               "invisible."
               if not both_blind else
               "A platform blind to both is a hole, not a partial view: on it neither the "
               "campaign's traffic nor its files could be found."))

    # ---- the sweeps ----
    domain_hits = rows(ev, "ioc_domains")
    cmdline_hits = rows(ev, "ioc_domains_on_command_lines")
    ip_hits = rows(ev, "ioc_ips")
    hash_hits = (rows(ev, "hash_matches_files") + rows(ev, "hash_matches_processes")
                 + rows(ev, "hash_matches_images"))
    bun_hits = rows(ev, "pinned_bun_build")

    for row in domain_hits:
        findings.append({
            "id": f"c2-domain-{row.get('Host')}",
            "what": (f"{(row.get('Rows') or 0):,} connection(s) to {row.get('Host')} from "
                     f"{(row.get('Devices') or 0)} device(s) - a campaign C2 or "
                     f"C2-resolution host"),
            "severity": "critical",
            "evidence": row,
        })
    # One pass, so the three buckets provably sum to the population and a row cannot be
    # counted twice by two calls that disagree.
    cmdline_by_class: Dict[str, List[dict]] = {EGRESS: [], TEXT: [], ANALYSIS: []}
    for row in cmdline_hits:
        verdict = classify_command_line(row)
        cmdline_by_class[verdict].append({**row, "classification": verdict})
    cmdline_egress = cmdline_by_class[EGRESS]
    cmdline_text = cmdline_by_class[TEXT]
    cmdline_analysis = cmdline_by_class[ANALYSIS]
    for row in cmdline_egress:
        findings.append({
            "id": f"c2-cmdline-{row.get('DeviceName')}-{row.get('Timestamp')}",
            "what": (f"A campaign hostname appears on the command line of a process that can "
                     f"make a network request, on {row.get('DeviceName')}: "
                     f"{row.get('ProcessCommandLine')}"),
            "severity": "critical",
            "evidence": row,
        })
    for row in hash_hits:
        findings.append({
            "id": f"hash-{(row.get('SHA1') or row.get('SHA256') or '')[:12]}",
            "what": (f"{row.get('FileName')} at {row.get('FolderPath')} on "
                     f"{row.get('DeviceName')} matches a published campaign hash"),
            "severity": "critical",
            "evidence": row,
        })

    # IP hits are NOT findings by themselves. Three of the four addresses are shared
    # infrastructure - two Cloudflare edges and an AWS host - so a hit is a lead that needs
    # the hostname to mean anything. Reporting a Cloudflare IP as a C2 hit is how a hunt
    # loses the audience it needs for the real one.
    shared = {i["value"] for i in IOC_IPS if i["shared_infrastructure"]}
    ip_leads = []
    for row in ip_hits:
        addr = row.get("RemoteIP")
        if addr in shared:
            ip_leads.append(row)
            unresolved.append(
                f"{(row.get('Rows') or 0):,} connection(s) to {addr} from "
                f"{(row.get('Devices') or 0)} device(s). This address is shared "
                f"infrastructure "
                f"({next((i['role'] for i in IOC_IPS if i['value'] == addr), 'shared')}), so "
                f"the hit is a lead and not attribution: the same address fronts unrelated "
                f"sites. Resolve it by checking the hostname on those rows, or the device's "
                f"DNS events, before treating it as campaign traffic. URLs seen: "
                f"{row.get('Urls')}")
        else:
            findings.append({
                "id": f"c2-ip-{addr}",
                "what": (f"{(row.get('Rows') or 0):,} connection(s) to {addr} "
                         f"({next((i['role'] for i in IOC_IPS if i['value'] == addr), '')}) "
                         f"from {(row.get('Devices') or 0)} device(s) - a dedicated campaign "
                         f"address, not shared infrastructure"),
                "severity": "critical",
                "evidence": row,
            })

    if cmdline_text:
        coverage.append(
            f"{len(cmdline_text)} command line(s) carry a campaign hostname as TEXT rather "
            f"than as a request - a search or read command, on "
            f"{len({r.get('DeviceName') for r in cmdline_text})} device(s). This hunt's own "
            f"analysis commands are the population: an operator grepping the IOC files "
            f"produces a process row containing the IOC. They are classified rather than "
            f"filtered, and each is listed verbatim in this artifact under "
            f"`command_line_text_references`, because a rule that deleted them would "
            f"eventually delete a real request that happened to mention a search tool.")

    if cmdline_analysis:
        coverage.append(
            f"{len(cmdline_analysis)} command line(s) carrying a campaign hostname are this "
            f"hunt reading or testing its OWN corpus, on "
            f"{len({r.get('DeviceName') for r in cmdline_analysis})} device(s) - the decisive "
            f"evidence is the PATH being worked in, this repository and the analyst tooling "
            f"that reads it, not the tool doing the working. Until 2026-08-11 this collector "
            f"classified on the tool first, so a `python3` heredoc importing this module to "
            f"test this very classifier was reported as a critical C2 contact. That is what "
            f"drove this vector to FINDINGS, and every row was us. Demoted rather than "
            f"deleted: each is written verbatim under `command_line_analysis_references`, the "
            f"class is counted above, and anything unrecognised still defaults to "
            f"egress-capable. Same judgement and same marker list as "
            f"`hunt_antiremediation.py`, which had already demoted 247 rows of this kind on "
            f"the same estate while this collector was reporting five of them as critical.")

    coverage.append(
        f"Campaign infrastructure swept: {len(IOC_DOMAINS)} domain(s) and {len(IOC_IPS)} "
        f"IPv4 address(es) over {lookback} days, against RemoteUrl and against process "
        f"command lines. {len(domain_hits)} host(s) matched on the network table, "
        f"{len(cmdline_hits)} row(s) matched on a command line, {len(ip_hits)} address(es) "
        f"matched. These indicators were published by the advisories and were NOT queried by "
        f"any earlier round of this hunt: r9's only network question was about Bun release "
        f"URLs.")
    coverage.append(
        f"Campaign file hashes swept: "
        f"{sum(1 for h in IOC_HASHES if h['algorithm'] == 'SHA1')} SHA-1 and "
        f"{sum(1 for h in IOC_HASHES if h['algorithm'] == 'SHA256')} SHA-256 value(s) across "
        f"DeviceFileEvents, DeviceProcessEvents and DeviceImageLoadEvents over {lookback} "
        f"days. {len(hash_hits)} row(s) matched. Earlier rounds matched these artifacts by "
        f"FILENAME only, which is a lead; a hash match is a verdict, and a hash zero over a "
        f"populated hash column is a real absence.")
    coverage.append(
        f"Pinned Bun build ({BUN_VERSION}, the version both advisories say the loader "
        f"fetches) searched as a string across process, file and network tables over "
        f"{lookback} days: {len(bun_hits)} row(s).")

    # ---- the coverage gap that bounds the domain result ----
    if blind_platforms:
        blind_names = ", ".join(str(r.get("OSPlatform") or "unknown")
                                for r in blind_platforms)
        blind_devices = sum((r.get("Devices") or 0) for r in blind_platforms)
        blind_netrows = sum((r.get("NetRows") or 0) for r in blind_platforms)
        coverage_gaps.append({
            "gap": "The campaign-domain sweep cannot answer for platforms that record no URL",
            "population": (
                f"{blind_devices:,} device(s) on {blind_names}, carrying {blind_netrows:,} "
                f"network row(s) over {lookback} days with zero of them populating "
                f"RemoteUrl. {len(seeing_platforms)} platform(s) do populate it and are "
                f"covered."),
            "named_by": (
                "the per-platform rows of url_coverage_by_platform in this artifact, and "
                "device by device by the same query grouped by DeviceId rather than "
                "OSPlatform - so the machines this sweep cannot answer for can be listed by "
                "name."),
            "cannot_confirm_or_deny": (
                "whether any of those devices connected to the campaign's C2 or to an "
                "Ethereum RPC endpoint. The command-line sweep partially compensates - it "
                "sees a hostname a process spelled out itself - but it cannot see egress "
                "from a compiled binary or a library call, which is exactly how the stage-2 "
                "payload makes its requests."),
            "closed_by": (
                "enabling Defender Network Protection (audit mode is sufficient) on macOS "
                "and Linux, the same single change that closes the tarball-attribution gap "
                "on the install-activity vector. One configuration change closes two blind "
                "spots on two different vectors."),
            "owner": ("Endpoint security - the team that owns the Defender device "
                      "configuration profiles for macOS and Linux"),
        })

    if hash_blind:
        names = ", ".join(str(r.get("OSPlatform") or "unknown") for r in hash_blind)
        devices = sum((r.get("Devices") or 0) for r in hash_blind)
        coverage_gaps.append({
            "gap": "The campaign-hash sweep cannot answer for platforms that record no hash",
            "population": (
                f"{devices:,} device(s) on {names}: their DeviceFileEvents rows carry neither "
                f"SHA1 nor SHA256 on effectively any row over {lookback} days."),
            "named_by": ("the per-platform rows of hash_coverage_by_platform in this "
                         "artifact, and per-device by the same query grouped by DeviceId"),
            "cannot_confirm_or_deny": (
                "whether a file at a published campaign hash exists on those devices. The "
                "filename sweep still runs there and still returns leads, but a name is not "
                "a verdict - setup.mjs has benign homonyms."),
            "closed_by": (
                "a Microsoft support case establishing whether file hashes can be populated "
                "on that platform at all. If they cannot, the gap is permanent and triage "
                "there rests on path and parent process, which is a documented limitation "
                "rather than a fix."),
            "owner": "Security operations, with Microsoft support",
        })

    # The one thing these tables cannot answer, stated rather than silently skipped.
    unresolved.append(
        f"The advisories name a User-Agent indicator (`Bun/{BUN_VERSION}`). Defender's "
        f"DeviceNetworkEvents does not carry a User-Agent column, so this indicator cannot "
        f"be matched on endpoint telemetry by anyone with any permission - it is a proxy or "
        f"web-gateway question. Not ours to close on this surface: route it to whoever owns "
        f"the outbound web proxy logs, where the field exists.")

    if findings:
        status = FINDINGS
    elif unresolved or not domain_control_ok or not cmdline_control_ok:
        status = INCOMPLETE
    else:
        status = CLEAR

    return {
        "name": "Advisory IOC sweep - campaign infrastructure and file hashes",
        "status": status,
        "as_of": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "scope": (f"All devices reporting to Microsoft Defender, {lookback}-day lookback. "
                  f"Indicators published by Integrity360 and Snyk, neither of which had been "
                  f"queried before this round."),
        "counts": {
            "Hunting queries executed": queries_run,
            "Hunting queries that FAILED to execute": len(queries_failed),
            "Campaign domains swept": len(IOC_DOMAINS),
            "Campaign IPv4 addresses swept": len(IOC_IPS),
            "Campaign file hashes swept": len(IOC_HASHES),
            "Domains matched on the network table": len(domain_hits),
            "Command lines carrying a campaign hostname": len(cmdline_hits),
            # These three sum to the line above them. They are printed even at zero, because
            # the reader has to be able to see that the split was made at all.
            "Of those, on a process that can make a request": len(cmdline_egress),
            "Of those, a search or read command": len(cmdline_text),
            "Of those, this hunt reading or testing its own corpus": len(cmdline_analysis),
            "IP addresses matched": len(ip_hits),
            "IP matches that are shared infrastructure (leads, not findings)": len(ip_leads),
            "File-hash matches": len(hash_hits),
            f"Rows naming the pinned Bun build {BUN_VERSION}": len(bun_hits),
        },
        "coverage": coverage,
        "unresolved_items": unresolved,
        "coverage_gaps": coverage_gaps,
        "access_required": access_required,
        "findings": findings,
        "ip_leads_requiring_hostname_resolution": ip_leads,
        "command_line_text_references": cmdline_text,
        # Verbatim, not counted-and-discarded. This is the artifact a reader opens to
        # disagree with the demotion, so it has to hold the whole row.
        "command_line_analysis_references": cmdline_analysis,
        "indicators": {"domains": IOC_DOMAINS, "ips": IOC_IPS, "hashes": IOC_HASHES,
                       "bun_version": BUN_VERSION},
        "identity": raw.get("identity"),
        "evidence": ev,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--lookback", type=int, default=LOOKBACK_DAYS)
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/advisory_iocs_r1.json")
    args = parser.parse_args()

    raw = collect(args.lookback)
    artifact = build(raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, default=str) + "\n")

    print(f"[advisory-iocs] {artifact['status']} -> {args.out}")
    for line in artifact["counts"].items():
        print(f"  {line[0]}: {line[1]}")
    for item in artifact["unresolved_items"]:
        print(f"  UNREAD: {item[:160]}")
    for gap in artifact["coverage_gaps"]:
        print(f"  GAP: {gap['gap']}")
    for finding in artifact["findings"]:
        print(f"  FINDING: {finding['what']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
