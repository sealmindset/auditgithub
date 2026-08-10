#!/usr/bin/env python3
"""Did anything in this estate install a malicious version, on an endpoint?

Why this is a separate collector from hunt_endpoint_defender.py
--------------------------------------------------------------
That one asks "did the payload execute here" — Bun spawned by node, credential access,
persistence. This one asks the earlier and narrower question: **did a tarball from the
malicious set ever land on a machine.** They fail differently. Execution evidence can be
absent because the dropper never ran; fetch evidence can be absent because nobody
installed anything at all that afternoon. The second is not a clean result, it is an
untested one, so this collector carries its own control.

It is also the corpus's oldest open gap. §9 item 1 has stood as "re-run the moment Graph
credentials are available" — which was never the blocker. `GraphClient.from_db` reads the
encrypted credential store, and `hunt_endpoint_defender.py` proved on 2026-08-07 that the
store holds a working app registration. The check had simply never been written.

The install window is NOT the publish window, and this is the part every earlier scoping
got wrong
---------------------------------------------------------------------------------------
The registry derivation bounds when malicious versions were *published*
(09:35:00.763Z – 13:18:41.376Z, bracket-independent as of round 4). A machine can install
one at any point between its publish and its **unpublish**, and npm's removals ran well
after propagation stopped. The corpus does not hold per-version unpublish timestamps, so
the exposure window has a proven start and an unproven end.

Therefore the query window deliberately runs to the end of 2026-08-04 UTC. That is not
averaging and not widening for its own sake: an install at 16:00Z of a version published
at 11:00Z is exactly as much of an infection as one at 11:01Z, and a window that ends at
the last publish cannot see it.

Matching is done here, not in KQL
---------------------------------
The malicious set is 2,208 specs across 443 names. Embedding those as `has_any` terms
would put the authoritative list inside a query string, where it drifts from
`rederive_window_*.json` the moment either changes. Instead the query returns every npm
tarball fetch in the window and the comparison happens in Python against the derivation
artifact — so the answer is reproducible from two files rather than from a query nobody
re-reads.

Reads only. Nothing is installed and nothing is executed. No GitHub budget is touched.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REPO_ROOT = Path(__file__).resolve().parents[2]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

CLEAR = "CLEAR"
INCOMPLETE = "INCOMPLETE"
FINDINGS = "FINDINGS"

# The exposure window. Start is the first malicious publish, proven at Tier 0. End is the
# end of the UTC day, for the reason in the module docstring: installs remain possible
# until a version is unpublished, and those times are not known.
WINDOW_START = "2026-08-04T09:35:00.763Z"
WINDOW_END = "2026-08-05T00:00:00Z"

# The npm tarball URL shape: registry.npmjs.org/<name>/-/<basename>-<version>.tgz. Scoped
# packages keep the scope in the path, so @keyv/redis fetches as
# registry.npmjs.org/@keyv/redis/-/redis-6.0.0.tgz - which is why the basename cannot be
# used as the package name and the path prefix must be.
TARBALL_RE = re.compile(r"registry\.npmjs\.org/((?:@[^/]+/)?[^/]+)/-/[^/]+-([0-9][^/]*)\.tgz",
                        re.IGNORECASE)

Q_REGISTRY_CONTROL = """
DeviceNetworkEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where RemoteUrl has "registry.npmjs.org" or RemoteUrl has "npmjs.org"
| summarize Rows = count(), Devices = dcount(DeviceId),
            TarballRows = countif(RemoteUrl has "/-/"),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
| limit 5
"""

# Where else a tarball could come from. The first run of this collector found 69 install
# command lines and ZERO tarball URLs in the same window, which is not an absence - it is a
# contradiction, and the likeliest explanation is that this estate does not install from
# registry.npmjs.org at all. An Azure Artifacts or Artifactory feed with npmjs upstream
# serves the same malicious version from a different hostname, and a hunt that only watches
# registry.npmjs.org would call that clean forever.
#
# So this asks the question the other way round: for the devices that demonstrably ran an
# install in the window, what package-registry hosts did they talk to at all?
Q_REGISTRY_HOSTS = """
DeviceNetworkEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where isnotempty(RemoteUrl)
// "nexus" alone was too loose: it matched nexus-websocket-a.intercom.io,
// nexus-gateway-prod.media.yahoo.com, nexus.ensighten.com and three more unrelated hosts,
// padding the host list in the report with traffic that has nothing to do with packages.
// Sonatype Nexus is matched on its repository path and its conventional hostname instead.
| where RemoteUrl has_any ("npmjs", "npm.", "pkgs.dev.azure.com", "pkgs.visualstudio.com",
                           "artifactory", "jfrog", "npm.pkg.github.com",
                           "registry.yarnpkg.com", "verdaccio", "packagecloud",
                           "gitlab.com/api/v4/packages", "codeartifact")
     or RemoteUrl has_any ("/nexus/repository", "/nexus/content", "/repository/npm")
     or RemoteUrl matches regex @"(?i)^(https?://)?nexus(\\.[a-z0-9-]+)*\\.(comfort|sleepnumber)\\."
| extend Host = tostring(split(tostring(split(RemoteUrl, "://")[-1]), "/")[0])
| summarize Rows = count(), Devices = dcount(DeviceId),
            TarballLike = countif(RemoteUrl has "/-/" or RemoteUrl has ".tgz"),
            LastSeen = max(Timestamp) by Host
| order by Rows desc
| limit 100
"""

Q_TARBALL_FETCHES = """
DeviceNetworkEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where RemoteUrl has "registry.npmjs.org"
| where RemoteUrl has "/-/"
| project Timestamp, DeviceName, DeviceId, RemoteUrl, InitiatingProcessFileName,
          InitiatingProcessCommandLine, InitiatingProcessAccountName
| order by Timestamp asc
| limit 10000
"""

# The readability control for the fetch query. A zero for malicious fetches means nothing
# unless somebody was installing packages in that window at all. If this returns nothing,
# the window is untested rather than clean and the whole vector is INCOMPLETE.
Q_INSTALL_PROCESSES = """
DeviceProcessEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where FileName in~ ("npm", "npm.exe", "npm-cli.js", "pnpm", "pnpm.exe",
                      "yarn", "yarn.exe", "bun", "bun.exe", "bunx", "bunx.exe",
                      "node", "node.exe")
| extend IsInstall = ProcessCommandLine has_any ("install", " i ", "add", "ci",
                                                 "update", "upgrade")
| summarize Events = count(), Devices = dcount(DeviceId),
            InstallEvents = countif(IsInstall),
            InstallDevices = dcountif(DeviceId, IsInstall),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
    by FileName
| order by Events desc
| limit 50
"""

# Why the fetch vector is blind, measured rather than guessed. The first version of this
# collector hypothesised a mirror. That was wrong: the Linux runner below reached
# registry.npmjs.org directly, and the row carried the hostname with no path. The tarball
# path can therefore never appear no matter which registry is used, so the question is not
# "which host" but "does RemoteUrl carry a path on the platform that installs". Split by
# OSPlatform because the answer differs by platform and only the installing platforms matter.
Q_URL_COVERAGE = """
DeviceNetworkEvents
| where Timestamp > ago(7d)
| summarize NetRows = count(), UrlRows = countif(isnotempty(RemoteUrl)),
            PathRows = countif(RemoteUrl contains "/"),
            Devices = dcount(DeviceId) by DeviceId
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(7d)
    | summarize arg_max(Timestamp, OSPlatform) by DeviceId
  ) on DeviceId
| summarize NetRows = sum(NetRows), UrlRows = sum(UrlRows), PathRows = sum(PathRows),
            Devices = dcount(DeviceId) by OSPlatform
| order by NetRows desc
| limit 40
"""

# The devices that actually ran an install in the window, each with its own URL coverage and
# platform. This is the join that names the gap: an install on a device whose RemoteUrl is
# never populated cannot be checked for what it downloaded, by anyone, with this table.
Q_INSTALLER_DEVICES = """
let Installers = DeviceProcessEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where FileName in~ ("npm", "npm.exe", "npm-cli.js", "pnpm", "pnpm.exe",
                      "yarn", "yarn.exe", "bun", "bun.exe", "bunx", "bunx.exe",
                      "node", "node.exe")
| where ProcessCommandLine has_any ("install", " i ", "add", "ci", "update", "upgrade")
| summarize InstallCmds = count(), DistinctCmds = dcount(ProcessCommandLine)
    by DeviceId, DeviceName;
Installers
| join kind=leftouter (
    DeviceNetworkEvents
    | where Timestamp between (datetime({start}) .. datetime({end}))
    | summarize NetRows = count(), UrlRows = countif(isnotempty(RemoteUrl)),
                NpmRows = countif(RemoteUrl has "npmjs"),
                TgzRows = countif(RemoteUrl has ".tgz" or RemoteUrl has "/-/") by DeviceId
  ) on DeviceId
| join kind=leftouter (
    DeviceInfo
    | where Timestamp > ago(30d)
    | summarize arg_max(Timestamp, OSPlatform, OSVersion) by DeviceId
  ) on DeviceId
| project DeviceName, OSPlatform, OSVersion, InstallCmds, DistinctCmds,
          NetRows, UrlRows, NpmRows, TgzRows
| order by InstallCmds desc
| limit 200
"""

# The install command lines themselves, verbatim. Needed because the aggregate count says
# nothing about whether these were project dependency installs (which resolve a lockfile and
# could pull a campaign spec) or global tool installs (which cannot).
Q_INSTALL_COMMANDS = """
DeviceProcessEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where FileName in~ ("npm", "npm.exe", "npm-cli.js", "pnpm", "pnpm.exe",
                      "yarn", "yarn.exe", "bun", "bun.exe", "bunx", "bunx.exe",
                      "node", "node.exe")
| where ProcessCommandLine has_any ("install", " i ", "add", "ci", "update", "upgrade")
| summarize Rows = count(), Devices = dcount(DeviceId), FirstSeen = min(Timestamp),
            LastSeen = max(Timestamp) by ProcessCommandLine
| order by Rows desc
| limit 100
"""

# The worm's own execution vector: a lifecycle script running out of an install. Matched by
# the generic hook names rather than the IOC names, because the point is to establish whether
# ANY postinstall script executed on an endpoint in the window - if none did, the lifecycle
# path is untested here; if some did, each needs attributing to a package.
#
# Split into an aggregate and a detail query on purpose. A single detail query with a row
# limit would have answered "how many campaign-named hooks ran" from whichever 1,000 rows
# came back first chronologically — so a campaign hook late in the window would have been
# truncated away and reported as absent. The aggregate has no row limit and therefore
# genuinely counts; the detail query filters to the campaign names only, so it cannot
# overflow.
Q_HOOK_CONTROL = """
DeviceProcessEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where ProcessCommandLine has_any ("install.cjs", "install.js", "postinstall",
                                    "preinstall", "setup.mjs", "bun_environment",
                                    "setup_bun", "math_init", "Math_Symbol",
                                    "router_runtime")
| summarize Rows = count(), Devices = dcount(DeviceId),
            IocRows = countif(ProcessCommandLine has_any ("setup.mjs", "bun_environment",
                                                          "setup_bun", "math_init",
                                                          "Math_Symbol", "router_runtime")),
            IocDevices = dcountif(DeviceId,
                                  ProcessCommandLine has_any ("setup.mjs", "bun_environment",
                                                              "setup_bun", "math_init",
                                                              "Math_Symbol",
                                                              "router_runtime")),
            FirstSeen = min(Timestamp), LastSeen = max(Timestamp)
"""

Q_POSTINSTALL_HOOKS = """
DeviceProcessEvents
| where Timestamp between (datetime({start}) .. datetime({end}))
| where ProcessCommandLine has_any ("setup.mjs", "bun_environment", "setup_bun",
                                    "math_init", "Math_Symbol", "router_runtime")
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine, AccountName
| order by Timestamp asc
| limit 1000
"""

# Dropped files, over 30 days rather than the window: a tarball fetched in the window
# leaves these on disk afterwards, and the file survives the fetch record's retention.
# setup.mjs and Math_Symbol.js both have benign homonyms, so hashes are returned for
# comparison rather than the names being treated as verdicts.
Q_DROPPED_FILES = """
DeviceFileEvents
| where Timestamp > ago(30d)
| where ActionType in~ ("FileCreated", "FileModified", "FileRenamed")
| where FileName in~ ("setup.mjs", "math_init.js", "Math_Symbol.js", "router_runtime.js")
| project Timestamp, DeviceName, DeviceId, FileName, FolderPath, SHA256, SHA1,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| limit 1000
"""


def parse_ts(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)


def load_derivation(path: Path) -> Tuple[set, set, dict]:
    """Malicious specs and names from the derivation artifact — the authoritative list."""
    data = json.loads(path.read_text())
    specs = set(data.get("malicious_specs") or [])
    suspected = set(data.get("suspected_uncleaned_specs") or [])
    names = {s.rpartition("@")[0] for s in specs if s.rpartition("@")[0]}
    return specs, suspected | specs, {
        "artifact": str(path.relative_to(REPO_ROOT)),
        "malicious_specs": len(specs),
        "suspected_uncleaned_specs": len(suspected),
        "distinct_malicious_names": len(names),
        "bound_summary": data.get("_bound_summary"),
    }


def collect(start: str, end: str) -> Dict[str, Any]:
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

    fmt = {"start": start, "end": end}
    return {
        "identity": identity,
        "window": {"start": start, "end": end},
        "evidence": {
            # §0.1: control first, and it gates everything under it.
            "registry_traffic_control": hunt(Q_REGISTRY_CONTROL.format(**fmt)),
            "registry_hosts_in_window": hunt(Q_REGISTRY_HOSTS.format(**fmt)),
            "install_process_control": hunt(Q_INSTALL_PROCESSES.format(**fmt)),
            "install_commands": hunt(Q_INSTALL_COMMANDS.format(**fmt)),
            "installer_devices": hunt(Q_INSTALLER_DEVICES.format(**fmt)),
            "url_coverage_by_platform": hunt(Q_URL_COVERAGE),
            "lifecycle_hook_control": hunt(Q_HOOK_CONTROL.format(**fmt)),
            "postinstall_hooks": hunt(Q_POSTINSTALL_HOOKS.format(**fmt)),
            "tarball_fetches": hunt(Q_TARBALL_FETCHES.format(**fmt)),
            "dropped_files_30d": hunt(Q_DROPPED_FILES),
        },
    }


def interpret(raw: Dict[str, Any], specs: set, all_specs: set,
              derivation: dict, known_hashes: Dict[str, str]) -> Dict[str, Any]:
    ev = raw["evidence"]
    control = ev["registry_traffic_control"]
    proc = ev["install_process_control"]
    fetches = ev["tarball_fetches"]
    dropped = ev["dropped_files_30d"]

    control_row = (control.get("rows") or [{}])[0]
    registry_rows = control_row.get("Rows") or 0
    tarball_rows_counted = control_row.get("TarballRows") or 0
    install_events = sum((r.get("InstallEvents") or 0) for r in (proc.get("rows") or []))
    install_devices = max([(r.get("InstallDevices") or 0)
                           for r in (proc.get("rows") or [])] or [0])

    # Parse every fetch and decide it against the derivation, exactly.
    matched_specs: List[dict] = []
    matched_names_other_version: List[dict] = []
    parsed = 0
    unparsed: List[str] = []
    for row in fetches.get("rows") or []:
        url = row.get("RemoteUrl") or ""
        m = TARBALL_RE.search(url)
        if not m:
            unparsed.append(url)
            continue
        parsed += 1
        name, version = m.group(1), m.group(2)
        spec = f"{name}@{version}"
        record = {**row, "package": name, "version": version, "spec": spec}
        if spec in all_specs:
            record["axis"] = ("malicious" if spec in specs
                              else "suspected_uncleaned_pending_hash")
            matched_specs.append(record)
        elif name in {s.rpartition("@")[0] for s in all_specs}:
            # A campaign package at a version the derivation does not call malicious. Not
            # an infection, and worth stating: it proves this estate consumes the package,
            # so the version boundary is the only thing that kept it clean.
            matched_names_other_version.append(record)

    # Dropped files: name alone is not a verdict. A known hash is.
    dropped_rows = dropped.get("rows") or []
    hash_confirmed = [r for r in dropped_rows
                      if (r.get("SHA256") or "").lower() in known_hashes]
    name_only = [r for r in dropped_rows if r not in hash_confirmed]

    findings: List[dict] = []
    for row in matched_specs:
        findings.append({
            "id": f"INSTALL-{row.get('DeviceName', 'unknown')}-{row['spec']}",
            "what": (f"{row['spec']} fetched from registry.npmjs.org on "
                     f"{row.get('DeviceName')} at {row.get('Timestamp')} — this spec is in "
                     f"the derived {row['axis']} set"),
            "evidence": row,
        })
    for row in hash_confirmed:
        findings.append({
            "id": f"DROPPER-{row.get('DeviceName', 'unknown')}",
            "what": (f"{row.get('FileName')} written to {row.get('FolderPath')} on "
                     f"{row.get('DeviceName')} at a KNOWN CAMPAIGN HASH "
                     f"({known_hashes[(row.get('SHA256') or '').lower()]})"),
            "evidence": row,
        })

    unresolved: List[str] = []
    coverage_gaps: List[dict] = []

    # The two ways this vector can be unreadable, kept apart because they are closed by
    # different work.
    if not control.get("ok") or not registry_rows:
        unresolved.append(
            "No DeviceNetworkEvents rows to registry.npmjs.org in the window"
            + (f" (query error: {control.get('error')})" if not control.get("ok") else "")
            + ". The fetch result is therefore untested, not clean: npm traffic is either "
              "not resolved to a URL on these devices, proxied under another hostname, or "
              "outside retention. Ours to close by establishing how npm egress appears in "
              "this tenant before the fetch zero is reported either way.")
    # The decisive control, and the one the first run of this collector got wrong. It
    # reported CLEAR on 14 npmjs.org rows while the tarball count was zero and 69 install
    # command lines had run in the same window. Installs happening with no tarball URL
    # anywhere is a contradiction, not an absence: it means package fetches are invisible
    # on this table, most likely because the estate installs from a mirror. A zero matched
    # against a set of 2,208 specs is worthless if no fetch was ever observable.
    hosts = ev.get("registry_hosts_in_window") or {"ok": False, "rows": []}
    host_rows = hosts.get("rows") or []
    tarball_like_hosts = [r for r in host_rows if (r.get("TarballLike") or 0) > 0]

    # The installing devices, each with its own URL coverage. This is what turns the
    # contradiction from a hypothesis into a named, closable gap.
    installer_rows = (ev.get("installer_devices") or {}).get("rows") or []
    blind_installers = [r for r in installer_rows if not (r.get("UrlRows") or 0)]
    seeing_installers = [r for r in installer_rows if (r.get("UrlRows") or 0)]
    blind_platforms = sorted({(r.get("OSPlatform") or "unknown") for r in blind_installers})
    blind_cmds = sum((r.get("InstallCmds") or 0) for r in blind_installers)

    if install_events and not tarball_rows_counted:
        named = ", ".join(
            f"{r.get('Host')} ({(r.get('Rows') or 0):,} rows, "
            f"{(r.get('TarballLike') or 0):,} tarball-like)"
            for r in host_rows[:10]) or "no package-registry host at all"
        # Two distinct causes, and the device-level join tells them apart. Naming the wrong
        # one sends somebody to configure a mirror allowlist that would change nothing.
        cause = ""
        if blind_installers:
            cause = (
                f" Cause, measured rather than inferred: {len(blind_installers)} of "
                f"{len(installer_rows)} installing device(s) "
                f"({', '.join(blind_platforms)}, {blind_cmds:,} of {install_events:,} install "
                f"command lines) produced DeviceNetworkEvents rows in the window with "
                f"RemoteUrl empty on every one, so no URL - malicious or benign - could have "
                f"been recorded for the traffic those installs generated.")
        if seeing_installers:
            cause += (
                f" On the {len(seeing_installers)} device(s) that do populate RemoteUrl, the "
                f"npmjs rows carry the hostname with no path, so the "
                f"'<name>/-/<name>-<version>.tgz' segment this check matches on cannot appear "
                f"there either. A mirror is therefore NOT the explanation: the connection to "
                f"the registry was recorded, only the path was not.")
        unresolved.append(
            f"CONTRADICTION, not a clean result: {install_events:,} package-manager install "
            f"command line(s) ran in the window and DeviceNetworkEvents recorded "
            f"{tarball_rows_counted:,} tarball fetches. Package downloads are therefore not "
            f"observable on this table, so matching against "
            f"{derivation['malicious_specs']:,} specs could not have found anything and this "
            f"vector must not be read as clean. Package-registry hosts actually seen in the "
            f"window: {named}.{cause} Ours to close, and it is a configuration change rather "
            f"than an access request: enable Defender Network Protection in block or audit "
            f"mode on macOS and Linux, which is the feature that populates RemoteUrl with a "
            f"full URL on those platforms. Until then, per-package install attribution on "
            f"endpoints is unavailable and the lockfile and Actions vectors carry this "
            f"question alone.")
        coverage_gaps.append({
            "gap": "DeviceNetworkEvents.RemoteUrl carries no path on the platforms that "
                   "install npm packages, so tarball-level install attribution is "
                   "impossible on endpoints",
            "measured": {
                "installing_devices": len(installer_rows),
                "devices_with_no_url_rows": len(blind_installers),
                "blind_platforms": blind_platforms,
                "install_command_lines_on_blind_devices": blind_cmds,
                "install_command_lines_total": install_events,
            },
            "closes_it": "Enable Defender Network Protection (audit mode is sufficient) on "
                         "macOS and Linux endpoints. Not a permission gap - "
                         "ThreatHunting.Read.All already returns these tables; the column is "
                         "empty at the source.",
        })
    if not install_events:
        unresolved.append(
            "No package-manager install command line ran on any onboarded device inside "
            f"the window {raw['window']['start']} .. {raw['window']['end']}. A zero for "
            "malicious fetches is then trivially true and says nothing about exposure — "
            "the window is untested. Ours to close by widening the process filter or "
            "confirming that installs in this estate happen on CI runners rather than "
            "endpoints, which moves the question to the Actions vector.")
    if unparsed:
        unresolved.append(
            f"{len(unparsed):,} registry URL(s) matched the tarball filter but not the "
            f"name/version pattern, so they were neither matched nor cleared. Example: "
            f"{unparsed[0][:160]}")
    if tarball_rows_counted > len(fetches.get("rows") or []):
        unresolved.append(
            f"The control counted {tarball_rows_counted:,} tarball rows but the fetch "
            f"query returned {len(fetches.get('rows') or []):,} — the 10,000-row limit "
            f"truncated the result, so the comparison ran on a sample and a zero is a "
            f"floor rather than an absence.")

    # The lifecycle-script path. This is the worm's own execution vector, so an execution here
    # is not a finding by itself - install.js is how thousands of legitimate packages build a
    # native module - but it is the population that has to be attributed before the endpoint
    # vector can be closed, and nothing in this corpus had ever counted it.
    hook_ctl = ((ev.get("lifecycle_hook_control") or {}).get("rows") or [{}])[0]
    hook_total = hook_ctl.get("Rows") or 0
    hook_devices = hook_ctl.get("Devices") or 0
    hook_ioc_count = hook_ctl.get("IocRows") or 0
    hooks = ev.get("postinstall_hooks") or {"ok": False, "rows": []}
    ioc_named = hooks.get("rows") or []
    for row in ioc_named:
        findings.append({
            "id": f"HOOK-{row.get('DeviceName', 'unknown')}-{row.get('Timestamp')}",
            "what": (f"lifecycle script matching a campaign artifact name executed on "
                     f"{row.get('DeviceName')} at {row.get('Timestamp')}: "
                     f"{(row.get('ProcessCommandLine') or '')[:200]}"),
            "evidence": row,
        })
    if hook_total and not ioc_named:
        unresolved.append(
            f"{hook_total:,} lifecycle-script execution(s) ran on "
            f"{hook_devices:,} device(s) in the window "
            f"(install.js / install.cjs and similar), none carrying a campaign artifact name. "
            f"None can be attributed to a package: DeviceProcessEvents records the command "
            f"line 'node install.cjs' and the parent shell, but not the working directory, so "
            f"the node_modules path that would name the package is absent. These executions "
            f"are the lifecycle vector this worm uses, and they are neither cleared nor "
            f"implicated. Ours to close by reading InitiatingProcessFolderPath against a "
            f"package manifest on the named devices, which is host-side work rather than a "
            f"query.")

    status = FINDINGS if findings else (INCOMPLETE if unresolved else CLEAR)

    coverage: List[str] = []
    coverage.append(
        f"Registry-traffic control: {registry_rows:,} DeviceNetworkEvents row(s) to "
        f"npmjs.org from {control_row.get('Devices') or 0:,} device(s) inside the window, "
        f"{tarball_rows_counted:,} of them tarball fetches "
        f"({control_row.get('FirstSeen')} .. {control_row.get('LastSeen')}). Without this "
        f"the fetch result below would be unreadable."
        if registry_rows else
        "REGISTRY-TRAFFIC CONTROL RETURNED NOTHING. Every fetch number below is "
        "uninterpretable and none of it should be read as clean.")
    coverage.append(
        f"Install-activity control: {install_events:,} package-manager command line(s) "
        f"carrying an install verb, on {install_devices:,} device(s), inside the window. "
        f"This is what makes a malicious-fetch zero a measured absence rather than an "
        f"untested window.")
    if installer_rows:
        coverage.append(
            "Installing devices, with the URL coverage of each — the join that decides "
            "whether any of these installs could have been attributed to a package: "
            + "; ".join(f"{r.get('DeviceName')} ({r.get('OSPlatform')} "
                        f"{r.get('OSVersion')}) {(r.get('InstallCmds') or 0):,} install "
                        f"cmd(s), {(r.get('NetRows') or 0):,} network row(s), "
                        f"{(r.get('UrlRows') or 0):,} with a URL, "
                        f"{(r.get('TgzRows') or 0):,} tarball-shaped"
                        for r in installer_rows[:20]))
    plat_rows = (ev.get("url_coverage_by_platform") or {}).get("rows") or []
    if plat_rows:
        coverage.append(
            "RemoteUrl population by platform over 7 days, which is the general form of the "
            "same limit: "
            + "; ".join(f"{r.get('OSPlatform') or 'unknown'} "
                        f"{(r.get('Devices') or 0):,} device(s), "
                        f"{(r.get('NetRows') or 0):,} row(s), "
                        f"{(r.get('UrlRows') or 0):,} with a URL, "
                        f"{(r.get('PathRows') or 0):,} with a path"
                        for r in plat_rows[:10]))
    # Self-hosted runners surfacing in endpoint telemetry: the two vectors are the same
    # machines, which changes what the Actions leg has to cover.
    runner_rows = [r for r in ((ev.get("install_commands") or {}).get("rows") or [])
                   if "hostedtoolcache" in (r.get("ProcessCommandLine") or "")
                   or "actions-runner" in (r.get("ProcessCommandLine") or "")]
    if runner_rows:
        coverage.append(
            f"{sum((r.get('Rows') or 0) for r in runner_rows):,} of the install command "
            f"line(s) ran from a self-hosted GitHub Actions runner toolcache path, so part of "
            f"this estate's CI executes on onboarded endpoints. Those devices are covered by "
            f"both this vector and the Actions posture sweep; a runner that installs a "
            f"campaign spec would appear here as an endpoint, which is why the two results "
            f"must not be added together as if they were separate populations.")
    if hook_total:
        coverage.append(
            f"Lifecycle-script control: {hook_total:,} execution(s) of an install-time script "
            f"on {hook_devices:,} device(s) in the window "
            f"({hook_ctl.get('FirstSeen')} .. {hook_ctl.get('LastSeen')}), "
            f"{hook_ioc_count:,} of them carrying a campaign artifact name. Counted by "
            f"aggregation rather than by reading rows, so the campaign-name figure is a count "
            f"over the whole window and not over a truncated sample. A zero for campaign "
            f"names is only meaningful because the total is non-zero — that is what proves "
            f"the table records lifecycle scripts at all.")
    coverage.append(
        f"Window {raw['window']['start']} .. {raw['window']['end']}, which deliberately "
        f"runs past the last malicious publish (13:18:41.376Z). A version stays installable "
        f"until it is unpublished, those removal times are not in this corpus, so an "
        f"install-side window bounded by the publish tail would be too narrow by an unknown "
        f"amount.")
    coverage.append(
        f"Matched against {derivation['malicious_specs']:,} malicious specs and "
        f"{derivation['suspected_uncleaned_specs']:,} suspected-uncleaned specs across "
        f"{derivation['distinct_malicious_names']:,} package names, read from "
        f"{derivation['artifact']} rather than embedded in the query.")
    if host_rows:
        coverage.append(
            "Package-registry hosts contacted in the window, which is what decides whether "
            "a fetch was observable at all: "
            + "; ".join(f"{r.get('Host')} {(r.get('Rows') or 0):,} row(s) from "
                        f"{(r.get('Devices') or 0):,} device(s), "
                        f"{(r.get('TarballLike') or 0):,} tarball-like"
                        for r in host_rows[:10])
            + (f". {len(tarball_like_hosts)} of {len(host_rows)} host(s) carried a "
               f"tarball-shaped URL." if host_rows else ""))
    coverage.append(
        f"{parsed:,} tarball fetch(es) parsed to a name and version and compared "
        f"individually. {len(matched_specs):,} matched the campaign set; "
        f"{len(matched_names_other_version):,} were campaign PACKAGES at non-malicious "
        f"versions.")
    if matched_names_other_version:
        sample = sorted({r["spec"] for r in matched_names_other_version})[:12]
        coverage.append(
            "This estate does consume packages from the campaign set, at versions the "
            "derivation does not call malicious: " + ", ".join(sample)
            + (" …" if len(matched_names_other_version) > 12 else "")
            + ". The version boundary is the only thing separating those from an infection, "
              "which is the argument for a release-age gate rather than a name blocklist.")
    coverage.append(
        f"Dropped-file sweep over 30 days: {len(dropped_rows):,} write(s) of setup.mjs, "
        f"math_init.js, Math_Symbol.js or router_runtime.js. {len(hash_confirmed):,} "
        f"matched a known campaign hash; the other {len(name_only):,} are name-only and "
        f"are leads, not findings — setup.mjs and Math_Symbol.js both have benign homonyms."
        if dropped_rows else
        "Dropped-file sweep over 30 days: no write of setup.mjs, math_init.js, "
        "Math_Symbol.js or router_runtime.js anywhere in the estate.")

    return {
        "name": "Endpoint install activity (Microsoft Defender)",
        "status": status,
        "as_of": datetime.now(timezone.utc).isoformat(),
        "scope": f"onboarded devices, window {raw['window']['start']} .. "
                 f"{raw['window']['end']}, 4 advanced-hunting queries",
        "counts": {
            "registry_rows_in_window": registry_rows,
            "tarball_rows_per_control": tarball_rows_counted,
            "tarball_fetches_returned": len(fetches.get("rows") or []),
            "tarball_fetches_parsed": parsed,
            "install_command_lines": install_events,
            "malicious_or_suspected_specs_fetched": len(matched_specs),
            "campaign_packages_at_clean_versions": len(matched_names_other_version),
            "dropped_file_writes_30d": len(dropped_rows),
            "dropped_files_at_known_hash": len(hash_confirmed),
        },
        "coverage": coverage,
        "unresolved_items": unresolved,
        "coverage_gaps": coverage_gaps,
        "access_required": [],
        "findings": findings,
        "campaign_packages_at_clean_versions": matched_names_other_version[:200],
        "dropped_file_leads_name_only": name_only[:200],
        "derivation": derivation,
        "identity": raw["identity"],
        "evidence": ev,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--derivation", type=Path,
                        default=REPO_ROOT / "exports/hunt/rederive_window_18z.json")
    parser.add_argument("--window-start", default=WINDOW_START)
    parser.add_argument("--window-end", default=WINDOW_END)
    parser.add_argument("--out", type=Path,
                        default=REPO_ROOT / "exports/hunt/install_activity_r1.json")
    args = parser.parse_args()

    if not args.derivation.exists():
        print(f"derivation artifact not found: {args.derivation}", file=sys.stderr)
        return 2
    specs, all_specs, derivation = load_derivation(args.derivation)
    if not specs:
        print("refusing to run: the derivation artifact holds no malicious specs",
              file=sys.stderr)
        return 2

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from verify_live_tarballs import load_known_hashes  # noqa: E402
    known_hashes = load_known_hashes()

    raw = collect(args.window_start, args.window_end)
    result = interpret(raw, specs, all_specs, derivation, known_hashes)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2, default=str))
    print(f"{result['status']}  ->  {args.out}")
    for line in result["coverage"]:
        print(f"  . {line}")
    for item in result["unresolved_items"]:
        print(f"  ! {item}")
    for finding in result["findings"]:
        print(f"  *** {finding['id']}: {finding['what']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
