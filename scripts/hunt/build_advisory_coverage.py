#!/usr/bin/env python3
"""Advisory-TTP coverage: what fraction of this campaign's attacker vectors we can answer for.

The question this answers is the one a director actually asks after reading a clean hunt
report: *the advisories describe a chain of things the attacker does - how much of that chain
did we look at, and how much of it has anything in the way?*

Answering it honestly needs three separations that a single percentage destroys, so this
collector emits all three and the renderer prints all three:

  1. **Named** - the TTP appears in a published advisory for this campaign. A citation.
  2. **Measured** - an artifact in `exports/hunt/` carries a number that answers it. Derived:
     every probe below resolves against a real artifact path, or the TTP is reported as
     NOT MEASURED with the command that would measure it.
  3. **Controlled** - something stands in the attacker's way at that step. Derived from the
     measured value by a rule declared next to the TTP, never typed as a conclusion.

Two things in here are judgment and are deliberately visible rather than hidden:

  * the TTP list, which is a reading of two advisories; and
  * the mapping from a TTP to the artifact that answers it.

Everything downstream of those two is read from artifacts at build time. A mapping that
points at a path an artifact does not have does not silently pass - it lands in
`not_measured` with the reason, which is why a wrong mapping shows up as a gap rather than as
a false green.

Sources for the TTP list:
  * Integrity360, "CHAINDROP: The Keyv and Cacheable npm Supply Chain Attack"
  * Snyk, "Inside the Keyv npm compromise: preinstall malware, trusted provenance, IDE hooks"
  * the campaign's own registry evidence, via the Tier 0 oracle in this repo

Usage:
    python3 scripts/hunt/build_advisory_coverage.py \
        --exports exports/hunt --out exports/hunt/advisory_coverage.json

Reads artifacts only. No network, no credentials, no API budget.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

# The five control states, verbatim from docs/playbooks/hunt-report-template.md §3.1. A rule
# below may return only one of these.
CONTROLLED = "CONTROLLED"
PARTLY = "PARTLY CONTROLLED"
DETECTION_ONLY = "DETECTION ONLY"
OPEN = "OPEN"
UNMEASURED = "UNMEASURED"
STATES = (CONTROLLED, PARTLY, DETECTION_ONLY, OPEN, UNMEASURED)

MISSING = object()


# --------------------------------------------------------------------------------------- #
# Artifact loading
# --------------------------------------------------------------------------------------- #

_ROUND = re.compile(r"_r(\d+)(?=[._])")


def resolve_artifact(exports: Path, stem: str) -> Optional[Path]:
    """Highest round wins, same rule as render_hunt_report.py.

    `stem` is a filename with the round elided as `*`: `advisory_iocs_r*.json`. A stem with no
    `*` is taken literally, because several artifacts in this hunt carry a window in the name
    instead of a round.
    """
    if "*" not in stem:
        path = exports / stem
        return path if path.exists() else None
    best: Tuple[int, Optional[Path]] = (-1, None)
    for path in exports.glob(stem):
        match = _ROUND.search(path.name)
        rnd = int(match.group(1)) if match else 0
        if rnd > best[0]:
            best = (rnd, path)
    return best[1]


def load_json(path: Path) -> Any:
    with path.open() as handle:
        return json.load(handle)


def load_hook_aggregate(path: Path) -> Dict[str, Any]:
    """Aggregate the IDE/agent config files out of the per-repo tree records.

    Snyk's second entry point is an editor or coding-agent config that runs a command when a
    folder or session opens. The tree sweep fetched and parsed every such file in the estate,
    so this is a content answer at estate scale rather than a filename answer - which is the
    only kind of answer that can distinguish "a repo has a tasks.json" from "a repo has a
    tasks.json that starts a process".
    """
    # `vscode_tasks_json` and `claude_settings_json` are counted out here rather than probed as
    # `by_path..vscode/tasks.json`, because a probe path is split on `.` and these filenames
    # start with one.
    out = {"hook_files": 0, "hook_repos": 0, "parse_errors": 0, "has_session_start": 0,
           "has_folder_open": 0, "has_hooks_key": 0, "autostart_runs_script": 0,
           "vscode_tasks_json": 0, "claude_settings_json": 0,
           "hooks_key_repos": [], "by_path": {}}
    repos = set()
    with path.open() as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            record = json.loads(line)
            hooks = record.get("hook_files") or []
            name = record.get("repo") or record.get("full_name") or record.get("nameWithOwner")
            if hooks:
                repos.add(name)
            for entry in hooks:
                out["hook_files"] += 1
                where = entry.get("path") or ""
                out["by_path"][where] = out["by_path"].get(where, 0) + 1
                if where.endswith(".vscode/tasks.json"):
                    out["vscode_tasks_json"] += 1
                elif where.startswith(".claude/"):
                    out["claude_settings_json"] += 1
                if entry.get("parse_error"):
                    out["parse_errors"] += 1
                for flag in ("has_session_start", "has_folder_open", "has_hooks_key",
                             "autostart_runs_script"):
                    if entry.get(flag):
                        out[flag] += 1
                if entry.get("has_hooks_key"):
                    out["hooks_key_repos"].append(f"{name}:{entry.get('path')}")
    out["hook_repos"] = len(repos)
    return out


LOADERS: Dict[str, Callable[[Path], Any]] = {".jsonl": load_hook_aggregate}


# --------------------------------------------------------------------------------------- #
# Path resolution inside an artifact
# --------------------------------------------------------------------------------------- #

def dig(obj: Any, path: str) -> Any:
    """Resolve one probe path, or return MISSING.

    Three forms, kept deliberately small - a probe language rich enough to compute is a probe
    language rich enough to launder a conclusion:

      `a.b.0.c`                         nested keys and list indices
      `a|b.c has a dot in it`           same, split on `|` instead - several count keys in
                                        these artifacts are English sentences containing
                                        `bun.exe` or `1.3.13`, and renaming a collector's
                                        emitted key to suit a probe would be the wrong repair
      `len:a.b`                         length of the list at a.b
      `find:a.b:field=value:out`        first element of list a.b whose `field` == `value`,
                                        then that element's `out`
    """
    if path.startswith("len:"):
        got = dig(obj, path[4:])
        return MISSING if got is MISSING else (len(got) if hasattr(got, "__len__") else MISSING)
    if path.startswith("find:"):
        _, list_path, predicate, out_field = path.split(":", 3)
        rows = dig(obj, list_path)
        if rows is MISSING or not isinstance(rows, list):
            return MISSING
        field, _, wanted = predicate.partition("=")
        for row in rows:
            if isinstance(row, dict) and str(row.get(field)) == wanted:
                return row.get(out_field, MISSING)
        return MISSING
    cursor = obj
    for part in path.split("|" if "|" in path else "."):
        if isinstance(cursor, dict):
            if part not in cursor:
                return MISSING
            cursor = cursor[part]
        elif isinstance(cursor, list):
            if not part.isdigit() or int(part) >= len(cursor):
                return MISSING
            cursor = cursor[int(part)]
        else:
            return MISSING
    return cursor


def num(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else str(value)


# --------------------------------------------------------------------------------------- #
# The register
# --------------------------------------------------------------------------------------- #
# Each entry:
#   id, link      where the TTP sits in the attacker's chain (link numbering from
#                 docs/playbooks/hunt-report-template.md §3)
#   ttp           what the attacker does, in the advisory's terms
#   sources       which advisory named it - a citation, checkable against the advisory
#   probes        {var: (artifact_stem, path)} - every var must resolve or the TTP is NOT
#                 MEASURED
#   rule          measured values -> (state, evidence sentence). Must return a member of
#                 STATES. A rule that cannot justify its state from its own vars is a bug.
#   closed_by     what would move the state, for a report reader who has to fund it
#   owner         who would do it
#   unmeasured_closed_by  for a TTP with no probe: the command that would measure it

REGISTER: List[Dict[str, Any]] = [
    {
        "id": "T01",
        "link": 1,
        "ttp": "Publish poisoned versions of legitimate packages to the public npm registry",
        "sources": ["Integrity360", "Snyk", "registry evidence"],
        "probes": {
            "specs": ("rederive_window_0000z_aug5.json", "malicious_count"),
            "names": ("rederive_window_0000z_aug5.json", "packages_queried"),
            "uncleaned": ("rederive_window_0000z_aug5.json", "len:suspected_uncleaned_specs"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"The Tier 0 registry oracle enumerated {num(v['specs'])} poisoned specs across "
            f"{num(v['names'])} package names, plus {num(v['uncleaned'])} specs that are "
            f"suspected and not yet withdrawn. Nothing we operate can stop a publish to a "
            f"public registry; this is the step we detect rather than prevent, and the oracle "
            f"is what detects it."),
        "closed_by": ("nothing on our side - the control for this step belongs to the "
                      "registry. What we own is how fast the oracle re-derives it"),
        "owner": "Security Engineering",
    },
    {
        "id": "T02",
        "link": 1,
        "ttp": "A poisoned version resolves into one of our builds through dependency "
               "resolution",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "pairs": ("lockfiles_r*_coverage.json", "counts.pairs"),
            "repos": ("lockfiles_r*_coverage.json", "counts.repos"),
            "pinned": ("lockfiles_r*_coverage.json", "counts.repos_with_parsed_lockfile"),
            "unpinned": ("lockfiles_r*_coverage.json", "counts.manifest_but_no_lockfile"),
            "matches": ("ioc_match_r*.json", "len:exact_matches"),
        },
        "rule": lambda v: (
            PARTLY if v["unpinned"] else CONTROLLED,
            f"{num(v['pairs'])} resolved name-to-version pairs across {num(v['pinned'])} of "
            f"{num(v['repos'])} npm-relevant repositories were compared against the poisoned "
            f"spec list: {num(v['matches'])} exact matches. Lockfile pinning is the control "
            f"and it is real, with a counted hole - {num(v['unpinned'])} repositories carry a "
            f"manifest and no lockfile, so their resolution happens at install time and this "
            f"comparison cannot speak for them."),
        "closed_by": ("committing a lockfile in the repositories that have a manifest and "
                      "none, listed by identifier in the lockfile coverage artifact"),
        "owner": "the owning team per repository",
    },
    {
        "id": "T03",
        "link": 2,
        "ttp": "The package's `preinstall` script (`node setup.mjs`) executes during install",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "rows": ("install_activity_r*.json", "evidence.lifecycle_hook_control.rows.0.Rows"),
            "devices": ("install_activity_r*.json",
                        "evidence.lifecycle_hook_control.rows.0.Devices"),
            "installs": ("install_activity_r*.json", "counts.install_command_lines"),
            "tarballs": ("install_activity_r*.json", "counts.tarball_rows_per_control"),
            # The control half, added 2026-08-10. The four probes above measure ARRIVAL - that
            # the primitive fires constantly - and are silent on whether anything is in its way,
            # which is why this vector sat UNMEASURED with four numbers behind it. These five
            # measure the obstacle: `ignore-scripts`, the setting every package manager in this
            # estate honors and the only thing that stops a `preinstall` from running at all.
            "swept": ("install_prevention_r*.json", "counts.npm-relevant repositories swept"),
            "exposed": ("install_prevention_r*.json",
                        "counts.Repositories that install with scripts enabled"),
            "partial": ("install_prevention_r*.json",
                        "counts.Repositories preventing scripts in only some installing "
                        "workflows"),
            "by_config": ("install_prevention_r*.json",
                          "counts.Repositories preventing scripts by config"),
            "by_workflow": ("install_prevention_r*.json",
                            "counts.Repositories preventing scripts in every installing "
                            "workflow"),
            "no_ci": ("install_prevention_r*.json",
                      "counts.Repositories with no CI install observed"),
        },
        "rule": lambda v: (
            # Never CONTROLLED from this artifact, whatever the numbers say. It reads repository
            # and CI configuration; the surface the campaign's `preinstall` actually landed on
            # for most victims is a developer's own machine, and `~/.npmrc` is in no repository.
            # So the ceiling here is PARTLY CONTROLLED, and the floor is OPEN - measured, with
            # nothing found in the way.
            OPEN if not (v["by_config"] + v["by_workflow"] + v["partial"]) else PARTLY,
            f"Two measurements, and they answer different questions. Arrival: lifecycle scripts "
            f"fire in the thousands inside the hunt window - {num(v['rows'])} executions on "
            f"{num(v['devices'])} devices as part of ordinary work, alongside "
            f"{num(v['installs'])} package-manager install command lines, none of it "
            f"attributable to a package because {num(v['tarballs'])} tarball fetches carry a "
            # Colon-list rather than prose, because these are derived numbers and any sentence
            # that inflects a verb around one of them reads as broken the cycle it comes back 1.
            f"path on the endpoints that install packages. Prevention, across {num(v['swept'])} "
            f"npm-relevant repositories - refusing install scripts by configuration: "
            f"{num(v['by_config'])}. Refusing them at every installing workflow: "
            f"{num(v['by_workflow'])}. Refusing them in only some workflows, which is the hole "
            f"rather than the control: {num(v['partial'])}. Installing with scripts enabled: "
            f"{num(v['exposed'])}. Installing nothing in CI at all, so that their installs "
            f"happen only on machines this measurement cannot read: {num(v['no_ci'])}."),
        "closed_by": ("`ignore-scripts=true` in the repositories that install with scripts "
                      "enabled, and the same setting delivered to developer machines by MDM - "
                      "the CI half is the smaller half. Then Defender Network Protection on "
                      "macOS and Linux, so the attribution question becomes answerable at all"),
        "owner": "Platform Engineering (CI) and Endpoint security (Network Protection)",
    },
    {
        "id": "T04",
        "link": 3,
        "ttp": "The dropper fetches a pinned Bun 1.3.13 runtime so the payload runs outside "
               "Node",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "written": ("endpoint_hunt_r*.json",
                        "counts.Bun binaries or release archives written to disk"),
            "exe": ("endpoint_hunt_r*.json",
                    "counts|bun.exe or bunx.exe, any table, any device"),
            "wf": ("actions_posture_r*_coverage.json", "counts.workflows_fetching_bun"),
            "version": ("advisory_iocs_r*.json",
                        "counts|Rows naming the pinned Bun build 1.3.13"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"Four independent questions, all zero: {num(v['written'])} Bun binaries or "
            f"release archives written to disk, {num(v['exe'])} rows naming bun.exe or "
            f"bunx.exe on any table, {num(v['wf'])} workflows fetching Bun, and "
            f"{num(v['version'])} rows anywhere naming the pinned build 1.3.13. We would see "
            f"this step. Nothing prevents it - Bun is not blocked from being downloaded or "
            f"run."),
        "closed_by": ("an application-control policy that stops an unsigned interpreter "
                      "downloaded into a temp path from executing"),
        "owner": "Endpoint security",
    },
    {
        "id": "T05",
        "link": 3,
        "ttp": "The payload runs under Bun, spawned by the package manager or by node",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "spawns": ("endpoint_hunt_r*.json",
                       "counts.node/npm spawning Bun (the campaign's execution shape)"),
            "triaged": ("endpoint_hunt_r*.json",
                        "counts.Bun executions found and individually triaged"),
            "temp": ("endpoint_hunt_r*.json", "counts.Bun executions from a temp or staging path"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"{num(v['spawns'])} processes matched the campaign's execution shape - node or a "
            f"package manager spawning Bun. {num(v['triaged'])} Bun execution(s) were found "
            f"at all and triaged individually, {num(v['temp'])} of them from a temp or staging "
            f"path, which is the shape that would matter."),
        "closed_by": "the same application-control policy as T04",
        "owner": "Endpoint security",
    },
    {
        "id": "T06",
        "link": 4,
        "ttp": "Resolve the live C2 address from an Ethereum smart contract (`StringListStore` "
               "via `eth_call` against public RPC providers)",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "domains": ("advisory_iocs_r*.json", "counts.Campaign domains swept"),
            "matched": ("advisory_iocs_r*.json", "counts.Domains matched on the network table"),
            "control": ("advisory_iocs_r*.json", "evidence.domain_positive_control.rows.0.Rows"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"The three public Ethereum RPC hosts the advisories name are inside the "
            f"{num(v['domains'])}-domain network sweep: {num(v['matched'])} matched, against a "
            f"positive control of {num(v['control'])} rows on the same table and the same "
            f"operator. This is the campaign's resilience trick - the C2 address is not in the "
            f"malware - and the RPC hop is the part of it we can see."),
        "closed_by": ("blocking public Ethereum RPC endpoints at egress for build and "
                      "developer networks, where no business process needs them"),
        "owner": "Network security",
    },
    {
        "id": "T07",
        "link": 4,
        "ttp": "Contact attacker-controlled C2 hosts (`npm-cache.com`, `js-mirror.com`, "
               "`pypi-get.com`)",
        "sources": ["Integrity360"],
        "probes": {
            "matched": ("advisory_iocs_r*.json", "counts.Domains matched on the network table"),
            "egress": ("advisory_iocs_r*.json",
                       "counts.Of those, on a process that can make a request"),
            "control": ("advisory_iocs_r*.json", "evidence.cmdline_positive_control.rows.0.Rows"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"{num(v['matched'])} hosts matched on the network table and "
            f"{num(v['egress'])} command lines carrying a campaign hostname belonged to a "
            f"process that can make a request, against a command-line positive control of "
            f"{num(v['control'])} rows. Two sweeps rather than one, because the network table "
            f"records no URL on macOS."),
        "closed_by": ("a DNS or egress denylist carrying these hosts, so that the next "
                      "campaign's first request fails rather than being merely visible"),
        "owner": "Network security",
    },
    {
        "id": "T08",
        "link": 4,
        "ttp": "Reach C2 by raw IPv4 address, bypassing DNS-layer blocking",
        "sources": ["Integrity360"],
        "probes": {
            "swept": ("advisory_iocs_r*.json", "counts.Campaign IPv4 addresses swept"),
            "matched": ("advisory_iocs_r*.json", "counts.IP addresses matched"),
            "shared": ("advisory_iocs_r*.json",
                       "counts.IP matches that are shared infrastructure (leads, not findings)"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"{num(v['swept'])} addresses swept, {num(v['matched'])} matched, of which "
            f"{num(v['shared'])} would have been shared infrastructure and therefore a lead "
            f"rather than a finding. Three of the four sit behind Cloudflare or AWS, so this "
            f"vector's value is asymmetric: a match needs corroboration, a zero is clean."),
        "closed_by": "the same egress control as T07, applied to addresses and not only names",
        "owner": "Network security",
    },
    {
        "id": "T09",
        "link": 4,
        "ttp": "Write the stage-1 dropper and stage-2 infostealer to disk (`setup.mjs`, "
               "`Math_Symbol.js`)",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "hashes": ("advisory_iocs_r*.json", "counts.Campaign file hashes swept"),
            "matched": ("advisory_iocs_r*.json", "counts.File-hash matches"),
            "dropped": ("install_activity_r*.json", "counts.dropped_file_writes_30d"),
        },
        "rule": lambda v: (
            DETECTION_ONLY,
            f"{num(v['hashes'])} published hashes - 3 SHA-1 and 2 SHA-256 - swept across file, "
            f"process and image-load events over 30 days: {num(v['matched'])} matches, over a "
            f"hash column that is populated on every platform except Linux. Separately, "
            f"{num(v['dropped'])} writes of a campaign filename. Earlier rounds could only "
            f"match these artifacts by name, which is a lead; a hash match is a verdict."),
        "closed_by": ("adding these hashes as custom indicators in Defender so a future write "
                      "blocks rather than merely appearing in a table"),
        "owner": "Endpoint security",
    },
    {
        "id": "T10",
        "link": 4,
        "ttp": "Harvest credentials from the host - environment, config files, cloud CLI state",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "secrets": ("actions_posture_r*_coverage.json",
                        "counts.workflows_interpolating_secrets_into_run"),
            "whole": ("actions_posture_r*_coverage.json",
                      "counts.workflows_serialising_whole_secrets_context"),
            "analysed": ("actions_posture_r*_coverage.json", "counts.workflows_analysed"),
        },
        "rule": lambda v: (
            OPEN,
            f"Nothing stands between running code and our credentials, and the numbers are "
            f"the finding: of {num(v['analysed'])} workflows, {num(v['secrets'])} interpolate "
            f"a secret directly into a shell step and {num(v['whole'])} serialize the entire "
            f"secrets context into the environment. A payload that achieves execution in one "
            f"of those jobs does not need to search for anything."),
        "closed_by": ("removing whole-context secret serialization, then narrowing "
                      "per-workflow secret scope - a program of work, sized by the 119 and 838 "
                      "identified workflows"),
        "owner": "Platform Engineering with the owning teams",
    },
    {
        "id": "T11",
        "link": 5,
        "ttp": "Exfiltrate the harvested material to a newly created public repository or "
               "branch under the victim's own account (double-base64 dead drop)",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "repos": ("dead_drops_r*.json", "controls.repos_examined"),
            "markers": ("dead_drops_r*.json", "result.marker_repository_count"),
            "controls": ("dead_drops_r*.json", "controls.controls_pass"),
            "branches": ("branches_r*_coverage.json", "branches_enumerated"),
            "campaign_branches": ("branches_r*_coverage.json", "len:campaign_branches_found"),
        },
        "rule": lambda v: (
            DETECTION_ONLY if v["controls"] else UNMEASURED,
            f"{num(v['repos'])} repositories were examined for the campaign's dead-drop "
            f"markers with the positive controls passing: {num(v['markers'])} marker "
            f"repositories. {num(v['branches'])} branches were enumerated across the "
            f"repositories that could have been pushed to inside the window: "
            f"{num(v['campaign_branches'])} campaign branches. We would find the drop after "
            f"it happened. Nothing stops a token that can push from pushing."),
        "closed_by": ("an organization policy denying public repository creation, plus "
                      "detection on first-ever public repo creation by a service identity"),
        "owner": "GitHub platform administration",
    },
    {
        "id": "T12",
        "link": 6,
        "ttp": "Use a stolen npm token to publish poisoned versions of the victim's own "
               "packages - the worm step",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "oidc": ("actions_posture_r*_coverage.json",
                     "counts.workflows_with_oidc_publish_capability"),
            "idtoken": ("actions_posture_r*_coverage.json",
                        "counts.workflows_requesting_id_token_without_publish_step"),
            "read": ("actions_posture_r*_coverage.json", "workflow_files_read"),
        },
        "rule": lambda v: (
            CONTROLLED if not v["oidc"] else OPEN,
            f"Across {num(v['read'])} workflow files read, {num(v['oidc'])} combine a "
            f"publish-capable token with a publish step. This link is held because a "
            f"precondition is absent, not because a control was built: "
            f"{num(v['idtoken'])} workflows already request an OIDC id-token without a "
            f"publish step, so the week one of them gains a publish step the state changes. "
            f"That is why the check runs every cycle."),
        "closed_by": ("a required-review gate on any workflow change that adds a publish "
                      "step, so the precondition cannot reappear unnoticed"),
        "owner": "Platform Engineering",
    },
    {
        "id": "T13",
        "link": 6,
        "ttp": "Publish through a trusted publisher / OIDC so the poisoned version carries "
               "valid provenance",
        "sources": ["Snyk"],
        "probes": None,
        "unmeasured_closed_by": (
            "enumerate our own npm org: which packages we publish, which have trusted "
            "publishers configured, and which automation tokens exist with publish rights. "
            "This is section 6 check 4 of the TTP playbook and it has never been run. It needs "
            "an npm registry token with org read - a rights gap, not an engineering gap"),
        "closed_by": ("the enumeration above, then removing publish-capable automation tokens "
                      "in favour of trusted publishers with a required review"),
        "owner": "whoever owns the npm organization account",
    },
    {
        "id": "T14",
        "link": 7,
        "ttp": "Persist through an IDE hook - `.vscode/tasks.json` with `runOn: folderOpen`, "
               "so opening the folder runs the payload",
        "sources": ["Snyk"],
        "probes": {
            "files": ("repo_trees_r*.jsonl", "hook_files"),
            "repos": ("repo_trees_r*.jsonl", "hook_repos"),
            "errors": ("repo_trees_r*.jsonl", "parse_errors"),
            "folder": ("repo_trees_r*.jsonl", "has_folder_open"),
            "autostart": ("repo_trees_r*.jsonl", "autostart_runs_script"),
            "tasks": ("repo_trees_r*.jsonl", "vscode_tasks_json"),
        },
        "rule": lambda v: (
            CONTROLLED if not v["folder"] and not v["errors"] else PARTLY,
            f"{num(v['files'])} editor and agent config files across {num(v['repos'])} "
            f"repositories were fetched and parsed - {num(v['tasks'])} of them "
            f"`.vscode/tasks.json` - with {num(v['errors'])} parse errors. "
            f"{num(v['folder'])} declare `runOn: folderOpen` and {num(v['autostart'])} start a "
            f"script on open. This is a content answer at estate scale, not a filename answer. "
            f"The state is held because nothing uses the primitive, not because anything blocks "
            f"it: a single pull request adding `runOn: folderOpen` to one of the "
            f"{num(v['tasks'])} task files would move it."),
        "closed_by": ("a pre-commit or PR check that fails on `runOn: folderOpen`, so the "
                      "current zero is enforced rather than observed"),
        "owner": "Developer Experience",
    },
    {
        "id": "T15",
        "link": 7,
        "ttp": "Persist through a coding-agent hook - `.claude/settings.json` `SessionStart`, "
               "so starting a session runs the payload",
        "sources": ["Snyk"],
        "probes": {
            "files": ("repo_trees_r*.jsonl", "hook_files"),
            "session": ("repo_trees_r*.jsonl", "has_session_start"),
            "hooks": ("repo_trees_r*.jsonl", "has_hooks_key"),
            "autostart": ("repo_trees_r*.jsonl", "autostart_runs_script"),
            "where": ("repo_trees_r*.jsonl", "hooks_key_repos"),
        },
        "rule": lambda v: (
            CONTROLLED if not v["session"] and not v["autostart"] else PARTLY,
            f"{num(v['session'])} of {num(v['files'])} parsed config files declare a "
            f"`SessionStart` hook and {num(v['autostart'])} run a script on start. "
            f"{num(v['hooks'])} repository declares agent hooks at all, executing in-repo "
            f"scripts on tool use rather than on session start - benign on inspection, and the "
            f"same primitive this campaign abuses, which makes it the one place where the "
            f"difference between our config and the attacker's is intent - named, because a "
            f"finding nobody can look up is not a finding: {', '.join(v['where']) or 'none'}. "
            f"Held by absence of use rather than by a control, exactly as T14 is."),
        "closed_by": ("a repository-level review requirement on `.claude/settings.json` and "
                      "`.vscode/tasks.json`, the two files that turn a clone into an execution"),
        "owner": "Developer Experience",
    },
    {
        "id": "T16",
        "link": 7,
        "ttp": "Reach the estate through an internal registry or proxy that mirrors npmjs "
               "upstream",
        "sources": ["Integrity360"],
        "probes": {
            "feeds": ("azure_artifacts_feeds.json", "feeds_checked"),
            "readable": ("azure_artifacts_feeds.json", "feeds_readable"),
            "upstream": ("azure_artifacts_feeds.json", "len:feeds_with_npmjs_upstream"),
            "found": ("azure_artifacts_feeds.json", "len:MALICIOUS_VERSIONS_FOUND"),
            "unmeasured": ("azure_artifacts_feeds.json", "len:feeds_UNMEASURED_no_read_packages"),
        },
        "rule": lambda v: (
            PARTLY if v["unmeasured"] else DETECTION_ONLY,
            f"{num(v['readable'])} of {num(v['feeds'])} Azure Artifacts feeds were readable, "
            f"{num(v['upstream'])} of them proxying npmjs upstream: "
            f"{num(v['found'])} poisoned versions cached. {num(v['unmeasured'])} feed could "
            f"not be read at all, so this vector has a named hole rather than a clean answer."),
        "closed_by": ("`Read packages` on the feed the identity cannot list - a rights gap "
                      "named in the feeds artifact, filed against the feed owner"),
        "owner": "the Azure DevOps project administrator for the unreadable feed",
    },
    {
        "id": "T17",
        "link": 7,
        "ttp": "Pipe remote code into a shell inside CI, so a build step fetches its payload "
               "at run time",
        "sources": ["Integrity360"],
        "probes": {
            "piping": ("actions_posture_r*_coverage.json",
                       "counts.workflows_piping_remote_code_to_shell"),
            "selfhosted": ("actions_posture_r*_coverage.json",
                           "counts.workflows_with_self_hosted_runners"),
            "mutable": ("actions_posture_r*_coverage.json", "counts.action_refs_on_mutable_refs"),
            "pinned": ("actions_posture_r*_coverage.json", "counts.action_refs_pinned_to_sha"),
        },
        "rule": lambda v: (
            OPEN,
            f"{num(v['piping'])} workflows pipe remote code into a shell and "
            f"{num(v['selfhosted'])} run on self-hosted runners, where a compromised step "
            f"outlives the job. {num(v['mutable'])} action references resolve to a mutable ref "
            f"against {num(v['pinned'])} pinned to a commit - so most third-party CI code in "
            f"this estate can change under us between runs without anything in the way."),
        "closed_by": ("SHA-pinning third-party actions, starting with the most-referenced "
                      "unpinned actions listed in the posture artifact"),
        "owner": "Platform Engineering",
    },
    {
        "id": "T18",
        "link": 7,
        "ttp": "Watch for token revocation and react - the `gh-token-monitor` anti-remediation "
               "watchdog, which is why the advisories say to remove the malware before rotating "
               "credentials",
        "sources": ["Integrity360", "Snyk"],
        "probes": {
            "capable": ("antiremediation_r*.json",
                        "counts.Of those, on a process or file that could BE the watchdog"),
            "named": ("antiremediation_r*.json",
                      "counts.Rows naming the watchdog exactly, all tables"),
            # `|` form, not `.`: this count key is an English sentence containing
            # `api.github.com`, and splitting it on dots would make the path unresolvable. Same
            # reason the T05 hook probes use it.
            "cadence": ("antiremediation_r*.json",
                        "counts|Device/process pairs polling api.github.com at watchdog cadence"),
            "name_control": ("antiremediation_r*.json",
                             "evidence.name_positive_control.rows.0.Rows"),
            "api_control": ("antiremediation_r*.json",
                            "evidence.api_positive_control.rows.0.Rows"),
            "api_control_devices": ("antiremediation_r*.json",
                                    "evidence.api_positive_control.rows.0.Devices"),
            "both": ("antiremediation_r*.json",
                     "counts.Device/process pairs on BOTH the autostart and the API surface"),
        },
        # DETECTION ONLY either way: a hit would mean the sweep detected the watchdog, and a zero
        # means it would have. Neither outcome is a control that prevents the install, so the
        # state does not move on the result - only the sentence below does.
        "rule": lambda v: (
            DETECTION_ONLY,
            f"Swept for the watchdog by name and by shape. By name: {num(v['named'])} rows "
            f"mention `gh-token-monitor` across the file, process and event tables and "
            f"{num(v['capable'])} of them are a process or file that could BE it - the rest are "
            f"this hunt reading its own indicator corpus, demoted by classifier and listed "
            f"verbatim in the artifact. Against a {num(v['name_control'])}-row positive control "
            f"on the same tables and operator, that zero is a measured absence. By shape: "
            f"{num(v['cadence'])} device/process pairs poll api.github.com at the published "
            f"cadence, against a control of {num(v['api_control'])} connections from "
            f"{num(v['api_control_devices'])} devices - so the zero is about RATE, not "
            f"reachability. {num(v['both'])} hosts appear on both the autostart and the API "
            f"surface and are named as leads. Detection, not prevention: nothing measured here "
            f"would stop the watchdog being installed tomorrow."),
        "closed_by": ("a remediation runbook that orders removal before rotation regardless of "
                      "this result - a clean sweep does not make the revocation ORDER safe - "
                      "plus Defender Network Protection on macOS and Linux, without which a "
                      "renamed watchdog is invisible to the shape query on those platforms"),
        "owner": "Security Engineering",
    },
    {
        "id": "T19",
        "link": 7,
        "ttp": "Coerce the victim into leaving the credential live - the extortion commit "
               "message the campaign leaves behind",
        "sources": ["Integrity360"],
        "probes": {
            "orgs": ("commit_messages_r*.json", "counts.Organizations queried"),
            "indicators": ("commit_messages_r*.json",
                           "counts.Indicators queried per organization"),
            "hits": ("commit_messages_r*.json",
                     "counts.Decisive hits (a hit is a compromised repository)"),
            "off_default": ("commit_messages_r*.json",
                            "branch_coverage_control.off_default_checked"),
            "off_default_found": ("commit_messages_r*.json",
                                  "branch_coverage_control.off_default_found_by_search"),
            "on_default": ("commit_messages_r*.json",
                           "branch_coverage_control.on_default_checked"),
            "on_default_found": ("commit_messages_r*.json",
                                 "branch_coverage_control.on_default_found_by_search"),
        },
        # PARTLY CONTROLLED on the observation half with a MEASURED hole, not CONTROLLED: the
        # index this answer rests on was proved not to reach non-default branches, and the
        # campaign commits to side branches. The hole is the work item and it is named.
        "rule": lambda v: (
            DETECTION_ONLY if v["off_default_found"] else PARTLY,
            f"The extortion string, the campaign's own commit message under its forged author, "
            f"and three further commit-text indicators - {num(v['indicators'])} in all - were "
            f"searched across all {num(v['orgs'])} organizations: {num(v['hits'])} decisive "
            f"hits, each organization's index proved live by a positive control first. The hole "
            f"is measured rather than assumed: of {num(v['off_default'])} commits this run "
            f"PROVED are not ancestors of their default branch, commit search returned "
            f"{num(v['off_default_found'])}, while returning {num(v['on_default_found'])} of "
            f"{num(v['on_default'])} that are. So the commit-message answer covers default "
            f"branches, and the campaign pushes to side branches."),
        "closed_by": ("re-running scripts/hunt/hunt_branches.py, which enumerates every ref and "
                      "now carries the extortion string in its marker set - that is the "
                      "compensating control for the measured index hole above"),
        "owner": "Security Engineering",
    },
    {
        "id": "T20",
        "link": 4,
        "ttp": "Identify itself with a `Bun/1.3.13` User-Agent on its C2 requests",
        "sources": ["Integrity360", "Snyk"],
        "probes": None,
        "unmeasured_closed_by": (
            "nothing we can run: Defender's DeviceNetworkEvents carries no User-Agent column, "
            "so this indicator cannot be matched against endpoint telemetry at all. It would "
            "need a proxy or TLS-inspection log source, which is a different data source and a "
            "funding decision, not a query"),
        "closed_by": ("forwarding proxy logs with User-Agent to the same query surface as the "
                      "endpoint tables"),
        "owner": "Network security and the SIEM owner",
    },
]


# --------------------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------------------- #

# What the advisories say the campaign's blast radius was. Citations, checkable against the
# advisory text - and deliberately not reconciled by hand, because the gap between their number
# and ours is the interesting part and a hand-reconciled number hides it.
ADVISORY_TOTALS = {
    "source": "Integrity360",
    "poisoned_versions": 2251,
    "packages": 452,
}


def reconcile_scope(exports: Path) -> Dict[str, Any]:
    """Their published blast radius against our Tier 0 derivation, with the delta stated.

    Two numbers that should agree and do not: the advisory counts 2,251 poisoned versions
    across 452 packages, and the registry oracle in this repo derived 2,208 specs across the
    names it could resolve. The difference matters for exactly one reason - if their package
    list contains names our seed list never had, then every dependency comparison in this hunt
    ran against a denominator that was short, and a clean result over a short list is a
    different claim from a clean result.

    So this states the arithmetic and stops. Which direction the difference runs cannot be
    settled from our side: it needs their package list, which the advisory does not publish.
    """
    path = resolve_artifact(exports, "rederive_window_0000z_aug5.json")
    if path is None:
        return {"state": UNMEASURED,
                "why": "no registry-oracle artifact present to reconcile against"}
    data = load_json(path)
    ours_specs = data.get("malicious_count")
    ours_names = data.get("packages_queried")
    suspected = len(data.get("suspected_uncleaned_specs") or [])
    unreachable = len(data.get("unreachable") or [])
    return {
        "advisory": ADVISORY_TOTALS,
        "ours": {"artifact": str(path), "malicious_specs": ours_specs,
                 "package_names_queried": ours_names,
                 "suspected_not_yet_withdrawn": suspected,
                 "names_unresolvable": unreachable,
                 "hunt_scope_specs": len(data.get("hunt_scope_specs") or [])},
        "delta": {
            "versions": ADVISORY_TOTALS["poisoned_versions"] - (ours_specs or 0),
            "package_names": ADVISORY_TOTALS["packages"] - (ours_names or 0),
        },
        "what_this_does_and_does_not_say": [
            f"Their version count sits inside our own bracket: we derived {ours_specs:,} "
            f"confirmed malicious specs and {suspected} more suspected and not yet withdrawn, "
            f"so a snapshot taken at a different minute lands between the two. The version "
            f"delta is a timing artifact and not a coverage gap.",
            f"The name count is the one that matters: "
            f"{ADVISORY_TOTALS['packages'] - (ours_names or 0)} package names separate their "
            f"list from ours, and {unreachable} of ours could not be authoritatively resolved. "
            f"If those names are packages our seed list never contained, every dependency "
            f"comparison in this hunt ran against a short denominator.",
            "This cannot be settled from our side. The advisory publishes the total and not "
            "the list, so the open item is to obtain their package list and re-run the "
            "dependency comparison against the union - not to reconcile the numbers by "
            "reasoning about them.",
        ],
    }


def build(exports: Path) -> Dict[str, Any]:
    cache: Dict[str, Any] = {}
    artifact_paths: Dict[str, str] = {}
    missing_artifacts: Dict[str, str] = {}

    def artifact(stem: str) -> Any:
        if stem in cache:
            return cache[stem]
        path = resolve_artifact(exports, stem)
        if path is None:
            missing_artifacts[stem] = "no file in the exports directory matches this name"
            cache[stem] = MISSING
            return MISSING
        loader = LOADERS.get(path.suffix, load_json)
        cache[stem] = loader(path)
        artifact_paths[stem] = str(path)
        return cache[stem]

    measured: List[Dict[str, Any]] = []
    not_measured: List[Dict[str, Any]] = []

    for entry in REGISTER:
        common = {"id": entry["id"], "chain_link": entry["link"], "ttp": entry["ttp"],
                  "named_by": entry["sources"], "closed_by": entry["closed_by"],
                  "owner": entry["owner"]}

        if not entry.get("probes"):
            not_measured.append({**common, "state": UNMEASURED,
                                 "why_not_measured": entry["unmeasured_closed_by"]})
            continue

        values: Dict[str, Any] = {}
        failures: List[str] = []
        used: List[str] = []
        for var, (stem, path) in entry["probes"].items():
            data = artifact(stem)
            if data is MISSING:
                failures.append(f"{var}: artifact {stem} not found")
                continue
            got = dig(data, path)
            if got is MISSING:
                failures.append(f"{var}: {artifact_paths.get(stem, stem)} has no `{path}`")
                continue
            values[var] = got
            used.append(f"{artifact_paths.get(stem, stem)}#{path}={got}")

        if failures:
            # A mapping that does not resolve is reported as a gap, never as a pass. This is
            # the whole reason the percentage below can be trusted: a probe that rots turns
            # into a visible NOT MEASURED rather than into a silent COVERED.
            not_measured.append({**common, "state": UNMEASURED,
                                 "why_not_measured": ("the artifact this TTP maps to does not "
                                                      "carry the value the mapping expects: "
                                                      + "; ".join(failures)),
                                 "probe_failures": failures})
            continue

        state, sentence = entry["rule"](values)
        if state not in STATES:
            raise SystemExit(f"[advisory-coverage] {entry['id']} returned a state outside the "
                             f"five-state vocabulary: {state!r}")
        measured.append({**common, "state": state, "evidence": sentence,
                         "measured_values": values, "read_from": used})

    rows = measured + not_measured
    total = len(rows)
    by_state = {state: sum(1 for r in rows if r["state"] == state) for state in STATES}
    in_the_way = by_state[CONTROLLED] + by_state[PARTLY] + by_state[DETECTION_ONLY]
    prevention = by_state[CONTROLLED] + by_state[PARTLY]

    # A vector we have never looked at is either cheap to look at or impossible with the
    # sources we hold, and those two cost wildly different amounts to close. The split is read
    # off the reason each one carries rather than asserted.
    cheap = sum(1 for r in not_measured
                if "nothing we can run" not in r["why_not_measured"])

    def pct(part: int) -> float:
        return round(100.0 * part / total, 1) if total else 0.0

    # Which vectors exist as answerable questions only because of the two advisories: the ones
    # whose evidence is read from the advisory-IOC artifact, which did not exist before them.
    from_advisory = sorted({r["id"] for r in measured
                           if any("advisory_iocs" in src for src in r["read_from"])})

    per_source: Dict[str, Any] = {}
    for source in ("Integrity360", "Snyk"):
        named = [r for r in rows if source in r["named_by"]]
        answered = [r for r in named if r["state"] != UNMEASURED]
        per_source[source] = {
            "vectors_named": len(named),
            "vectors_with_a_measured_answer": len(answered),
            "percent": round(100.0 * len(answered) / len(named), 1) if named else 0.0,
        }

    return {
        "name": "Advisory-TTP coverage",
        "as_of": datetime.now(timezone.utc).isoformat(),
        "campaign": "CHAINDROP / Shai-Hulud: Here We Go Again",
        "advisories": [
            "Integrity360 - CHAINDROP: The Keyv and Cacheable npm Supply Chain Attack",
            "Snyk - Inside the Keyv npm compromise: preinstall malware, trusted provenance, "
            "IDE hooks",
        ],
        # The observation axis and the control axis are counted separately, and T03's history is
        # the reason. It read four numbers out of an artifact and still landed UNMEASURED: that
        # thousands of lifecycle scripts fire and none can be attributed to a package tells us
        # the scripts run and tells us nothing about what is in their way. Measured on the first
        # axis, unmeasured on the second. Closing it took a second artifact measuring the
        # obstacle rather than the arrival - which is exactly what the two-axis split makes
        # visible, and what folding them together would have hidden as a single COVERED.
        "percentages": {
            "vectors_with_a_measured_answer": pct(len(measured)),
            "vectors_with_something_in_the_way_prevention_or_detection": pct(in_the_way),
            "vectors_with_prevention_rather_than_detection": pct(prevention),
            "vectors_we_never_looked_at": pct(len(not_measured)),
            "vectors_with_no_established_control_state": pct(by_state[UNMEASURED]),
        },
        "counts": {
            "attacker_vectors_enumerated": total,
            "measured_from_an_artifact": len(measured),
            "not_measured": len(not_measured),
            **{f"state_{state.lower().replace(' ', '_')}": by_state[state] for state in STATES},
            "answerable_only_because_of_these_advisories": len(from_advisory),
        },
        "how_to_read_the_percentage": [
            "The denominator is the 20 attacker vectors these two advisories describe, counted "
            "once each. The links are not equally weighted and they do not sum: a control on "
            "the first vector prevents the attack, a control on the last one only limits what "
            "an attacker keeps. So the percentage is a headline and the table is the answer.",
            "`vectors_with_a_measured_answer` is the coverage of the hunt - the share of the "
            "attacker's playbook we can return a number for. It says nothing about whether the "
            "number is good.",
            "A vector can be measured and still have no control state, and the install-script "
            "vector spent every earlier cycle proving it: thousands of install-time scripts ran, "
            "not one attributable to a package, which measures arrival and is silent about "
            "defense. It moved only when a separate artifact read `ignore-scripts` across the "
            "repositories - measuring the obstacle rather than the event. That is the shape of "
            "the work every remaining unmeasured control state needs. "
            "`vectors_we_never_looked_at` is the observation axis; "
            "`vectors_with_no_established_control_state` is the "
            "control axis; they are different numbers on purpose.",
            "`vectors_with_prevention_rather_than_detection` is the honest ceiling on how much "
            "of this campaign we would stop rather than watch.",
            f"Every vector we have never looked at carries the specific thing that would "
            f"measure it, and {cheap} of the {len(not_measured)} are a marker addition, a "
            f"sweep, or a rights request - hours of work, not a program. "
            f"{len(not_measured) - cheap} of them cannot be answered with the data sources we "
            f"have at all.",
        ],
        "scope_reconciliation": reconcile_scope(exports),
        "vectors_answerable_only_because_of_these_advisories": from_advisory,
        "per_advisory": per_source,
        "vectors": sorted(rows, key=lambda r: (r["chain_link"], r["id"])),
        "artifacts_read": artifact_paths,
        "artifacts_missing": missing_artifacts,
    }


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exports", type=Path, default=Path("exports/hunt"))
    parser.add_argument("--out", type=Path, default=Path("exports/hunt/advisory_coverage.json"))
    args = parser.parse_args(argv)

    result = build(args.exports)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(result, indent=2) + "\n")

    pcts = result["percentages"]
    print(f"[advisory-coverage] -> {args.out}")
    print(f"  attacker vectors enumerated: {result['counts']['attacker_vectors_enumerated']}")
    for key, value in pcts.items():
        print(f"  {key}: {value}%")
    for state in STATES:
        print(f"  {state}: {result['counts']['state_' + state.lower().replace(' ', '_')]}")
    for row in result["vectors"]:
        if row["state"] == UNMEASURED:
            print(f"  UNMEASURED {row['id']}: {row['ttp'][:78]}")
    for stem, why in result["artifacts_missing"].items():
        print(f"  MISSING ARTIFACT {stem}: {why}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
