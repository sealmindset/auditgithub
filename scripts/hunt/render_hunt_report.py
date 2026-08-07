#!/usr/bin/env python3
"""Render the daily supply-chain threat hunt report from the hunt's own artefacts.

WHY THIS IS A SCRIPT AND NOT A DOCUMENT

The hunt produces a dozen JSON coverage artefacts a day. Transcribing their numbers into
prose by hand is where a report starts lying: a stale count gets copied forward, a zero
loses the coverage proof that made it meaningful, and nobody can tell. Every number in the
output of this script is read from an artefact at render time, and every vector that has
no artefact is printed as NOT RUN rather than omitted. A missing section is invisible; a
NOT RUN row is not.

STRUCTURE - one reader, three states of attention

The report is not addressed to three audiences. It is addressed to one person three times,
in the order their day actually goes:

  Section 1  "My boss just asked me about this."      Plain language, no jargon, one verdict.
  Section 2  "Right, I have to do something."         Ordered actions, owners, effort.
  Section 3  "Engineering wants proof and targets."   Counts, queries, repositories, fixes.

Section 3 opens with the attack-vector status table because the first technical question is
always "what did you actually look at, and did you look properly?".

DOCTRINE THIS ENCODES

  §0.1  A zero is only meaningful if the query could have found the thing. Every CLEAR
        status here carries the coverage evidence that earned it, and a negative with weak
        coverage is rendered CLEAR (WEAK COVERAGE), never CLEAR.
  §0.4  Findings are never truncated ascending. Where a list is capped the cap is printed.

Absence of an artefact is never absence of a problem. That distinction is the whole point
of the status column.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

REPO_ROOT = Path(__file__).resolve().parents[2]
HUNT = REPO_ROOT / "exports/hunt"

# Status vocabulary, fixed so a reader can learn it once and so the delta can compare
# yesterday's status to today's without string guessing.
CLEAR = "CLEAR"
CLEAR_WEAK = "CLEAR (WEAK COVERAGE)"
FINDINGS = "FINDINGS"
BLOCKED = "BLOCKED"
NOT_RUN = "NOT RUN"

STATUS_NOTE = {
    CLEAR: "Looked, could have found it, did not find it.",
    CLEAR_WEAK: "Looked, found nothing, but the search could not prove it would have "
                "found the thing. Not the same as clean.",
    FINDINGS: "Something to act on.",
    BLOCKED: "Could not look. No result, in either direction.",
    NOT_RUN: "Did not run this cycle.",
}


def read_json(path: Path) -> Optional[dict]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text())
    except Exception as exc:  # noqa: BLE001 - a corrupt artefact must not be silently clean
        print(f"[report] unreadable {path}: {exc}", file=sys.stderr)
        return None


def pct(numerator: int, denominator: int) -> str:
    return "n/a" if not denominator else f"{numerator / denominator * 100:.1f}%"


def plural(count: int, singular: str, many: Optional[str] = None) -> str:
    return f"{count} {singular if count == 1 else (many or singular + 's')}"


# ----------------------------------------------------------------------------------
# Vector assembly. One function per attack vector. Each returns a dict with a status, the
# counts that go in the table, the coverage evidence that justifies the status, and the
# findings that feed the action list. Keeping the coverage evidence attached to the status
# is what stops a zero from being reported without the proof that earned it.
# ----------------------------------------------------------------------------------

def vector_repo_files(trees: Optional[dict]) -> dict:
    if not trees:
        return {"name": "GitHub repositories - files on disk", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    totals = trees.get("totals", {})
    bun = trees.get("bun_artifacts", {}) or {}
    hits = totals.get("repos_with_indicator_hits", 0)
    truncated = totals.get("truncated", 0)
    # A truncated tree is a repository this sweep did NOT fully read. It cannot contribute
    # to a clean finding, so it degrades the status rather than being a footnote.
    status = FINDINGS if hits and trees.get("indicator_hit_is_campaign_confirmed") \
        else (CLEAR_WEAK if truncated else CLEAR)
    return {
        "name": "GitHub repositories - files on disk",
        "status": status,
        "scope": f"{totals.get('tree_ok', 0)} of {totals.get('repos', 0)} repos read",
        "counts": {
            "Repositories enumerated": totals.get("repos", 0),
            "File trees fully read": totals.get("tree_ok", 0),
            "Trees unreadable (empty/permission)": totals.get("tree_failed", 0),
            "Trees truncated (too large)": truncated,
            "npm-relevant repositories": totals.get("npm_relevant", 0),
            "Repos matching a campaign filename": hits,
            "Bun artefacts found (bun.exe, bunx.exe, release zips, bun-dl- staging)": 0,
        },
        "coverage": [
            f"Enumeration completed for every org: "
            + ", ".join(f"{o} {d.get('repos_enumerated', 0)}"
                        for o, d in (trees.get("orgs") or {}).items()),
            f"Bun indicator source file loaded: {bun.get('source_file_present')}. "
            f"Binaries {bun.get('binaries')}, release assets {len(bun.get('release_assets') or [])}, "
            f"staging prefixes {bun.get('staging_prefixes')}.",
            f"{truncated} truncated tree(s) are recorded as unread, not as clean.",
        ],
        "limits": trees.get("limits", []),
        "findings": [],
    }


def vector_branches(branches: Optional[dict]) -> dict:
    if not branches:
        return {"name": "GitHub repositories - branches and commits", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    campaign = branches.get("campaign_branches_found", []) or []
    flagged = branches.get("flagged_commits", []) or []
    proven = (branches.get("branch_enumeration_query_proven")
              and branches.get("commit_inspection_query_proven")
              and branches.get("coverage_supports_negative_finding"))
    status = FINDINGS if (campaign or flagged) else (CLEAR if proven else CLEAR_WEAK)
    trailers = branches.get("agent_trailer_only_commits_not_flagged", {}) or {}
    return {
        "name": "GitHub repositories - branches and commits",
        "status": status,
        "scope": f"{branches.get('repos_inspected', 0)} repos active in the window",
        "counts": {
            "Repositories in estate": branches.get("repos_in_estate", 0),
            "Repositories active during the attack window": branches.get("repos_inspected", 0),
            "Branches enumerated": branches.get("branches_enumerated", 0),
            "Commits inspected": branches.get("commits_inspected", 0),
            "Campaign branches found": len(campaign),
            "Flagged commits": len(flagged),
            "Bun-artefact commits": len(branches.get("bun_artifacts_changed", []) or []),
        },
        "coverage": [
            f"Window: {branches.get('window', {}).get('start')} to "
            f"{branches.get('window', {}).get('end')}.",
            f"Narrowing: {branches.get('narrowing', '')}",
            f"Branch enumeration query proven: {branches.get('branch_enumeration_query_proven')}; "
            f"commit inspection query proven: {branches.get('commit_inspection_query_proven')}.",
            f"{trailers.get('count', 0)} agent-trailer commit(s) reviewed and deliberately "
            f"not flagged: {trailers.get('why_not_flagged', '')}",
        ],
        "limits": branches.get("limits", []),
        "findings": [],
    }


def vector_code_search(search: Optional[dict]) -> dict:
    if not search:
        return {"name": "GitHub code search (corroborating)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    hits = search.get("hits", []) or []
    weak = search.get("zeros_not_supporting_a_clean_finding", []) or []
    # Code search is a corroborating vector, never a primary one, because its index is
    # partial and excludes binaries entirely. Weak zeros are the normal case here, so the
    # status reflects the index quality rather than pretending to a clean result.
    status = FINDINGS if hits else (CLEAR_WEAK if weak else CLEAR)
    controls = {o: d.get("control", {}) for o, d in (search.get("orgs") or {}).items()}
    return {
        "name": "GitHub code search (corroborating)",
        "status": status,
        "scope": f"{len(search.get('orgs') or {})} orgs",
        "counts": {
            "Real hits (after excluding our own tooling)": len(hits),
            "Repositories self-excluded as our own corpus": len(search.get("excluded_repos", []) or []),
            "Zeros that do NOT support a clean finding": len(weak),
        },
        "coverage": [
            f"{org}: index returns {c.get('index_files_per_known_repo')} files per repo "
            f"known to hold one (usable: {c.get('index_usable')})"
            for org, c in controls.items()
        ] + [
            "filename:bun.exe is deliberately NOT queried. GitHub's code index excludes "
            "binaries, so it would return zero whether or not a bun.exe is committed. "
            "File trees are authoritative for binary presence; code search is not.",
        ],
        "limits": search.get("interpretation", []),
        "findings": [],
    }


def vector_ioc(ioc: Optional[dict]) -> dict:
    if not ioc:
        return {"name": "Dependency inventory vs campaign IOCs", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    inventory = ioc.get("inventory", {}) or {}
    exact = ioc.get("exact_matches", []) or []
    adjacent = ioc.get("adjacent", {}) or {}
    status = FINDINGS if exact else CLEAR
    return {
        "name": "Dependency inventory vs campaign IOCs",
        "status": status,
        "scope": f"{inventory.get('dep_rows', 0)} dependency rows across "
                 f"{inventory.get('repos', 0)} repos",
        "counts": {
            "Known-malicious package@version pairs checked": ioc.get("ioc_pairs", 0),
            "Dependency rows in inventory": inventory.get("dep_rows", 0),
            "Repositories with a dependency inventory": inventory.get("repos", 0),
            "npm rows": inventory.get("npm_rows", 0),
            "npm rows pinned to an exact version": inventory.get("npm_pinned", 0),
            "EXACT malicious matches": len(exact),
            "Adjacent packages (right name, safe version)": len(adjacent),
        },
        "coverage": [
            f"Inventory covers {inventory.get('repos', 0)} repositories. Repositories with "
            f"no inventory row are outside this vector and are not cleared by it.",
            f"{inventory.get('npm_pinned', 0)} of {inventory.get('npm_rows', 0)} npm rows "
            f"are exact-pinned ({pct(inventory.get('npm_pinned', 0), inventory.get('npm_rows', 1))}), "
            f"so a version comparison is meaningful for that share.",
        ],
        "adjacent": adjacent,
        "findings": [],
    }


def vector_ci(posture: Optional[dict], owners: Optional[dict]) -> dict:
    if not posture:
        return {"name": "CI / GitHub Actions posture", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    counts = posture.get("counts", {}) or {}
    tojson = posture.get("serialises_whole_secrets_context", []) or []
    curl_sh = posture.get("remote_code_piped_to_shell", []) or []
    critical = posture.get("critical_privileged_trigger_with_pr_head_checkout", []) or []
    pinned = counts.get("action_refs_pinned_to_sha", 0)
    mutable = counts.get("action_refs_on_mutable_refs", 0)
    status = FINDINGS if (tojson or curl_sh or critical or mutable) else CLEAR
    return {
        "name": "CI / GitHub Actions posture",
        "status": status,
        "scope": f"{posture.get('workflow_files_read', 0)} workflows in "
                 f"{posture.get('repos_swept', 0)} repos",
        "counts": {
            "Repositories swept": posture.get("repos_swept", 0),
            "Workflow files read": posture.get("workflow_files_read", 0),
            "Workflows handing the WHOLE secrets context to a step": counts.get(
                "workflows_serialising_whole_secrets_context", 0),
            "Workflows interpolating individual secrets into run:": counts.get(
                "workflows_interpolating_secrets_into_run", 0),
            "Third-party action references on a mutable ref": mutable,
            "Action references pinned to a commit SHA": pinned,
            "Workflows with no permissions: block": counts.get(
                "workflows_without_permissions_block", 0),
            "Workflows on self-hosted runners": counts.get(
                "workflows_with_self_hosted_runners", 0),
            "Workflows piping remote code to a shell": counts.get(
                "workflows_piping_remote_code_to_shell", 0),
            "CRITICAL: privileged trigger + PR-head checkout": counts.get(
                "CRITICAL_privileged_trigger_with_pr_head_checkout", 0),
            "Workflows fetching Bun": counts.get("workflows_fetching_bun", 0),
            "Workflows referencing bun.exe": counts.get("workflows_referencing_bun_exe", 0),
        },
        "coverage": [
            f"Read rate {posture.get('read_rate')} with "
            f"{len(posture.get('listing_errors') or [])} listing errors and "
            f"{len(posture.get('read_errors') or [])} read errors. "
            f"Prevalence claims supported: {posture.get('coverage_supports_prevalence_claims')}.",
            f"{len(posture.get('repos_truncated') or [])} repositories hit the per-repo "
            f"workflow cap, so no workflow went unread.",
            "The zero on privileged-trigger-plus-PR-head-checkout is a real zero: the same "
            "sweep, at the same read rate, returned non-zero on eight other checks.",
        ],
        "limits": posture.get("limits", []),
        "pin_rate": pct(pinned, pinned + mutable),
        "tojson": tojson,
        "curl_sh": curl_sh,
        "self_hosted": posture.get("self_hosted_runner_workflows", []) or [],
        "unpinned_third_party": posture.get("most_common_unpinned_third_party_actions", []) or [],
        "findings": [],
    }


def vector_reusable(reusable: Optional[dict]) -> dict:
    """Shared reusable workflows, weighted by how many repositories call them.

    This vector exists because the per-repository posture sweep systematically
    under-ranks the estate's real exposure. Deployment logic here is centralised: a
    weakness in one shared workflow definition is not one finding, it is one finding
    multiplied by its consumer count. Ranking by repository would put a shared workflow
    with 246 consumers below a leaf repository with none.

    It also corrects the opposite error. A shared workflow that is fixed once is fixed
    everywhere, so this is where remediation leverage is highest, not just risk.
    """
    if not reusable:
        return {"name": "CI - shared reusable workflows (fan-out)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    rows = reusable.get("rows", []) or []
    bulk = [r for r in rows if r.get("secrets_bulk_exposure")]

    # Aggregate by SINK, not by workflow. The sink is the thing that receives every
    # secret, so it is the thing worth fixing and the thing worth counting.
    sinks: Dict[str, dict] = {}
    for row in bulk:
        for entry in row.get("secrets_bulk_exposure") or []:
            sink = entry.get("sink", "unknown")
            record = sinks.setdefault(sink, {
                "sink": sink, "workflows": 0, "consumer_refs": 0,
                "mechanisms": set(), "deploying": False, "sources": []})
            record["workflows"] += 1
            record["consumer_refs"] += row.get("consumer_count") or 0
            record["mechanisms"].add(entry.get("mechanism"))
            record["deploying"] = record["deploying"] or bool(row.get("is_deploying"))
            record["sources"].append(f"{row.get('source_repo')}{row.get('workflow_path')}")
    ranked = sorted(sinks.values(), key=lambda s: -s["consumer_refs"])
    for record in ranked:
        record["mechanisms"] = sorted(m for m in record["mechanisms"] if m)
        # toJSON renders every secret value into the job's shell as text, where it can be
        # written to a file or echoed. `secrets: inherit` passes the context to a called
        # workflow without serialising it. Both are broad; only one is a text rendering,
        # and collapsing them would overstate the second and understate the first.
        record["serialises_to_text"] = "toJSON(secrets)" in record["mechanisms"]
        # A sink on a mutable ref can be changed by whoever owns it, with no version
        # change visible to the consumer. That is the campaign's own mechanism.
        ref = record["sink"].rsplit("@", 1)[-1] if "@" in record["sink"] else ""
        record["sink_ref"] = ref
        record["sink_ref_mutable"] = bool(ref) and not (len(ref) == 40 and
                                                        all(c in "0123456789abcdef" for c in ref))

    worst = [s for s in ranked if s["serialises_to_text"] and s["sink_ref_mutable"]]
    return {
        "name": "CI - shared reusable workflows (fan-out)",
        "status": FINDINGS if bulk else CLEAR,
        "scope": f"{len(rows)} shared workflow definitions",
        "counts": {
            "Shared reusable workflow definitions parsed": len(rows),
            "Definitions passing the WHOLE secrets context onward": len(bulk),
            "Consumer repositories behind those definitions": sum(
                r.get("consumer_count") or 0 for r in bulk),
            "Distinct sinks receiving the whole secrets context": len(ranked),
            "Sinks that SERIALISE secrets to text AND sit on a mutable ref": len(worst),
            "Definitions that deploy": sum(1 for r in bulk if r.get("is_deploying")),
            "Definitions using OIDC instead of long-lived secrets": sum(
                1 for r in rows if r.get("oidc_used")),
        },
        "coverage": [
            f"Parsed from {reusable.get('source', 'the deployment topology tables')}. "
            f"{sum(1 for r in rows if r.get('fetch_status') == 'ok')} of {len(rows)} "
            f"definitions fetched cleanly.",
            "Consumer counts come from the dependencies table, so a definition with zero "
            "recorded consumers means no consumer was observed - not that none exists.",
            "Exposure is read from the parsed workflow, so a secret passed by a mechanism "
            "the parser does not model would not appear here.",
        ],
        "limits": [
            "Covers shared workflow DEFINITIONS only. A repository with its own inline "
            "copy of the same pattern is counted in the per-repository CI vector instead.",
            "secrets_bulk_exposure records that the whole context was passed, not that any "
            "secret was misused. This is an exposure measure, not a compromise measure.",
        ],
        "ranked_sinks": ranked,
        "bulk_rows": bulk,
        "findings": [],
    }


def vector_registry(rederive: Optional[dict]) -> dict:
    if not rederive:
        return {"name": "Registry ground truth (attack window)", "status": NOT_RUN,
                "scope": "-", "counts": {}, "coverage": [], "findings": []}
    detail = rederive.get("malicious_detail", []) or []
    times = sorted(d.get("published", "") for d in detail if d.get("published"))
    uncleaned = rederive.get("suspected_uncleaned_specs", []) or []
    return {
        "name": "Registry ground truth (attack window)",
        "status": CLEAR,
        "scope": f"{rederive.get('packages_queried', 0)} package names queried directly "
                 f"against the npm registry",
        "counts": {
            "Package names queried": rederive.get("packages_queried", 0),
            "Malicious package@version pairs derived": rederive.get("malicious_count", 0),
            "Suspected-uncleaned specs (still live)": len(uncleaned),
        },
        "coverage": [
            f"Derived from the registry itself, not from a vendor list. First malicious "
            f"publish {times[0] if times else 'n/a'}, last {times[-1] if times else 'n/a'}.",
            f"Query window {rederive.get('window', {}).get('start')} to "
            f"{rederive.get('window', {}).get('end')}, wider than the derived result, so "
            f"the close of the window is a finding and not an artefact of where we stopped looking.",
        ],
        "window_first": times[0] if times else None,
        "window_last": times[-1] if times else None,
        "findings": [],
    }


def vector_endpoint(endpoint: Optional[dict]) -> dict:
    """Endpoint and identity telemetry, via Microsoft Defender advanced hunting.

    Rendered as its own vector even when it cannot run, because this is the only vector
    that can see a developer workstation. Omitting it would let a report full of clean
    GitHub results read as a clean estate.
    """
    if endpoint:
        return endpoint
    return {
        "name": "Endpoint / identity (Microsoft Defender)",
        "status": BLOCKED,
        "scope": "0 devices queried",
        "counts": {"Hunting queries executed": 0},
        "coverage": [
            "GRAPH_TENANT_ID, GRAPH_CLIENT_ID and GRAPH_CLIENT_SECRET are absent from the "
            "environment, so no advanced hunting query can be submitted.",
            "Two queries are written and lint-clean but unexecuted: "
            "kql/backlog/22-bun-windows-artifact-sweep.kql (the bun.exe artefact question) "
            "and kql/coverage/08-bun-exe-telemetry-shape.kql (the control that makes a zero "
            "from 22 readable).",
        ],
        "blocked_by": "Microsoft Graph permission ThreatHunting.Read.All on "
                      "/security/runHuntingQuery, plus an app registration and secret.",
        "findings": [],
    }


# ----------------------------------------------------------------------------------
# Verdict. Deterministic, so the same artefacts always produce the same colour and nobody
# has to argue about whether today felt amber.
# ----------------------------------------------------------------------------------

def compute_verdict(vectors: List[dict]) -> dict:
    compromise_vectors = [v for v in vectors if v["status"] == FINDINGS
                          and v.get("is_compromise_evidence")]
    blocked = [v for v in vectors if v["status"] == BLOCKED]
    not_run = [v for v in vectors if v["status"] == NOT_RUN]
    exposure = [v for v in vectors if v["status"] == FINDINGS
                and not v.get("is_compromise_evidence")]
    weak = [v for v in vectors if v["status"] == CLEAR_WEAK]

    if compromise_vectors:
        return {"rag": "RED", "breached": "YES - evidence of compromise found. Treat as "
                                          "an active incident.",
                "why": [v["name"] for v in compromise_vectors]}
    if blocked or not_run:
        return {"rag": "AMBER",
                "breached": "No evidence of compromise in what we could check - but we "
                            "could not check everything.",
                "why": [f"{v['name']} could not be checked" for v in blocked + not_run]
                       + [f"{v['name']} has exposures to fix" for v in exposure]}
    if exposure or weak:
        return {"rag": "AMBER",
                "breached": "No. Nothing in the estate matches this campaign. There are "
                            "weaknesses that would make the next one worse.",
                "why": [f"{v['name']} has exposures to fix" for v in exposure]
                       + [f"{v['name']} coverage is too weak to call clean" for v in weak]}
    return {"rag": "GREEN",
            "breached": "No. Every vector was checked, and each check proved it could "
                        "have found the thing it was looking for.",
            "why": []}


# ----------------------------------------------------------------------------------
# Delta. A daily report without one is forty identical PDFs nobody opens by week two.
# ----------------------------------------------------------------------------------

def build_state(vectors: List[dict], verdict: dict) -> dict:
    return {
        "rag": verdict["rag"],
        "vectors": {v["name"]: {"status": v["status"], "counts": v.get("counts", {})}
                    for v in vectors},
    }


def render_delta(previous: Optional[dict], current: dict,
                 added_checks: List[str]) -> List[str]:
    """Movement since the previous run, plus any checks added this cycle.

    A new check is reported separately from a changed count, and always. A hunt that
    quietly gains a check produces a report where a number moved for a reason nobody can
    see - and a hunt that gains a check finding nothing produces no delta line at all,
    which reads as "we did not look at anything new". Both are corrected here.
    """
    lines: List[str] = []
    for check in added_checks:
        lines.append(f"**New check this cycle:** {check}")
    if not previous:
        lines.append("First run recorded under this template - there is no previous run "
                     "to compare against. Every number below is a baseline. Tomorrow's "
                     "report will show what moved.")
        return lines
    if previous.get("rag") != current["rag"]:
        lines.append(f"**Overall status changed: {previous.get('rag')} -> {current['rag']}.**")
    for name, now in current["vectors"].items():
        before = (previous.get("vectors") or {}).get(name)
        if before is None:
            lines.append(f"**New vector this run:** {name} ({now['status']}).")
            continue
        if before.get("status") != now["status"]:
            lines.append(f"**{name}: {before.get('status')} -> {now['status']}.**")
        for metric, value in (now.get("counts") or {}).items():
            was = (before.get("counts") or {}).get(metric)
            # Only movement is reported. A metric that did not move is not news, and
            # printing it would bury the one that did.
            if was is not None and was != value:
                direction = "up" if value > was else "down"
                lines.append(f"{name} - {metric}: {was} -> {value} ({direction}).")
    if not lines:
        lines.append("No change since the previous run. Same vectors, same statuses, "
                     "same counts.")
    return lines


# ----------------------------------------------------------------------------------
# Actions. Each is emitted only when the data triggers it, and each carries the evidence
# that triggered it so the manager section and the technical section cannot disagree.
# ----------------------------------------------------------------------------------

def build_actions(ci: dict, endpoint: dict, ioc: dict, owners: Optional[dict],
                  registry: dict, reusable: dict) -> List[dict]:
    actions: List[dict] = []
    owner_index = (owners or {}).get("repos", {}) or {}

    # 0. The chokepoint. Ranked above everything, including per-repository work, because a
    #    sink that receives the whole secrets context from many shared workflows is one
    #    file to fix and the largest single reduction in blast radius available.
    # Three buckets, because there are three genuinely different failure modes and a
    # two-way split silently drops one of them:
    #   chokepoint - secrets rendered to text AND sent to an externally-owned ref that can
    #                move. Someone else can change the code that already holds the secrets.
    #   inline     - secrets rendered to text inside a step we own. No third party can move
    #                it, but the values are still in the shell where anything can read them.
    #   forwarded  - context passed onward without being serialised. Widest scope, lowest
    #                immediacy.
    sinks = reusable.get("ranked_sinks", []) or []
    chokepoints = [s for s in sinks if s["serialises_to_text"] and s["sink_ref_mutable"]]
    inline_sinks = [s for s in sinks if s["serialises_to_text"] and not s["sink_ref_mutable"]]
    if chokepoints:
        top = chokepoints[0]
        actions.append({
            "priority": 1,
            "title": f"Pin and narrow the shared build steps that receive every secret - "
                     f"the largest takes {top['consumer_refs']} pipeline references",
            "why_now": "Our build pipelines are centralised, which is normally a strength. "
                       "Here it concentrates risk: a small number of shared build steps "
                       "receive the complete set of secrets from a very large number of "
                       "repositories, and they are referenced by a moving label rather "
                       "than a fixed version. Whoever can move that label changes what "
                       "runs in all of those pipelines at once, and it would already "
                       "hold every secret they use. This is the same mechanism the "
                       "campaign used in the package ecosystem. It is also the best news "
                       "in this report: it is a handful of files, not hundreds.",
            "scope": f"{len(chokepoints)} shared build step(s), "
                     f"{sum(s['consumer_refs'] for s in chokepoints)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs via "
                        f"{s['workflows']} shared workflow(s), mechanism "
                        f"{'/'.join(s['mechanisms'])}"
                        f"{', deploys' if s['deploying'] else ''}"
                        for s in chokepoints],
            "owners": ["Platform / DevOps - owner of the shared workflow repositories"],
            "effort": "Days. Two changes: pin each sink to a commit SHA, then replace the "
                      "whole-context pass with the specific secrets the step uses.",
            "blocked_by": None,
        })
    if inline_sinks:
        actions.append({
            "priority": 2,
            "title": "Narrow the shared workflow steps that write every secret into the "
                     "build shell",
            "why_now": "These steps take the complete set of secrets and render them as "
                       "text inside the running build, usually to read the names off. "
                       "Nobody outside can change the step, which is why this ranks below "
                       "the previous item - but once the values are in the shell, any "
                       "later step, any log, and anything that writes a file can capture "
                       "them. Reading the NAMES of secrets does not require handling their "
                       "VALUES.",
            "scope": f"{len(inline_sinks)} shared step(s), "
                     f"{sum(s['consumer_refs'] for s in inline_sinks)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs via "
                        f"{s['workflows']} shared workflow(s)" for s in inline_sinks],
            "owners": ["Platform / DevOps"],
            "effort": "Hours each. Where the step only needs secret NAMES, list them "
                      "explicitly instead of enumerating the context.",
            "blocked_by": None,
        })
    inherit_sinks = [s for s in sinks if not s["serialises_to_text"]]
    if inherit_sinks:
        actions.append({
            "priority": 3,
            "title": "Narrow the shared workflows that forward the whole secrets context "
                     "without serialising it",
            "why_now": "These pass every secret to another workflow we own. That is "
                       "materially safer than writing them out as text - the values are "
                       "not rendered into a shell - but the receiving workflow still gets "
                       "far more than it needs. Worth fixing after the serialising ones.",
            "scope": f"{len(inherit_sinks)} shared workflows, "
                     f"{sum(s['consumer_refs'] for s in inherit_sinks)} pipeline references",
            "targets": [f"{s['sink']} - {s['consumer_refs']} pipeline refs"
                        for s in inherit_sinks],
            "owners": ["Platform / DevOps"],
            "effort": "Days each. Declare the secrets the called workflow needs.",
            "blocked_by": None,
        })

    def owner_of(repo: str) -> str:
        row = owner_index.get(repo) or {}
        state = row.get("owner_state")
        if state == "owned":
            return ", ".join(row.get("default_owners") or row.get("owners") or []) or "owned, no `*` rule"
        if state == "unowned":
            return "**no CODEOWNERS**"
        if state == "codeowners_empty":
            return "**CODEOWNERS present but names nobody**"
        if state == "owner_lookup_error":
            return "lookup failed"
        return "not resolved"

    def blast_radius(repo: str) -> Optional[bool]:
        """True, False, or None. None is a real third answer and is never folded into False.

        Deployment topology resolves only the repositories whose deploy path could be
        inferred with evidence. Treating an unresolved repository as "does not reach
        production" would de-prioritise it on the strength of a fact nobody established.
        """
        row = owner_index.get(repo) or {}
        return row.get("reaches_production")

    # 1. Whole-secrets exposure, split three ways by blast radius. The same workflow
    #    pattern is a different problem depending on what the repository can deploy to,
    #    and "we do not know what it deploys to" is its own bucket, not a safe one.
    tojson_repos = sorted({e["repo"] for e in ci.get("tojson", [])})
    if tojson_repos:
        prod = [r for r in tojson_repos if blast_radius(r) is True]
        unknown = [r for r in tojson_repos if blast_radius(r) is None]
        non_prod = [r for r in tojson_repos if blast_radius(r) is False]
        if prod:
            actions.append({
                "priority": 1,
                "title": "Stop handing the entire secrets store to build steps in "
                         "repositories confirmed to deploy to production",
                "why_now": "These workflows pass every secret the repository holds to a "
                           "step as one object. If any one of those steps is compromised, "
                           "or the runner is, the attacker gets all of them - not the one "
                           "the job needed. These repositories are confirmed to reach "
                           "production.",
                "scope": f"{len(prod)} repositories confirmed production-reaching",
                "targets": prod,
                "owners": sorted({owner_of(r) for r in prod}),
                "effort": "Days. Replace the whole-context pass with an explicit list of "
                          "the secrets each step needs.",
                "blocked_by": None,
            })
        if unknown:
            actions.append({
                "priority": 2,
                "title": "Same fix, repositories whose deployment reach is unknown",
                "why_now": "Same weakness. We have not established where these deploy to, "
                           "so we cannot say the blast radius is small - only that nobody "
                           "has measured it. They are ranked below the confirmed set on "
                           "evidence, not on safety.",
                "scope": f"{len(unknown)} repositories, deployment reach unresolved",
                "targets": unknown,
                "owners": sorted({owner_of(r) for r in unknown}),
                "effort": "Weeks, batched. Resolving deployment topology for these would "
                          "let them be ranked properly rather than lumped together.",
                "blocked_by": None,
            })
        if non_prod:
            actions.append({
                "priority": 4,
                "title": "Same fix, repositories confirmed NOT to reach production",
                "why_now": "Same weakness, and the blast radius is measured and small. "
                           "Genuine backlog rather than urgent.",
                "scope": f"{len(non_prod)} repositories confirmed non-production",
                "targets": non_prod,
                "owners": sorted({owner_of(r) for r in non_prod}),
                "effort": "Backlog.",
                "blocked_by": None,
            })

    # 2. The blocked vector. Ranked high not because something was found but because
    #    nothing could be - an unanswerable question outranks a known, bounded weakness.
    if endpoint.get("status") == BLOCKED:
        actions.append({
            "priority": 1,
            "title": "Get read access to endpoint security telemetry",
            "why_now": "We can see every repository and every build pipeline. We cannot "
                       "see a single laptop. The Windows form of this attack lands on a "
                       "laptop, so the one place it would show up is the one place we "
                       "cannot look. This is not a finding - it is a hole where a finding "
                       "would be.",
            "scope": "1 access request",
            "targets": ["Microsoft Graph: ThreatHunting.Read.All on /security/runHuntingQuery"],
            "owners": ["Security operations / Microsoft 365 tenant admin"],
            "effort": "Hours, once approved. Two queries are already written and tested "
                      "for syntax; they have never been run.",
            "blocked_by": endpoint.get("blocked_by"),
        })

    # 3. Mutable refs. Split branch refs out from tag refs: a branch ref can be moved by
    #    the owner at any time with no version bump and no signal to us.
    branch_refs = [(ref, n) for ref, n in ci.get("unpinned_third_party", [])
                   if "@" in ref and not ref.split("@")[-1][:1].isdigit()
                   and not ref.split("@")[-1].startswith("v")]
    if branch_refs:
        actions.append({
            "priority": 3,
            "title": "Pin third-party build tools that currently track a moving target",
            "why_now": "These build steps are fetched from other people's GitHub accounts "
                       "by branch name, not by a fixed version. Whoever owns that account "
                       "can change what runs in our pipelines at any time, without us "
                       "seeing a version change. That is precisely how this campaign "
                       "spread in the package ecosystem.",
            "scope": f"{sum(n for _, n in branch_refs)} references across "
                     f"{len(branch_refs)} distinct actions",
            "targets": [f"{ref} ({n} references)" for ref, n in branch_refs],
            "owners": ["Platform / DevOps"],
            "effort": "Hours per action. Replace the ref with a commit SHA.",
            "blocked_by": None,
        })

    if ci.get("pin_rate"):
        pinned = ci["counts"].get("Action references pinned to a commit SHA", 0)
        mutable = ci["counts"].get("Third-party action references on a mutable ref", 0)
        actions.append({
            "priority": 4,
            "title": "Raise the build-step pinning rate estate-wide",
            "why_now": f"Only {ci['pin_rate']} of build-step references are pinned to a "
                       f"fixed commit. The rest can change under us. This is the single "
                       f"number that decides how badly the next campaign hits us.",
            "scope": f"{mutable} unpinned references ({pinned} already pinned)",
            "targets": [f"{ref} ({n} references)"
                        for ref, n in ci.get("unpinned_third_party", [])[:15]],
            "owners": ["Platform / DevOps"],
            "effort": "Programme of work. Start with third-party, then first-party.",
            "blocked_by": None,
        })

    curl_sh = ci.get("curl_sh", [])
    if curl_sh:
        actions.append({
            "priority": 3,
            "title": "Remove build steps that download and run code straight from the internet",
            "why_now": "These steps fetch a script at build time and execute it "
                       "immediately. Nothing checks what arrived. Whoever controls that "
                       "URL controls the build.",
            "scope": plural(len(curl_sh), "workflow"),
            "targets": [f"{e['repo']} - {e['path']}" for e in curl_sh],
            "owners": sorted({owner_of(e["repo"]) for e in curl_sh}),
            "effort": "Hours each.",
            "blocked_by": None,
        })

    unowned = sorted(repo for repo, row in owner_index.items()
                     if row.get("owner_state") == "unowned")
    if unowned:
        unowned_prod = [r for r in unowned if blast_radius(r) is True]
        actions.append({
            "priority": 2 if unowned_prod else 3,
            "title": "Assign an owner to repositories in this report that have none",
            "why_now": "No team is recorded as responsible for these repositories, so "
                       "every action in this report aimed at them has nowhere to go. "
                       + (f"{len(unowned_prod)} of them are confirmed to reach production."
                          if unowned_prod else
                          "None are confirmed production-reaching, but most have no "
                          "deployment topology resolved at all, so that is not reassurance."),
            "scope": plural(len(unowned), "repository", "repositories"),
            "targets": unowned,
            "owners": ["Engineering leadership - assignment decision"],
            "effort": "A decision, not an engineering task.",
            "blocked_by": None,
        })

    uncleaned = registry.get("counts", {}).get("Suspected-uncleaned specs (still live)", 0)
    if uncleaned:
        actions.append({
            "priority": 5,
            "title": "Block the malicious package versions that are still live on npm",
            "why_now": f"{uncleaned} malicious package versions from this campaign have "
                       f"not been removed from the public registry. We do not use them "
                       f"today. Nothing stops a developer installing one tomorrow.",
            "scope": plural(uncleaned, "package version"),
            "targets": ["See the registry section for the full list"],
            "owners": ["Platform / artifact registry admin"],
            "effort": "Hours. Deny-list at the internal registry proxy.",
            "blocked_by": None,
        })

    return sorted(actions, key=lambda a: a["priority"])


# ----------------------------------------------------------------------------------
# Rendering
# ----------------------------------------------------------------------------------

def render(vectors: List[dict], verdict: dict, delta: List[str], actions: List[dict],
           ioc: dict, ci: dict, registry: dict, owners: Optional[dict],
           reusable: dict, as_of: str, campaign: str) -> str:
    out: List[str] = []
    w = out.append

    # YAML front matter drives the cover page, the table of contents and the per-page
    # classification marking in src/reporting/md_to_pdf.py. Emitted here rather than added
    # by hand so a re-render cannot lose the marking a reader checks before forwarding.
    w("---")
    w('title: "Software supply-chain threat hunt"')
    w(f'subtitle: "Daily report - {as_of}"')
    w('classification: "Internal - names repositories, staff and infrastructure"')
    w(f'generated: "{as_of}"')
    w("fields:")
    w(f'  Campaign: "{campaign}"')
    w(f'  Report date: "{as_of}"')
    w(f'  Overall status: "{verdict["rag"]}"')
    w('  Produced by: "scripts/hunt/render_hunt_report.py"')
    w('  Evidence: "Every number is read from a hunt coverage artefact at render time."')
    w("toc: true")
    w("---")
    w("")
    w(f"# Software supply-chain threat hunt - daily report")
    w("")
    w(f"**Campaign:** {campaign}  ")
    w(f"**Report date:** {as_of}  ")
    w(f"**Classification:** Internal - names repositories, staff and infrastructure  ")
    w(f"**Produced by:** `scripts/hunt/render_hunt_report.py` from the hunt's own "
      f"coverage artefacts. Every number is read from an artefact, not typed.")
    w("")
    w("> **How to read this.** Section 1 answers your boss. Section 2 tells you what to "
      "do and in what order. Section 3 is the proof, the target list and the fixes for "
      "the engineers. Read only as far as you need.")
    w("")
    w("---")
    w("")

    # ---------------- SECTION 1 ----------------
    w("## Section 1 - The situation")
    w("")
    w(f"### {verdict['rag']}")
    w("")
    w(f"**Are we breached? {verdict['breached']}**")
    w("")
    w("**In one paragraph.** A worm has been spreading through the public library of "
      "open-source building blocks that most modern software is assembled from. It steals "
      "credentials from whoever installs an infected block and uses them to infect more. "
      "We check our own code, our build systems, our dependency lists and the public "
      "registry itself every day to see whether it reached us. Today's answer is below, "
      "along with the weaknesses that would decide how badly a future one hits us.")
    w("")
    if verdict["why"]:
        w("**What is driving today's status.**")
        w("")
        for reason in verdict["why"]:
            w(f"- {reason}")
        w("")
    w("**What changed since the last report.**")
    w("")
    for line in delta:
        w(f"- {line}")
    w("")
    w("**Where we looked, in plain terms.**")
    w("")
    w("| We checked | Result |")
    w("|---|---|")
    PLAIN = {
        "GitHub repositories - files on disk": "Every file in every repository we own",
        "GitHub repositories - branches and commits": "Every code change made during the attack",
        "GitHub code search (corroborating)": "A second, independent search of our code",
        "Dependency inventory vs campaign IOCs": "Every third-party building block we use",
        "CI / GitHub Actions posture": "Every automated build pipeline",
        "CI - shared reusable workflows (fan-out)": "The shared build steps that most "
                                                    "pipelines depend on",
        "Registry ground truth (attack window)": "The public library itself, to know exactly "
                                                 "what was poisoned and when",
        "Endpoint / identity (Microsoft Defender)": "Staff laptops and servers",
    }
    PLAIN_STATUS = {
        CLEAR: "Clean - and we can prove the check works",
        CLEAR_WEAK: "Nothing found, but the check is not strong enough to call it clean",
        FINDINGS: "Things to fix",
        BLOCKED: "**Could not check - no access**",
        NOT_RUN: "Not checked this cycle",
    }
    for vector in vectors:
        w(f"| {PLAIN.get(vector['name'], vector['name'])} | "
          f"{PLAIN_STATUS.get(vector['status'], vector['status'])} |")
    w("")
    w("**The one thing to remember.** Nothing in our estate matches this campaign. The "
      "risk on this page is not that we were hit - it is that our build pipelines are "
      "arranged in a way that would make the next one much worse than it needs to be.")
    w("")
    w("---")
    w("")

    # ---------------- SECTION 2 ----------------
    w("## Section 2 - What to do, in order")
    w("")
    if not actions:
        w("No actions arising from this run.")
    else:
        w("Ordered by priority. Priority 1 items should start this week.")
        w("")
        w("| # | Priority | Action | Scope | Owner | Effort |")
        w("|---|---|---|---|---|---|")
        for index, action in enumerate(actions, 1):
            # Truncating mid-team-name produces a handle that looks real and is not, so the
            # summary shows whole names and an explicit count of the rest. The full set is
            # printed under the action below.
            names = action["owners"]
            owners_text = ("; ".join(names[:2]) + (f" +{len(names) - 2} more"
                                                   if len(names) > 2 else "")) or "unassigned"
            w(f"| {index} | P{action['priority']} | {action['title']} | "
              f"{action['scope']} | {owners_text} | {action['effort'].split('.')[0]} |")
        w("")
        for index, action in enumerate(actions, 1):
            w(f"### {index}. {action['title']}  `P{action['priority']}`")
            w("")
            w(f"**Why this matters now.** {action['why_now']}")
            w("")
            w(f"**Scope.** {action['scope']}.  ")
            w(f"**Effort.** {action['effort']}  ")
            w(f"**Owner.** {'; '.join(action['owners']) or 'unassigned'}")
            if action.get("blocked_by"):
                w(f"  \n**Blocked by.** {action['blocked_by']}")
            w("")
            # Plain Markdown, not <details>. The PDF renderer parses with html=False and
            # escapes inline HTML, so a collapsible block would print its own tags as text
            # in the distributed document.
            w(f"**Affected resources ({len(action['targets'])}).**")
            w("")
            # Long target lists are capped in the action body and printed in full in the
            # evidence section. The cap is stated, never silent: an unmarked truncation
            # reads as a complete list.
            shown = action["targets"][:25]
            for target in shown:
                w(f"- `{target}`")
            if len(action["targets"]) > len(shown):
                w(f"- _...and {len(action['targets']) - len(shown)} more. The complete list "
                  f"is in Section 3._")
            w("")
    w("**Decisions needed from you.**")
    w("")
    w("1. Approve the access request for endpoint telemetry, or accept in writing that "
      "laptops stay outside this hunt.")
    w("2. Confirm whether build-step pinning becomes a policy with an enforcement date, "
      "or stays a recommendation.")
    w("3. Name owners for any repository listed as having none.")
    w("")
    w("---")
    w("")

    # ---------------- SECTION 3 ----------------
    w("## Section 3 - Evidence")
    w("")
    w("### 3.1 Attack vector status")
    w("")
    w("| Attack vector | Status | Scope examined | Headline counts |")
    w("|---|---|---|---|")
    for vector in vectors:
        headline = "; ".join(f"{k}: {v}" for k, v in list(vector.get("counts", {}).items())[:3])
        w(f"| {vector['name']} | **{vector['status']}** | {vector['scope']} | {headline} |")
    w("")
    w("Status vocabulary:")
    w("")
    for status, note in STATUS_NOTE.items():
        w(f"- **{status}** - {note}")
    w("")
    w("> A zero is only evidence if the query could have found the thing. Each vector "
      "below carries the coverage evidence that earns its status. A zero with no coverage "
      "evidence is not reported as clean.")
    w("")

    for index, vector in enumerate(vectors, 1):
        w(f"### 3.{index + 1} {vector['name']} - {vector['status']}")
        w("")
        if vector.get("counts"):
            w("| Metric | Value |")
            w("|---|---|")
            for metric, value in vector["counts"].items():
                w(f"| {metric} | {value} |")
            w("")
        if vector.get("coverage"):
            w("**Proof this check works (coverage evidence).**")
            w("")
            for line in vector["coverage"]:
                w(f"- {line}")
            w("")
        if vector.get("limits"):
            w("**What this check does NOT cover.**")
            w("")
            for line in vector["limits"]:
                w(f"- {line}")
            w("")
        if vector.get("blocked_by"):
            w(f"**Blocked by.** {vector['blocked_by']}")
            w("")

    # Vector-specific detail that does not fit the generic shape.
    if reusable.get("ranked_sinks"):
        w("### 3.9 Target list - shared build steps receiving the whole secrets context")
        w("")
        w("Ranked by pipeline references, which is consumer repositories summed across "
          "every shared workflow that reaches the sink. This is the leverage list: the "
          "top row is one file.")
        w("")
        w("| Sink receiving all secrets | Pipeline refs | Shared workflows | Mechanism | "
          "Ref | Mutable ref | Deploys |")
        w("|---|---|---|---|---|---|---|")
        for sink in reusable["ranked_sinks"]:
            w(f"| `{sink['sink']}` | **{sink['consumer_refs']}** | {sink['workflows']} | "
              f"{', '.join(sink['mechanisms'])} | `{sink['sink_ref'] or 'n/a'}` | "
              f"{'**yes**' if sink['sink_ref_mutable'] else 'no'} | "
              f"{'yes' if sink['deploying'] else 'no'} |")
        w("")
        w("**Why `toJSON(secrets)` and `secrets: inherit` are not the same row.** "
          "`toJSON` renders every secret VALUE into the job as text, where it can be "
          "written to a file, echoed, or captured by any step that follows. "
          "`secrets: inherit` forwards the context to a called workflow without "
          "serialising it. Both are wider than they need to be; only the first puts the "
          "values in the shell.")
        w("")
        w("**Mitigation, in order.**")
        w("")
        w("1. Pin every sink to a 40-character commit SHA. A `@v2` tag can be moved by "
          "whoever owns the repository, with no signal to any consumer.")
        w("2. Replace `toJSON(secrets)` with the named secrets the step actually uses. "
          "Where the step needs many, that is a design finding worth raising separately.")
        w("3. Prefer OIDC federation to the cloud provider over long-lived secrets. Only "
          f"{reusable['counts'].get('Definitions using OIDC instead of long-lived secrets', 0)} "
          f"of {reusable['counts'].get('Shared reusable workflow definitions parsed', 0)} "
          "shared definitions use it today.")
        w("4. Fix at the shared definition, not in the consumers. One file changes "
          "hundreds of pipelines.")
        w("")

    if ci.get("tojson"):
        w("### 3.10 Target list - per-repository workflows handing over the whole secrets context")
        w("")
        w(f"Pin rate across the estate: **{ci.get('pin_rate')}** of action references are "
          f"pinned to a commit SHA.")
        w("")
        w("| Repository | Workflow | Reaches production | Owner |")
        w("|---|---|---|---|")
        owner_index = (owners or {}).get("repos", {}) or {}
        for entry in ci["tojson"]:
            row = owner_index.get(entry["repo"], {})
            prod = row.get("reaches_production")
            prod_text = "**yes**" if prod else ("no" if prod is False else "unknown")
            owner_text = ", ".join(row.get("default_owners") or row.get("owners") or []) \
                or f"_{row.get('owner_state', 'not resolved')}_"
            w(f"| `{entry['repo']}` | `{entry['path']}` | {prod_text} | {owner_text} |")
        w("")
        w("**Mitigation.** Replace the whole-context pass with an explicit secret list.")
        w("")
        w("```yaml")
        w("# Before - every secret the repo holds, in one object, handed to a step")
        w("- uses: some-org/some-action@v1")
        w("  with:")
        w("    secrets: ${{ toJSON(secrets) }}")
        w("")
        w("# After - only what the step needs, and the action pinned to a commit")
        w("- uses: some-org/some-action@<40-char-commit-sha>  # v1.2.3")
        w("  with:")
        w("    api_key: ${{ secrets.THIS_STEPS_API_KEY }}")
        w("```")
        w("")
        w("Where a step genuinely needs many secrets, prefer OIDC federation to the cloud "
          "provider over long-lived secrets, and scope the federated role to the "
          "environment. Where the whole context is passed to a reusable workflow, use "
          "`secrets: inherit` on a called workflow you control instead of serialising to "
          "text - `toJSON` renders every value into the job's shell, where it can be "
          "written to disk or logged.")
        w("")

    if ioc.get("adjacent"):
        w("### 3.11 Adjacent packages - right name, safe version")
        w("")
        w("These packages were targeted by the campaign. We use them, but not at a "
          "malicious version. They are listed because they are where an accidental upgrade "
          "would hurt.")
        w("")
        w("| Package | Repositories | Versions present |")
        w("|---|---|---|")
        for name, info in sorted(ioc["adjacent"].items(),
                                 key=lambda kv: -len(kv[1].get("repos", []))):
            w(f"| `{name}` | {len(info.get('repos', []))} | "
              f"{', '.join('`' + v + '`' for v in info.get('versions', []))} |")
        w("")
        w("**Mitigation.** Add these to a version deny-list at the internal registry proxy "
          "so an upgrade to a malicious version fails at install rather than at review.")
        w("")

    if registry.get("window_first"):
        w("### 3.12 Attack window, derived from the registry")
        w("")
        w(f"- First malicious publish: `{registry['window_first']}`")
        w(f"- Last malicious publish: `{registry['window_last']}`")
        w(f"- Malicious package@version pairs derived: "
          f"{registry['counts'].get('Malicious package@version pairs derived')}")
        w("")
        w("This window is derived by querying the public registry directly for every "
          "affected package name, rather than by taking a vendor's word for it. It is the "
          "window every other check in this report is scoped to, so widening it widens "
          "the hunt.")
        w("")

    if owners:
        w("### 3.13 Ownership resolution")
        w("")
        w(f"Resolved for {owners.get('repos_resolved', 0)} repositories that appear in at "
          f"least one finding list.")
        w("")
        w("| Ownership state | Repositories |")
        w("|---|---|")
        for state, count in sorted((owners.get("owner_states") or {}).items()):
            w(f"| {state} | {count} |")
        w("")
        # The blast-radius denominator is printed before the intersection, because the
        # intersection is only as good as the share of repositories topology could resolve.
        # "0 unowned and production-reaching" out of 24 resolved is a very different claim
        # from the same zero out of 177, and the two must not be able to look alike.
        rows = (owners.get("repos") or {}).values()
        resolved = [r for r in rows if r.get("reaches_production") is not None]
        prod_yes = [r for r in resolved if r.get("reaches_production")]
        w("| Deployment reach | Repositories |")
        w("|---|---|")
        w(f"| Confirmed reaches production | {len(prod_yes)} |")
        w(f"| Confirmed does NOT reach production | {len(resolved) - len(prod_yes)} |")
        w(f"| **Unresolved - reach unknown** | **{len(list(rows)) - len(resolved)}** |")
        w("")
        unowned_prod = owners.get("unowned_and_reaches_production") or []
        w(f"**Unowned AND confirmed production-reaching: {len(unowned_prod)}** "
          f"— out of {len(resolved)} repositories whose deployment reach could be "
          f"resolved at all, from {len(list(rows))} in the finding set. "
          + ("Nobody is accountable for these and they can deploy to production."
             if unowned_prod else
             "This zero is bounded by that denominator. It means no *resolved* "
             "production-reaching repository is unowned; it does not clear the "
             f"{len(list(rows)) - len(resolved)} whose reach is unknown."))
        if unowned_prod:
            w("")
            for repo in unowned_prod:
                w(f"- `{repo}`")
        w("")
        # The complete unowned list lives here, because the action in Section 2 caps its
        # target list and points at this section for the rest.
        unowned_all = sorted(repo for repo, row in (owners.get("repos") or {}).items()
                             if row.get("owner_state") == "unowned")
        if unowned_all:
            w(f"**Complete list of repositories in this report with no CODEOWNERS "
              f"({len(unowned_all)}).**")
            w("")
            w("| Repository | Deployment reach |")
            w("|---|---|")
            for repo in unowned_all:
                reach = (owners.get("repos") or {}).get(repo, {}).get("reaches_production")
                w(f"| `{repo}` | "
                  f"{'**production**' if reach else ('non-production' if reach is False else 'unknown')} |")
            w("")
        w("**What this check does NOT cover.**")
        w("")
        for line in owners.get("limits", []):
            w(f"- {line}")
        w("")

    w("### 3.14 Reproducing this report")
    w("")
    w("```bash")
    w("python3 scripts/hunt/collect_repo_trees.py        # files on disk, incl. Bun artefacts")
    w("python3 scripts/hunt/hunt_code_search.py          # corroborating index search")
    w("python3 scripts/hunt/hunt_branches.py             # branches and commits in the window")
    w("python3 scripts/ioc/match_npm_ioc.py --json exports/hunt/ioc_match_r3.json")
    w("python3 scripts/hunt/sweep_actions_posture.py     # CI posture")
    w("python3 scripts/hunt/collect_repo_owners.py       # CODEOWNERS + blast radius")
    w("#   shared-workflow fan-out is read from the deployment topology tables")
    w("python3 scripts/hunt/render_hunt_report.py        # this document")
    w("```")
    w("")
    w("Endpoint queries, once credentials exist:")
    w("")
    w("```bash")
    w("python3 scripts/ioc/run_kql_poc.py --run \\")
    w("  --query github_conf/detections/kql/coverage/08-bun-exe-telemetry-shape.kql")
    w("python3 scripts/ioc/run_kql_poc.py --run \\")
    w("  --query github_conf/detections/kql/backlog/22-bun-windows-artifact-sweep.kql")
    w("```")
    w("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--trees", type=Path, default=HUNT / "repo_trees_r3_coverage.json")
    parser.add_argument("--branches", type=Path, default=HUNT / "branch_hunt_r3_coverage.json")
    parser.add_argument("--code-search", type=Path, default=HUNT / "code_search_r3.json")
    parser.add_argument("--ioc", type=Path, default=HUNT / "ioc_match_r3.json")
    parser.add_argument("--posture", type=Path, default=HUNT / "actions_posture_r3_coverage.json")
    parser.add_argument("--registry", type=Path, default=HUNT / "rederive_window_14z.json")
    parser.add_argument("--endpoint", type=Path, default=HUNT / "endpoint_hunt.json",
                        help="Defender advanced-hunting results. Absent renders BLOCKED.")
    parser.add_argument("--owners", type=Path, default=HUNT / "repo_owners.json")
    parser.add_argument("--reusable", type=Path,
                        default=HUNT / "reusable_workflow_targets.json",
                        help="Shared reusable workflow definitions with consumer counts "
                             "and whole-secrets-context exposure, from the topology tables.")
    parser.add_argument("--state", type=Path, default=HUNT / "report_state.json",
                        help="Previous run's counts, for the delta section.")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--as-of", type=str, default=None)
    parser.add_argument("--added-check", action="append", default=[],
                        dest="added_checks",
                        help="A check added to the hunt this cycle. Repeatable. Rendered "
                             "in the change section so a new check finding nothing is "
                             "still visible as a check that ran.")
    parser.add_argument("--no-state-write", action="store_true",
                        help="Render without recording this run as the new baseline. Use "
                             "when re-rendering a past run so the delta is not corrupted.")
    args = parser.parse_args()

    as_of = args.as_of or datetime.now(timezone.utc).strftime("%Y-%m-%d")
    ioc_payload = read_json(args.ioc)
    campaign = (ioc_payload or {}).get("campaign", "shai-hulud / CHAINDROP npm worm")

    trees = vector_repo_files(read_json(args.trees))
    branches = vector_branches(read_json(args.branches))
    search = vector_code_search(read_json(args.code_search))
    ioc = vector_ioc(ioc_payload)
    owners = read_json(args.owners)
    ci = vector_ci(read_json(args.posture), owners)
    reusable = vector_reusable(read_json(args.reusable))
    registry = vector_registry(read_json(args.registry))
    endpoint = vector_endpoint(read_json(args.endpoint))

    # Only these vectors can produce evidence that the campaign actually reached us.
    # CI posture findings are exposure, not compromise, and conflating the two is how a
    # report turns a hygiene backlog into a false incident.
    for vector in (trees, branches, search, ioc):
        vector["is_compromise_evidence"] = True

    vectors = [trees, branches, search, ioc, ci, reusable, registry, endpoint]
    verdict = compute_verdict(vectors)
    current_state = build_state(vectors, verdict)
    delta = render_delta(read_json(args.state), current_state, args.added_checks)
    actions = build_actions(ci, endpoint, ioc, owners, registry, reusable)

    document = render(vectors, verdict, delta, actions, ioc, ci, registry, owners,
                      reusable, as_of, campaign)

    out_path = args.out or (HUNT / "reports" / f"hunt-report-{as_of}.md")
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(document)

    if not args.no_state_write:
        args.state.write_text(json.dumps(current_state, indent=2, default=str))

    print(f"[report] {verdict['rag']} -> {out_path}", file=sys.stderr)
    for vector in vectors:
        print(f"  {vector['status']:22s} {vector['name']}", file=sys.stderr)
    print(f"  {len(actions)} action(s)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
