"""
Threat-hunting tools for the zero-day analyst agent.

The existing zero-day tools answer one question: "does anything in our database mention
this string?" That is a keyword lookup against previously collected scan data. It cannot
tell you whether a package version was malicious, whether a build ran during the attack
window, whether a host executed the payload, or whether the estate was even observable at
the time.

These tools add those surfaces, following docs/playbooks/supply-chain-hunt-ttp.md:

  hunt_intel_sources        tiered advisory registry, with URLs
  hunt_registry_truth       registry ground truth — which versions were really malicious
  hunt_arbitrate            reconcile vendor claims against ground truth
  hunt_dependency_exposure  which repositories declare the affected specs
  hunt_ci_activity          workflow runs and deployments inside the attack window
  hunt_coverage_control     prove telemetry exists before believing any zero
  hunt_endpoint_execution   Defender XDR process evidence
  hunt_alerts               unified alerts, correctly paginated
  hunt_access_coverage      what the current credentials can and cannot see

Every tool returns a `coverage` block. That is the point of this module as much as the
queries are: rule 0.1 of the playbook says a zero result is only a finding if a control
proves the query could have returned something, and the previous implementation had no
way to express "I could not see" as distinct from "there was nothing".
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def _utc(dt: Optional[datetime]) -> Optional[datetime]:
    if dt is None:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _parse_when(value: Any) -> Optional[datetime]:
    """Accept a datetime or an ISO-8601 string, including a trailing Z."""
    if value is None or isinstance(value, datetime):
        return _utc(value)
    try:
        return _utc(datetime.fromisoformat(str(value).replace("Z", "+00:00")))
    except ValueError:
        logger.warning(f"Unparseable timestamp: {value!r}")
        return None


# =============================================================================
# Phase 1 — intel and ground truth
# =============================================================================

def hunt_intel_sources(ecosystem: Optional[str] = None,
                       max_tier: int = 3) -> Dict[str, Any]:
    """
    List the threat-intel sources available for a hunt, with URLs and tier.

    Returns real URLs rather than vendor names, so a report can be checked by following
    the citation, and so a reader can see which claims came from an authoritative
    registry and which came from a blog post.
    """
    from src.threat_intel import DISQUALIFIED, SOURCES, Tier

    sources = []
    for source in SOURCES.values():
        if source.tier > max_tier or not source.enabled:
            continue
        if ecosystem and source.ecosystems and ecosystem not in source.ecosystems:
            continue
        sources.append({
            "id": source.id,
            "name": source.name,
            "tier": int(source.tier),
            "tier_name": Tier(source.tier).name,
            "kind": source.kind.value if hasattr(source.kind, "value") else str(source.kind),
            "url": source.url,
            "authoritative": source.is_authoritative,
            "description": source.description,
            "calibration_notes": source.calibration_notes,
        })

    return {
        "sources": sorted(sources, key=lambda s: (s["tier"], s["id"])),
        "count": len(sources),
        "disqualified": {k: v for k, v in DISQUALIFIED.items()},
        "coverage": {
            "note": ("Tier 0 sources are registries and authoritative feeds and decide "
                     "disputes outright. Tiers 1-3 are vendor and press reporting, used "
                     "to widen the hunt scope, never to settle a fact."),
        },
    }


def hunt_registry_truth(packages: List[str], window_start: Any, window_end: Any,
                        ecosystem: str = "npm",
                        force_refresh: bool = False) -> Dict[str, Any]:
    """
    Ask the package registry which versions were actually malicious.

    For npm this is decisive rather than probabilistic. The packument's `time` map retains
    every version ever published, while `versions` lists only what is currently
    published; the difference is the set of unpublished versions. A version both
    published inside the attack window and subsequently unpublished is the attacker's,
    and no advisory is needed to establish it.

    Confidence varies by ecosystem and the result says so: crates.io is strong (`yanked`
    plus `created_at`), RubyGems moderate, and PyPI weakest, because a deleted PyPI
    release leaves no tombstone at all.
    """
    from src.threat_intel import RegistryOracle

    start = _parse_when(window_start)
    end = _parse_when(window_end)
    if not start or not end:
        return {"error": "window_start and window_end must be ISO-8601 timestamps",
                "malicious_specs": [], "coverage": {"usable": False}}

    oracle = RegistryOracle(force_refresh=force_refresh)
    result = oracle.derive_malicious_set(packages, start, end, ecosystem)

    unreachable = result.get("unreachable") or []
    detail = result.get("malicious_detail", [])

    # The searched window and the window the evidence actually supports are different
    # facts, and conflating them is how a report ends up claiming a window "derived from
    # registry timestamps" that is really just the range someone typed in. Narrow the
    # searched window to the first and last malicious publish and report both.
    published = sorted(d["published"] for d in detail if d.get("published"))
    derived_window = (
        {"start": published[0], "end": published[-1],
         "basis": "first and last attacker publish observed in the registry's own time map"}
        if published else
        {"start": None, "end": None,
         "basis": "no attacker-published version found, so no window can be derived"}
    )

    return {
        "ecosystem": ecosystem,
        "window_searched": {"start": start.isoformat(), "end": end.isoformat()},
        # Retained under the original key so existing consumers keep working, but it now
        # carries the derived window when one exists, since that is the defensible one.
        "window": (derived_window if published
                   else {"start": start.isoformat(), "end": end.isoformat()}),
        "derived_window": derived_window,
        "packages_queried": len(packages),
        "packages_with_malicious_versions": sorted({d["name"] for d in detail if d.get("name")}),
        "malicious_version_count": len(detail),
        "malicious_specs": result.get("malicious_specs", []),
        "malicious_detail": detail,
        # Registry cleanup misses: published inside the window, still installable, but
        # with sibling in-window versions withdrawn. Kept out of malicious_specs because
        # the strict rule is what makes that set defensible, and carried in
        # hunt_scope_specs because two of these were confirmed live malware by tarball
        # hash on 2026-08-06 — @ornikar/intl-config@10.0.10 and
        # @ornikar/react-native-svg-transformer@1.0.13, both still serving setup.mjs at
        # fd3ca400… with a preinstall hook. Dropping them here once already turned a
        # real exposure into a silent zero.
        "suspected_uncleaned_specs": result.get("suspected_uncleaned_specs", []),
        "suspected_uncleaned_detail": result.get("suspected_uncleaned_detail", []),
        "hunt_scope_specs": result.get("hunt_scope_specs", []),
        "per_package": result.get("per_package", {}),
        "coverage": {
            "usable": True,
            "unreachable": unreachable,
            "warning": result.get("coverage_warning"),
            "scope_vs_verdict": (
                "Query the estate for hunt_scope_specs; report verdicts from "
                "malicious_specs. They differ by the cleanup misses, and scoping to the "
                "narrower set is how a still-live malicious version goes unsearched."
            ),
            "note": ("Derive the attack window from these publish timestamps, not from "
                     "advisory prose. In the reference run every vendor named a first "
                     "compromised package that the registry shows was the seventh, and "
                     "the true window was 2h40m rather than the 69 minutes reported."),
        },
    }


def hunt_arbitrate(claims: List[Dict[str, Any]],
                   malicious_specs: Optional[List[str]] = None,
                   ground_truth_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Reconcile competing source claims into a hunt scope and a verdict set.

    Two outputs, deliberately different sizes. `hunt_scope` is the union of everything
    any source asserted — hunt all of it, because omission by one vendor is not denial.
    `verdict_set` is only what survived arbitration — report that. Disagreements are
    preserved with the losing source named, so the report shows its work.

    Pass `malicious_specs` from hunt_registry_truth to give arbitration a tier-0 oracle.
    Without it, a unanimous set of vendors that are all wrong together resolves as
    consensus, which is how the reference run first accepted a 69-minute attack window
    that the registry shows was 2h40m.
    """
    from src.threat_intel import Claim, ClaimType, Stance, arbitrate_all

    built: List[Claim] = []
    rejected: List[Dict[str, str]] = []
    for spec in claims:
        # A bare string is the shape a planner reaches for first, and indexing it by name
        # raised TypeError one frame later — which the except clause below did not catch,
        # so the whole arbitration step died instead of reporting an unusable input.
        if not isinstance(spec, dict):
            rejected.append({
                "claim": str(spec)[:120],
                "reason": ("TypeError: claim must be an object with claim_type, subject, "
                           "value and assertions, not a bare "
                           f"{type(spec).__name__}"),
            })
            continue
        try:
            claim = Claim(
                claim_type=ClaimType(spec["claim_type"]),
                subject=spec["subject"],
                value=spec.get("value"),
            )
            for a in spec.get("assertions", []):
                claim.add(
                    a["source_id"],
                    Stance(a.get("stance", "assert")),
                    value=a.get("value"),
                    detail=a.get("detail") or "",
                )
            built.append(claim)
        except (KeyError, ValueError, TypeError) as exc:
            # A dropped claim must surface in the return value, not only in the log. Every
            # claim silently discarded shrinks the verdict set, and an empty verdict set is
            # indistinguishable from "nothing was found" to any caller — including the LLM
            # synthesizing the report. Rejecting all four inputs once produced a completely
            # clean-looking arbitration result.
            logger.warning(f"Skipping malformed claim {spec!r}: {exc}")
            rejected.append({
                "claim": f"{spec.get('claim_type')}:{spec.get('subject')}={spec.get('value')}",
                "reason": f"{type(exc).__name__}: {exc}",
            })

    oracle = None
    if malicious_specs is not None:
        known = set(malicious_specs)

        def oracle(claim):  # noqa: F811 — deliberate: only defined when specs supplied
            """Resolve version-level claims against the registry-derived set.

            Only claim types the registry can actually settle are answered. Returning
            {"resolved": False} for anything else is the honest response: a registry
            knows which versions existed, not what a payload did.
            """
            if claim.claim_type not in (ClaimType.MALICIOUS_VERSION, ClaimType.AFFECTED_PACKAGE):
                return {"resolved": False}
            if claim.claim_type == ClaimType.MALICIOUS_VERSION:
                spec = f"{claim.subject}@{claim.value}"
                return {
                    "resolved": True,
                    "value": spec in known,
                    "url": ground_truth_url or "https://registry.npmjs.org/",
                    "detail": ("Present in the registry-derived malicious set."
                               if spec in known else
                               "Not published-then-unpublished inside the window, so not "
                               "attacker-published on the registry's own evidence."),
                }
            hit = any(s.rsplit("@", 1)[0] == claim.subject for s in known)
            return {
                "resolved": True,
                "value": hit,
                "url": ground_truth_url or "https://registry.npmjs.org/",
                "detail": (f"{claim.subject} has at least one malicious version in the "
                           "derived set." if hit else
                           f"No version of {claim.subject} was published-then-unpublished "
                           "inside the window."),
            }

    result = arbitrate_all(built, ground_truth=oracle)

    caveats = ["Hunt the union (hunt_scope); report the arbitrated set (verdict_set). "
               "A source omitting a package has not denied it."]
    if rejected:
        caveats.append(
            f"REJECTED INPUT: {len(rejected)} of {len(claims)} claims could not be parsed "
            "and were not arbitrated at all. They are absent from hunt_scope and "
            "verdict_set. Do not read their absence as a negative verdict — they were "
            "never assessed. Valid stances are 'assert', 'deny', 'omit'."
        )
    if oracle is None:
        caveats.append(
            "No tier-0 oracle was supplied, so vendor consensus went unchallenged and "
            "every verdict rests on agreement between sources rather than on registry "
            "evidence."
        )

    return {
        "claims_submitted": len(claims),
        "claims_arbitrated": len(built),
        "claims_rejected": rejected,
        "hunt_scope": sorted(result.get("hunt_scope", [])),
        "verdict_set": sorted(result.get("verdict_set", [])),
        "unverified": sorted(result.get("unverified", [])),
        "by_resolution": result.get("by_resolution", {}),
        "results": result.get("results", []),
        "disagreements": result.get("disagreements", []),
        "source_scorecard": result.get("source_scorecard", {}),
        "source_urls": result.get("source_urls", {}),
        "coverage": {
            "usable": bool(built) and not rejected,
            "claims_rejected_count": len(rejected),
            "ground_truth_available": oracle is not None,
            "note": " ".join(caveats),
        },
    }


# =============================================================================
# Phase 3 — dependency exposure
# =============================================================================

def _inventory_control(db, organization_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Per-organization inventory and SBOM collection counts.

    Credential provenance answers "were we allowed to look". This answers the separate
    question "did anything ever get collected". They come apart: on this estate the
    `sleepnumber` organization has a verified owner-scope-listed token and zero
    repositories in the database, so every DB-backed hunt returns a clean zero for it
    while having examined nothing. Without this control that reads as an all-clear.
    """
    from sqlalchemy import func

    from src.api import models

    out: Dict[str, Any] = {"per_organization": {}, "errors": []}
    try:
        orgs = (db.query(models.Organization)
                .filter(models.Organization.is_active.is_(True)).all())
        if organization_id:
            orgs = [o for o in orgs if str(o.id) == str(organization_id)]

        for org in orgs:
            repos = (db.query(func.count(models.Repository.id))
                     .filter(models.Repository.organization_id == org.id).scalar()) or 0
            with_deps = (db.query(func.count(func.distinct(models.Dependency.repository_id)))
                         .join(models.Repository,
                               models.Repository.id == models.Dependency.repository_id)
                         .filter(models.Repository.organization_id == org.id).scalar()) or 0
            dep_rows = (db.query(func.count(models.Dependency.id))
                        .join(models.Repository,
                              models.Repository.id == models.Dependency.repository_id)
                        .filter(models.Repository.organization_id == org.id).scalar()) or 0
            out["per_organization"][org.github_org] = {
                "repositories": repos,
                "repositories_with_dependency_records": with_deps,
                "dependency_rows": dep_rows,
                "sbom_coverage_pct": round(100.0 * with_deps / repos, 1) if repos else 0.0,
            }
    except Exception as exc:  # pragma: no cover - control must never break a hunt
        out["errors"].append(f"inventory_control: {type(exc).__name__}: {exc}")

    per = out["per_organization"]
    out["repositories_total"] = sum(v["repositories"] for v in per.values())
    out["repositories_with_dependency_records_total"] = sum(
        v["repositories_with_dependency_records"] for v in per.values())
    out["organizations_with_no_repositories"] = [
        name for name, v in per.items() if v["repositories"] == 0]
    out["organizations_with_no_dependency_records"] = [
        name for name, v in per.items()
        if v["repositories"] and not v["repositories_with_dependency_records"]]
    total = out["repositories_total"]
    out["sbom_coverage_pct"] = (
        round(100.0 * out["repositories_with_dependency_records_total"] / total, 1)
        if total else 0.0
    )
    return out


def _uncovered_caveat(control: Dict[str, Any]) -> Optional[str]:
    """One sentence naming the organizations a DB-backed zero did not actually cover."""
    empty = control.get("organizations_with_no_repositories") or []
    no_sbom = control.get("organizations_with_no_dependency_records") or []
    parts = []
    if empty:
        parts.append(
            f"{', '.join(empty)} — no repositories are recorded at all, so this "
            "organization contributed nothing to the query and is NOT covered by any "
            "zero above"
        )
    if no_sbom:
        parts.append(
            f"{', '.join(no_sbom)} — repositories are inventoried but no dependency "
            "records exist, so dependency questions could not have been answered for it"
        )
    if not parts:
        return None
    return "NOT COVERED: " + "; ".join(parts) + "."


def hunt_dependency_exposure(db, specs: List[str],
                             organization_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Find repositories declaring any of a set of exact name@version specs.

    Matches on exact version, because a supply-chain hunt is not asking "do we use this
    package" but "do we use the poisoned release". Reports floating ranges separately:
    a repository pinning a safe version is not exposed, while one declaring `^2.5.0` was
    reachable by `2.5.1` even if its lockfile currently says otherwise.

    Code search is not used here. GitHub does not index files larger than 384 KB, and the
    lockfiles in this estate run from 415 KB to 950 KB, so they are structurally
    invisible to it — searching would return a confident zero.
    """
    from .db_tools import search_dependencies

    exposed: Dict[str, Dict[str, Any]] = {}
    per_spec: Dict[str, int] = {}
    floating: List[Dict[str, Any]] = []
    errors: List[str] = []

    for spec in specs:
        name, _, version = spec.rpartition("@")
        if not name:  # bare package name, no version
            name, version = spec, None
        try:
            rows = search_dependencies(
                db, package_name=name, version_spec=version,
                use_fuzzy=False, organization_id=organization_id,
            )
        except Exception as exc:
            errors.append(f"{spec}: {type(exc).__name__}: {exc}")
            continue

        per_spec[spec] = len(rows)
        for row in rows:
            declared = str(row.get("version") or "")
            key = f"{row.get('repository_id')}::{spec}"
            record = {**row, "matched_spec": spec, "declared_version": declared}
            if any(c in declared for c in "^~><*"):
                record["exposure"] = "range_declared"
                floating.append(record)
            else:
                record["exposure"] = "pinned_match"
            exposed[key] = record

    # Family control. A zero for `pkg@6.0.0` means something quite different depending on
    # whether `pkg` appears in the estate at any version: if it does, the query demonstrably
    # works and the version genuinely is not present; if the name never appears, the zero is
    # equally consistent with "not used" and "SBOM never collected for the repos that use
    # it". Only the first case supports a clean bill of health, so record which it is.
    family_presence: Dict[str, Dict[str, Any]] = {}
    try:
        from sqlalchemy import func

        from src.api import models

        for spec in specs:
            name, _, _version = spec.rpartition("@")
            name = name or spec
            if name in family_presence:
                continue
            q = db.query(models.Dependency.version,
                         func.count(models.Dependency.id)).filter(
                models.Dependency.name == name)
            if organization_id:
                q = (q.join(models.Repository,
                            models.Repository.id == models.Dependency.repository_id)
                     .filter(models.Repository.organization_id == organization_id))
            rows = q.group_by(models.Dependency.version).all()
            family_presence[name] = {
                "rows": sum(c for _v, c in rows),
                "versions_present": sorted({str(v) for v, _c in rows})[:40],
            }
    except Exception as exc:
        errors.append(f"family_control: {type(exc).__name__}: {exc}")

    absent_families = [n for n, v in family_presence.items() if not v["rows"]]

    control = _inventory_control(db, organization_id=organization_id)
    caveats = [
        "A zero here means no *recorded* dependency, not no dependency.",
        f"SBOM coverage: {control['repositories_with_dependency_records_total']} of "
        f"{control['repositories_total']} inventoried repositories have dependency records "
        f"({control['sbom_coverage_pct']}%). Any zero below is bounded to that subset; the "
        "remainder was never examined.",
    ]
    uncovered = _uncovered_caveat(control)
    if uncovered:
        caveats.append(uncovered)
    if absent_families:
        caveats.append(
            f"UNBOUNDED ZERO: {', '.join(absent_families)} appear in the dependency records "
            "at no version whatsoever. That is consistent with genuine non-use and equally "
            "consistent with the consuming repositories never having had an SBOM collected. "
            "Do not report these as cleared on this evidence alone."
        )
    present_families = [n for n, v in family_presence.items() if v["rows"]]
    if present_families:
        caveats.append(
            f"CONTROLLED ZERO: {', '.join(present_families)} are present at other versions, "
            "so the query provably can return rows for these names and the absence of the "
            "hunted version is evidence."
        )

    return {
        "specs_queried": len(specs),
        "matches": list(exposed.values()),
        "match_count": len(exposed),
        "per_spec_counts": per_spec,
        "floating_ranges": floating,
        "family_presence": family_presence,
        "coverage": {
            "usable": not errors,
            "errors": errors,
            "method": "database SBOM/dependency records, exact version match",
            "not_used": ("GitHub code search — it does not index files over 384 KB and "
                         "the lockfiles here are 415-950 KB, so it returns false zeros"),
            "inventory_control": control,
            "families_absent_entirely": absent_families,
            "families_present_at_other_versions": present_families,
            "caveat": " ".join(caveats),
        },
    }


# =============================================================================
# Phase 4 — CI/CD execution surface
# =============================================================================

def hunt_ci_activity(db, window_start: Any, window_end: Any,
                     repository_names: Optional[List[str]] = None,
                     organization_id: Optional[str] = None) -> Dict[str, Any]:
    """
    Find workflow runs and deployments that overlap the attack window.

    A build that ran while a poisoned version was live is the mechanism by which a
    lockfile dependency becomes an executed payload. These two tables already existed in
    db_tools and were never reachable by the analyst agent, so this question could not
    previously be asked at all.
    """
    from .db_tools import search_deployments, search_workflow_runs

    start = _parse_when(window_start)
    end = _parse_when(window_end)
    if not start or not end:
        return {"error": "window_start and window_end must be ISO-8601 timestamps",
                "coverage": {"usable": False}}

    now = datetime.now(timezone.utc)
    days_back = max(1, (now - start).days + 1)

    runs, deployments, errors = [], [], []
    targets = repository_names or [None]

    for repo in targets:
        try:
            runs.extend(search_workflow_runs(
                db, repository_name=repo, days_back=days_back,
                organization_id=organization_id,
            ))
        except Exception as exc:
            errors.append(f"workflow_runs({repo}): {type(exc).__name__}: {exc}")
        try:
            deployments.extend(search_deployments(
                db, repository_name=repo, days_back=days_back,
                organization_id=organization_id,
            ))
        except Exception as exc:
            errors.append(f"deployments({repo}): {type(exc).__name__}: {exc}")

    # Distinguish "queried and found nothing in the window" from "this data was never
    # collected". Both return zero rows and they mean opposite things: the first is
    # evidence, the second is a hole. As of this writing both tables are empty
    # estate-wide, so every in-window count here is structurally zero.
    ingestion = {}
    try:
        from sqlalchemy import func

        from src.api import models

        ingestion = {
            "workflow_run_rows_total": db.query(func.count(models.WorkflowRun.id)).scalar(),
            "deployment_rows_total": db.query(func.count(models.Deployment.id)).scalar(),
        }
    except Exception as exc:
        errors.append(f"ingestion_control: {type(exc).__name__}: {exc}")

    never_collected = [
        name for name, key in (("workflow runs", "workflow_run_rows_total"),
                               ("deployments", "deployment_rows_total"))
        if ingestion.get(key) == 0
    ]

    def in_window(row: Dict[str, Any], *fields: str) -> bool:
        for f in fields:
            ts = _parse_when(row.get(f))
            if ts and start <= ts <= end:
                return True
        return False

    runs_in_window = [r for r in runs if in_window(r, "started_at", "created_at", "run_started_at")]
    deploys_in_window = [d for d in deployments if in_window(d, "deployed_at", "created_at")]

    return {
        "window": {"start": start.isoformat(), "end": end.isoformat()},
        "days_back_queried": days_back,
        "workflow_runs_total": len(runs),
        "workflow_runs_in_window": runs_in_window,
        "workflow_runs_in_window_count": len(runs_in_window),
        "deployments_total": len(deployments),
        "deployments_in_window": deploys_in_window,
        "deployments_in_window_count": len(deploys_in_window),
        "coverage": {
            "usable": bool(runs or deployments) and not errors,
            "errors": errors,
            "ingestion_control": ingestion,
            "never_collected": never_collected,
            "caveat": (
                (f"NOT COLLECTED: the {' and '.join(never_collected)} table(s) are empty "
                 "estate-wide, so this query could not have returned anything. Zero "
                 "in-window activity here is not evidence that nothing built or deployed "
                 "— it means CI/CD telemetry was never ingested. Do not report an "
                 "all-clear on execution from this result. ")
                if never_collected else
                "Only runs and deployments already ingested are considered. "
            ) + ("Check hunt_access_coverage for the org's recorded privilege: "
                 "org-level Actions endpoints require owner, and two of the three "
                 "organizations here resolve to member-level tokens."),
        },
    }


def hunt_dead_drop_repos(db, markers: List[str],
                         organization_id: Optional[str] = None,
                         created_after: Any = None) -> Dict[str, Any]:
    """
    Sweep the repository inventory for exfiltration dead-drop markers.

    Worm-class supply-chain malware exfiltrates by creating a repository under the
    victim's own account and writing the stolen data into it. Those repositories carry a
    recognizable description — `Shai-Hulud: Here We Go Again.` in the reference incident
    — so the inventory itself is an exfiltration detector.

    Matches description, name and topics, because the marker string has appeared in all
    three across variants. Also reports repositories created inside the window with no
    marker at all: a renamed dead drop still has an anomalous creation timestamp, and
    that residue is the only signal left once the description is edited.
    """
    from sqlalchemy import Text, cast, or_

    from src.api import models

    if not markers:
        return {"error": "no markers supplied", "coverage": {"usable": False}}

    query = db.query(models.Repository)
    if organization_id:
        query = query.filter(models.Repository.organization_id == organization_id)

    conditions = []
    for marker in markers:
        pattern = f"%{marker}%"
        conditions.append(models.Repository.description.ilike(pattern))
        conditions.append(models.Repository.name.ilike(pattern))
        # topics is JSONB; cast to text so a marker inside the array is reachable.
        conditions.append(cast(models.Repository.topics, Text).ilike(pattern))

    matches = query.filter(or_(*conditions)).all()

    def summarize(repo):
        return {
            "id": str(repo.id),
            "name": repo.name,
            "full_name": repo.full_name,
            "description": repo.description,
            "visibility": repo.visibility,
            "is_private": repo.is_private,
            "created_at": repo.github_created_at.isoformat() if repo.github_created_at else None,
            "pushed_at": repo.pushed_at.isoformat() if repo.pushed_at else None,
            "url": repo.url,
            "topics": repo.topics,
        }

    window_created = []
    cutoff = _parse_when(created_after)
    if cutoff:
        rows = (query.filter(models.Repository.github_created_at.isnot(None))
                .filter(models.Repository.github_created_at >= cutoff.replace(tzinfo=None))
                .all())
        window_created = [summarize(r) for r in rows]

    total = query.count()
    control = _inventory_control(db, organization_id=organization_id)
    note = ("A zero is only meaningful if the inventory is current. "
            f"{total} repositories were in scope for this query, distributed as "
            + ", ".join(f"{name}={v['repositories']}"
                        for name, v in control["per_organization"].items())
            + ".")
    uncovered = _uncovered_caveat(control)
    if uncovered:
        note += " " + uncovered
    return {
        "markers": markers,
        "marker_matches": [summarize(r) for r in matches],
        "marker_match_count": len(matches),
        "created_in_window": window_created,
        "created_in_window_count": len(window_created),
        "repositories_searched": total,
        "repositories_by_organization": {
            name: v["repositories"] for name, v in control["per_organization"].items()
        },
        "coverage": {
            "usable": total > 0,
            "inventory_control": control,
            "note": note,
            "caveat": ("Dead drops are created under the *victim user's* account, which "
                       "may sit outside every scanned organization. An org-scoped sweep "
                       "cannot see those; user-namespace repositories must be checked "
                       "separately, and a clean result here does not cover them."),
            "second_signal": ("created_in_window lists repositories created inside the "
                              "window regardless of marker, because renaming a dead drop "
                              "removes the marker but not the timestamp."),
        },
    }


# =============================================================================
# Phase 5 — endpoint and identity telemetry
# =============================================================================

def hunt_coverage_control(db, hours: int = 24) -> Dict[str, Any]:
    """
    Prove telemetry exists before any zero from Defender is believed.

    Run this first. If it returns nothing, the pipeline is the finding and every other
    query in the hunt is uninterpretable.
    """
    from src.api.integrations.msgraph import GraphClient, GraphError

    try:
        client = GraphClient.from_db(db)
        return client.coverage_control(hours=hours)
    except GraphError as exc:
        return {
            "telemetry_present": False,
            "error": str(exc),
            "interpretation": ("Could not establish a telemetry control. Do not report "
                               "any Defender result from this run as evidence of absence."),
        }


_BROWSERS = ("msedge.exe", "chrome.exe", "firefox.exe", "iexplore.exe", "brave.exe",
             "opera.exe", "safari")

# Tools an analyst runs while hunting. Their presence in the results is the hunt observing
# itself: searching DeviceProcessEvents for `keyv` returns the grep that searched for keyv.
_ANALYST_TOOLS = ("grep", "rg", "ripgrep", "findstr", "ack", "ag", "claude", "zsh", "bash",
                  "sh", "fish", "pwsh", "powershell", "python", "python3", "node", "gh",
                  "git", "xargs", "jq", "curl", "sandbox-exec", "env", "code", "docker")

_TAKE_LIMIT = 500


def _classify_hit(row: Dict[str, Any], indicators: List[str]) -> str:
    """
    Say why a row matched, so a count is not mistaken for a compromise count.

    The live case that motivated this: searching for `shai-hulud` over seven days returned
    eight `msedge.exe` events launched by Teams. Every one was a staff member clicking a
    Safe Links wrapper around a Chainguard or Phoenix write-up of the incident. The
    indicator was in the URL, doubly percent-encoded, and never executed. Reported as a
    raw count those eight rows read as endpoint compromise on two managed workstations.

    Classification is conservative: a hit is only demoted when the process is a browser
    AND the indicator appears solely inside a URL. Anything else stays an execution
    candidate, because a false negative here is far more costly than a false positive.
    """
    file_name = str(row.get("FileName") or "").lower()
    initiator = str(row.get("InitiatingProcessFileName") or "").lower()
    if not (any(b in file_name for b in _BROWSERS) or any(b in initiator for b in _BROWSERS)):
        return "execution_candidate"

    from urllib.parse import unquote

    command = str(row.get("ProcessCommandLine") or "")
    decoded = unquote(unquote(command)).lower()
    if "http://" not in decoded and "https://" not in decoded:
        return "execution_candidate"

    for indicator in indicators:
        needle = indicator.lower()
        position = decoded.find(needle)
        while position != -1:
            # Walk back to the token start; if no scheme precedes the match within the
            # same whitespace-delimited token, the indicator is not part of a URL.
            token_start = max(decoded.rfind(" ", 0, position),
                              decoded.rfind('"', 0, position)) + 1
            token = decoded[token_start:position]
            if "http://" not in token and "https://" not in token:
                return "execution_candidate"
            position = decoded.find(needle, position + 1)

    return "url_reference_in_browser"


def _is_analyst_tooling(row: Dict[str, Any]) -> bool:
    """
    Whether a row is plausibly the investigation appearing in its own results.

    Searching process telemetry for `keyv` returns every `grep keyv` an analyst ran while
    hunting, and on this estate that was 110 grep, 133 zsh and 163 claude events across
    four analyst workstations — 487 rows that read as widespread execution.

    These rows are flagged but deliberately NOT removed from the execution-candidate
    count. An attacker running a payload from a shell would land in exactly this bucket,
    and suppressing the bucket would hide them. The count stays conservative; the flag
    tells a reader which rows to triage first.
    """
    name = str(row.get("FileName") or "").lower()
    stem = name.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    stem = stem[:-4] if stem.endswith(".exe") else stem
    return any(stem == tool or stem.startswith(tool) for tool in _ANALYST_TOOLS)


def hunt_endpoint_execution(db, indicators: List[str], hours: int = 168,
                            table: str = "DeviceProcessEvents") -> Dict[str, Any]:
    """
    Search Defender XDR process telemetry for indicator strings.

    Establishes the telemetry control first and refuses to interpret a zero without it.
    Note the platform limit that matters locally: Docker Desktop on macOS runs a Linux
    VM, so processes inside a container are invisible to the macOS Defender agent. The
    host-side `docker` invocation is captured; what the container ran is not.
    """
    from src.api.integrations.msgraph import GraphClient, GraphError, KqlLintError

    if not indicators:
        return {"error": "no indicators supplied", "coverage": {"usable": False}}

    try:
        client = GraphClient.from_db(db)
    except GraphError as exc:
        return {"error": str(exc), "coverage": {"usable": False}}

    control = client.coverage_control(hours=min(hours, 24))
    escaped = ", ".join('"' + i.replace('"', '\\"') + '"' for i in indicators)
    query = f"""
{table}
| where Timestamp > ago({hours}h)
| where ProcessCommandLine has_any ({escaped})
    or InitiatingProcessCommandLine has_any ({escaped})
    or FileName has_any ({escaped})
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine,
          InitiatingProcessFileName, InitiatingProcessCommandLine
| order by Timestamp desc
| take {_TAKE_LIMIT}
"""

    try:
        result = client.run_hunting_query(query.strip())
    except (GraphError, KqlLintError) as exc:
        return {"error": str(exc), "coverage": {"usable": False,
                                                "control": control.get("telemetry_present")}}

    classified = []
    for row in result.rows:
        classified.append(dict(
            row,
            indicator_context=_classify_hit(row, indicators),
            analyst_tooling=_is_analyst_tooling(row),
        ))
    reference_only = [r for r in classified
                      if r["indicator_context"] == "url_reference_in_browser"]
    execution_candidates = [r for r in classified
                            if r["indicator_context"] != "url_reference_in_browser"]
    analyst_rows = [r for r in execution_candidates if r["analyst_tooling"]]

    # Which indicator produced the volume. A bare word like `keyv` matches every path
    # containing it, so a per-indicator breakdown is what tells a reader whether 487 hits
    # came from a real IOC or from one over-broad search term.
    per_indicator: Dict[str, int] = {}
    for indicator in indicators:
        needle = indicator.lower()
        per_indicator[indicator] = sum(
            1 for r in classified
            if needle in " ".join(str(r.get(f) or "").lower() for f in
                                  ("ProcessCommandLine", "InitiatingProcessCommandLine",
                                   "FileName"))
        )

    truncated = result.count >= _TAKE_LIMIT
    caveats = [
        "Advanced hunting retains 30 days. A zero bounds that window only.",
        "Containers on macOS hosts are invisible to the endpoint agent; the "
        "host-side docker invocation is captured, the in-container process is not.",
        "has_any with a bare word matches substrings — verify each hit rather "
        "than counting rows.",
    ]
    if reference_only:
        caveats.append(
            f"{len(reference_only)} of {result.count} hits are browser navigations whose "
            "only match is inside a URL — staff reading vendor write-ups about the "
            "incident, not the indicator executing. They are retained in `rows` but "
            "excluded from execution_candidate_count. Counting all rows as compromise "
            "would have inverted this result."
        )
    if analyst_rows:
        tools = sorted({str(r.get("FileName") or "?") for r in analyst_rows})[:8]
        devices = sorted({str(r.get("DeviceName") or "?") for r in analyst_rows})
        caveats.append(
            f"{len(analyst_rows)} of {len(execution_candidates)} execution candidates are "
            f"analyst tooling ({', '.join(tools)}) on {len(devices)} host(s) — the "
            "investigation observing itself: a search for these indicators returns the "
            "commands that searched for them. They remain counted, because a payload run "
            "from a shell is indistinguishable here and suppressing the bucket would hide "
            "it. Triage these rows before treating the count as compromise."
        )
    if truncated:
        caveats.append(
            f"TRUNCATED: the query caps at {_TAKE_LIMIT} rows and returned exactly "
            f"{result.count}, so this is a floor and not a total. The real number is "
            "unknown and may be far larger. Narrow the indicators or the window and re-run "
            "before quoting any count from this result."
        )
    broad = [i for i, n in per_indicator.items() if n >= _TAKE_LIMIT // 2 and len(i) <= 12]
    if broad:
        caveats.append(
            f"OVER-BROAD INDICATORS: {', '.join(broad)} each matched a large share of the "
            "result set. Short bare words match any path or argument containing them and "
            "are not indicators of compromise on their own. Re-run with full file names, "
            "hashes, or exact marker strings."
        )

    return {
        "table": table,
        "indicators": indicators,
        "hours": hours,
        "count": result.count,
        "execution_candidate_count": len(execution_candidates),
        "url_reference_count": len(reference_only),
        "analyst_tooling_count": len(analyst_rows),
        "hits_per_indicator": per_indicator,
        "execution_candidates": execution_candidates,
        "rows": classified,
        "query": result.query,
        "coverage": {
            "usable": control.get("telemetry_present", False),
            "truncated": truncated,
            "row_limit": _TAKE_LIMIT,
            "control_events": control.get("total_events"),
            "control_devices": control.get("max_devices_in_any_hour"),
            "interpretation": control.get("interpretation"),
            "warnings": result.warnings,
            "caveats": caveats,
        },
    }


def hunt_alerts(db, days: int = 7, severities: Optional[List[str]] = None,
                title_contains: Optional[str] = None) -> Dict[str, Any]:
    """
    List unified alerts across the window, paginated correctly.

    alerts_v2 silently caps a response at 100 rows and supplies no continuation link, so
    a single call reads as a complete answer when it is not. Over a recent 7-day window
    the correct count was 514 against a naive 100. Title matching is applied client-side
    because `title` is not $filter-able.
    """
    from src.api.integrations.msgraph import GraphClient, GraphError

    try:
        client = GraphClient.from_db(db)
    except GraphError as exc:
        return {"error": str(exc), "coverage": {"usable": False}}

    until = datetime.now(timezone.utc)
    try:
        result = client.list_alerts(since=until - timedelta(days=days), until=until,
                                    severities=severities)
    except GraphError as exc:
        return {"error": str(exc), "coverage": {"usable": False}}

    alerts = result["alerts"]
    if title_contains:
        needle = title_contains.lower()
        alerts = [a for a in alerts if needle in (a.get("title") or "").lower()]

    return {
        "count": len(alerts),
        "total_in_window": result["count"],
        "alerts": alerts,
        "window": result["window"],
        "api_calls": result["api_calls"],
        "coverage": {
            "usable": True,
            "truncated": result["truncated"],
            "warnings": result["warnings"],
            "note": result["note"],
        },
    }


# =============================================================================
# Access coverage
# =============================================================================

def hunt_access_coverage(db) -> Dict[str, Any]:
    """
    Report what the current credentials can and cannot reach.

    Belongs in every hunt result. Two of the three GitHub organizations resolve to a
    member-level token, which means org runner enumeration returns 403 and private
    repositories not individually granted are invisible. Without this block, those
    absences read as clean results.
    """
    from src.api import credentials as cred_service
    from src.api import models

    control = _inventory_control(db)
    per_org_inventory = control["per_organization"]

    orgs = []
    for org in db.query(models.Organization).order_by(models.Organization.name).all():
        resolved = cred_service.resolve_github_token(db, org)
        entry = {"organization": org.github_org, **resolved.provenance()}
        entry["inventory"] = per_org_inventory.get(org.github_org) or {
            "repositories": 0, "repositories_with_dependency_records": 0,
            "dependency_rows": 0, "sbom_coverage_pct": 0.0,
        }
        orgs.append(entry)

    graph = cred_service.resolve_graph_credentials(db)
    graph_block = graph.provenance()
    try:
        from src.api.integrations.msgraph import GraphClient

        client = GraphClient.from_db(db)
        graph_block["verified"] = client.verify()
    except Exception as exc:
        graph_block["verified"] = {"status": "error", "detail": str(exc)}

    blind_spots = []
    for entry in orgs:
        for gap in entry.get("known_gaps", []):
            blind_spots.append(f"{entry['organization']}: {gap}")
        # A shared fallback credential is owned but not org-specific, and the difference
        # is material: sleepnumber has no dedicated token, so it inherits the identity and
        # privilege of whichever account the tenant-wide credential belongs to. That is
        # the recorded cause of three private repositories being invisible to scans.
        if entry.get("source") in ("db_global", "env_default") and entry.get("organization"):
            blind_spots.append(
                f"{entry['organization']}: no organization-specific credential; resolved "
                f"via the shared tenant-wide token at {entry.get('privilege_level')} level. "
                "Whatever that identity cannot see, this organization's results omit."
            )
        if entry.get("privilege_level") in ("unknown", None):
            blind_spots.append(
                f"{entry['organization']}: privilege level was never verified, so the "
                "extent of visibility is unknown rather than known-good. Run "
                "POST /credentials/github/verify."
            )
        # Permission to look and having looked are different facts, and a verified
        # credential over an empty inventory is the more dangerous of the two failures
        # because it produces confident zeros. Reported at credential level so it appears
        # in the same block a reader consults before believing any result.
        inv = entry["inventory"]
        if inv["repositories"] == 0:
            blind_spots.append(
                f"{entry['organization']}: credential resolves and verifies, but ZERO "
                "repositories are recorded in the database for this organization. Every "
                "database-backed hunt result returns an empty set for it while having "
                "examined nothing. This organization is NOT covered by any zero in this "
                "hunt. Run a repository scan before treating it as clear."
            )
        elif inv["repositories_with_dependency_records"] == 0:
            blind_spots.append(
                f"{entry['organization']}: {inv['repositories']} repositories inventoried "
                "but none carry dependency records, so no dependency or SBOM question was "
                "answerable for this organization."
            )
        elif inv["sbom_coverage_pct"] < 50:
            blind_spots.append(
                f"{entry['organization']}: dependency records exist for only "
                f"{inv['repositories_with_dependency_records']} of {inv['repositories']} "
                f"repositories ({inv['sbom_coverage_pct']}%). Dependency zeros are bounded "
                "to that subset and say nothing about the remainder."
            )
    for gap in graph_block.get("known_gaps", []):
        blind_spots.append(f"graph: {gap}")

    return {
        "github": orgs,
        "graph": graph_block,
        "blind_spots": blind_spots,
        "coverage": {
            "borrowed_credentials": [o["organization"] for o in orgs
                                     if not o.get("owned_by_auditgithub")],
            "inventory_control": control,
            "organizations_with_no_data": control["organizations_with_no_repositories"],
            "note": ("Any surface listed in blind_spots must be reported as unexamined. "
                     "A hunt may not convert 'not permitted to look' into 'nothing found', "
                     "nor 'never collected' into 'nothing there'."),
        },
    }


# Tool descriptions handed to the planner. Kept next to the implementations so the
# advertised surface cannot drift from the callable one.
HUNT_TOOL_SPECS = [
    {"name": "hunt_intel_sources",
     "signature": "hunt_intel_sources(ecosystem=None, max_tier=3)",
     "description": "List threat-intel sources with real URLs and evidentiary tier. "
                    "Tier 0 registries decide disputes; tiers 1-3 widen scope only."},
    {"name": "hunt_registry_truth",
     "signature": "hunt_registry_truth(packages, window_start, window_end, ecosystem='npm')",
     "description": "Ask the package registry which versions were actually malicious "
                    "(published in window AND later unpublished). Decisive for npm. Use "
                    "this to derive the attack window instead of trusting advisories."},
    # The shape of `claims` is spelled out because leaving it implicit produced bare
    # strings from the planner, and the tool then arbitrated nothing at all.
    {"name": "hunt_arbitrate",
     "signature": ("hunt_arbitrate(claims, malicious_specs=None) where claims is a list "
                   "of objects, each {\"claim_type\": one of malicious_version|"
                   "affected_package|timestamp|ioc_hash|ioc_filename|ioc_network|"
                   "ioc_marker|persistence|scope_count|mitigation|safe_version, "
                   "\"subject\": package or entity name, \"value\": the asserted value, "
                   "\"assertions\": [{\"source_id\": source id from hunt_intel_sources, "
                   "\"stance\": assert|deny|omit, \"detail\": why}]}"),
     "description": "Reconcile conflicting vendor claims against ground truth. Returns "
                    "hunt_scope (union, hunt all of it) and verdict_set (report this). "
                    "Claims must be objects, not strings: a bare \"pkg@1.2.3\" carries no "
                    "source or stance, so there is nothing to arbitrate and it is "
                    "rejected. Example: [{\"claim_type\": \"malicious_version\", "
                    "\"subject\": \"keyv\", \"value\": \"6.0.0\", \"assertions\": "
                    "[{\"source_id\": \"socket\", \"stance\": \"assert\", \"detail\": "
                    "\"named in advisory\"}, {\"source_id\": \"phoenix\", \"stance\": "
                    "\"deny\", \"detail\": \"absent from their list\"}]}]"},
    {"name": "hunt_dependency_exposure",
     "signature": "hunt_dependency_exposure(specs)",
     "description": "Which repositories declare these exact name@version specs. Also "
                    "flags floating ranges that could have resolved to a bad version."},
    {"name": "hunt_dead_drop_repos",
     "signature": "hunt_dead_drop_repos(markers, created_after=None)",
     "description": "Sweep the repository inventory for exfiltration dead-drop markers "
                    "(e.g. 'Shai-Hulud: Here We Go Again.'), plus repositories created "
                    "in the window with no marker — a renamed dead drop keeps its date."},
    {"name": "hunt_ci_activity",
     "signature": "hunt_ci_activity(window_start, window_end, repository_names=None)",
     "description": "Workflow runs and deployments overlapping the attack window — the "
                    "mechanism turning a declared dependency into an executed payload."},
    {"name": "hunt_coverage_control",
     "signature": "hunt_coverage_control(hours=24)",
     "description": "Prove Defender telemetry exists. Run FIRST. If this is empty, every "
                    "other zero in the hunt is uninterpretable."},
    {"name": "hunt_endpoint_execution",
     "signature": "hunt_endpoint_execution(indicators, hours=168)",
     "description": "Search Defender XDR process telemetry for indicator strings, with "
                    "the telemetry control attached to the result."},
    {"name": "hunt_alerts",
     "signature": "hunt_alerts(days=7, severities=None, title_contains=None)",
     "description": "Unified alerts, paginated around the silent 100-row cap. Title is "
                    "matched client-side because it is not $filter-able."},
    {"name": "hunt_access_coverage",
     "signature": "hunt_access_coverage()",
     "description": "What the current credentials can and cannot see, per organization. "
                    "Include in every hunt so blind spots are not read as clean results."},
]
