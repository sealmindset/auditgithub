"""
Render hunt evidence and coverage limits into report sections.

One definition, consumed by all four zero-day exporters (PDF, DOCX, and both
repository-list variants). Without a shared builder the coverage section would exist in
some formats and not others, and a reader would have no way to tell which document was
complete — a PDF that omits the blind-spot list looks like a hunt that had none.

Section shape:
    {"heading": str, "paragraphs": [str], "table": {"headers": [...], "rows": [[...]]}}

Both `paragraphs` and `table` are optional. The caller renders them; this module decides
only what is worth saying.
"""

from typing import Any, Dict, List, Optional


def _s(value: Any, default: str = "") -> str:
    if value is None:
        return default
    return value if isinstance(value, str) else str(value)


def coverage_section(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Build the coverage / blind-spot section.

    Returned even when the hunt found nothing to report, because "no coverage data was
    recorded" is itself a caveat a reader must see. Only returns None when the payload
    carries no hunt fields at all, i.e. an analysis predating this feature, where
    inventing a section would misrepresent what was run.
    """
    notes = payload.get("coverage_notes")
    hunt_enabled = payload.get("hunt_enabled")
    orgs = payload.get("organizations_in_scope")
    evidence = payload.get("hunt_evidence")

    if notes is None and hunt_enabled is None and not evidence:
        return None

    paragraphs: List[str] = []
    if orgs:
        paragraphs.append("Organizations in scope: " + ", ".join(_s(o) for o in orgs))

    if hunt_enabled is False:
        paragraphs.append(
            "External evidence was NOT gathered: the requesting account does not hold the "
            "hunt:execute permission. Package-registry ground truth, CI/CD activity, "
            "endpoint telemetry and alert data were not consulted. Nothing in this report "
            "may be read as evidence about those surfaces."
        )
    elif hunt_enabled is True:
        paragraphs.append("External evidence surfaces were available to this run.")

    if notes:
        paragraphs.append(
            "The following limits applied. Each one marks a surface that was not examined; "
            "an absence of findings on these surfaces is not a finding of absence:"
        )
        paragraphs.extend(f"• {_s(n)}" for n in notes)
    elif notes is not None:
        paragraphs.append(
            "No coverage limits were recorded. Treat this with suspicion unless the access "
            "coverage tool ran: with no coverage data, no zero result in this report can "
            "be interpreted."
        )

    return {"heading": "Coverage and Blind Spots", "paragraphs": paragraphs}


def arbitration_section(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Ground truth, the arbitrated verdict set, and where sources disagreed."""
    evidence = payload.get("hunt_evidence") or {}
    registry = evidence.get("hunt_registry_truth") or {}
    arb = evidence.get("hunt_arbitrate") or {}
    if not registry and not arb:
        return None

    paragraphs: List[str] = []

    if registry:
        searched = registry.get("window_searched") or registry.get("window") or {}
        derived = registry.get("derived_window") or {}
        if derived.get("start"):
            paragraphs.append(
                f"Attack window derived from registry publish timestamps: "
                f"{_s(derived.get('start'))} to {_s(derived.get('end'))} — the "
                f"{_s(derived.get('basis'), 'registry time map')}. This is the registry's "
                f"own record, not an advisory's summary of it. The range searched was "
                f"{_s(searched.get('start'), 'unknown')} to "
                f"{_s(searched.get('end'), 'unknown')}; anything outside that range was "
                f"not examined, so the derived window is a lower bound on the attack."
            )
        else:
            paragraphs.append(
                f"No attacker-published version was found in "
                f"{_s(searched.get('start'), 'unknown')} to "
                f"{_s(searched.get('end'), 'unknown')}, so no attack window could be "
                f"derived. A wider search range may be required before concluding anything."
            )
        specs = registry.get("malicious_specs") or []
        affected = registry.get("packages_with_malicious_versions") or []
        paragraphs.append(
            f"Authoritative malicious set: {len(specs)} version(s) across "
            f"{len(affected)} of {registry.get('packages_queried', 0)} packages queried"
            + (": " + ", ".join(_s(s) for s in specs) if specs else " — none established")
        )
        warning = (registry.get("coverage") or {}).get("warning")
        if warning:
            paragraphs.append(f"Registry coverage warning: {_s(warning)}")

    if arb:
        hunt_scope = arb.get("hunt_scope") or []
        verdict = arb.get("verdict_set") or []
        unverified = arb.get("unverified") or []
        paragraphs.append(
            f"Arbitration: {len(hunt_scope)} claims were hunted (the union of everything "
            f"any source asserted), {len(verdict)} survived arbitration and are reported "
            f"as established, {len(unverified)} remain unverified and are reported as such."
        )
        if unverified:
            paragraphs.append("Unverified claims: " + ", ".join(_s(u) for u in unverified))
        rejected = arb.get("claims_rejected") or []
        if rejected:
            paragraphs.append(
                f"NOT ARBITRATED: {len(rejected)} of {arb.get('claims_submitted', 0)} "
                "submitted claims were malformed and never assessed. They appear in no set "
                "above, and their absence is not a verdict: "
                + "; ".join(f"{_s(r.get('claim'))} ({_s(r.get('reason'))})" for r in rejected)
            )
        if (arb.get("coverage") or {}).get("ground_truth_available") is False:
            paragraphs.append(
                "No registry ground truth was available to this arbitration, so vendor "
                "consensus went unchallenged. Verdicts rest on source agreement, not on "
                "registry evidence, and a unanimous error would survive."
            )
        for url_source, url in (arb.get("source_urls") or {}).items():
            paragraphs.append(f"• {_s(url_source)}: {_s(url)}")

    table = None
    disagreements = arb.get("disagreements") or []
    if disagreements:
        rows = []
        for d in disagreements:
            rows.append([
                _s(d.get("subject"))[:40],
                _s(d.get("claimed_value"))[:24],
                _s(d.get("resolution"))[:18],
                ", ".join(_s(x) for x in (d.get("incorrect_sources") or []))[:30],
                _s(d.get("rationale"))[:220],
            ])
        table = {"headers": ["Subject", "Claimed", "Resolution", "Contradicted", "Basis"],
                 "rows": rows}

    scorecard = arb.get("source_scorecard") or {}
    if scorecard:
        paragraphs.append(
            "Source scorecard (carried into future hunts so a source proven wrong starts "
            "calibrated): "
            + "; ".join(f"{_s(k)} correct={v.get('correct', 0)} incorrect={v.get('incorrect', 0)}"
                        for k, v in scorecard.items())
        )

    return {"heading": "Ground Truth and Source Arbitration",
            "paragraphs": paragraphs, "table": table}


def evidence_section(payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Execution evidence: CI activity, endpoint telemetry, alerts, dead drops."""
    evidence = payload.get("hunt_evidence") or {}
    if not evidence:
        return None

    paragraphs: List[str] = []

    access = evidence.get("hunt_access_coverage")
    if access:
        for entry in access.get("github", []):
            inv = entry.get("inventory") or {}
            # Privilege alone reads as coverage. Printing the inventory beside it is what
            # stops an organization with a verified token and no collected data from
            # appearing in this list indistinguishably from a fully scanned one.
            inv_text = (
                f", {inv.get('repositories', 0)} repositories recorded / "
                f"{inv.get('repositories_with_dependency_records', 0)} with dependency data"
                if inv else ""
            )
            paragraphs.append(
                f"• {_s(entry.get('organization'))}: privilege "
                f"{_s(entry.get('privilege_level'), 'unknown')}, credential source "
                f"{_s(entry.get('source'))}{inv_text}"
            )
        no_data = (access.get("coverage") or {}).get("organizations_with_no_data") or []
        if no_data:
            paragraphs.append(
                "NOT EXAMINED: " + ", ".join(_s(n) for n in no_data)
                + " — no repositories are recorded for these organizations, so no "
                "database-backed result in this report covers them. Their absence from "
                "every finding above reflects absent data, not absent risk."
            )
        graph = access.get("graph") or {}
        if graph:
            paragraphs.append(
                f"• Microsoft Graph roles held: "
                + (", ".join(_s(r) for r in (graph.get("scopes") or [])) or "none recorded")
            )

    control = evidence.get("hunt_coverage_control")
    if control:
        paragraphs.append(
            f"Endpoint telemetry control: present={control.get('telemetry_present')}, "
            f"{control.get('total_events', 0)} events across "
            f"{control.get('buckets_returned', 0)} of {control.get('hours_requested', 0)} "
            f"hourly buckets, peak {control.get('max_devices_in_any_hour', 0)} devices. "
            f"{_s(control.get('interpretation'))}"
        )

    ci = evidence.get("hunt_ci_activity")
    if ci:
        paragraphs.append(
            f"CI/CD activity inside the window: "
            f"{ci.get('workflow_runs_in_window_count', 0)} workflow runs, "
            f"{ci.get('deployments_in_window_count', 0)} deployments."
        )
        never = (ci.get("coverage") or {}).get("never_collected")
        if never:
            paragraphs.append(
                f"These counts are structurally zero: the {', '.join(_s(n) for n in never)} "
                "table(s) hold no rows at all, so no build or deployment could have been "
                "found. Execution via CI was NOT ruled out; it was never observable."
            )

    endpoint = evidence.get("hunt_endpoint_execution")
    if endpoint:
        paragraphs.append(
            f"Endpoint process telemetry: {endpoint.get('count', 0)} matching events over "
            f"{endpoint.get('hours', 0)} hours in {_s(endpoint.get('table'))}, of which "
            f"{endpoint.get('execution_candidate_count', endpoint.get('count', 0))} are "
            f"execution candidates."
        )
        refs = endpoint.get("url_reference_count") or 0
        if refs:
            paragraphs.append(
                f"{refs} of those hits are browser navigations where the indicator appears "
                "only inside a URL — staff opening vendor write-ups of this incident, not "
                "the indicator running. They are excluded from the execution-candidate "
                "count; reporting the raw total as compromise would have been wrong."
            )
        analyst = endpoint.get("analyst_tooling_count") or 0
        if analyst:
            paragraphs.append(
                f"{analyst} execution candidates are analyst tooling — the investigation "
                "appearing in its own results, since a search for these indicators also "
                "returns the commands that searched for them. They remain counted because "
                "a payload launched from a shell is indistinguishable at this level, but "
                "they must be triaged before the count is read as compromise."
            )
        ecov = endpoint.get("coverage") or {}
        if ecov.get("truncated"):
            paragraphs.append(
                f"This endpoint count is TRUNCATED at the {ecov.get('row_limit')}-row query "
                "limit and is therefore a floor, not a total. No conclusion about scale may "
                "be drawn from it until the search is narrowed and re-run."
            )
        per_ind = endpoint.get("hits_per_indicator") or {}
        if per_ind:
            paragraphs.append(
                "Hits per indicator: "
                + ", ".join(f"{_s(k)}={v}" for k, v in per_ind.items())
                + ". A short bare word matches any path containing it and is not an "
                  "indicator of compromise on its own."
            )

    alerts = evidence.get("hunt_alerts")
    if alerts:
        paragraphs.append(
            f"Unified alerts: {alerts.get('count', 0)} matching of "
            f"{alerts.get('total_in_window', 0)} in the window, assembled from "
            f"{alerts.get('api_calls', 0)} API calls."
        )

    dead_drop = evidence.get("hunt_dead_drop_repos")
    if dead_drop:
        paragraphs.append(
            f"Dead-drop sweep: {dead_drop.get('marker_match_count', 0)} marker matches "
            f"across {dead_drop.get('repositories_searched', 0)} repositories; "
            f"{dead_drop.get('created_in_window_count', 0)} repositories were created "
            f"inside the window irrespective of marker."
        )
        for repo in (dead_drop.get("marker_matches") or [])[:20]:
            paragraphs.append(
                f"• MARKER MATCH {_s(repo.get('full_name'))} created "
                f"{_s(repo.get('created_at'), 'unknown')}: {_s(repo.get('description'))[:200]}"
            )

    exposure = evidence.get("hunt_dependency_exposure")
    table = None
    if exposure:
        cov = exposure.get("coverage") or {}
        control = cov.get("inventory_control") or {}
        paragraphs.append(
            f"Dependency exposure: {exposure.get('match_count', 0)} matches across "
            f"{exposure.get('specs_queried', 0)} exact name@version specs; "
            f"{len(exposure.get('floating_ranges') or [])} declarations were floating "
            "ranges that could have resolved to an affected version."
        )
        if control:
            paragraphs.append(
                f"Bound on that result: dependency records exist for "
                f"{control.get('repositories_with_dependency_records_total', 0)} of "
                f"{control.get('repositories_total', 0)} inventoried repositories "
                f"({control.get('sbom_coverage_pct', 0)}%). The exposure figure describes "
                "that subset only."
            )
        absent = cov.get("families_absent_entirely") or []
        present = cov.get("families_present_at_other_versions") or []
        if present:
            paragraphs.append(
                "Controlled zero — these package names are present at other versions, so "
                "the query provably returns rows for them and absence of the hunted "
                "version is evidence: " + ", ".join(_s(p) for p in present) + "."
            )
        if absent:
            paragraphs.append(
                "Unbounded zero — these package names appear at no version at all, which is "
                "equally consistent with genuine non-use and with the consuming "
                "repositories never having had dependencies collected. Not cleared on this "
                "evidence: " + ", ".join(_s(a) for a in absent) + "."
            )
        rows = []
        for match in (exposure.get("matches") or [])[:60]:
            rows.append([
                _s(match.get("repository"))[:40],
                _s(match.get("matched_spec"))[:32],
                _s(match.get("declared_version"))[:18],
                _s(match.get("exposure"))[:16],
            ])
        if rows:
            table = {"headers": ["Repository", "Matched Spec", "Declared", "Exposure"],
                     "rows": rows}

    if not paragraphs and not table:
        return None

    return {"heading": "Hunt Evidence", "paragraphs": paragraphs, "table": table}


def build_sections(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    All evidence sections for a report, in reading order.

    Coverage comes last deliberately: a reader who stops early should still have seen the
    findings, and a reader who reaches the end finishes on what the hunt could not see
    rather than on a conclusion.
    """
    sections = []
    for builder in (arbitration_section, evidence_section, coverage_section):
        section = builder(payload)
        if section:
            sections.append(section)
    return sections
