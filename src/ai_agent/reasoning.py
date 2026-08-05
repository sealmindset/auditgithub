"""
AI reasoning engine for analyzing stuck scans.

Coordinates AI providers to analyze diagnostic data and generate insights.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List

from .providers import AIProvider, AIAnalysis
from .diagnostics import DiagnosticCollector

import json
from sqlalchemy.orm import Session
from .tools.db_tools import search_dependencies, search_repositories_by_technology

logger = logging.getLogger(__name__)

# Hunt payloads are large — an alert list can hold hundreds of objects — so each is
# reduced to the facts the synthesis step reasons over. The reduction is per-tool and
# deliberate rather than a generic truncation, because truncating a payload can remove the
# coverage warning while keeping the row count, which is precisely the wrong half.
_EVIDENCE_ROW_LIMIT = 15


def _summarize_hunt_evidence(name: str, payload: Any) -> str:
    """Render one hunt tool's output for the synthesis prompt."""
    if isinstance(payload, list):
        # search_workflow_runs / search_deployments return bare lists.
        head = "\n".join(f"    - {row}" for row in payload[:_EVIDENCE_ROW_LIMIT])
        if len(payload) > _EVIDENCE_ROW_LIMIT:
            head += (f"\n    ... {len(payload) - _EVIDENCE_ROW_LIMIT} more rows not shown "
                     f"(total {len(payload)})")
        return head or "  (no rows)"
    if not isinstance(payload, dict):
        return f"  {payload}"

    lines = []
    if payload.get("error"):
        lines.append(f"  ERROR: {payload['error']}")

    if name == "hunt_registry_truth":
        # Both windows, so the model cannot present the range it searched as the range the
        # evidence supports. The searched range bounds the finding; the derived one is it.
        lines.append(f"  window searched: {payload.get('window_searched')}")
        lines.append(f"  window derived from publish timestamps: "
                     f"{payload.get('derived_window')}")
        lines.append(f"  malicious specs ({len(payload.get('malicious_specs', []))}): "
                     f"{', '.join(payload.get('malicious_specs', [])[:40])}")
        for item in payload.get("malicious_detail", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - {item.get('spec')} published {item.get('published')} "
                         f"({item.get('reason', 'unpublished')})")
    elif name == "hunt_arbitrate":
        lines.append(f"  hunt_scope: {payload.get('hunt_scope')}")
        lines.append(f"  verdict_set: {payload.get('verdict_set')}")
        lines.append(f"  unverified: {payload.get('unverified')}")
        for d in payload.get("disagreements", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - {d.get('subject')}={d.get('claimed_value')} "
                         f"[{d.get('resolution')}] wrong: {d.get('incorrect_sources')} "
                         f"| {d.get('rationale', '')[:240]}")
        lines.append(f"  source_scorecard: {payload.get('source_scorecard')}")
        lines.append(f"  source_urls: {payload.get('source_urls')}")
    elif name == "hunt_intel_sources":
        for s in payload.get("sources", []):
            lines.append(f"    - [tier {s['tier']}] {s['id']}: {s['url']}")
        for sid, why in (payload.get("disqualified") or {}).items():
            lines.append(f"    - DISQUALIFIED {sid}: {why}")
    elif name == "hunt_access_coverage":
        for entry in payload.get("github", []):
            lines.append(f"    - {entry.get('organization')}: "
                         f"privilege={entry.get('privilege_level')} "
                         f"source={entry.get('source')} "
                         f"owned={entry.get('owned_by_auditgithub')}")
        graph = payload.get("graph", {})
        lines.append(f"    - graph: source={graph.get('source')} "
                     f"roles={graph.get('scopes')}")
        for spot in payload.get("blind_spots", []):
            lines.append(f"    - BLIND SPOT: {spot}")
    elif name == "hunt_dependency_exposure":
        lines.append(f"  matches: {payload.get('match_count')} "
                     f"per_spec: {payload.get('per_spec_counts')}")
        for m in payload.get("matches", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - {m.get('repository')}: {m.get('matched_spec')} "
                         f"declared={m.get('declared_version')} ({m.get('exposure')})")
    elif name == "hunt_ci_activity":
        lines.append(f"  runs in window: {payload.get('workflow_runs_in_window_count')}, "
                     f"deployments in window: {payload.get('deployments_in_window_count')}")
        for r in payload.get("workflow_runs_in_window", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - run {r.get('repository')}/{r.get('workflow_name')} "
                         f"{r.get('started_at') or r.get('created_at')} "
                         f"{r.get('conclusion')}")
        for d in payload.get("deployments_in_window", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - deploy {d.get('repository')} -> {d.get('environment')} "
                         f"{d.get('deployed_at') or d.get('created_at')}")
    elif name == "hunt_dead_drop_repos":
        lines.append(f"  marker matches: {payload.get('marker_match_count')} of "
                     f"{payload.get('repositories_searched')} repositories searched")
        for r in payload.get("marker_matches", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - MARKER {r.get('full_name')} created {r.get('created_at')}: "
                         f"{(r.get('description') or '')[:160]}")
        for r in payload.get("created_in_window", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - created in window: {r.get('full_name')} "
                         f"{r.get('created_at')} ({r.get('visibility')})")
    elif name == "hunt_coverage_control":
        lines.append(f"  telemetry_present={payload.get('telemetry_present')} "
                     f"events={payload.get('total_events')} "
                     f"buckets={payload.get('buckets_returned')}/"
                     f"{payload.get('hours_requested')} "
                     f"peak_devices={payload.get('max_devices_in_any_hour')}")
        lines.append(f"  {payload.get('interpretation')}")
    elif name == "hunt_endpoint_execution":
        lines.append(f"  {payload.get('count')} events over {payload.get('hours')}h "
                     f"in {payload.get('table')}; "
                     f"{payload.get('execution_candidate_count')} execution candidates, "
                     f"{payload.get('url_reference_count')} URL references only, "
                     f"{payload.get('analyst_tooling_count')} analyst tooling")
        if payload.get("hits_per_indicator"):
            lines.append(f"  hits per indicator: {payload['hits_per_indicator']}")
        # Label every row with why it matched. Handed an unlabelled list, the model has no
        # way to tell a browser opening an article about the indicator from the indicator
        # executing, and the two lead to opposite conclusions.
        for r in payload.get("rows", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - [{r.get('indicator_context', 'unclassified')}] "
                         f"{r.get('Timestamp')} {r.get('DeviceName')} "
                         f"{r.get('AccountName')}: "
                         f"{str(r.get('ProcessCommandLine'))[:200]}")
    elif name == "hunt_alerts":
        lines.append(f"  {payload.get('count')} matching of "
                     f"{payload.get('total_in_window')} in {payload.get('window')}")
        for a in payload.get("alerts", [])[:_EVIDENCE_ROW_LIMIT]:
            lines.append(f"    - {a.get('createdDateTime')} [{a.get('severity')}] "
                         f"{a.get('title')} ({a.get('status')})")
    else:
        for key, value in payload.items():
            if key in ("rows", "alerts", "buckets", "per_package", "results"):
                continue
            lines.append(f"  {key}: {str(value)[:400]}")

    coverage = payload.get("coverage") if isinstance(payload, dict) else None
    if isinstance(coverage, dict):
        for key in ("usable", "truncated", "warning", "caveat", "note", "errors"):
            if coverage.get(key) not in (None, [], ""):
                lines.append(f"  coverage.{key}: {str(coverage[key])[:400]}")

    return "\n".join(lines) if lines else "  (no data)"


class ReasoningEngine:
    """Coordinates AI analysis of stuck scans."""
    
    def __init__(
        self,
        provider: AIProvider,
        diagnostic_collector: DiagnosticCollector,
        max_cost_per_analysis: float = 0.50
    ):
        """
        Initialize the reasoning engine.
        
        Args:
            provider: AI provider to use (OpenAI or Claude)
            diagnostic_collector: Diagnostic data collector
            max_cost_per_analysis: Maximum cost per analysis in USD
        """
        self.provider = provider
        self.diagnostic_collector = diagnostic_collector
        self.max_cost_per_analysis = max_cost_per_analysis
        self.analysis_history: List[Dict[str, Any]] = []
    
    async def analyze_stuck_scan(
        self,
        repo_name: str,
        scanner: str,
        phase: str,
        timeout_duration: int,
        repo_metadata: Optional[Dict[str, Any]] = None,
        scanner_progress: Optional[Dict[str, Any]] = None
    ) -> AIAnalysis:
        """
        Analyze a stuck scan using AI.
        
        Args:
            repo_name: Name of the repository
            scanner: Scanner that was running
            phase: Current phase
            timeout_duration: Timeout duration in seconds
            repo_metadata: Optional repository metadata
            scanner_progress: Optional scanner progress
            
        Returns:
            AIAnalysis with root cause and suggestions
        """
        try:
            # Check cost budget
            # Check cost budget
            # We want to ensure we don't exceed the max cost *per analysis* on average, 
            # but we also need to allow the first analysis to run!
            current_cost = self.provider.get_total_cost()
            
            # If we haven't done any analysis yet, we should allow it (unless cost is already high from somewhere else)
            # If we have done analysis, we check if we are over budget
            if len(self.analysis_history) > 0:
                average_cost = current_cost / len(self.analysis_history)
                if average_cost > self.max_cost_per_analysis:
                     logger.warning(
                        f"AI average cost per analysis (${average_cost:.2f}) exceeds limit (${self.max_cost_per_analysis:.2f}). "
                        f"Total cost: ${current_cost:.2f}. Skipping analysis for {repo_name}"
                    )
                     return self._create_fallback_analysis(
                        "Cost budget exceeded",
                        repo_name,
                        scanner
                    )
            elif current_cost > self.max_cost_per_analysis:
                 # Even with 0 history, if we somehow have high cost, stop.
                 logger.warning(
                    f"AI total cost (${current_cost:.2f}) exceeds limit for single analysis (${self.max_cost_per_analysis:.2f}). "
                    f"Skipping analysis for {repo_name}"
                )
                 return self._create_fallback_analysis(
                    "Cost budget exceeded",
                    repo_name,
                    scanner
                )
            
            # Collect diagnostic data
            logger.info(f"Collecting diagnostic data for {repo_name}...")
            diagnostic_data = self.diagnostic_collector.collect(
                repo_name=repo_name,
                scanner=scanner,
                phase=phase,
                timeout_duration=timeout_duration,
                repo_metadata=repo_metadata,
                scanner_progress=scanner_progress
            )
            
            # Get historical data for this repo
            historical_data = [
                entry for entry in self.analysis_history
                if entry.get("repo_name") == repo_name
            ]
            
            # Analyze with AI
            logger.info(f"Analyzing stuck scan with AI provider: {self.provider.__class__.__name__}")
            analysis = await self.provider.analyze_stuck_scan(
                diagnostic_data=diagnostic_data,
                historical_data=historical_data
            )
            
            # Store in history
            self.analysis_history.append({
                "repo_name": repo_name,
                "scanner": scanner,
                "timestamp": diagnostic_data.get("timestamp"),
                "analysis": analysis,
                "diagnostic_data": diagnostic_data
            })
            
            logger.info(
                f"AI analysis complete for {repo_name}: "
                f"{len(analysis.remediation_suggestions)} suggestions, "
                f"confidence={analysis.confidence:.2f}, "
                f"cost=${analysis.estimated_cost:.4f}"
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"AI analysis failed for {repo_name}: {e}", exc_info=True)
            return self._create_fallback_analysis(str(e), repo_name, scanner)
    
    async def explain_timeout(
        self,
        repo_name: str,
        scanner: str,
        timeout_duration: int,
        context: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Generate a human-readable explanation of the timeout.
        
        Args:
            repo_name: Repository name
            scanner: Scanner name
            timeout_duration: Timeout duration
            context: Optional context
            
        Returns:
            Human-readable explanation
        """
        try:
            return await self.provider.explain_timeout(
                repo_name=repo_name,
                scanner=scanner,
                timeout_duration=timeout_duration,
                context=context or {}
            )
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return f"The {scanner} scanner timed out after {timeout_duration} seconds while scanning {repo_name}."

    async def generate_remediation(
        self,
        vuln_type: str,
        description: str,
        context: str,
        language: str
    ) -> Dict[str, str]:
        """
        Generate a remediation plan using the AI provider.
        """
        try:
            return await self.provider.generate_remediation(
                vuln_type=vuln_type,
                description=description,
                context=context,
                language=language
            )
        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}")
            return {"remediation": "AI generation failed.", "diff": ""}

    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate an architecture overview for the repository.
        """
        try:
            # Check if provider has this method (it might not if we haven't added it yet)
            if not hasattr(self.provider, 'generate_architecture_overview'):
                return "AI provider does not support architecture analysis."
                
            return await self.provider.generate_architecture_overview(
                repo_name=repo_name,
                file_structure=file_structure,
                config_files=config_files
            )
        except Exception as e:
            logger.error(f"Failed to generate architecture overview: {e}")
            return f"Failed to generate architecture overview: {e}"

    async def triage_finding(
        self,
        title: str,
        description: str,
        severity: str,
        scanner: str
    ) -> Dict[str, Any]:
        """
        Triage a finding using the AI provider.
        """
        try:
            return await self.provider.triage_finding(
                title=title,
                description=description,
                severity=severity,
                scanner=scanner
            )
        except Exception as e:
            logger.error(f"Failed to triage finding: {e}")
            return {
                "priority": severity,
                "confidence": 0.0,
                "reasoning": f"AI triage failed: {e}",
                "false_positive_probability": 0.0
            }

    async def analyze_finding(
        self,
        finding: Dict[str, Any],
        user_prompt: Optional[str] = None
    ) -> str:
        """
        Analyze a finding using the AI provider.
        """
        try:
            return await self.provider.analyze_finding(
                finding=finding,
                user_prompt=user_prompt
            )
        except Exception as e:
            logger.error(f"Failed to analyze finding: {e}")
            return f"AI analysis failed: {e}"

    async def analyze_zero_day(
        self,
        query: str,
        db_session: Session,
        scope: Optional[List[str]] = None,
        allow_hunt: bool = False
    ) -> Dict[str, Any]:
        """
        Run a zero-day / supply-chain hunt.

        Tool-use pattern:
        1. Ask the LLM for a plan over the full tool catalogue
        2. Execute the plan, recording coverage limits alongside results
        3. Pass results plus coverage back to the LLM for synthesis

        Args:
            query: User's natural language query
            db_session: Database session
            scope: Optional list of scopes to search (dependencies, findings, languages, all)
            allow_hunt: Whether the caller holds hunt:execute. When False the plan's
                database tools still run, but any tool reaching an external system —
                package registries, GitHub, Microsoft Graph — is skipped and recorded as
                an unexamined surface. It is not silently dropped: a hunt that could not
                look must not read as a hunt that found nothing.
        """
        try:
            logger.info(f"Analyzing zero-day query: {query} (scope: {scope})")

            # Get the current organization ID for multi-tenant filtering
            from ..api.database import get_request_org_id
            from sqlalchemy import text
            organization_id = get_request_org_id()

            # Fall back to default organization if no context is set
            if not organization_id:
                try:
                    result = db_session.execute(text("SELECT id FROM organizations WHERE is_default = true LIMIT 1"))
                    row = result.fetchone()
                    if row:
                        organization_id = str(row[0])
                except Exception:
                    pass

            logger.info(f"Zero-day analysis scoped to organization: {organization_id}")

            # Import here to avoid circular dependency
            from . import zda_prompt
            from .tools.db_tools import (
                search_dependencies,
                search_findings,
                search_languages,
                search_repositories_by_technology,
                search_all_sources,
                search_deployments,
                search_workflow_runs
            )

            # Which organizations the hunt can name. Listed in the prompt so the model
            # knows the estate spans three GitHub organizations rather than assuming the
            # single one implied by the request's tenant context.
            org_names = []
            try:
                from ..api import models
                org_names = [
                    o.github_org for o in
                    db_session.query(models.Organization)
                    .filter(models.Organization.is_active.is_(True))
                    .order_by(models.Organization.name).all()
                ]
            except Exception as org_error:
                logger.warning(f"Could not enumerate organizations for prompt: {org_error}")

            # Step 1: Determine Plan.
            # The prompt is built from zda_prompt so that GET /ai/zero-day/prompt returns
            # the prompt actually in use, and so the advertised tool catalogue is
            # generated from the same specs the dispatcher below can execute.
            planning_prompt = zda_prompt.build_planning_prompt(
                query=query, scope=scope, organizations=org_names,
            )

            # Call AI for planning
            if hasattr(self.provider, "execute_prompt"):
                plan_json_str = await self.provider.execute_prompt(planning_prompt)
            else:
                return {"error": "AI Provider does not support direct prompting for Zero Day analysis."}

            # Parse JSON plan
            try:
                clean_json = plan_json_str.strip()
                if clean_json.startswith("```json"):
                    clean_json = clean_json.replace("```json", "").replace("```", "")
                elif clean_json.startswith("```"):
                    clean_json = clean_json.replace("```", "")
                
                plan = json.loads(clean_json)
                logger.info(f"AI Plan: {plan.get('thought', 'No reasoning provided')}")
            except json.JSONDecodeError as e:
                logger.warning(f"Failed to parse plan JSON: {plan_json_str[:200]}... Error: {e}")
                # Fallback: Use search_all_sources with the raw query
                plan = {
                    "thought": "Fallback to comprehensive search",
                    "tools": [{"name": "search_all_sources", "args": {"query": query, "scopes": scope}}]
                }

            # Step 2: Execute Tools
            execution_results = []
            affected_repos = []
            all_details = []  # Store all match details for synthesis
            hunt_evidence = {}   # Raw hunt-tool output, keyed by tool name
            coverage_notes = []  # Every limit on what this run could see

            from .tools import hunt_tools

            for tool in plan.get("tools", []):
                tool_name = tool.get("name")
                args = tool.get("args", {})

                # Hunt tools reach live external systems (registries, GitHub, Graph), so
                # they are gated separately from database reads. A denied tool is recorded
                # as a coverage gap rather than dropped, because the synthesis step must
                # be able to say which questions went unasked.
                if tool_name in zda_prompt.HUNT_TOOL_NAMES and not allow_hunt:
                    msg = (f"{tool_name}: SKIPPED - requires the hunt:execute permission. "
                           "This surface was not examined and no conclusion may be drawn "
                           "from its absence.")
                    execution_results.append(msg)
                    coverage_notes.append(msg)
                    continue

                try:
                    if tool_name == "search_dependencies":
                        results = search_dependencies(
                            db_session,
                            package_name=args.get("package_name"),
                            version_spec=args.get("version_spec"),
                            use_fuzzy=True,
                            organization_id=organization_id
                        )
                        execution_results.append(f"Dependencies: Found {len(results)} repos using '{args.get('package_name')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)

                    elif tool_name == "search_findings":
                        results = search_findings(
                            db_session,
                            query=args.get("query"),
                            severity_filter=args.get("severity_filter"),
                            organization_id=organization_id
                        )
                        execution_results.append(f"Findings: Found {len(results)} security findings matching '{args.get('query')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)

                    elif tool_name == "search_languages":
                        results = search_languages(
                            db_session,
                            language_name=args.get("language"),
                            use_fuzzy=True,
                            organization_id=organization_id
                        )
                        execution_results.append(f"Languages: Found {len(results)} repos using '{args.get('language')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)

                    elif tool_name == "search_technology":
                        results = search_repositories_by_technology(
                            db_session,
                            technology=args.get("keyword"),
                            organization_id=organization_id
                        )
                        execution_results.append(f"Technology: Found {len(results)} repos matching '{args.get('keyword')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)

                    elif tool_name == "search_all_sources":
                        all_results = search_all_sources(
                            db_session,
                            query=args.get("query"),
                            scopes=args.get("scopes") or scope,
                            organization_id=organization_id
                        )
                        # Extract aggregated results
                        agg_repos = all_results.get("aggregated_repositories", [])
                        execution_results.append(f"All Sources: Found {len(agg_repos)} unique repos across all data sources")
                        affected_repos.extend(agg_repos)
                        # Store detailed results
                        for source_name, source_results in all_results.items():
                            if source_name != "aggregated_repositories":
                                all_details.extend(source_results)

                    elif tool_name == "search_workflow_runs":
                        results = search_workflow_runs(
                            db_session,
                            repository_name=args.get("repository_name"),
                            workflow_name=args.get("workflow_name"),
                            branch=args.get("branch"),
                            status=args.get("status"),
                            conclusion=args.get("conclusion"),
                            days_back=args.get("days_back", 30),
                            organization_id=organization_id
                        )
                        execution_results.append(
                            f"Workflow runs: {len(results)} runs in the last "
                            f"{args.get('days_back', 30)} days"
                        )
                        hunt_evidence["search_workflow_runs"] = results
                        all_details.extend(results)

                    elif tool_name == "search_deployments":
                        results = search_deployments(
                            db_session,
                            repository_name=args.get("repository_name"),
                            environment=args.get("environment"),
                            commit_sha=args.get("commit_sha"),
                            status=args.get("status"),
                            days_back=args.get("days_back", 90),
                            organization_id=organization_id
                        )
                        execution_results.append(
                            f"Deployments: {len(results)} deployments in the last "
                            f"{args.get('days_back', 90)} days"
                        )
                        hunt_evidence["search_deployments"] = results
                        all_details.extend(results)

                    # --- hunt tools ------------------------------------------------
                    elif tool_name == "hunt_access_coverage":
                        result = hunt_tools.hunt_access_coverage(db_session)
                        hunt_evidence[tool_name] = result
                        borrowed = result.get("coverage", {}).get("borrowed_credentials", [])
                        execution_results.append(
                            f"Access coverage: {len(result.get('github', []))} organizations, "
                            f"{len(result.get('blind_spots', []))} recorded blind spots, "
                            f"borrowed credentials: {borrowed or 'none'}"
                        )
                        coverage_notes.extend(result.get("blind_spots", []))

                    elif tool_name == "hunt_intel_sources":
                        result = hunt_tools.hunt_intel_sources(
                            ecosystem=args.get("ecosystem"),
                            max_tier=args.get("max_tier", 3),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Intel sources: {result['count']} available, "
                            f"{len(result['disqualified'])} disqualified"
                        )

                    elif tool_name == "hunt_registry_truth":
                        result = hunt_tools.hunt_registry_truth(
                            packages=args.get("packages") or [],
                            window_start=args.get("window_start"),
                            window_end=args.get("window_end"),
                            ecosystem=args.get("ecosystem", "npm"),
                            force_refresh=args.get("force_refresh", False),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Registry ground truth: {len(result.get('malicious_specs', []))} "
                            f"malicious specs across {result.get('packages_queried', 0)} packages"
                        )
                        warning = result.get("coverage", {}).get("warning")
                        if warning:
                            coverage_notes.append(f"registry: {warning}")

                    elif tool_name == "hunt_arbitrate":
                        # Reuse the registry result from this same plan when the planner
                        # did not pass specs explicitly. Arbitration without a tier-0
                        # oracle silently accepts vendor consensus, which is the exact
                        # failure this tool exists to prevent.
                        specs = args.get("malicious_specs")
                        if specs is None:
                            specs = (hunt_evidence.get("hunt_registry_truth", {})
                                     .get("malicious_specs"))
                        result = hunt_tools.hunt_arbitrate(
                            claims=args.get("claims") or [],
                            malicious_specs=specs,
                            ground_truth_url=args.get("ground_truth_url"),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Arbitration: {len(result['hunt_scope'])} claims in hunt scope, "
                            f"{len(result['verdict_set'])} accepted, "
                            f"{len(result['disagreements'])} disagreements"
                        )
                        if specs is None:
                            coverage_notes.append(
                                "arbitration ran without a tier-0 oracle: accepted claims "
                                "rest on vendor consensus alone and are not verified"
                            )

                    elif tool_name == "hunt_dependency_exposure":
                        result = hunt_tools.hunt_dependency_exposure(
                            db_session,
                            specs=args.get("specs") or [],
                            organization_id=organization_id,
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Dependency exposure: {result['match_count']} matches across "
                            f"{result['specs_queried']} exact specs, "
                            f"{len(result['floating_ranges'])} floating ranges"
                        )
                        affected_repos.extend(result["matches"])
                        all_details.extend(result["matches"])
                        coverage_notes.append(f"dependency exposure: {result['coverage']['caveat']}")

                    elif tool_name == "hunt_ci_activity":
                        result = hunt_tools.hunt_ci_activity(
                            db_session,
                            window_start=args.get("window_start"),
                            window_end=args.get("window_end"),
                            repository_names=args.get("repository_names"),
                            organization_id=organization_id,
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"CI activity in window: "
                            f"{result.get('workflow_runs_in_window_count', 0)} workflow runs, "
                            f"{result.get('deployments_in_window_count', 0)} deployments"
                        )
                        caveat = result.get("coverage", {}).get("caveat")
                        if caveat:
                            coverage_notes.append(f"CI activity: {caveat}")

                    elif tool_name == "hunt_dead_drop_repos":
                        result = hunt_tools.hunt_dead_drop_repos(
                            db_session,
                            markers=args.get("markers") or [],
                            organization_id=organization_id,
                            created_after=args.get("created_after"),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Dead-drop sweep: {result.get('marker_match_count', 0)} marker "
                            f"matches, {result.get('created_in_window_count', 0)} repos "
                            f"created in window, {result.get('repositories_searched', 0)} searched"
                        )
                        coverage_notes.append(
                            f"dead-drop sweep: {result.get('coverage', {}).get('caveat', '')}"
                        )

                    elif tool_name == "hunt_coverage_control":
                        result = hunt_tools.hunt_coverage_control(
                            db_session, hours=args.get("hours", 24)
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Telemetry control: present={result.get('telemetry_present')}, "
                            f"{result.get('total_events', 0)} events, "
                            f"{result.get('max_devices_in_any_hour', 0)} devices peak hour"
                        )
                        if not result.get("telemetry_present"):
                            coverage_notes.append(
                                "NO ENDPOINT TELEMETRY: every zero from Defender in this run "
                                "is uninterpretable; the pipeline is the finding"
                            )

                    elif tool_name == "hunt_endpoint_execution":
                        result = hunt_tools.hunt_endpoint_execution(
                            db_session,
                            indicators=args.get("indicators") or [],
                            hours=args.get("hours", 168),
                            table=args.get("table", "DeviceProcessEvents"),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Endpoint execution: {result.get('count', 0)} matching process "
                            f"events (control usable={result.get('coverage', {}).get('usable')})"
                        )
                        coverage_notes.extend(result.get("coverage", {}).get("caveats", []))

                    elif tool_name == "hunt_alerts":
                        result = hunt_tools.hunt_alerts(
                            db_session,
                            days=args.get("days", 7),
                            severities=args.get("severities"),
                            title_contains=args.get("title_contains"),
                        )
                        hunt_evidence[tool_name] = result
                        execution_results.append(
                            f"Alerts: {result.get('count', 0)} matching of "
                            f"{result.get('total_in_window', 0)} in window "
                            f"({result.get('api_calls', 0)} API calls)"
                        )
                        if result.get("coverage", {}).get("truncated"):
                            coverage_notes.append(
                                "alert enumeration hit its row ceiling: the alert count is a "
                                "lower bound, not a total"
                            )

                    else:
                        msg = (f"{tool_name}: unknown tool, not executed. "
                               f"Available: {', '.join(zda_prompt.tool_names())}")
                        logger.warning(msg)
                        execution_results.append(msg)
                        coverage_notes.append(msg)

                except Exception as tool_error:
                    logger.error(f"Tool {tool_name} failed: {tool_error}", exc_info=True)
                    execution_results.append(f"{tool_name}: Error - {str(tool_error)}")
                    # A failed tool is a coverage gap. Without this the synthesis step
                    # cannot distinguish "queried and found nothing" from "never ran".
                    coverage_notes.append(
                        f"{tool_name} failed ({type(tool_error).__name__}): that surface was "
                        f"not examined and its absence is not evidence"
                    )

            # Deduplicate repositories by ID
            unique_repos = {}
            for repo in affected_repos:
                repo_id = repo.get("repository_id")
                if repo_id and repo_id not in unique_repos:
                    unique_repos[repo_id] = repo
                elif repo_id:
                    # Merge sources if duplicate
                    if "matched_sources" in repo and "matched_sources" in unique_repos[repo_id]:
                        unique_repos[repo_id]["matched_sources"].extend(repo.get("matched_sources", []))
                        unique_repos[repo_id]["matched_sources"] = list(set(unique_repos[repo_id]["matched_sources"]))

            # ENHANCEMENT: Fetch deployment information for affected repositories
            from .tools.db_tools import get_repository_deployment_status
            deployment_info = {}

            for repo_id, repo_data in unique_repos.items():
                try:
                    deploy_status = get_repository_deployment_status(db_session, repo_id)
                    if deploy_status and deploy_status.get("total_environments", 0) > 0:
                        deployment_info[repo_id] = deploy_status["environments"]
                        # Add deployment flag to repo data
                        repo_data["has_deployments"] = True
                        repo_data["deployment_count"] = len(deploy_status["environments"])
                except Exception as e:
                    logger.warning(f"Could not fetch deployment info for {repo_id}: {e}")
                    repo_data["has_deployments"] = False

            # Step 3: Synthesize Answer with AI
            # Format repository list with last updated dates AND deployment info
            repo_list_items = []
            deployed_repos = []  # Track repos that are deployed

            for r in unique_repos.values():
                repo_name = r.get('repository')
                repo_id = r.get('repository_id')
                source = r.get('source', 'unknown')
                last_updated = r.get('last_updated')
                has_deployments = r.get('has_deployments', False)

                # Build repo line
                repo_line = f"- **{repo_name}** ({source} match"

                if last_updated:
                    from datetime import datetime
                    try:
                        dt = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                        date_str = dt.strftime('%Y-%m-%d')
                        repo_line += f", last updated: {date_str}"
                    except:
                        pass

                # Add deployment information if available
                if has_deployments and repo_id in deployment_info:
                    envs = deployment_info[repo_id]
                    env_names = [e.get("environment") for e in envs]
                    repo_line += f", **DEPLOYED to: {', '.join(env_names)}**"
                    deployed_repos.append({
                        "repository": repo_name,
                        "environments": env_names,
                        "deployment_details": envs
                    })

                repo_line += ")"
                repo_list_items.append(repo_line)

            repo_list_str = "\n".join(repo_list_items)

            # Create deployment summary
            deployment_summary = ""
            if deployed_repos:
                deployment_summary = f"\n\n**CRITICAL: {len(deployed_repos)} repositories are currently deployed:**\n"
                for dr in deployed_repos:
                    deployment_summary += f"  - {dr['repository']}: {', '.join(dr['environments'])}\n"

            # Include sample details for context
            detail_summary = []
            for detail in all_details[:10]:  # Limit to first 10 for token efficiency
                if detail.get("source") == "findings":
                    detail_summary.append(f"  - Finding: {detail.get('title')} (Severity: {detail.get('severity')}, CVE: {detail.get('cve_id')})")
                elif detail.get("source") == "dependencies":
                    detail_summary.append(f"  - Dependency: {detail.get('package_name')} v{detail.get('version')}")
            
            detail_str = "\n".join(detail_summary) if detail_summary else "No additional details available."

            # Hunt evidence, summarized rather than dumped whole: a single alert list can
            # run to hundreds of objects and would crowd out everything else in the
            # context window.
            evidence_lines = []
            for name, payload in hunt_evidence.items():
                evidence_lines.append(f"### {name}")
                evidence_lines.append(_summarize_hunt_evidence(name, payload))
            evidence_str = ("\n".join(evidence_lines) if evidence_lines
                            else "No hunt tools were executed in this run.")

            if not coverage_notes:
                coverage_str = ("No coverage limits were recorded. Note that this is itself "
                                "suspect unless hunt_access_coverage ran: with no coverage "
                                "data, no zero in this analysis can be interpreted.")
            else:
                # Deduplicate while keeping order; the same caveat arrives from several tools.
                seen_notes = set()
                ordered = []
                for note in coverage_notes:
                    note = (note or "").strip()
                    if note and note not in seen_notes:
                        seen_notes.add(note)
                        ordered.append(f"- {note}")
                coverage_str = "\n".join(ordered)
                if not allow_hunt:
                    coverage_str = ("- Caller lacks hunt:execute; all external-evidence "
                                    "tools were skipped.\n") + coverage_str

            synthesis_prompt = zda_prompt.build_synthesis_prompt(
                query=query,
                plan=json.dumps(plan.get("tools", []), indent=2),
                execution_results=chr(10).join(execution_results),
                coverage=coverage_str,
                repo_count=len(unique_repos),
                repo_list=repo_list_str,
                deployment_summary=deployment_summary,
                detail_str=detail_str + "\n\nHunt Evidence:\n" + evidence_str,
            )

            if hasattr(self.provider, "execute_prompt"):
                final_answer = await self.provider.execute_prompt(synthesis_prompt)
            else:
                final_answer = f"Analysis complete. Found {len(unique_repos)} potentially affected repositories."

            return {
                "answer": final_answer,
                "affected_repositories": list(unique_repos.values()),
                "plan": plan,
                "execution_summary": execution_results,
                # Returned so the report exporters and the UI can show the evidence and
                # the blind spots, not only the model's prose about them.
                "hunt_evidence": hunt_evidence,
                "coverage_notes": [n for n in coverage_notes if n],
                "hunt_enabled": allow_hunt,
                "organizations_in_scope": org_names,
            }

        except Exception as e:
            logger.error(f"Zero Day analysis failed: {e}", exc_info=True)
            return {
                "answer": f"An error occurred during analysis: {str(e)}",
                "affected_repositories": [],
                "error": str(e)
            }
    
    def get_analysis_history(self) -> List[Dict[str, Any]]:
        """Get the history of all analyses."""
        return self.analysis_history
    
    def get_total_cost(self) -> float:
        """Get total cost of all AI analyses."""
        return self.provider.get_total_cost()
    
    def _create_fallback_analysis(
        self,
        error_msg: str,
        repo_name: str,
        scanner: str
    ) -> AIAnalysis:
        """
        Create a fallback analysis when AI fails.
        
        Args:
            error_msg: Error message
            repo_name: Repository name
            scanner: Scanner name
            
        Returns:
            Fallback AIAnalysis
        """
        from .providers.base import AIAnalysis, Severity
        
        return AIAnalysis(
            root_cause=f"AI analysis unavailable: {error_msg}",
            severity=Severity.MEDIUM,
            remediation_suggestions=[],
            confidence=0.0,
            explanation=f"Unable to perform AI analysis for {repo_name} ({scanner}). Using fallback.",
            estimated_cost=0.0,
            tokens_used=0
        )
