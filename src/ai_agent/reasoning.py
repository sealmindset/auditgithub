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
        scope: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Analyze a zero-day query with comprehensive database search.
        
        This uses an enhanced "Tool Use" pattern:
        1. Ask LLM to determine the search strategy across multiple sources
        2. Execute the tools (DB queries) with fuzzy matching
        3. Pass results back to LLM to generate the final answer
        
        Args:
            query: User's natural language query
            db_session: Database session
            scope: Optional list of scopes to search (dependencies, findings, languages, all)
        """
        try:
            logger.info(f"Analyzing zero-day query: {query} (scope: {scope})")
            
            # Import here to avoid circular dependency
            from .tools.db_tools import (
                search_dependencies, 
                search_findings, 
                search_languages,
                search_repositories_by_technology,
                search_all_sources
            )
            
            # Step 1: Determine Plan
            # Enhanced prompt with all available search tools
            scope_str = f"Scope Restriction: {', '.join(scope)}" if scope else "Scope: All sources"
            
            planning_prompt = f"""
            You are a Senior Security Analyst Agent analyzing Zero Day vulnerabilities.

            User Query: "{query}"
            {scope_str}

            Available Search Tools:
            1. search_dependencies(package_name, version_spec) - Search SBOM/Dependencies for libraries/packages
            2. search_findings(query, severity_filter) - Search security findings (CVE, CWE, vulnerabilities)
            3. search_languages(language) - Find repositories using specific programming language
            4. search_technology(keyword) - Find repos by language or description match

            NORMALIZATION RULES (90% Confidence Fuzzy Matching):
            - "react.js" or "React" or "ReactJS" → "react"
            - "next.js" or "Next.JS" or "NextJS" → "next"
            - "log4j" → "log4j-core" or "log4j"
            - "python" → "python" or "py"
            - Extract CVE IDs (CVE-YYYY-NNNNN format)
            - Extract CWE IDs (CWE-NNN format)

            SEARCH STRATEGY:
            - For package/library vulnerabilities → Use search_dependencies and/or search_findings
            - For CVE/CWE queries → Use search_findings
            - For technology/language queries → Use search_languages and/or search_technology
            - For comprehensive searches → Use multiple tools

            Generate a search plan as JSON. Format:
            {{
                "thought": "Explain your reasoning and which sources to search",
                "tools": [
                    {{"name": "search_dependencies", "args": {{"package_name": "react"}}}},
                    {{"name": "search_findings", "args": {{"query": "CVE-2024-12345", "severity_filter": "Critical"}}}},
                    {{"name": "search_languages", "args": {{"language": "python"}}}}
                ]
            }}

            IMPORTANT: Return ONLY the JSON object, no markdown formatting.
            """
            
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
            
            for tool in plan.get("tools", []):
                tool_name = tool.get("name")
                args = tool.get("args", {})
                
                try:
                    if tool_name == "search_dependencies":
                        results = search_dependencies(
                            db_session, 
                            package_name=args.get("package_name"), 
                            version_spec=args.get("version_spec"),
                            use_fuzzy=True
                        )
                        execution_results.append(f"Dependencies: Found {len(results)} repos using '{args.get('package_name')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)
                        
                    elif tool_name == "search_findings":
                        results = search_findings(
                            db_session,
                            query=args.get("query"),
                            severity_filter=args.get("severity_filter")
                        )
                        execution_results.append(f"Findings: Found {len(results)} security findings matching '{args.get('query')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)
                    
                    elif tool_name == "search_languages":
                        results = search_languages(
                            db_session,
                            language_name=args.get("language"),
                            use_fuzzy=True
                        )
                        execution_results.append(f"Languages: Found {len(results)} repos using '{args.get('language')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)
                        
                    elif tool_name == "search_technology":
                        results = search_repositories_by_technology(
                            db_session,
                            technology=args.get("keyword")
                        )
                        execution_results.append(f"Technology: Found {len(results)} repos matching '{args.get('keyword')}'")
                        affected_repos.extend(results)
                        all_details.extend(results)
                    
                    elif tool_name == "search_all_sources":
                        all_results = search_all_sources(
                            db_session,
                            query=args.get("query"),
                            scopes=args.get("scopes") or scope
                        )
                        # Extract aggregated results
                        agg_repos = all_results.get("aggregated_repositories", [])
                        execution_results.append(f"All Sources: Found {len(agg_repos)} unique repos across all data sources")
                        affected_repos.extend(agg_repos)
                        # Store detailed results
                        for source_name, source_results in all_results.items():
                            if source_name != "aggregated_repositories":
                                all_details.extend(source_results)
                                
                except Exception as tool_error:
                    logger.error(f"Tool {tool_name} failed: {tool_error}")
                    execution_results.append(f"{tool_name}: Error - {str(tool_error)}")

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

            # Step 3: Synthesize Answer with AI
            repo_list_str = "\n".join([
                f"- **{r.get('repository')}** ({r.get('source', 'unknown')} match)" 
                for r in unique_repos.values()
            ])
            
            # Include sample details for context
            detail_summary = []
            for detail in all_details[:10]:  # Limit to first 10 for token efficiency
                if detail.get("source") == "findings":
                    detail_summary.append(f"  - Finding: {detail.get('title')} (Severity: {detail.get('severity')}, CVE: {detail.get('cve_id')})")
                elif detail.get("source") == "dependencies":
                    detail_summary.append(f"  - Dependency: {detail.get('package_name')} v{detail.get('version')}")
            
            detail_str = "\n".join(detail_summary) if detail_summary else "No additional details available."
            
            synthesis_prompt = f"""
            User Query: "{query}"
            
            Search Strategy Executed:
            {json.dumps(plan.get('tools', []), indent=2)}
            
            Execution Results:
            {chr(10).join(execution_results)}
            
            Identified Repositories ({len(unique_repos)} total):
            {repo_list_str}
            
            Sample Match Details:
            {detail_str}
            
            Please provide a comprehensive final answer:
            1. **Summary**: Briefly explain what the query is about (vulnerability, technology, etc.)
            2. **Affected Repositories**: List the repositories and explain WHY each matched (based on dependencies, findings, language, etc.)
            3. **Risk Assessment**: Evaluate the severity and potential impact
            4. **Remediation Steps**: Provide 2-3 specific, actionable mitigation or remediation recommendations
            
            Format your response in clean Markdown with proper headings and bullet points.
            """
            
            if hasattr(self.provider, "execute_prompt"):
                final_answer = await self.provider.execute_prompt(synthesis_prompt)
            else:
                final_answer = f"Analysis complete. Found {len(unique_repos)} potentially affected repositories."

            return {
                "answer": final_answer,
                "affected_repositories": list(unique_repos.values()),
                "plan": plan,
                "execution_summary": execution_results
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
