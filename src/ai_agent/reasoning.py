"""
AI reasoning engine for analyzing stuck scans.

Coordinates AI providers to analyze diagnostic data and generate insights.
"""

import logging
import asyncio
from typing import Dict, Any, Optional, List

from .providers import AIProvider, AIAnalysis
from .diagnostics import DiagnosticCollector

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
