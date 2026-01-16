
import logging
from typing import Dict, Any, List, Optional
from .base import AIProvider, AIAnalysis

logger = logging.getLogger(__name__)

class FailoverProvider(AIProvider):
    """
    Wrapper provider that implements failover logic between a primary and secondary provider.
    """
    
    def __init__(self, primary: AIProvider, secondary: AIProvider):
        """
        Initialize FailoverProvider.
        """
        super().__init__("failover", "multi-model", 0)
        self.primary = primary
        self.secondary = secondary
        self.primary_failed = False

    async def _execute_with_failover(self, method_name: str, *args, **kwargs):
        """
        Execute a method on the primary provider, falling back to secondary on failure.
        """
        if not self.primary_failed:
            try:
                method = getattr(self.primary, method_name)
                return await method(*args, **kwargs)
            except Exception as e:
                logger.warning(f"Primary provider ({self.primary.__class__.__name__}) failed: {e}. Switching to secondary ({self.secondary.__class__.__name__}).")
                self.primary_failed = True
        
        # Secondary execution
        try:
            method = getattr(self.secondary, method_name)
            return await method(*args, **kwargs)
        except Exception as e:
            logger.error(f"Secondary provider ({self.secondary.__class__.__name__}) also failed: {e}")
            raise e

    async def analyze_stuck_scan(self, diagnostic_data: Dict[str, Any], historical_data: Optional[List[Dict[str, Any]]] = None) -> AIAnalysis:
        return await self._execute_with_failover("analyze_stuck_scan", diagnostic_data, historical_data)

    async def explain_timeout(self, repo_name: str, scanner: str, timeout_duration: int, context: Dict[str, Any]) -> str:
        return await self._execute_with_failover("explain_timeout", repo_name, scanner, timeout_duration, context)

    async def generate_remediation(self, vuln_type: str, description: str, context: str, language: str) -> Dict[str, str]:
        return await self._execute_with_failover("generate_remediation", vuln_type, description, context, language)

    async def triage_finding(self, title: str, description: str, severity: str, scanner: str) -> Dict[str, Any]:
        return await self._execute_with_failover("triage_finding", title, description, severity, scanner)

    async def analyze_finding(self, finding: Dict[str, Any], user_prompt: Optional[str] = None) -> str:
        return await self._execute_with_failover("analyze_finding", finding, user_prompt)

    async def analyze_component(self, package_name: str, version: str, package_manager: str) -> Dict[str, Any]:
        return await self._execute_with_failover("analyze_component", package_name, version, package_manager)

    async def generate_architecture_overview(self, repo_name: str, file_structure: str, config_files: Dict[str, str]) -> str:
        return await self._execute_with_failover("generate_architecture_overview", repo_name, file_structure, config_files)

    async def generate_architecture_report(self, repo_name: str, file_structure: str, config_files: Dict[str, str]) -> str:
        return await self._execute_with_failover("generate_architecture_report", repo_name, file_structure, config_files)

    async def generate_diagram_code(self, repo_name: str, report_content: str, diagrams_index: Optional[Dict[str, str]] = None) -> str:
        return await self._execute_with_failover("generate_diagram_code", repo_name, report_content, diagrams_index)

    async def execute_prompt(self, prompt: str) -> str:
        return await self._execute_with_failover("execute_prompt", prompt)

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        # Default to primary's cost estimation unless it failed
        if not self.primary_failed:
            return self.primary.estimate_cost(input_tokens, output_tokens)
        return self.secondary.estimate_cost(input_tokens, output_tokens)

    def get_total_cost(self) -> float:
        return self.primary.get_total_cost() + self.secondary.get_total_cost()

    def get_total_tokens(self) -> int:
        return self.primary.get_total_tokens() + self.secondary.get_total_tokens()
