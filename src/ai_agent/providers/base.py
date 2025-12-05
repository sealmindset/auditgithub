"""
Base abstract class for AI providers.

Defines the interface that all AI providers (OpenAI, Claude, etc.) must implement.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from enum import Enum


class Severity(str, Enum):
    """Severity levels for stuck scan issues."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class RemediationAction(str, Enum):
    """Types of remediation actions the AI can suggest."""
    INCREASE_TIMEOUT = "increase_timeout"
    EXCLUDE_PATTERNS = "exclude_patterns"
    REDUCE_PARALLELISM = "reduce_parallelism"
    SKIP_SCANNER = "skip_scanner"
    CHUNK_SCAN = "chunk_scan"
    ADJUST_RESOURCES = "adjust_resources"


@dataclass
class RemediationSuggestion:
    """A specific remediation suggestion from the AI."""
    action: RemediationAction
    params: Dict[str, Any]
    rationale: str
    confidence: float  # 0.0 to 1.0
    estimated_impact: str
    safety_level: str  # "safe", "moderate", "risky"


@dataclass
class AIAnalysis:
    """Complete AI analysis of a stuck scan."""
    root_cause: str
    severity: Severity
    remediation_suggestions: List[RemediationSuggestion]
    confidence: float  # 0.0 to 1.0
    explanation: str
    estimated_cost: float  # USD
    tokens_used: int


class AIProvider(ABC):
    """Abstract base class for AI providers."""
    
    def __init__(self, api_key: str, model: str, max_tokens: int = 2000):
        """
        Initialize the AI provider.
        
        Args:
            api_key: API key for the provider
            model: Model name to use
            max_tokens: Maximum tokens for responses
        """
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self._total_cost = 0.0
        self._total_tokens = 0
    
    @abstractmethod
    async def analyze_stuck_scan(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> AIAnalysis:
        """
        Analyze a stuck scan and provide remediation suggestions.
        
        Args:
            diagnostic_data: Diagnostic information about the stuck scan
            historical_data: Optional historical data from previous analyses
            
        Returns:
            AIAnalysis object with root cause, suggestions, and confidence
        """
        pass
    
    @abstractmethod
    async def explain_timeout(
        self,
        repo_name: str,
        scanner: str,
        timeout_duration: int,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate a human-readable explanation of why a scan timed out.
        
        Args:
            repo_name: Name of the repository
            scanner: Scanner that timed out
            timeout_duration: How long before timeout (seconds)
            context: Additional context about the scan
            
        Returns:
            Human-readable explanation string
        """
        pass

    @abstractmethod
    async def generate_remediation(
        self,
        vuln_type: str,
        description: str,
        context: str,
        language: str
    ) -> Dict[str, str]:
        """
        Generate a remediation plan for a specific vulnerability.
        
        Args:
            vuln_type: Type of vulnerability (e.g., SQL Injection)
            description: Description of the finding
            context: Code snippet or dependency context
            language: Programming language
            
        Returns:
            Dict with 'remediation' (text) and 'diff' (code diff)
        """
        pass

    @abstractmethod
    async def triage_finding(
        self,
        title: str,
        description: str,
        severity: str,
        scanner: str
    ) -> Dict[str, Any]:
        """
        Analyze and triage a finding.
        
        Args:
            title: Finding title
            description: Finding description
            severity: Reported severity
            scanner: Scanner name
            
        Returns:
            Dict with priority, confidence, reasoning, etc.
        """
        pass

    @abstractmethod
    async def analyze_finding(
        self,
        finding: Dict[str, Any],
        user_prompt: Optional[str] = None
    ) -> str:
        """
        Analyze a finding and provide detailed insights or answer user questions.
        
        Args:
            finding: Dictionary containing finding details (title, description, code, etc.)
            user_prompt: Optional specific question from the user
            
        Returns:
            Markdown formatted analysis
        """
        pass

    @abstractmethod
    async def analyze_component(
        self,
        package_name: str,
        version: str,
        package_manager: str
    ) -> Dict[str, Any]:
        """
        Analyze a software component for vulnerabilities and risks.
        
        Args:
            package_name: Name of the package
            version: Version of the package
            package_manager: Package manager (npm, pip, etc.)
            
        Returns:
            Dict with keys: analysis_text, vulnerability_summary, severity, exploitability, fixed_version
        """
        pass

    @abstractmethod
    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate an architecture overview for the repository.
        
        Args:
            repo_name: Name of the repository
            file_structure: String representation of file tree
            config_files: Dict of config filename -> content
            
        Returns:
            Markdown formatted architecture overview
        """
        pass

    @abstractmethod
    async def generate_architecture_report(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate a text-based architecture report.
        """
        pass

    @abstractmethod
    async def generate_diagram_code(
        self,
        repo_name: str,
        report_content: str,
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate Python code for the architecture diagram based on the report.
        """
        pass

    @abstractmethod
    async def execute_prompt(self, prompt: str) -> str:
        """
        Execute a raw text prompt against the AI model.
        
        Args:
            prompt: User prompt
            
        Returns:
            AI response as text
        """
        pass

    
    @abstractmethod
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate the cost of an API call.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Estimated cost in USD
        """
        pass
    
    def get_total_cost(self) -> float:
        """Get total cost of all API calls made by this provider."""
        return self._total_cost
    
    def get_total_tokens(self) -> int:
        """Get total tokens used by this provider."""
        return self._total_tokens
    
    def _build_analysis_prompt(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> str:
        """
        Build the prompt for stuck scan analysis.
        
        Args:
            diagnostic_data: Diagnostic information
            historical_data: Optional historical data
            
        Returns:
            Formatted prompt string
        """
        prompt = f"""You are an expert DevSecOps engineer analyzing a stuck security scan.

Repository: {diagnostic_data.get('repo_name', 'unknown')}
Scanner: {diagnostic_data.get('scanner', 'unknown')}
Timeout Duration: {diagnostic_data.get('timeout_duration', 0)} seconds
Phase: {diagnostic_data.get('phase', 'unknown')}

Repository Metadata:
- Size: {diagnostic_data.get('repo_metadata', {}).get('size_mb', 'unknown')} MB
- Files: {diagnostic_data.get('repo_metadata', {}).get('file_count', 'unknown')}
- Primary Language: {diagnostic_data.get('repo_metadata', {}).get('primary_language', 'unknown')}
- Lines of Code: {diagnostic_data.get('repo_metadata', {}).get('loc', 'unknown')}

System Metrics:
- CPU Usage: {diagnostic_data.get('system_metrics', {}).get('cpu_percent', 'unknown')}%
- Memory Usage: {diagnostic_data.get('system_metrics', {}).get('memory_percent', 'unknown')}%
- Disk I/O Wait: {diagnostic_data.get('system_metrics', {}).get('disk_io_wait', 'unknown')}

Scanner Progress:
- Files Scanned: {diagnostic_data.get('scanner_progress', {}).get('files_scanned', 'unknown')}
- Files Remaining: {diagnostic_data.get('scanner_progress', {}).get('files_remaining', 'unknown')}

Historical Timeouts: {diagnostic_data.get('historical_timeouts', 0)}
"""

        if historical_data:
            prompt += f"\n\nHistorical Data:\n"
            for entry in historical_data[-3:]:  # Last 3 entries
                prompt += f"- {entry.get('timestamp')}: {entry.get('suggestion')} -> {entry.get('outcome')}\n"

        prompt += """
Analyze this stuck scan and provide a JSON response with:
1. root_cause: Why did it timeout? (string)
2. severity: How critical is this? (critical/high/medium/low)
3. remediation_suggestions: Array of specific, actionable fixes
   Each suggestion should have:
   - action: Type of fix (increase_timeout, exclude_patterns, reduce_parallelism, skip_scanner, chunk_scan, adjust_resources)
   - params: Specific parameters for the action (object)
   - rationale: Why this will help (string)
   - confidence: How confident are you? (0.0-1.0)
   - estimated_impact: Expected improvement (string)
   - safety_level: How safe is this action? (safe/moderate/risky)
4. confidence: Overall confidence in analysis (0.0-1.0)
5. explanation: Detailed explanation of the issue (string)

Focus on practical, safe remediation strategies. Prioritize actions that don't modify source code.
"""
        return prompt
