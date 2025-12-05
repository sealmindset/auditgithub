"""
Ollama provider implementation for local LLM support.
"""
import logging
import json
import os
from typing import Dict, Any, Optional, List
from openai import AsyncOpenAI

from .base import (
    AIProvider,
    AIAnalysis,
    RemediationSuggestion,
    Severity,
    RemediationAction
)

logger = logging.getLogger(__name__)

class OllamaProvider(AIProvider):
    """Ollama provider for local LLM analysis."""
    
    def __init__(self, base_url: str, model: str = "llama3", max_tokens: int = 2000):
        """
        Initialize Ollama provider.
        
        Args:
            base_url: Ollama API base URL (e.g., http://localhost:11434/v1)
            model: Model name to use
            max_tokens: Maximum tokens for responses
        """
        # API Key is not needed for Ollama usually, but client might require non-empty
        super().__init__("ollama", model, max_tokens)
        
        # Ensure base_url ends with /v1 for OpenAI compatibility if not present
        if not base_url.endswith("/v1"):
            base_url = f"{base_url.rstrip('/')}/v1"
            
        self.client = AsyncOpenAI(
            base_url=base_url,
            api_key="ollama" # Dummy key
        )
        logger.info(f"Initialized Ollama provider with model: {model} at {base_url}")

    async def analyze_stuck_scan(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> AIAnalysis:
        """Analyze stuck scan using Ollama."""
        try:
            prompt = self._build_analysis_prompt(diagnostic_data, historical_data)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are an expert DevSecOps engineer. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"}
            )
            
            content = response.choices[0].message.content
            usage = response.usage
            
            analysis_data = json.loads(content)
            
            # Cost is 0 for local
            self._total_tokens += usage.total_tokens
            
            suggestions = []
            for sug in analysis_data.get("remediation_suggestions", []):
                suggestions.append(RemediationSuggestion(
                    action=RemediationAction(sug["action"]),
                    params=sug.get("params", {}),
                    rationale=sug.get("rationale", ""),
                    confidence=float(sug.get("confidence", 0.5)),
                    estimated_impact=sug.get("estimated_impact", "Unknown"),
                    safety_level=sug.get("safety_level", "moderate")
                ))
                
            return AIAnalysis(
                root_cause=analysis_data.get("root_cause", "Unknown"),
                severity=Severity(analysis_data.get("severity", "medium")),
                remediation_suggestions=suggestions,
                confidence=float(analysis_data.get("confidence", 0.5)),
                explanation=analysis_data.get("explanation", ""),
                estimated_cost=0.0,
                tokens_used=usage.total_tokens
            )
            
        except Exception as e:
            logger.error(f"Ollama analysis failed: {e}")
            return AIAnalysis(
                root_cause=f"AI analysis failed: {str(e)}",
                severity=Severity.MEDIUM,
                remediation_suggestions=[],
                confidence=0.0,
                explanation="Unable to complete AI analysis.",
                estimated_cost=0.0,
                tokens_used=0
            )

    async def explain_timeout(
        self,
        repo_name: str,
        scanner: str,
        timeout_duration: int,
        context: Dict[str, Any]
    ) -> str:
        """Generate explanation using Ollama."""
        try:
            prompt = f"Explain why {scanner} scan timed out on {repo_name} after {timeout_duration}s."
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=200
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error generating explanation: {e}"

    async def generate_remediation(
        self,
        vuln_type: str,
        description: str,
        context: str,
        language: str
    ) -> Dict[str, str]:
        """Generate remediation using Ollama."""
        prompt = f"""Vulnerability: {vuln_type}
Description: {description}
Language: {language}
Context: {context}

Provide a fix in JSON format: {{ "remediation": "...", "diff": "..." }}
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a secure coding expert. Output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            logger.error(f"Ollama remediation failed: {e}")
            return {"remediation": f"Error: {e}", "diff": ""}

    async def triage_finding(
        self,
        title: str,
        description: str,
        severity: str,
        scanner: str
    ) -> Dict[str, Any]:
        """Triage finding using Ollama."""
        prompt = f"""Triage this finding: {title} ({severity}) from {scanner}.
Description: {description}

Output JSON: {{ "priority": "...", "confidence": 0.0-1.0, "reasoning": "..." }}
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security analyst. Output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {"priority": severity, "confidence": 0.0, "reasoning": str(e)}

    async def analyze_finding(
        self,
        finding: Dict[str, Any],
        user_prompt: Optional[str] = None
    ) -> str:
        """Analyze finding using Ollama."""
        finding_context = json.dumps(finding, indent=2)
        
        if user_prompt:
            prompt = f"Finding: {finding_context}\n\nQuestion: {user_prompt}"
        else:
            prompt = f"Analyze this finding: {finding_context}"

        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security expert."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    async def analyze_component(
        self,
        package_name: str,
        version: str,
        package_manager: str
    ) -> Dict[str, Any]:
        """Analyze component using Ollama."""
        prompt = f"""Analyze component: {package_name} {version} ({package_manager}).
Output JSON: {{ "analysis_text": "...", "vulnerability_summary": "...", "severity": "...", "exploitability": "...", "fixed_version": "..." }}
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security researcher. Output valid JSON."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            return json.loads(response.choices[0].message.content)
        except Exception as e:
            return {
                "analysis_text": f"Error: {e}",
                "vulnerability_summary": "Analysis failed",
                "severity": "Unknown",
                "exploitability": "Unknown",
                "fixed_version": "Unknown"
            }

    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """Generate architecture overview using Ollama."""
        prompt = f"Analyze architecture for {repo_name}.\nFiles:\n{file_structure}"
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            return f"Error: {e}"

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        return 0.0

    async def execute_prompt(self, prompt: str) -> str:
        """Execute a raw prompt using Ollama."""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.choices[0].message.content
        except Exception as e:
            logger.error(f"Ollama execute_prompt failed: {e}")
            return f"Error: {e}"

    async def generate_architecture_report(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate a text-based architecture report.
        """
        return await self.generate_architecture_overview(repo_name, file_structure, config_files)

    async def generate_diagram_code(
        self,
        repo_name: str,
        report_content: str,
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate Python code for the architecture diagram based on the report.
        """
        return "# Diagram generation not yet supported for Ollama provider."


class DockerAIProvider(OllamaProvider):
    """
    Docker AI provider.
    Same as Ollama but typically runs on a specific internal host and may ignore model name.
    """
    def __init__(self, base_url: str = "http://host.docker.internal:11434", model: str = "docker-ai", max_tokens: int = 2000):
        # Docker AI often runs on host.docker.internal from within containers
        super().__init__(base_url, model, max_tokens)
