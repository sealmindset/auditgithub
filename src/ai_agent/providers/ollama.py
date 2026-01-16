"""
Ollama provider implementation for local LLM support.
"""
import logging
import json
import os
import re
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


def _extract_json_from_response(content: str) -> str:
    """
    Extract JSON from a response that may be wrapped in markdown code blocks.
    Handles responses like: ```json\n{...}\n```
    Also handles malformed JSON with backticks inside string values.
    """
    if not content:
        return content
    
    # Try to find JSON in markdown code blocks
    # Match ```json or ``` followed by JSON content
    patterns = [
        r'```(?:json)?\s*\n?([\s\S]*?)\n?```',  # Markdown code blocks
        r'`([\s\S]*?)`',  # Inline code
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, content, re.DOTALL)
        for match in matches:
            match = match.strip()
            if match.startswith('{') and match.endswith('}'):
                return match
    
    # If content starts with ``` strip it
    content = content.strip()
    if content.startswith('```'):
        # Find the end
        lines = content.split('\n')
        if lines[0].startswith('```'):
            lines = lines[1:]  # Remove first line
        if lines and lines[-1].strip() == '```':
            lines = lines[:-1]  # Remove last line
        content = '\n'.join(lines)
    
    # If no code blocks, return original (might be plain JSON)
    return content.strip()


def _safe_parse_json(content: str) -> Dict[str, Any]:
    """
    Safely parse JSON, handling common LLM output issues like backticks in strings.
    """
    # First try normal parsing
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass
    
    # Try to extract just the parts we need using regex
    remediation_match = re.search(r'"remediation"\s*:\s*"([^"]*(?:\\"[^"]*)*)"', content)
    diff_match = re.search(r'"diff"\s*:\s*["`]([^"`]*(?:\\.[^"`]*)*)["`]', content)
    
    result = {}
    if remediation_match:
        result["remediation"] = remediation_match.group(1).replace('\\"', '"')
    if diff_match:
        result["diff"] = diff_match.group(1).replace('\\"', '"')
    
    if result:
        return result
    
    # Last resort: try to clean up backticks that might be causing issues
    # Replace backtick-quoted strings with regular quotes
    cleaned = re.sub(r'`([^`]*)`', r'"\1"', content)
    try:
        return json.loads(cleaned)
    except json.JSONDecodeError:
        pass
    
    # Give up and return empty
    raise json.JSONDecodeError("Could not parse JSON", content, 0)


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
            
            # Extract JSON from potential markdown wrapping
            clean_content = _extract_json_from_response(content)
            analysis_data = json.loads(clean_content)
            
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

You MUST respond with a JSON object containing exactly two string fields:
- "remediation": A string containing the explanation of how to fix this vulnerability
- "diff": A string containing the code changes (before/after) to fix the vulnerability

Example format:
{{"remediation": "Use parameterized queries to prevent SQL injection...", "diff": "# Before:\\nquery = 'SELECT * FROM users WHERE id = ' + user_id\\n\\n# After:\\ncursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"}}
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a secure coding expert. Output valid JSON only with string values, no nested objects."},
                    {"role": "user", "content": prompt}
                ],
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content

            try:
                # First try to extract JSON from potential markdown wrapping
                clean_content = _extract_json_from_response(content)
                result = json.loads(clean_content)
                
                # Ensure remediation and diff are strings
                if isinstance(result.get("remediation"), dict):
                    result["remediation"] = json.dumps(result["remediation"], indent=2)
                if isinstance(result.get("diff"), dict):
                    result["diff"] = json.dumps(result["diff"], indent=2)
                    
                return {
                    "remediation": str(result.get("remediation", "")),
                    "diff": str(result.get("diff", ""))
                }
            except json.JSONDecodeError as json_err:
                logger.error(f"JSON parsing error: {json_err}")
                logger.error(f"Raw content (first 500 chars): {repr(content[:500])}")
                return {
                    "remediation": f"AI response could not be parsed as JSON. Raw response:\n\n{content}",
                    "diff": ""
                }
        except Exception as e:
            logger.error(f"Ollama remediation failed: {e}", exc_info=True)
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
    Docker Model Runner provider.
    Uses Docker Desktop's built-in Model Runner with OpenAI-compatible API at /engines/v1.
    Note: Default context size is 4096 tokens. Large prompts will be truncated.
    """
    def __init__(self, base_url: str = "http://localhost:12434", model: str = "ai/llama3.2:latest", max_tokens: int = 2000):
        # Docker Model Runner uses /engines/v1 for OpenAI-compatible API
        # Skip parent __init__ and configure manually
        super(AIProvider, self).__init__()
        self.provider_name = "docker"
        self.model = model
        self.max_tokens = max_tokens
        self._total_tokens = 0
        self._total_cost = 0.0
        # Docker Model Runner default context is 4096, reserve tokens for response
        self.max_context_tokens = 3500  # Leave room for response
        
        # Ensure base_url uses /engines/v1 for Docker Model Runner
        base_url = base_url.rstrip('/')
        if base_url.endswith('/v1') or base_url.endswith('/engines/v1'):
            base_url = base_url.rsplit('/', 1)[0]  # Remove /v1 or /engines/v1
        
        api_base = f"{base_url}/engines/v1"
        
        self.client = AsyncOpenAI(
            base_url=api_base,
            api_key="docker"  # Dummy key, not needed for Docker Model Runner
        )
        logger.info(f"Initialized Docker Model Runner provider with model: {model} at {api_base}")
    
    def _truncate_prompt(self, text: str, max_chars: int = 12000) -> str:
        """
        Truncate text to fit within context limits.
        Rough estimate: ~4 chars per token, so 12000 chars ≈ 3000 tokens.
        """
        if len(text) <= max_chars:
            return text
        
        # Truncate and add indicator
        truncated = text[:max_chars]
        # Try to end at a sentence or newline
        last_newline = truncated.rfind('\n')
        last_period = truncated.rfind('. ')
        
        cut_point = max(last_newline, last_period)
        if cut_point > max_chars * 0.7:  # Only use if we keep at least 70%
            truncated = truncated[:cut_point + 1]
        
        return truncated + "\n[... content truncated for context limit ...]"
    
    async def generate_remediation(
        self,
        vuln_type: str,
        description: str,
        context: str,
        language: str
    ) -> Dict[str, str]:
        """Generate remediation using Docker Model Runner with context-aware truncation."""
        # Truncate context if needed (most likely culprit for large prompts)
        truncated_context = self._truncate_prompt(context, max_chars=8000)
        truncated_desc = self._truncate_prompt(description, max_chars=2000)
        
        prompt = f"""Vulnerability: {vuln_type}
Description: {truncated_desc}
Language: {language}
Context: {truncated_context}

Respond with JSON containing exactly two string fields:
- "remediation": explanation of how to fix this vulnerability
- "diff": code changes showing before/after fix

Example: {{"remediation": "Use parameterized queries...", "diff": "# Before:\\nold_code\\n\\n# After:\\nnew_code"}}
"""
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a secure coding expert. Output valid JSON only."},
                    {"role": "user", "content": prompt}
                ],
                max_tokens=self.max_tokens,
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content

            try:
                clean_content = _extract_json_from_response(content)
                # Use safe parsing that handles backticks and other LLM quirks
                result = _safe_parse_json(clean_content)
                
                # Ensure remediation and diff are strings
                if isinstance(result.get("remediation"), dict):
                    result["remediation"] = json.dumps(result["remediation"], indent=2)
                if isinstance(result.get("diff"), dict):
                    result["diff"] = json.dumps(result["diff"], indent=2)
                    
                return {
                    "remediation": str(result.get("remediation", "")),
                    "diff": str(result.get("diff", ""))
                }
            except json.JSONDecodeError as json_err:
                logger.error(f"JSON parsing error: {json_err}")
                # Try to extract useful content even if JSON parsing failed
                remediation = content
                if "remediation" in content.lower():
                    # Try to get just the remediation text
                    match = re.search(r'"remediation"\s*:\s*["`]([^"`]+)', content)
                    if match:
                        remediation = match.group(1)
                return {
                    "remediation": remediation[:1000] if len(remediation) > 1000 else remediation,
                    "diff": ""
                }
        except Exception as e:
            error_msg = str(e)
            if "exceed_context_size" in error_msg or "context size" in error_msg.lower():
                logger.warning(f"Context size exceeded, retrying with smaller prompt")
                # Try again with more aggressive truncation
                return await self._retry_with_minimal_prompt(vuln_type, language)
            logger.error(f"Docker Model Runner remediation failed: {e}", exc_info=True)
            return {"remediation": f"Error: {e}", "diff": ""}
    
    async def _retry_with_minimal_prompt(self, vuln_type: str, language: str) -> Dict[str, str]:
        """Retry with a minimal prompt when context is exceeded."""
        prompt = f"""Fix for {vuln_type} vulnerability in {language}. 
Respond with JSON: {{"remediation": "how to fix", "diff": "code changes"}}"""
        
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                response_format={"type": "json_object"}
            )
            content = response.choices[0].message.content
            clean_content = _extract_json_from_response(content)
            result = json.loads(clean_content)
            return {
                "remediation": str(result.get("remediation", "")),
                "diff": str(result.get("diff", ""))
            }
        except Exception as e:
            return {"remediation": f"Error with minimal prompt: {e}", "diff": ""}
