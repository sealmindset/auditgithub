"""
Gemini (Google) provider implementation.

Uses Google's Generative AI SDK to interact with Gemini models.
"""

import json
import logging
import asyncio
from typing import Dict, Any, Optional, List

try:
    import google.generativeai as genai
    from google.api_core import exceptions as google_exceptions
    GOOGLE_AVAILABLE = True
except ImportError:
    GOOGLE_AVAILABLE = False

from .base import (
    AIProvider,
    AIAnalysis,
    RemediationSuggestion,
    Severity,
    RemediationAction
)

logger = logging.getLogger(__name__)


class GeminiProvider(AIProvider):
    """Google Gemini provider."""
    
    def __init__(self, api_key: str, model: str = "gemini-1.5-pro-latest", max_tokens: int = 4000):
        """
        Initialize Gemini provider.
        
        Args:
            api_key: Google API key
            model: Model name (default: gemini-1.5-pro-latest)
            max_tokens: Maximum tokens for responses
        """
        if not GOOGLE_AVAILABLE:
            raise ImportError(
                "Google Generative AI library not installed. Install with: pip install google-generativeai"
            )
        
        super().__init__(api_key, model, max_tokens)
        genai.configure(api_key=api_key)
        self.model_name = model
        self.client = genai.GenerativeModel(model)
        logger.info(f"Initialized Gemini provider with model: {model}")

    async def _call_api_with_retry(self, prompt: str, system_instruction: str = None, retries: int = 3) -> str:
        """Video-game style retry logic for API calls."""
        base_delay = 2
        
        # Configure generation config
        generation_config = genai.types.GenerationConfig(
            max_output_tokens=self.max_tokens,
            temperature=0.3,
        )
        
        # Gemini uses 'system_instruction' in the model constuctor or chat history usually,
        # but for single turn generation we can prepend it or use the system_instruction param if supported.
        # The python SDK v0.5+ supports system_instruction in GenerativeModel constructor.
        # Since we use one instance, we might need to recreate it or just prepend to prompt.
        # Prepending is safer for stateless usage across different system prompts.
        full_prompt = prompt
        if system_instruction:
            full_prompt = f"System Instruction: {system_instruction}\n\nUser Question: {prompt}"

        for attempt in range(retries + 1):
            try:
                # Run in executor because genai is synchronous blocking
                loop = asyncio.get_running_loop()
                response = await loop.run_in_executor(
                    None, 
                    lambda: self.client.generate_content(
                        full_prompt, 
                        generation_config=generation_config
                    )
                )
                
                # Check safeguards
                if response.prompt_feedback and response.prompt_feedback.block_reason:
                    logger.warning(f"Gemini blocked prompt: {response.prompt_feedback.block_reason}")
                    raise ValueError(f"Prompt blocked: {response.prompt_feedback.block_reason}")
                
                return response.text
                
            except Exception as e:
                error_str = str(e).lower()
                # Check for 429 or quota exceeded
                if "429" in error_str or "quota" in error_str or "resource_exhausted" in error_str:
                    if attempt < retries:
                        delay = base_delay * (2 ** attempt)
                        logger.warning(f"Gemini rate limit hit. Retrying in {delay}s... (Attempt {attempt+1}/{retries})")
                        await asyncio.sleep(delay)
                        continue
                
                logger.error(f"Gemini API call failed: {e}")
                if attempt == retries:
                    raise e
                    
        return ""

    async def analyze_stuck_scan(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> AIAnalysis:
        """Analyze a stuck scan using Gemini."""
        prompt = self._build_analysis_prompt(diagnostic_data, historical_data)
        system = "You are an expert DevSecOps engineer specializing in security scanning and performance optimization. Provide practical, actionable advice in JSON format."
        
        try:
            content = await self._call_api_with_retry(prompt, system)
            
            # Parse JSON
            content = self._clean_json_block(content)
            analysis_data = json.loads(content)
            
            # Gemini cost estimation is tricky without specific token counts in response in older SDK versions
            # Assuming ~0 for now or implement token counting if critical
            cost = 0.0 
            
            suggestions = []
            for sug in analysis_data.get("remediation_suggestions", []):
                suggestions.append(RemediationSuggestion(
                    action=RemediationAction(sug.get("action", "unknown")),
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
                estimated_cost=cost,
                tokens_used=0 
            )
            
        except Exception as e:
            logger.error(f"Gemini analysis failed: {e}")
            return AIAnalysis(
                root_cause=f"AI analysis failed: {str(e)}",
                severity=Severity.MEDIUM,
                remediation_suggestions=[],
                confidence=0.0,
                explanation="Unable to complete AI analysis due to an error.",
                estimated_cost=0.0,
                tokens_used=0
            )

    async def explain_timeout(self, repo_name: str, scanner: str, timeout_duration: int, context: Dict[str, Any]) -> str:
        prompt = f"""Explain in 2-3 sentences why this security scan timed out:
Repository: {repo_name}
Scanner: {scanner}
Timeout: {timeout_duration} seconds
Context: {json.dumps(context, indent=2)}
Provide a clear, non-technical explanation suitable for developers."""
        
        try:
            return await self._call_api_with_retry(prompt, "You are a helpful DevSecOps assistant.")
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return f"The {scanner} scanner exceeded the timeout while scanning {repo_name}."

    async def generate_remediation(self, vuln_type: str, description: str, context: str, language: str) -> Dict[str, str]:
        prompt = f"""You are an expert secure coding assistant.
Vulnerability: {vuln_type}
Description: {description}
Language: {language}
Context:
{context}

Task:
1. Analyze the vulnerability.
2. Provide a secure remediation explanation.
3. Provide a code diff or fixed code snippet.

Return ONLY valid JSON with fields: "remediation" (string) and "diff" (string).
"""
        try:
            content = await self._call_api_with_retry(prompt, "You are a security expert. Output valid JSON only.")
            content = self._clean_json_block(content)
            return json.loads(content)
        except Exception as e:
            logger.error(f"Gemini remediation failed: {e}")
            return {"remediation": f"Error generating remediation: {e}", "diff": ""}

    async def triage_finding(self, title: str, description: str, severity: str, scanner: str) -> Dict[str, Any]:
        prompt = f"""Analyze security finding: {title}
Description: {description}
Severity: {severity}
Scanner: {scanner}

Determine Priority, Confidence, False Positive Probability, and Reasoning.
Output JSON with keys: priority, confidence, false_positive_probability, reasoning.
"""
        try:
            content = await self._call_api_with_retry(prompt, "You are a security analyst. Output valid JSON only.")
            content = self._clean_json_block(content)
            return json.loads(content)
        except Exception as e:
            logger.error(f"Gemini triage failed: {e}")
            return {"priority": severity}

    async def analyze_finding(self, finding: Dict[str, Any], user_prompt: Optional[str] = None) -> str:
        finding_context = json.dumps(finding, indent=2)
        if user_prompt:
            prompt = f"Finding Details:\n{finding_context}\n\nUser Question: {user_prompt}"
        else:
            prompt = f"Finding Details:\n{finding_context}\n\nProvide a detailed analysis."
            
        return await self._call_api_with_retry(prompt, "You are a senior security engineer.")

    async def analyze_component(self, package_name: str, version: str, package_manager: str) -> Dict[str, Any]:
        prompt = f"""Analyze component: {package_name} version {version} ({package_manager}) for security risks.
Return JSON with: analysis_text, vulnerability_summary, severity, exploitability, fixed_version.
"""
        try:
            content = await self._call_api_with_retry(prompt, "You are a security researcher. Output valid JSON only.")
            content = self._clean_json_block(content)
            return json.loads(content)
        except Exception as e:
            logger.error(f"Gemini component analysis failed: {e}")
            return {
                "analysis_text": f"Analysis failed: {e}",
                "vulnerability_summary": "Analysis failed.",
                "severity": "Unknown",
                "exploitability": "Unknown",
                "fixed_version": "Unknown"
            }

    async def generate_architecture_report(self, repo_name: str, file_structure: str, config_files: Dict[str, str]) -> str:
        configs_str = "\n".join([f"--- {k} ---\n{v}\n" for k, v in config_files.items()])
        prompt = f"""Analyze this repository and provide an End-to-End Architecture Overview.
Repository: {repo_name}
File Structure:
{file_structure}
Configurations:
{configs_str}

Provide a comprehensive Markdown report covering: High-Level Overview, Tech Stack, Architecture, UI/UX, Storage, API, Fault Tolerance, Unique Features.
"""
        try:
            return await self._call_api_with_retry(prompt, "You are a Senior Software Architect.")
        except Exception as e:
             if "429" in str(e) or "quota" in str(e).lower():
                 return "Error: Rate limit exceeded. Please try again in a minute."
             return f"Error generating report: {e}"

    async def generate_diagram_code(self, repo_name: str, report_content: str, diagrams_index: Optional[Dict[str, str]] = None) -> str:
        prompt = f"""You are a Python expert specializing in the `diagrams` library.
Based on the Architecture Report, generate a Python script to visualize the architecture.

Repository: {repo_name}
Report:
{report_content}

Generate a **Python script** using the `diagrams` library.
- Import correct nodes (e.g., `from diagrams.onprem.network import Internet`).
- Use `Diagram(..., show=False, filename="architecture_diagram", graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}})`.
- Determine cloud provider from report (AWS/Azure/GCP) and use appropriate icons.
- Add comments for assumptions.

Return ONLY the Python code block.
"""
        try:
            content = await self._call_api_with_retry(prompt, "You are a Python expert.")
            return self._clean_python_block(content)
        except Exception as e:
            if "429" in str(e) or "quota" in str(e).lower():
                 return "# Error: Rate limit exceeded. Please try again in a minute."
            return f"# Error generating diagram code: {e}"

    async def generate_architecture_overview(self, repo_name: str, file_structure: str, config_files: Dict[str, str]) -> str:
        """Combine report and diagram generation."""
        try:
            report = await self.generate_architecture_report(repo_name, file_structure, config_files)
            diagram_code = await self.generate_diagram_code(repo_name, report)
            return f"{report}\n\n## Architecture Diagram\n\n{diagram_code}"
        except Exception as e:
            logger.error(f"Failed to generate architecture overview: {e}")
            return f"Failed to generate architecture overview: {e}"

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost for Gemini API call.
        Pricing (1.5 Pro): ~$3.50 / 1M input, ~$10.50 / 1M output (approx)
        """
        # Pricing varies by prompt length (<=128k vs >128k), simplified here
        input_cost = (input_tokens / 1_000_000) * 3.50
        output_cost = (output_tokens / 1_000_000) * 10.50
        return input_cost + output_cost

    async def execute_prompt(self, prompt: str) -> str:
        try:
            return await self._call_api_with_retry(prompt, "You are an expert AI assistant.")
        except Exception as e:
             if "429" in str(e) or "quota" in str(e).lower():
                 return "# Error: Rate limit exceeded. Please try again in a minute."
             return f"Error: {e}"

    async def fix_and_enhance_diagram_code(self, code: str, error: str, diagrams_index: Optional[Dict[str, str]] = None, report_context: Optional[str] = None) -> str:
        prompt = f"""You are a Python expert specializing in the `diagrams` library.
The following code failed to execute:

```python
{code}
```

Error:
{error}

Task:
1. Fix the error (imports, syntax).
2. Enhance layout (`graph_attr={{"splines": "ortho"}}`).
3. Substitute missing components.

Return ONLY the fixed Python code.
"""
        try:
            content = await self._call_api_with_retry(prompt, "You are a Python expert.")
            return self._clean_python_block(content)
        except Exception as e:
            if "429" in str(e) or "quota" in str(e).lower():
                 return "# Error: Rate limit exceeded."
            return f"# Error fixing code: {e}"

    def _clean_json_block(self, content: str) -> str:
        if "```json" in content:
            return content.split("```json")[1].split("```")[0].strip()
        elif "```" in content:
            return content.split("```")[1].split("```")[0].strip()
        return content.strip()

    def _clean_python_block(self, content: str) -> str:
        if "```python" in content:
            return content.split("```python")[1].split("```")[0].strip()
        elif "```" in content:
            return content.split("```")[1].split("```")[0].strip()
        return content.strip()
