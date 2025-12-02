"""
OpenAI provider implementation for AI-enhanced self-annealing.

Uses OpenAI's GPT-4 models to analyze stuck scans and suggest remediation.
"""

import json
import logging
from typing import Dict, Any, Optional, List

try:
    from openai import AsyncOpenAI
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

from .base import (
    AIProvider,
    AIAnalysis,
    RemediationSuggestion,
    Severity,
    RemediationAction
)

logger = logging.getLogger(__name__)


class OpenAIProvider(AIProvider):
    """OpenAI GPT-4 provider for stuck scan analysis."""
    
    # Pricing per 1K tokens (as of 2024)
    PRICING = {
        "gpt-4-turbo": {"input": 0.01, "output": 0.03},
        "gpt-4": {"input": 0.03, "output": 0.06},
        "gpt-4-turbo-preview": {"input": 0.01, "output": 0.03},
        "gpt-4o": {"input": 0.005, "output": 0.015},
        "gpt-5": {"input": 0.01, "output": 0.03}, # Placeholder
    }
    
    def __init__(self, api_key: str, model: str = "gpt-4-turbo", max_tokens: int = 2000):
        """
        Initialize OpenAI provider.
        
        Args:
            api_key: OpenAI API key
            model: Model name (default: gpt-4-turbo)
            max_tokens: Maximum tokens for responses
        """
        if not OPENAI_AVAILABLE:
            raise ImportError(
                "OpenAI library not installed. Install with: pip install openai"
            )
        
        super().__init__(api_key, model, max_tokens)
        self.client = AsyncOpenAI(api_key=api_key)
        logger.info(f"Initialized OpenAI provider with model: {model}")
    
    async def analyze_stuck_scan(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> AIAnalysis:
        """
        Analyze a stuck scan using OpenAI GPT-4.
        
        Args:
            diagnostic_data: Diagnostic information about the stuck scan
            historical_data: Optional historical data from previous analyses
            
        Returns:
            AIAnalysis object with root cause and suggestions
        """
        try:
            # Build the prompt
            prompt = self._build_analysis_prompt(diagnostic_data, historical_data)
            
            # Call OpenAI API with function calling for structured output
            # Use max_completion_tokens for newer models (GPT-5+), fallback to max_tokens for older models
            api_params = {
                "model": self.model,
                "messages": [
                    {
                        "role": "system",
                        "content": "You are an expert DevSecOps engineer specializing in security scanning and performance optimization. Provide practical, actionable advice."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                "response_format": {"type": "json_object"}
            }
            
            # GPT-5 and newer models use max_completion_tokens and don't support temperature
            if "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower():
                api_params["max_completion_tokens"] = self.max_tokens
                # GPT-5+ doesn't support custom temperature, only default (1)
            else:
                api_params["max_tokens"] = self.max_tokens
                api_params["temperature"] = 0.3  # Lower temperature for more consistent analysis
            
            response = await self.client.chat.completions.create(**api_params)
            
            # Extract the response
            content = response.choices[0].message.content
            usage = response.usage
            
            if not content:
                logger.error("OpenAI returned empty content")
                raise ValueError("OpenAI returned empty content")
            
            # Parse JSON response
            try:
                cleaned_content = self._clean_json_response(content)
                analysis_data = json.loads(cleaned_content)
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse OpenAI response as JSON: {e}")
                logger.debug(f"Raw content: {content}")
                # Fallback to a basic structure if JSON parsing fails
                analysis_data = {
                    "root_cause": "Failed to parse AI response",
                    "severity": "medium",
                    "confidence": 0.0,
                    "remediation_suggestions": []
                }
            
            # Calculate cost
            cost = self.estimate_cost(usage.prompt_tokens, usage.completion_tokens)
            self._total_cost += cost
            self._total_tokens += usage.total_tokens
            
            # Build remediation suggestions
            suggestions = []
            for sug in analysis_data.get("remediation_suggestions", []):
                try:
                    suggestions.append(RemediationSuggestion(
                        action=RemediationAction(sug["action"]),
                        params=sug.get("params", {}),
                        rationale=sug.get("rationale", ""),
                        confidence=float(sug.get("confidence", 0.5)),
                        estimated_impact=sug.get("estimated_impact", "Unknown"),
                        safety_level=sug.get("safety_level", "moderate")
                    ))
                except (KeyError, ValueError) as e:
                    logger.warning(f"Skipping invalid suggestion: {e}")
                    continue
            
            # Build AI analysis
            analysis = AIAnalysis(
                root_cause=analysis_data.get("root_cause", "Unknown"),
                severity=Severity(analysis_data.get("severity", "medium")),
                remediation_suggestions=suggestions,
                confidence=float(analysis_data.get("confidence", 0.5)),
                explanation=analysis_data.get("explanation", ""),
                estimated_cost=cost,
                tokens_used=usage.total_tokens
            )
            
            logger.info(
                f"OpenAI analysis complete: {len(suggestions)} suggestions, "
                f"confidence={analysis.confidence:.2f}, cost=${cost:.4f}"
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"OpenAI analysis failed: {e}", exc_info=True)
            # Return a fallback analysis
            return AIAnalysis(
                root_cause=f"AI analysis failed: {str(e)}",
                severity=Severity.MEDIUM,
                remediation_suggestions=[],
                confidence=0.0,
                explanation="Unable to complete AI analysis due to an error.",
                estimated_cost=0.0,
                tokens_used=0
            )
    
    def _clean_json_response(self, content: str) -> str:
        """Clean JSON response from Markdown formatting."""
        content = content.strip()
        if content.startswith("```"):
            # Remove opening ```json or ```
            content = content.split("\n", 1)[1]
            # Remove closing ```
            if content.endswith("```"):
                content = content.rsplit("```", 1)[0]
        return content.strip()

    async def triage_finding(
        self,
        title: str,
        description: str,
        severity: str,
        scanner: str
    ) -> Dict[str, Any]:
        """
        Analyze and triage a finding using OpenAI.
        """
        try:
            prompt = f"""You are a security analyst. Triage this security finding.

Title: {title}
Description: {description}
Reported Severity: {severity}
Scanner: {scanner}

Analyze the finding and provide a JSON response with:
1. "priority": Recommended priority (Critical, High, Medium, Low, Info).
2. "confidence": Confidence score (0.0 - 1.0).
3. "reasoning": Explanation for the priority rating.
4. "false_positive_probability": Estimated probability this is a false positive (0.0 - 1.0).
"""
            is_reasoning_model = "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower()

            if is_reasoning_model:
                # Reasoning models (o1/gpt-5) often don't support 'system' role or 'response_format'
                # Merge system prompt into user prompt
                full_prompt = f"System: You are a security analyst.\n\nUser: {prompt}"
                messages = [{"role": "user", "content": full_prompt}]
                
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": 500
                }
            else:
                # Standard GPT-4 models
                api_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security analyst."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 500,
                    "temperature": 0.3
                }

            response = await self.client.chat.completions.create(**api_params)
            content = response.choices[0].message.content
            
            # Track cost
            cost = self.estimate_cost(response.usage.prompt_tokens, response.usage.completion_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.total_tokens

            try:
                cleaned_content = self._clean_json_response(content)
                return json.loads(cleaned_content)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse AI triage response. Content: {repr(content)}")
                return {
                    "priority": severity,
                    "confidence": 0.0,
                    "reasoning": "Failed to parse AI response",
                    "false_positive_probability": 0.0
                }

        except Exception as e:
            logger.error(f"Failed to triage finding: {e}")
            return {
                "priority": severity,
                "confidence": 0.0,
                "reasoning": f"AI triage failed: {e}",
                "false_positive_probability": 0.0
            }

    async def explain_timeout(
        self,
        repo_name: str,
        scanner: str,
        timeout_duration: int,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate a human-readable explanation using OpenAI.
        
        Args:
            repo_name: Name of the repository
            scanner: Scanner that timed out
            timeout_duration: How long before timeout (seconds)
            context: Additional context
            
        Returns:
            Human-readable explanation
        """
        try:
            prompt = f"""Explain in 2-3 sentences why this security scan timed out:

Repository: {repo_name}
Scanner: {scanner}
Timeout: {timeout_duration} seconds
Context: {json.dumps(context, indent=2)}

Provide a clear, non-technical explanation suitable for developers."""

            api_params = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": "You are a helpful DevSecOps assistant."},
                    {"role": "user", "content": prompt}
                ],
                "temperature": 0.5
            }
            
            # GPT-5 and newer models use max_completion_tokens
            if "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower():
                api_params["max_completion_tokens"] = 200
            else:
                api_params["max_tokens"] = 200
            
            response = await self.client.chat.completions.create(**api_params)
            
            explanation = response.choices[0].message.content.strip()
            
            # Track cost
            cost = self.estimate_cost(
                response.usage.prompt_tokens,
                response.usage.completion_tokens
            )
            self._total_cost += cost
            self._total_tokens += response.usage.total_tokens
            
            return explanation
            
        except Exception as e:
            logger.error(f"Failed to generate explanation: {e}")
            return f"The {scanner} scanner exceeded the {timeout_duration} second timeout while scanning {repo_name}."

    async def generate_remediation(
        self,
        vuln_type: str,
        description: str,
        context: str,
        language: str
    ) -> Dict[str, str]:
        """
        Generate a remediation plan for a specific vulnerability using OpenAI.
        """
        try:
            prompt = f"""You are a security expert. Provide a remediation plan for this vulnerability.

Vulnerability: {vuln_type}
Description: {description}
Language: {language}

Context (Code or Dependency):
```
{context}
```

Provide a JSON response with exactly these fields:
1. "remediation": A detailed explanation of how to fix the issue (in Markdown).
2. "diff": A unified diff showing the code changes (if applicable). If no code change is possible (e.g. config change), return an empty string.
"""
            is_reasoning_model = "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower()

            if is_reasoning_model:
                # Reasoning models (o1/gpt-5) often don't support 'system' role or 'response_format'
                # Merge system prompt into user prompt
                full_prompt = f"System: You are a security expert providing remediation plans.\n\nUser: {prompt}"
                messages = [{"role": "user", "content": full_prompt}]
                
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": 1000
                }
            else:
                # Standard GPT-4 models
                api_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security expert providing remediation plans."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 1000,
                    "temperature": 0.2
                }

            response = await self.client.chat.completions.create(**api_params)
            content = response.choices[0].message.content
            
            # Track cost
            cost = self.estimate_cost(response.usage.prompt_tokens, response.usage.completion_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.total_tokens

            try:
                cleaned_content = self._clean_json_response(content)
                return json.loads(cleaned_content)
            except json.JSONDecodeError:
                logger.error(f"Failed to parse AI remediation response. Content: {repr(content)}")
                return {"remediation": content, "diff": ""}

        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}")
            return {"remediation": f"AI generation failed: {e}", "diff": ""}

    def build_architecture_prompt(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str],
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """Build the architecture analysis prompt."""
        configs_str = ""
        for name, content in config_files.items():
            configs_str += f"\n--- {name} ---\n{content}\n"
            
        index_str = ""
        if diagrams_index:
            # We can't include the whole index (too large), but we can mention it's available
            # Or better, we can provide a condensed list of common nodes or just instruct the AI
            # that we have an index and it should try to use specific names.
            # Actually, for the initial prompt, the AI doesn't know what it needs yet.
            # So we just give it general instructions.
            # BUT, if we want it to use specific icons, we could provide a list of ALL available node names (just names).
            # That might be a few thousand tokens.
            # Let's try providing a hint.
            pass

        # Cloud Provider Detection & Icon Preference
        provider_preference = ""
        is_azure = "azure" in repo_name.lower() or "azure" in file_structure.lower() or "azure" in configs_str.lower()
        is_aws = "aws" in repo_name.lower() or "aws" in file_structure.lower() or "aws" in configs_str.lower()
        is_gcp = "gcp" in repo_name.lower() or "google" in repo_name.lower() or "gcp" in configs_str.lower()

        if is_azure:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: AZURE**
This repository appears to be an Azure project. You **MUST** prioritize using icons from `diagrams.azure.*`.
**Preferred Azure Mappings**:
- Network Security Group (NSG) -> `from diagrams.azure.network import NetworkSecurityGroupsClassic`
- Virtual Network (VNet) -> `from diagrams.azure.network import VirtualNetworks`
- Subnet -> `from diagrams.azure.network import Subnets`
- Private DNS Zone -> `from diagrams.azure.network import DNSPrivateZones`
- Key Vault -> `from diagrams.azure.security import KeyVaults`
- Managed Identity -> `from diagrams.azure.identity import ManagedIdentities`
- Azure OpenAI -> `from diagrams.azure.ml import AzureOpenAI`
- App Service -> `from diagrams.azure.web import AppServices`
- Function App -> `from diagrams.azure.compute import FunctionApps`
"""
        elif is_aws:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: AWS**
This repository appears to be an AWS project. You **MUST** prioritize using icons from `diagrams.aws.*`.
"""
        elif is_gcp:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: GCP**
This repository appears to be a Google Cloud project. You **MUST** prioritize using icons from `diagrams.gcp.*`.
"""
        else:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: GENERIC/HYBRID**
No specific cloud provider detected.
- Use **generic icons** where possible (e.g. `diagrams.onprem.*`, `diagrams.programming.*`).
- Use the most appropriate technology-specific icon if a generic one is not available (e.g. `diagrams.onprem.database.PostgreSQL` for Postgres).
"""

        return f"""You are a Senior Software Architect. Analyze this repository and provide an End-to-End Architecture Overview.
            
Repository: {repo_name}

File Structure:
{file_structure}

Configuration Files:
{configs_str}

Provide a comprehensive Markdown report covering:
1. **High-Level Overview**: What does this project do?
2. **Tech Stack**: Languages, Frameworks, Databases, Tools.
3. **Architecture**: Monolith/Microservice? Layers? Patterns?
4. **UI/UX**: Frontend framework, styling, user interaction model (if applicable).
5. **Storage**: Database schema, file storage, caching (inferred from configs).
6. **API**: REST/GraphQL? Endpoints structure?
7. **Fault Tolerance & Error Handling**: Retries, circuit breakers, logging (inferred).
8. **Unique Features**: What stands out?

**IMPORTANT**:
Include a **Python script** using the `diagrams` library to visualize the architecture.
- Provide the Python code inside a code block labeled `python`.
- Import from `diagrams` and `diagrams.aws`, `diagrams.azure`, `diagrams.gcp`, `diagrams.onprem`, etc. as appropriate.
- **NOTE**: `Internet` is located in `diagrams.onprem.network`. Use `from diagrams.onprem.network import Internet`.
- **DO NOT** use `with Diagram(...)`. Instead, instantiate `Diagram` with `show=False` and `filename="architecture_diagram"`.
- Example: `with Diagram("Architecture", show=False, filename="architecture_diagram"):`
{provider_preference}
- **VALIDATION**:
    - If you are unsure about a specific component or connection, use a generic node.
    - **CRITICAL**: Add a comment in the Python code explaining any gaps, missing information, or assumptions.
    - Example: `# GAP: Database type unknown, assuming generic SQL`
    - Example: `# GAP: Auth provider not found in code, assuming internal`
- Ensure the code is valid and self-contained.
- Use generic nodes if specific cloud providers are not obvious.

Format as clean Markdown. Be concise but technical.
"""

    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate an architecture overview using OpenAI.
        """
        try:
            prompt = self.build_architecture_prompt(repo_name, file_structure, config_files)
            return await self.execute_prompt(prompt)

        except Exception as e:
            logger.error(f"Failed to generate architecture overview: {e}")
            return f"Failed to generate architecture overview: {e}"

    async def execute_prompt(self, prompt: str) -> str:
        """Execute a raw prompt against the AI model."""
        try:
            is_reasoning_model = "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower()

            if is_reasoning_model:
                # Reasoning models (o1/gpt-5) often don't support 'system' role
                full_prompt = f"System: You are a Senior Software Architect.\n\nUser: {prompt}"
                messages = [{"role": "user", "content": full_prompt}]
                
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": 10000
                }
            else:
                # Standard GPT-4 models
                api_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a Senior Software Architect."},
                        {"role": "user", "content": prompt}
                    ],
                    "max_tokens": 4000,
                    "temperature": 0.3
                }

            logger.info(f"Calling OpenAI with params: model={api_params['model']}")

            response = await self.client.chat.completions.create(**api_params)
            content = response.choices[0].message.content
            
            logger.info(f"OpenAI Response Content Length: {len(content) if content else 0}")
            if not content:
                logger.warning(f"OpenAI returned empty content. Finish reason: {response.choices[0].finish_reason}")
            
            # Track cost
            cost = self.estimate_cost(response.usage.prompt_tokens, response.usage.completion_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.total_tokens
            
            return content
            
        except Exception as e:
            logger.error(f"Failed to execute prompt: {e}")
            raise e

    async def fix_and_enhance_diagram_code(
        self, 
        code: str, 
        error: str,
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Fix broken diagram code and enhance it.
        """
        index_context = ""
        if diagrams_index:
            # We can provide a look-up context.
            # Since we don't know which nodes are needed, we can't provide specific paths easily without analyzing the code.
            # But we can tell the AI that we have an index and it can "ask" or we can just dump the keys?
            # Dumping keys (node names) might be helpful.
            # There are ~1000 nodes. That's a lot of tokens.
            # Let's try to extract potential node names from the code and look them up.
            import re
            potential_nodes = set(re.findall(r'\b([A-Z][a-zA-Z0-9]*)\b', code))
            found_nodes = {}
            for node in potential_nodes:
                if node in diagrams_index:
                    found_nodes[node] = diagrams_index[node]
            
            if found_nodes:
                index_context = "\n**Available Node Imports (Found in Index):**\n"
                for node, path in found_nodes.items():
                    index_context += f"- {node}: `from {path.rsplit('.', 1)[0]} import {node}`\n"
            
            # Also add a general instruction
            index_context += "\n**Note**: You can use any node from the `diagrams` library. If you need a specific icon (e.g. NetworkSecurityGroup), ensure you import it correctly.\n"

        # Cloud Provider Preference
        provider_preference = ""
        is_azure = "azure" in code.lower() or "azure" in error.lower()
        is_aws = "aws" in code.lower() or "aws" in error.lower() or "amazon" in code.lower()
        is_gcp = "gcp" in code.lower() or "google" in code.lower()

        if is_azure:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: AZURE**
You **MUST** prioritize using icons from `diagrams.azure.*`.
**Preferred Azure Mappings**:
- Network Security Group (NSG) -> `from diagrams.azure.network import NetworkSecurityGroupsClassic`
- Virtual Network (VNet) -> `from diagrams.azure.network import VirtualNetworks`
- Subnet -> `from diagrams.azure.network import Subnets`
- Private DNS Zone -> `from diagrams.azure.network import DNSPrivateZones`
- Key Vault -> `from diagrams.azure.security import KeyVaults`
- Managed Identity -> `from diagrams.azure.identity import ManagedIdentities`
- Azure OpenAI -> `from diagrams.azure.ml import AzureOpenAI`
"""
        elif is_aws:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: AWS**
You **MUST** prioritize using icons from `diagrams.aws.*`.
"""
        elif is_gcp:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: GCP**
You **MUST** prioritize using icons from `diagrams.gcp.*`.
"""
        else:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: GENERIC/HYBRID**
No specific cloud provider detected.
- Use **generic icons** where possible (e.g. `diagrams.onprem.*`, `diagrams.programming.*`).
- Use the most appropriate technology-specific icon if a generic one is not available (e.g. `diagrams.onprem.database.PostgreSQL` for Postgres).
"""

        prompt = f"""You are a Python expert specializing in the `diagrams` library.
The following code failed to execute:

```python
{code}
```

Error:
{error}

{index_context}
{provider_preference}

**Task**:
1. **Fix the error**: Correct imports, syntax, or logic errors.
   - Use the provided **Available Node Imports** to fix `ImportError`.
   - Note: `Internet` is in `diagrams.onprem.network`.
2. **Enhance and Beautify**:
   - Improve the layout and grouping.
   - Use `Cluster` to group related components logically (e.g., "VPC", "Subnet", "Security Layer").
   - Add more descriptive labels.
   - Ensure the diagram is visually appealing and professional.
3. **Substitute Missing Components**:
   - If a specific node class is missing or causing import errors, substitute it with a generic one or a suitable alternative from the same provider.
   - Add a comment explaining the substitution.

**Output**:
Return ONLY the corrected and enhanced Python code.
- The code MUST be self-contained (include all imports).
- The code MUST generate a diagram with `filename="architecture_diagram"` and `show=False`.
- Do not wrap in markdown code blocks if possible, or I will strip them.
"""
        return await self.execute_prompt(prompt)
    
    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate cost for OpenAI API call.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Estimated cost in USD
        """
        pricing = self.PRICING.get(self.model, self.PRICING["gpt-4-turbo"])
        input_cost = (input_tokens / 1000) * pricing["input"]
        output_cost = (output_tokens / 1000) * pricing["output"]
        return input_cost + output_cost
