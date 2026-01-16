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

    async def analyze_finding(
        self,
        finding: Dict[str, Any],
        user_prompt: Optional[str] = None
    ) -> str:
        """
        Analyze a finding and answer user questions using OpenAI.
        """
        try:
            # Format finding details for the prompt
            finding_context = f"""
Title: {finding.get('title', 'Unknown')}
Type: {finding.get('finding_type', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
File: {finding.get('file_path', 'Unknown')}
Line: {finding.get('line_start', '?')} - {finding.get('line_end', '?')}
Description: {finding.get('description', 'No description')}

Code Snippet:
```
{finding.get('code_snippet', 'No code snippet')}
```
"""
            
            system_prompt = "You are a senior security engineer. Analyze the provided security finding."
            
            if user_prompt:
                user_msg = f"""Finding Details:
{finding_context}

User Question: {user_prompt}

Answer the user's question based on the finding details. Be technical, precise, and helpful."""
            else:
                user_msg = f"""Finding Details:
{finding_context}

Provide a detailed analysis of this finding including:
1. **Explanation**: What is the vulnerability and how does it work?
2. **Impact**: What is the potential impact if exploited?
3. **Verification**: How can I verify if this is a true positive?
4. **Remediation**: Specific steps to fix the issue.
"""

            is_reasoning_model = "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower()

            if is_reasoning_model:
                full_prompt = f"System: {system_prompt}\n\nUser: {user_msg}"
                messages = [{"role": "user", "content": full_prompt}]
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": 2000
                }
            else:
                api_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_msg}
                    ],
                    "max_tokens": 2000,
                    "temperature": 0.4
                }

            response = await self.client.chat.completions.create(**api_params)
            content = response.choices[0].message.content
            
            # Track cost
            cost = self.estimate_cost(response.usage.prompt_tokens, response.usage.completion_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.total_tokens
            
            return content

        except Exception as e:
            logger.error(f"Failed to analyze finding: {e}")
            return f"Failed to analyze finding: {e}"

    async def analyze_component(
        self,
        package_name: str,
        version: str,
        package_manager: str
    ) -> Dict[str, Any]:
        """
        Analyze a software component for vulnerabilities and risks using OpenAI.
        """
        try:
            prompt = f"""You are a software security researcher. Analyze this component for security risks.

Component: {package_name}
Version: {version}
Package Manager: {package_manager}

Perform a security assessment and provide a JSON response with:
1. "analysis_text": A detailed Markdown summary of known vulnerabilities, security posture, and risks associated with this specific version. Mention if it's outdated or end-of-life.
2. "vulnerability_summary": A concise 1-sentence summary of the most critical issues (e.g., "Contains 2 critical CVEs related to RCE").
3. "severity": Overall risk severity (Critical, High, Medium, Low, Safe).
4. "exploitability": Is it susceptible to compromise? (High, Moderate, Low, Theoretical). Mention if PoC code exists.
5. "fixed_version": The recommended version to upgrade to (e.g., "1.2.3" or "None").
"""
            is_reasoning_model = "gpt-5" in self.model.lower() or "o1" in self.model.lower() or "o3" in self.model.lower()

            if is_reasoning_model:
                full_prompt = f"System: You are a security researcher.\n\nUser: {prompt}"
                messages = [{"role": "user", "content": full_prompt}]
                api_params = {
                    "model": self.model,
                    "messages": messages,
                    "max_completion_tokens": 1000
                }
            else:
                api_params = {
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": "You are a security researcher."},
                        {"role": "user", "content": prompt}
                    ],
                    "response_format": {"type": "json_object"},
                    "max_tokens": 1000,
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
                logger.error(f"Failed to parse AI component analysis response. Content: {repr(content)}")
                return {
                    "analysis_text": content,
                    "vulnerability_summary": "Failed to parse structured analysis.",
                    "severity": "Unknown",
                    "exploitability": "Unknown",
                    "fixed_version": "Unknown"
                }

        except Exception as e:
            logger.error(f"Failed to analyze component: {e}")
            return {
                "analysis_text": f"AI analysis failed: {e}",
                "vulnerability_summary": "Analysis failed.",
                "severity": "Unknown",
                "exploitability": "Unknown",
                "fixed_version": "Unknown"
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
                    "max_completion_tokens": 2000  # Increased to ensure complete response
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
                    "max_tokens": 2000,  # Increased to ensure complete response with diff
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
            except json.JSONDecodeError as json_err:
                logger.error(f"JSON parsing error: {json_err}")
                logger.error(f"Raw content (first 500 chars): {repr(content[:500])}")
                # Return the content as-is if JSON parsing fails
                return {
                    "remediation": f"AI response could not be parsed as JSON. Raw response:\n\n{content}",
                    "diff": ""
                }

        except Exception as e:
            logger.error(f"Failed to generate remediation: {e}", exc_info=True)
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

        # Cloud Provider Preference - Delegate to AI
        provider_preference = """
**CLOUD PROVIDER & ICON INSTRUCTIONS**:
1. **Identify the Cloud Provider**: Based on the file structure, config files, and code analysis, determine if this is an **Azure**, **AWS**, or **GCP** project.
2. **Select the Correct Icons**: You **MUST** use the icons specific to the identified provider.
   - **Azure**: Use `diagrams.azure.*`.
     - NSG -> `diagrams.azure.network.NetworkSecurityGroupsClassic`
     - VNet -> `diagrams.azure.network.VirtualNetworks`
     - Subnet -> `diagrams.azure.network.Subnets`
     - Private DNS -> `diagrams.azure.network.DNSPrivateZones`
     - Key Vault -> `diagrams.azure.security.KeyVaults`
     - Managed Identity -> `diagrams.azure.identity.ManagedIdentities`
     - Azure OpenAI -> `diagrams.azure.ml.AzureOpenAI`
     - App Service -> `diagrams.azure.web.AppServices`
     - Function App -> `diagrams.azure.compute.FunctionApps`
   - **AWS**: Use `diagrams.aws.*`.
   - **GCP**: Use `diagrams.gcp.*`.
3. **Fallback**: If NO specific cloud provider is detected (Generic/Hybrid):
   - Use **generic icons** only if the component is not identifiable.
   - Use the most appropriate technology-specific icons first (e.g. `diagrams.onprem.database.PostgreSQL`).
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
- **DO NOT** use `with Diagram(...)`. Instead, instantiate `Diagram` with `show=False`, `filename="architecture_diagram"`, and **graph_attr** for a clean layout.
- **LAYOUT INSTRUCTIONS**:
    - Use `graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}` to ensure the diagram is spaced out and not cluttered.
    - Group related components into `Cluster`s (e.g., "VPC", "Database Layer", "Services").
- Example: `with Diagram("Architecture", show=False, filename="architecture_diagram", graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}):`
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

    async def generate_architecture_report(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate a text-based architecture report.
        """
        configs_str = ""
        for name, content in config_files.items():
            configs_str += f"\n--- {name} ---\n{content}\n"

        prompt = f"""You are a Senior Software Architect. Analyze this repository and provide an End-to-End Architecture Overview.
            
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

Format as clean Markdown. Be concise but technical.
**DO NOT** generate any diagram code in this step. Focus purely on the technical analysis and report.
"""
        try:
            return await self.execute_prompt(prompt)
        except Exception as e:
            logger.error(f"Failed to generate architecture report: {e}")
            return f"Failed to generate architecture report: {e}"

    async def generate_diagram_code(
        self,
        repo_name: str,
        report_content: str,
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate Python code for the architecture diagram based on the report.
        """
        # Cloud Provider Preference - Delegate to AI
        provider_preference = """
**CLOUD PROVIDER & ICON INSTRUCTIONS**:
1. **Identify the Cloud Provider**: Based on the architecture report, determine if this is an **Azure**, **AWS**, or **GCP** project.
2. **Select the Correct Icons**: You **MUST** use the icons specific to the identified provider.
   - **Azure**: Use `diagrams.azure.*`.
     - NSG -> `diagrams.azure.network.NetworkSecurityGroupsClassic`
     - VNet -> `diagrams.azure.network.VirtualNetworks`
     - Subnet -> `diagrams.azure.network.Subnets`
     - Private DNS -> `diagrams.azure.network.DNSPrivateZones`
     - Key Vault -> `diagrams.azure.security.KeyVaults`
     - Managed Identity -> `diagrams.azure.identity.ManagedIdentities`
     - Azure OpenAI -> `diagrams.azure.ml.AzureOpenAI`
     - App Service -> `diagrams.azure.web.AppServices`
     - Function App -> `diagrams.azure.compute.FunctionApps`
   - **AWS**: Use `diagrams.aws.*`.
   - **GCP**: Use `diagrams.gcp.*`.
3. **Fallback**: If NO specific cloud provider is detected (Generic/Hybrid):
   - Use **generic icons** only if the component is not identifiable.
   - Use the most appropriate technology-specific icons first (e.g. `diagrams.onprem.database.PostgreSQL`).
"""

        prompt = f"""You are a Python expert specializing in the `diagrams` library.
Based on the following Architecture Report, generate a Python script to visualize the architecture.

Repository: {repo_name}

Architecture Report:
{report_content}

**IMPORTANT**:
Generate a **Python script** using the `diagrams` library.
- Provide the Python code inside a code block labeled `python`.
- Import from `diagrams` and `diagrams.aws`, `diagrams.azure`, `diagrams.gcp`, `diagrams.onprem`, etc. as appropriate.
- **NOTE**: `Internet` is located in `diagrams.onprem.network`. Use `from diagrams.onprem.network import Internet`.
- **DO NOT** use `with Diagram(...)`. Instead, instantiate `Diagram` with `show=False`, `filename="architecture_diagram"`, and **graph_attr** for a clean layout.
- **LAYOUT INSTRUCTIONS**:
    - Use `graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}` to ensure the diagram is spaced out and not cluttered.
    - Group related components into `Cluster`s (e.g., "VPC", "Database Layer", "Services").
- Example: `with Diagram("Architecture", show=False, filename="architecture_diagram", graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}):`
{provider_preference}
- **VALIDATION**:
    - If you are unsure about a specific component or connection, use a generic node.
    - **CRITICAL**: Add a comment in the Python code explaining any gaps, missing information, or assumptions.
    - Example: `# GAP: Database type unknown, assuming generic SQL`
    - Example: `# GAP: Auth provider not found in code, assuming internal`
- Ensure the code is valid and self-contained.
- Use generic nodes if specific cloud providers are not obvious.

Return ONLY the Python code block.
"""
        try:
            return await self.execute_prompt(prompt)
        except Exception as e:
            logger.error(f"Failed to generate diagram code: {e}")
            return f"# Failed to generate diagram code: {e}"

    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate an architecture overview using OpenAI.
        DEPRECATED: Use generate_architecture_report and generate_diagram_code instead.
        """
        try:
            # For backward compatibility, we can call the new methods and combine them
            report = await self.generate_architecture_report(repo_name, file_structure, config_files)
            diagram_code = await self.generate_diagram_code(repo_name, report)
            
            return f"{report}\n\n## Architecture Diagram\n\n{diagram_code}"

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
        diagrams_index: Optional[Dict[str, str]] = None,
        report_context: Optional[str] = None
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
        
        # Use report context if available to determine provider
        context_to_check = (report_context or "") + code + error
        
        is_azure = "azure" in context_to_check.lower()
        is_aws = "aws" in context_to_check.lower() or "amazon" in context_to_check.lower()
        is_gcp = "gcp" in context_to_check.lower() or "google" in context_to_check.lower()

        if is_azure:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: AZURE**
Based on the Architecture Report/Code, this is an **Azure** project.
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
Based on the Architecture Report/Code, this is an **AWS** project.
You **MUST** prioritize using icons from `diagrams.aws.*`.
"""
        elif is_gcp:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: GCP**
Based on the Architecture Report/Code, this is an **GCP** project.
You **MUST** prioritize using icons from `diagrams.gcp.*`.
"""
        else:
            provider_preference = """
**CLOUD PROVIDER PREFERENCE: CLOUD PROVIDER CENTRIC**
When No specific cloud provider is detected.
- Use **generic icons** only when if the cloud provider or the resource or components are not identifiable
- Use the most appropriate technology-specific icons first, or all other attempts have been exhasuted then use generic icons
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
   - **LAYOUT**: Use `graph_attr={{"splines": "ortho", "nodesep": "1.0", "ranksep": "1.0"}}` in the `Diagram` constructor to ensure the diagram is spaced out and clean.
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
