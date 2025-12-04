"""
Claude (Anthropic) provider implementation for AI-enhanced self-annealing.

Uses Anthropic's Claude models to analyze stuck scans and suggest remediation.
"""

import json
import logging
from typing import Dict, Any, Optional, List

try:
    from anthropic import AsyncAnthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

from .base import (
    AIProvider,
    AIAnalysis,
    RemediationSuggestion,
    Severity,
    RemediationAction
)

logger = logging.getLogger(__name__)


class ClaudeProvider(AIProvider):
    """Anthropic Claude provider for stuck scan analysis."""
    
    # Pricing per 1M tokens (as of 2024)
    PRICING = {
        "claude-3-opus-20240229": {"input": 15.00, "output": 75.00},
        "claude-3-sonnet-20240229": {"input": 3.00, "output": 15.00},
        "claude-3-haiku-20240307": {"input": 0.25, "output": 1.25},
    }
    
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229", max_tokens: int = 2000):
        """
        Initialize Claude provider.
        
        Args:
            api_key: Anthropic API key
            model: Model name (default: claude-3-sonnet)
            max_tokens: Maximum tokens for responses
        """
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "Anthropic library not installed. Install with: pip install anthropic"
            )
        
        super().__init__(api_key, model, max_tokens)
        self.client = AsyncAnthropic(api_key=api_key)
        logger.info(f"Initialized Claude provider with model: {model}")
    
    async def analyze_stuck_scan(
        self,
        diagnostic_data: Dict[str, Any],
        historical_data: Optional[List[Dict[str, Any]]] = None
    ) -> AIAnalysis:
        """
        Analyze a stuck scan using Claude.
        
        Args:
            diagnostic_data: Diagnostic information about the stuck scan
            historical_data: Optional historical data from previous analyses
            
        Returns:
            AIAnalysis object with root cause and suggestions
        """
        try:
            # Build the prompt
            prompt = self._build_analysis_prompt(diagnostic_data, historical_data)
            
            # Call Claude API
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0.3,
                system="You are an expert DevSecOps engineer specializing in security scanning and performance optimization. Provide practical, actionable advice in JSON format.",
                messages=[
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            )
            
            # Extract the response
            content = response.content[0].text
            usage = response.usage
            
            # Parse JSON response
            analysis_data = json.loads(content)
            
            # Calculate cost
            cost = self.estimate_cost(usage.input_tokens, usage.output_tokens)
            self._total_cost += cost
            self._total_tokens += usage.input_tokens + usage.output_tokens
            
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
                tokens_used=usage.input_tokens + usage.output_tokens
            )
            
            logger.info(
                f"Claude analysis complete: {len(suggestions)} suggestions, "
                f"confidence={analysis.confidence:.2f}, cost=${cost:.4f}"
            )
            
            return analysis
            
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}", exc_info=True)
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
    
    async def explain_timeout(
        self,
        repo_name: str,
        scanner: str,
        timeout_duration: int,
        context: Dict[str, Any]
    ) -> str:
        """
        Generate a human-readable explanation using Claude.
        
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

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=200,
                temperature=0.5,
                system="You are a helpful DevSecOps assistant.",
                messages=[
                    {"role": "user", "content": prompt}
                ]
            )
            
            explanation = response.content[0].text.strip()
            
            # Track cost
            cost = self.estimate_cost(
                response.usage.input_tokens,
                response.usage.output_tokens
            )
            self._total_cost += cost
            self._total_tokens += response.usage.input_tokens + response.usage.output_tokens
            
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
        """Generate remediation using Claude."""
        prompt = f"""You are an expert secure coding assistant.
Vulnerability: {vuln_type}
Description: {description}
Language: {language}

Context:
{context}

Task:
1. Analyze the vulnerability in the context.
2. Provide a secure fixed version of the code.
3. Explain the fix.

Output JSON:
{{
    "remediation": "Explanation of the fix...",
    "diff": "Unified diff or code snippet showing the change..."
}}
"""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0.2,
                system="You are a security expert. Output valid JSON only.",
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
            
            # Clean up potential markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
                
            return json.loads(content)
        except Exception as e:
            logger.error(f"Claude remediation failed: {e}")
            return {"remediation": f"Error generating remediation: {e}", "diff": ""}

    async def triage_finding(
        self,
        title: str,
        description: str,
        severity: str,
        scanner: str
    ) -> Dict[str, Any]:
        """Triage finding using Claude."""
        prompt = f"""Analyze this security finding:
Title: {title}
Description: {description}
Reported Severity: {severity}
Scanner: {scanner}

Determine:
1. Real Priority (Critical, High, Medium, Low, Info)
2. Confidence Score (0.0 - 1.0)
3. False Positive Probability (0.0 - 1.0)
4. Reasoning

Output JSON:
{{
    "priority": "High",
    "confidence": 0.9,
    "false_positive_probability": 0.1,
    "reasoning": "..."
}}
"""
        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0.2,
                system="You are a security analyst. Output valid JSON only.",
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
            return json.loads(content)
        except Exception as e:
            logger.error(f"Claude triage failed: {e}")
            return {
                "priority": severity,
            }

    async def generate_architecture_report(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate a text-based architecture report using Claude.
        """
        configs_str = "\n".join([f"--- {k} ---\n{v}\n" for k, v in config_files.items()])
        
        prompt = f"""Analyze this repository and provide an End-to-End Architecture Overview.
            
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
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.4,
                system="You are a Senior Software Architect.",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude architecture report generation failed: {e}")
            return f"Error generating architecture report: {e}"

    async def generate_diagram_code(
        self,
        repo_name: str,
        report_content: str,
        diagrams_index: Optional[Dict[str, str]] = None
    ) -> str:
        """
        Generate Python code for the architecture diagram based on the report using Claude.
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
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=4000,
                temperature=0.2,
                system="You are a Python expert.",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude diagram code generation failed: {e}")
            return f"# Error generating diagram code: {e}"

    async def generate_architecture_overview(
        self,
        repo_name: str,
        file_structure: str,
        config_files: Dict[str, str]
    ) -> str:
        """
        Generate architecture overview using Claude.
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

    def estimate_cost(self, input_tokens: int, output_tokens: int) -> float:
        """
        Estimate cost for Claude API call.
        
        Args:
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens
            
        Returns:
            Estimated cost in USD
        """
        pricing = self.PRICING.get(self.model, self.PRICING["claude-3-sonnet-20240229"])
        input_cost = (input_tokens / 1_000_000) * pricing["input"]
        output_cost = (output_tokens / 1_000_000) * pricing["output"]
        return input_cost + output_cost
