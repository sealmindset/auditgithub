"""
Claude (Anthropic) provider implementation for AI-enhanced self-annealing.

Uses Anthropic's Claude models to analyze stuck scans and suggest remediation.
Includes DOE self-annealing for model configuration error detection and correction.
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
from src.services.prompt_loader import get_prompt, render_prompt, get_prompt_with_system

logger = logging.getLogger(__name__)


# =============================================================================
# DOE Self-Annealing: Model Configuration Error Detection
# =============================================================================

class ClaudeModelSelfAnnealing:
    """
    DOE Self-Annealing for Claude model configuration errors.
    
    Detects model mismatches from API errors and auto-corrects them.
    """
    
    VALID_CLAUDE_MODELS = [
        "claude-3-opus-20240229",
        "claude-3-sonnet-20240229",
        "claude-3-haiku-20240307",
        "claude-sonnet-4-20250514",
        "claude-3-5-sonnet-20241022",
        "claude-opus-4-5-20251101",  # Claude Opus 4.5
        # Azure AI Foundry deployment names
        "cogdep-aifoundry",  # Prefix for Azure AI Foundry models
    ]

    DEFAULT_MODEL = "claude-sonnet-4-20250514"  # Default for direct Anthropic API
    
    def __init__(self):
        self.corrections = []
        self.logger = logging.getLogger("DOE.SelfAnnealing.Claude")
    
    def detect_model_error(self, error_message: str) -> bool:
        """Detect if error is due to invalid model configuration."""
        error_lower = error_message.lower()
        
        # Pattern: "model: llama3" or similar non-Claude model in error
        invalid_models = ["llama", "gpt-", "mistral", "gemma", "phi", "qwen"]
        if "model:" in error_lower:
            for invalid in invalid_models:
                if invalid in error_lower:
                    return True
        
        # Pattern: "not_found_error" with model reference
        if "not_found_error" in error_lower and "model" in error_lower:
            return True
        
        return False
    
    def extract_bad_model(self, error_message: str) -> Optional[str]:
        """Extract the invalid model name from error message."""
        import re
        # Pattern: "model: llama3" or "model: gpt-4"
        match = re.search(r"model:\s*(\S+)", error_message, re.IGNORECASE)
        if match:
            return match.group(1).strip("'\"")
        return None
    
    def correct_model(self, current_model: str, error_message: str) -> str:
        """Auto-correct to a valid Claude model."""
        bad_model = self.extract_bad_model(error_message) or current_model
        
        correction = {
            "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
            "original_model": bad_model,
            "corrected_model": self.DEFAULT_MODEL,
            "error_trigger": error_message[:200],
            "reason": f"Model '{bad_model}' is not a valid Claude model"
        }
        self.corrections.append(correction)
        
        self.logger.warning(
            f"DOE Self-Annealing: Detected invalid Claude model '{bad_model}' from API error. "
            f"Auto-correcting to '{self.DEFAULT_MODEL}'"
        )
        
        return self.DEFAULT_MODEL
    
    def validate_model(self, model: str) -> str:
        """Validate model at initialization, correct if invalid."""
        model_lower = model.lower() if model else ""
        
        # Check if it's a valid Claude model pattern
        if not any(valid.lower() in model_lower or model_lower in valid.lower() 
                   for valid in self.VALID_CLAUDE_MODELS):
            self.logger.warning(
                f"DOE Self-Annealing: Model '{model}' doesn't appear to be a valid Claude model. "
                f"Correcting to '{self.DEFAULT_MODEL}'"
            )
            self.corrections.append({
                "timestamp": __import__("datetime").datetime.utcnow().isoformat(),
                "original_model": model,
                "corrected_model": self.DEFAULT_MODEL,
                "reason": "Model validation at initialization"
            })
            return self.DEFAULT_MODEL
        
        return model


# Global self-annealing instance for Claude
claude_model_annealing = ClaudeModelSelfAnnealing()


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
        
        # DOE Self-Annealing: Validate and correct model at initialization
        validated_model = claude_model_annealing.validate_model(model)
        
        super().__init__(api_key, validated_model, max_tokens)
        self.client = AsyncAnthropic(api_key=api_key)
        logger.info(f"Initialized Claude provider with model: {validated_model}")

    def _get_db_session(self):
        """Get a database session for prompt loading. Returns None if unavailable."""
        try:
            from src.api.database import SessionLocal
            return SessionLocal()
        except Exception:
            return None

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
            # Try managed prompt for system message
            sys_prompt_data = get_prompt("devsecops-analyst-system")
            system_msg = sys_prompt_data["content"] if sys_prompt_data else "You are an expert DevSecOps engineer specializing in security scanning and performance optimization. Provide practical, actionable advice in JSON format."

            # Build the prompt
            prompt = self._build_analysis_prompt(diagnostic_data, historical_data)

            # Call Claude API
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=0.3,
                system=system_msg,
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
            prompt = render_prompt("timeout-explanation", variables={
                "repo_name": repo_name, "scanner": scanner,
                "timeout_duration": str(timeout_duration),
                "context_json": json.dumps(context, indent=2)
            })
            if not prompt:
                logger.error("Prompt 'timeout-explanation' not found in any tier")
                prompt = f"Explain why the {scanner} scan timed out on {repo_name} after {timeout_duration}s. Context: {json.dumps(context)}"

            sys_data = get_prompt("devsecops-assistant-system")
            system_msg = sys_data["content"] if sys_data else "You are a helpful DevSecOps assistant."

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=200,
                temperature=0.5,
                system=system_msg,
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
        try:
            prompt = render_prompt("remediation-generation", variables={
                "vuln_type": vuln_type, "description": description,
                "language": language, "context": context
            })
            if not prompt:
                logger.error("Prompt 'remediation-generation' not found in any tier")
                prompt = f"Generate JSON remediation for {vuln_type} in {language}. Description: {description}. Context: {context}. Return JSON with 'remediation' and 'diff' fields."

            sys_data = get_prompt("secure-coding-assistant-system")
            system_msg = sys_data["content"] if sys_data else "You are a security expert. Output valid JSON only."

            response = await self.client.messages.create(
                model=self.model,
                max_tokens=4000,  # Increased from self.max_tokens to ensure complete response
                temperature=0.2,
                system=system_msg,
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text

            # Log response metadata
            logger.info(f"Remediation response - stop_reason: {response.stop_reason}, usage: {response.usage}")

            # Check if response was truncated
            if response.stop_reason == "max_tokens":
                logger.warning(f"Response was truncated due to max_tokens limit. Consider increasing max_tokens.")

            # Clean up potential markdown code blocks
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()

            # Try to parse JSON
            try:
                return json.loads(content)
            except json.JSONDecodeError as json_err:
                logger.error(f"JSON parsing error: {json_err}")
                logger.error(f"Raw content length: {len(content)} chars")
                logger.error(f"Raw content (last 200 chars): {repr(content[-200:])}")
                logger.error(f"Stop reason: {response.stop_reason}")

                # Try to fix incomplete JSON by completing it
                content_stripped = content.strip()

                # Check for various incomplete patterns and fix them
                if content_stripped.endswith('"diff": "'):
                    # The diff field was started but not completed - close it with empty string
                    content = content_stripped + '"}'
                    logger.info("Attempting to fix incomplete JSON by closing empty diff field")
                elif content_stripped.endswith('"diff":'):
                    # The diff field key exists but no value - add empty string
                    content = content_stripped + ' ""}'
                    logger.info("Attempting to fix incomplete JSON by adding empty diff value")
                elif '"diff"' in content_stripped and not content_stripped.rstrip().endswith('}'):
                    # diff field exists but JSON isn't closed - try to close it
                    content = content_stripped + '}'
                    logger.info("Attempting to fix incomplete JSON by closing the object")

                # Try parsing the fixed content
                try:
                    return json.loads(content)
                except json.JSONDecodeError:
                    logger.warning("Auto-fix failed, returning fallback response")
                    pass

                # Fallback: Try to extract remediation text from the content
                # Even if it's not valid JSON, return something useful
                return {
                    "remediation": f"AI response could not be parsed as JSON. Raw response:\n\n{content}",
                    "diff": ""
                }

        except json.JSONDecodeError as e:
            logger.error(f"Claude remediation JSON parsing failed: {e}")
            return {"remediation": f"Error parsing remediation response: {e}", "diff": ""}
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
        prompt = render_prompt("finding-triage", variables={
            "title": title, "description": description,
            "severity": severity, "scanner": scanner
        })
        if not prompt:
            logger.error("Prompt 'finding-triage' not found in any tier")
            prompt = f"Triage security finding. Title: {title}. Severity: {severity}. Scanner: {scanner}. Description: {description}. Return JSON with priority, confidence, false_positive_probability, reasoning."

        sys_data = get_prompt("security-analyst-json-system")
        system_msg = sys_data["content"] if sys_data else "You are a security analyst. Output valid JSON only."

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=1000,
                temperature=0.2,
                system=system_msg,
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

    async def analyze_finding(
        self,
        finding: Dict[str, Any],
        user_prompt: Optional[str] = None
    ) -> str:
        """Analyze finding using Claude."""
        finding_context = json.dumps(finding, indent=2)
        sys_data = get_prompt("security-engineer-analysis-system")
        system_prompt = sys_data["content"] if sys_data else "You are a senior security engineer. Analyze the provided security finding."
        
        if user_prompt:
            user_msg = f"Finding Details:\n{finding_context}\n\nUser Question: {user_prompt}"
        else:
            user_msg = f"Finding Details:\n{finding_context}\n\nProvide a detailed analysis."

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.4,
                system=system_prompt,
                messages=[{"role": "user", "content": user_msg}]
            )
            content = response.content[0].text
            
            # Track cost
            cost = self.estimate_cost(response.usage.input_tokens, response.usage.output_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.input_tokens + response.usage.output_tokens
            
            return content
        except Exception as e:
            logger.error(f"Claude analysis failed: {e}")
            return f"Error: {e}"

    async def analyze_component(
        self,
        package_name: str,
        version: str,
        package_manager: str
    ) -> Dict[str, Any]:
        """Analyze component using Claude."""
        prompt = render_prompt("component-analysis", variables={
            "package_name": package_name, "version": version,
            "package_manager": package_manager
        })
        if not prompt:
            logger.error("Prompt 'component-analysis' not found in any tier")
            prompt = f"Analyze {package_name} v{version} ({package_manager}) for security risks. Return JSON with analysis_text, vulnerability_summary, severity, exploitability, fixed_version."

        sys_data = get_prompt("security-analyst-json-system")
        system_msg = sys_data["content"] if sys_data else "You are a security researcher. Output valid JSON only."

        try:
            response = await self.client.messages.create(
                model=self.model,
                max_tokens=2000,
                temperature=0.3,
                system=system_msg,
                messages=[{"role": "user", "content": prompt}]
            )
            content = response.content[0].text
            
            # Track cost
            cost = self.estimate_cost(response.usage.input_tokens, response.usage.output_tokens)
            self._total_cost += cost
            self._total_tokens += response.usage.input_tokens + response.usage.output_tokens

            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].split("```")[0].strip()
                
            return json.loads(content)
        except Exception as e:
            logger.error(f"Claude component analysis failed: {e}")
            return {
                "analysis_text": f"Analysis failed: {e}",
                "vulnerability_summary": "Analysis failed.",
                "severity": "Unknown",
                "exploitability": "Unknown",
                "fixed_version": "Unknown"
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
        # Sort config files by key for deterministic output
        configs_str = "\n".join([f"--- {k} ---\n{v}\n" for k, v in sorted(config_files.items())])

        prompt = render_prompt("architecture-report", variables={
            "repo_name": repo_name, "file_structure": file_structure,
            "configs_str": configs_str
        })
        if not prompt:
            logger.error("Prompt 'architecture-report' not found in any tier")
            prompt = f"Analyze repository {repo_name} and generate an architecture overview report in Markdown. File structure: {file_structure[:500]}. Config files: {configs_str[:500]}"
        try:
            response = await self._call_api_with_retry(
                model=self.model,
                max_tokens=4000,
                temperature=0.0,  # Set to 0 for deterministic output
                system="You are a Senior Software Architect.",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude architecture report generation failed: {e}")
            if "429" in str(e) or "rate_limit" in str(e).lower():
                 return "Error: Rate limit exceeded. Please try again in a minute."
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
        # Technology-Based Icon Selection
        icon_selection_guide = """
**ICON SELECTION BASED ON DETECTED TECHNOLOGY**:

**1. Database Icons** (from `diagrams.onprem.database`):
- Oracle: `Oracle` - Oracle Database (PL/SQL, Oracle packages)
- PostgreSQL: `PostgreSQL` - PostgreSQL (pg_*, JSONB, PostgreSQL syntax)
- MySQL: `MySQL` - MySQL/MariaDB
- MongoDB: `MongoDB` - MongoDB (collections, documents)
- Redis: `Redis` - Redis (caching, key-value)
- SQL Server: `Mssql` - Microsoft SQL Server
- Other: `Cassandra`, `Clickhouse`, `Cockroachdb`, `Couchdb`, `Influxdb`, etc.

**2. Application/Service Icons**:
- Python apps: `diagrams.programming.language.Python`
- Node.js apps: `diagrams.programming.language.NodeJS`
- Java apps: `diagrams.programming.language.Java`
- Go apps: `diagrams.programming.language.Go`
- Generic services: `diagrams.onprem.compute.Server`

**3. Frontend Icons**:
- React: `diagrams.programming.framework.React`
- Vue: `diagrams.programming.framework.Vue`
- Angular: `diagrams.programming.framework.Angular`
- Generic web UI: `diagrams.onprem.client.Users`

**4. Message Queue Icons**:
- Kafka: `diagrams.onprem.queue.Kafka`
- RabbitMQ: `diagrams.onprem.queue.RabbitMQ`
- Redis Queue: `diagrams.onprem.inmemory.Redis`

**5. Cloud Provider Icons** (ONLY if cloud configs detected):
- **Azure**: Use `diagrams.azure.*` (NSG, VNet, App Service, Function Apps, Key Vault, etc.)
- **AWS**: Use `diagrams.aws.*` (Lambda, S3, RDS, EC2, API Gateway, etc.)
- **GCP**: Use `diagrams.gcp.*` (Functions, Storage, SQL, Compute, etc.)

**6. Generic Icons**:
- Users: `diagrams.onprem.client.Users`
- Internet: `diagrams.onprem.network.Internet`
- Storage: `diagrams.generic.storage.Storage`
- Custom: `diagrams.generic.blank.Blank`

**CRITICAL RULES**:
- **NEVER use cloud icons without evidence of cloud deployment in configuration files**
- Choose icons based on actual detected technologies (imports, syntax, config files)
- Use `diagrams.onprem.*` or `diagrams.generic.*` for on-premises/self-hosted deployments
- Match icons to the technologies identified in the architecture report
"""

        prompt = render_prompt("diagram-code-generation", variables={
            "repo_name": repo_name, "report_content": report_content
        })
        if not prompt:
            logger.error("Prompt 'diagram-code-generation' not found in any tier")
            prompt = f"Generate a Python script using the `diagrams` library to visualize the architecture for {repo_name}. Report: {report_content[:1000]}"

        sys_data = get_prompt("python-diagrams-expert-system")
        system_msg = sys_data["content"] if sys_data else "You are a Python expert."
        try:
            response = await self._call_api_with_retry(
                model=self.model,
                max_tokens=4000,
                temperature=0.0,  # Set to 0 for deterministic output
                system=system_msg,
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude diagram code generation failed: {e}")
            if "429" in str(e) or "rate_limit" in str(e).lower():
                 return "# Error: Rate limit exceeded. Please try again in/a minute."
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

    async def _call_api_with_retry(self, **kwargs):
        """Execute Claude API call with retry logic for rate limits and DOE self-annealing for model errors."""
        import asyncio
        
        # Max retries for rate limits
        retries = 3
        base_delay = 5  # Start with 5 seconds
        model_corrected = False
        
        for attempt in range(retries + 1):
            try:
                return await self.client.messages.create(**kwargs)
            except Exception as e:
                error_str = str(e)
                error_lower = error_str.lower()
                
                # DOE Self-Annealing: Check for model configuration error
                if claude_model_annealing.detect_model_error(error_str) and not model_corrected:
                    corrected_model = claude_model_annealing.correct_model(self.model, error_str)
                    logger.warning(
                        f"DOE Self-Annealing: Model error detected. "
                        f"Correcting from '{self.model}' to '{corrected_model}' and retrying..."
                    )
                    # Update the model for this instance
                    self.model = corrected_model
                    kwargs['model'] = corrected_model
                    model_corrected = True
                    # Retry immediately with corrected model
                    continue
                
                # Check for rate limit error
                if "429" in error_lower or "rate_limit" in error_lower:
                    if attempt < retries:
                        delay = base_delay * (2 ** attempt)  # Exponential backoff: 5, 10, 20
                        logger.warning(f"Claude rate limit hit. Retrying in {delay}s... (Attempt {attempt+1}/{retries})")
                        await asyncio.sleep(delay)
                        continue
                
                logger.error(f"Claude API call failed: {e}")
                raise e

    async def execute_prompt(self, prompt: str) -> str:
        """Execute a raw prompt using Claude."""
        try:
            response = await self._call_api_with_retry(
                model=self.model,
                max_tokens=4000,
                temperature=0.3,
                system="You are an expert AI assistant.",
                messages=[{"role": "user", "content": prompt}]
            )
            return response.content[0].text
        except Exception as e:
            logger.error(f"Claude execute_prompt failed: {e}")
            # Identify if this was a rate limit error that persisted
            if "429" in str(e) or "rate_limit" in str(e).lower():
                 return "# Error: Rate limit exceeded. Please try again in a minute."
            return f"# Error: {e}"

    async def fix_and_enhance_diagram_code(
        self,
        code: str,
        error: str,
        diagrams_index: Optional[Dict[str, str]] = None,
        report_context: Optional[str] = None
    ) -> str:
        """
        Fix broken diagram code and enhance it using Claude.
        """
        import re

        index_context = ""
        if diagrams_index:
            # Extract potential node names from the code and look them up
            # Sort for deterministic order
            potential_nodes = sorted(set(re.findall(r'\b([A-Z][a-zA-Z0-9]*)\b', code)))
            found_nodes = {}
            for node in potential_nodes:
                if node in diagrams_index:
                    found_nodes[node] = diagrams_index[node]

            if found_nodes:
                index_context = "\n**Available Node Imports (Found in Index):**\n"
                # Sort dictionary items for deterministic order
                for node, path in sorted(found_nodes.items()):
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
   - Note: `Powershell` does not exist. Use generic nodes or appropriate alternatives.
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
