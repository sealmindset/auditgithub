
"""
Main AI Agent class for orchestrating AI-driven security analysis.
"""
import logging
from typing import Optional

from .providers.openai import OpenAIProvider
from .providers.claude import ClaudeProvider
from .providers.ollama import OllamaProvider, DockerAIProvider
from .providers.anthropic_foundry import AnthropicFoundryProvider
from .providers.gemini import GeminiProvider
from .diagnostics import DiagnosticCollector
from .reasoning import ReasoningEngine
from .remediation import RemediationEngine
from .learning import LearningSystem

logger = logging.getLogger(__name__)

class AIAgent:
    """
    Main AI Agent that coordinates all AI components.
    """
    def __init__(
        self,
        openai_api_key: Optional[str] = None,
        anthropic_api_key: Optional[str] = None,
        provider: str = "openai",
        model: Optional[str] = None,  # No default - must be provided by config
        ollama_base_url: Optional[str] = None,
        azure_foundry_endpoint: Optional[str] = None,
        azure_foundry_api_key: Optional[str] = None,
        gemini_api_key: Optional[str] = None,
        enable_failover: bool = False,
        failover_model: str = "ai/qwen3"
    ):
        """
        Initialize the AI Agent.
        
        Args:
            openai_api_key: API key for OpenAI
            anthropic_api_key: API key for Anthropic  
            provider: 'openai', 'claude', 'ollama', 'docker', or 'anthropic_foundry'
            model: Model name to use (must be provided from config)
            ollama_base_url: Base URL for Ollama
            azure_foundry_endpoint: Endpoint for Azure AI Foundry
            azure_foundry_api_key: API Key for Azure AI Foundry
            gemini_api_key: API Key for Google Gemini
            enable_failover: Enable failover to local Docker AI
            failover_model: Model to use for failover (default: ai/qwen3)
        """
        # Ensure model is provided
        if not model:
            raise ValueError(f"Model must be specified for provider '{provider}'")
        self.provider_name = provider
        self.model = model
        
        # 1. Initialize Primary Provider
        primary_provider = None
        if provider == "openai":
            if not openai_api_key:
                raise ValueError("OpenAI API key required for openai provider")
            primary_provider = OpenAIProvider(api_key=openai_api_key, model=model)
        elif provider == "claude":
            if not anthropic_api_key:
                raise ValueError("Anthropic API key required for claude provider")
            primary_provider = ClaudeProvider(api_key=anthropic_api_key, model=model)
        elif provider == "ollama":
            if not ollama_base_url:
                ollama_base_url = "http://ollama:11434"
            primary_provider = OllamaProvider(base_url=ollama_base_url, model=model)
        elif provider == "docker":
            # Docker Model Runner at localhost:12434 or DOCKER_BASE_URL
            import os
            base_url = os.getenv('DOCKER_BASE_URL', 'http://localhost:12434')
            # Default to ai/llama3.2:latest if no model specified
            docker_model = model if model and model != "gpt-4" else "ai/llama3.2:latest"
            primary_provider = DockerAIProvider(base_url=base_url, model=docker_model)
        elif provider == "anthropic_foundry":
            if not azure_foundry_endpoint or not azure_foundry_api_key:
                raise ValueError("Endpoint and API Key required for anthropic_foundry provider")
            primary_provider = AnthropicFoundryProvider(
                api_key=azure_foundry_api_key,
                base_url=azure_foundry_endpoint,
                model=model
            )
        elif provider == "gemini" or provider == "google":
            if not gemini_api_key:
                raise ValueError("Gemini API key required for gemini provider")
            primary_provider = GeminiProvider(api_key=gemini_api_key, model=model)
        else:
            raise ValueError(f"Unsupported provider: {provider}")
            
        self.provider = primary_provider

        # 2. Setup Failover if requested
        if enable_failover and provider != "docker": # Don't failover if primary IS docker
            from .providers.failover import FailoverProvider
            import os
            
            logger.info(f"Enhancing agent with Failover capability to Docker AI ({failover_model})")
            base_url = os.getenv('DOCKER_BASE_URL', 'http://localhost:12434')
            
            try:
                # Initialize secondary provider (Docker AI)
                secondary_provider = DockerAIProvider(base_url=base_url, model=failover_model)
                
                # Wrap primary with failover
                self.provider = FailoverProvider(primary=primary_provider, secondary=secondary_provider)
                logger.info("Failover protection ENABLED")
            except Exception as e:
                logger.warning(f"Failed to initialize failover provider: {e}. Running without failover.")

        # 3. Initialize Components
        self.diagnostic_collector = DiagnosticCollector()
        
        self.reasoning_engine = ReasoningEngine(
            provider=self.provider,
            diagnostic_collector=self.diagnostic_collector
        )
        
        self.remediation_engine = RemediationEngine()
        
        self.learning_system = LearningSystem()
        
        logger.info(f"AI Agent initialized with {provider} ({model})")


    async def analyze_stuck_scan(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.analyze_stuck_scan(*args, **kwargs)

    async def generate_remediation(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.generate_remediation(*args, **kwargs)

    async def triage_finding(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.triage_finding(*args, **kwargs)

    async def generate_architecture_overview(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.generate_architecture_overview(*args, **kwargs)

    async def analyze_finding(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.analyze_finding(*args, **kwargs)

    async def analyze_zero_day(self, *args, **kwargs):
        """Delegate to reasoning engine."""
        return await self.reasoning_engine.analyze_zero_day(*args, **kwargs)
