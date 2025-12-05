
"""
Main AI Agent class for orchestrating AI-driven security analysis.
"""
import logging
from typing import Optional

from .providers.openai import OpenAIProvider
from .providers.claude import ClaudeProvider
from .providers.ollama import OllamaProvider, DockerAIProvider
from .providers.anthropic_foundry import AnthropicFoundryProvider
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
        azure_foundry_api_key: Optional[str] = None
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
        """
        # Ensure model is provided
        if not model:
            raise ValueError(f"Model must be specified for provider '{provider}'")
        self.provider_name = provider
        self.model = model
        
        # 1. Initialize Provider
        if provider == "openai":
            if not openai_api_key:
                raise ValueError("OpenAI API key required for openai provider")
            self.provider = OpenAIProvider(api_key=openai_api_key, model=model)
        elif provider == "claude":
            if not anthropic_api_key:
                raise ValueError("Anthropic API key required for claude provider")
            self.provider = ClaudeProvider(api_key=anthropic_api_key, model=model)
        elif provider == "ollama":
            if not ollama_base_url:
                ollama_base_url = "http://ollama:11434"
            self.provider = OllamaProvider(base_url=ollama_base_url, model=model)
        elif provider == "docker":
            base_url = ollama_base_url or "http://host.docker.internal:11434"
            self.provider = DockerAIProvider(base_url=base_url)
        elif provider == "anthropic_foundry":
            if not azure_foundry_endpoint or not azure_foundry_api_key:
                raise ValueError("Endpoint and API Key required for anthropic_foundry provider")
            self.provider = AnthropicFoundryProvider(
                api_key=azure_foundry_api_key,
                base_url=azure_foundry_endpoint,
                model=model
            )
        else:
            raise ValueError(f"Unsupported provider: {provider}")
            
        # 2. Initialize Components
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
