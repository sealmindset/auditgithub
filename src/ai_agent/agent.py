
"""
Main AI Agent class for orchestrating AI-driven security analysis.
"""
import logging
from typing import Optional

from .providers.openai import OpenAIProvider
from .providers.claude import ClaudeProvider
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
        model: str = "gpt-4o"
    ):
        """
        Initialize the AI Agent.
        
        Args:
            openai_api_key: API key for OpenAI
            anthropic_api_key: API key for Anthropic
            provider: 'openai' or 'claude'
            model: Model name to use
        """
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
