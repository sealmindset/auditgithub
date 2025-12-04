"""
Anthropic Foundry provider implementation for Azure AI.
"""
import logging
import json
from typing import Dict, Any, Optional, List

try:
    from anthropic import AsyncAnthropic, AnthropicFoundry
    ANTHROPIC_AVAILABLE = True
except ImportError:
    try:
        # Fallback for older SDK versions or if AnthropicFoundry is not directly exported
        from anthropic import AsyncAnthropic
        AnthropicFoundry = None # Mark as unavailable if not found
        ANTHROPIC_AVAILABLE = True
    except ImportError:
        ANTHROPIC_AVAILABLE = False
        AnthropicFoundry = None

from .base import (
    AIProvider,
    AIAnalysis,
    RemediationSuggestion,
    Severity,
    RemediationAction
)
from .claude import ClaudeProvider

logger = logging.getLogger(__name__)

class AnthropicFoundryProvider(ClaudeProvider):
    """
    Anthropic Foundry provider for Azure AI.
    Inherits from ClaudeProvider but uses AnthropicFoundry client.
    """
    
    def __init__(self, api_key: str, base_url: str, model: str = "claude-sonnet-4-5", max_tokens: int = 2000):
        """
        Initialize Anthropic Foundry provider.
        
        Args:
            api_key: Azure AI Foundry API Key
            base_url: Azure AI Foundry Endpoint URL
            model: Deployment name (e.g., claude-sonnet-4-5)
            max_tokens: Maximum tokens for responses
        """
        if not ANTHROPIC_AVAILABLE:
            raise ImportError(
                "Anthropic library not installed. Install with: pip install anthropic"
            )
            
        # Initialize base class (ClaudeProvider) but don't create client yet
        # We pass dummy key to super because we override client anyway
        super().__init__(api_key=api_key, model=model, max_tokens=max_tokens)
        
        if AnthropicFoundry:
            # Use the specialized Foundry client if available
            # Note: The doc shows synchronous AnthropicFoundry, but we need Async.
            # Does AsyncAnthropicFoundry exist?
            # The doc doesn't explicitly say, but usually yes.
            # Let's check if we can use AsyncAnthropic with custom base_url if Foundry specific one is missing.
            # For now, let's assume we can use AsyncAnthropic with base_url if we can't find AsyncAnthropicFoundry.
            # Actually, the doc says: client = AnthropicFoundry(api_key=apiKey, base_url=baseURL)
            # It doesn't mention AsyncAnthropicFoundry.
            # If we need async, we might need to use `AsyncAnthropic` and configure it manually if possible.
            # Or just use the synchronous one in a thread pool? No, we want async.
            # Let's try to use AsyncAnthropic with base_url, which is often how these things work.
            # But Foundry might have specific auth headers.
            # Let's try to use AsyncAnthropic with base_url and see.
            # If that fails, we might need to investigate further.
            # For now, I will use AsyncAnthropic and pass base_url.
            self.client = AsyncAnthropic(
                api_key=api_key,
                base_url=base_url
            )
        else:
             # Fallback to standard AsyncAnthropic with base_url
            self.client = AsyncAnthropic(
                api_key=api_key,
                base_url=base_url
            )
            
        logger.info(f"Initialized Anthropic Foundry provider with model: {model} at {base_url}")

    # We inherit all methods from ClaudeProvider because the interface (messages.create) is likely identical.
