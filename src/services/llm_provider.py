"""
LLM Provider Abstraction
Supports multiple LLM providers: Anthropic, Azure AI Foundry, AWS Bedrock, OpenAI, etc.
"""

import os
import logging
from typing import Dict, List, Any, Optional
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class LLMProvider(ABC):
    """Abstract base class for LLM providers"""

    @abstractmethod
    def create_message(
        self,
        messages: List[Dict[str, str]],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.3
    ) -> Dict[str, Any]:
        """Create a message and return response"""
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        """Get the model name being used"""
        pass


class AnthropicProvider(LLMProvider):
    """Direct Anthropic API provider"""

    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY")
        )
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        logger.info(f"Initialized Anthropic provider with model: {self.model}")

    def create_message(self, messages, system, max_tokens=4096, temperature=0.3):
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=messages
        )
        return {
            "content": response.content[0].text,
            "tokens_used": response.usage.input_tokens + response.usage.output_tokens,
            "model": self.model
        }

    def get_model_name(self) -> str:
        return self.model


class AnthropicFoundryProvider(LLMProvider):
    """Azure AI Foundry provider (Anthropic via Azure)"""

    def __init__(self):
        import anthropic
        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_FOUNDRY_API_KEY"),
            base_url=os.getenv("ANTHROPIC_FOUNDRY_BASE_URL")
        )
        self.model = os.getenv(
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "cogdep-aifoundry-dev-eus2-claude-sonnet-4-5"
        )
        logger.info(f"Initialized Azure AI Foundry provider with model: {self.model}")

    def create_message(self, messages, system, max_tokens=4096, temperature=0.3):
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=messages
        )
        return {
            "content": response.content[0].text,
            "tokens_used": response.usage.input_tokens + response.usage.output_tokens,
            "model": self.model
        }

    def get_model_name(self) -> str:
        return self.model


class AWSBedrockProvider(LLMProvider):
    """AWS Bedrock provider (future implementation)"""

    def __init__(self):
        # TODO: Implement AWS Bedrock client
        # import boto3
        # self.client = boto3.client('bedrock-runtime', region_name=os.getenv("AWS_REGION"))
        self.model = os.getenv("BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0")
        logger.info(f"Initialized AWS Bedrock provider with model: {self.model}")
        raise NotImplementedError("AWS Bedrock provider not yet implemented")

    def create_message(self, messages, system, max_tokens=4096, temperature=0.3):
        # TODO: Implement Bedrock message creation
        raise NotImplementedError("AWS Bedrock provider not yet implemented")

    def get_model_name(self) -> str:
        return self.model


class OpenAIProvider(LLMProvider):
    """OpenAI provider (future implementation)"""

    def __init__(self):
        # TODO: Implement OpenAI client
        # import openai
        # self.client = openai.OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
        self.model = os.getenv("OPENAI_MODEL", "gpt-4")
        logger.info(f"Initialized OpenAI provider with model: {self.model}")
        raise NotImplementedError("OpenAI provider not yet implemented")

    def create_message(self, messages, system, max_tokens=4096, temperature=0.3):
        # TODO: Implement OpenAI message creation
        raise NotImplementedError("OpenAI provider not yet implemented")

    def get_model_name(self) -> str:
        return self.model


def get_llm_provider() -> LLMProvider:
    """
    Factory function to get the appropriate LLM provider based on environment configuration

    Reads AI_PROVIDER from environment:
    - anthropic: Direct Anthropic API
    - anthropic_foundry: Azure AI Foundry (Anthropic via Azure)
    - bedrock: AWS Bedrock
    - openai: OpenAI
    - claude: Alias for anthropic

    Returns:
        LLMProvider instance configured for the specified provider
    """
    provider = os.getenv("AI_PROVIDER", "anthropic").lower()

    logger.info(f"Initializing LLM provider: {provider}")

    if provider in ["anthropic", "claude"]:
        return AnthropicProvider()
    elif provider == "anthropic_foundry":
        return AnthropicFoundryProvider()
    elif provider in ["bedrock", "aws_bedrock"]:
        return AWSBedrockProvider()
    elif provider == "openai":
        return OpenAIProvider()
    else:
        logger.warning(f"Unknown AI_PROVIDER '{provider}', defaulting to Anthropic")
        return AnthropicProvider()
