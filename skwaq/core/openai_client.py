"""OpenAI client implementation for Skwaq.

This module provides a wrapper around the OpenAI API client with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

from typing import Dict, List, Optional

from openai import AsyncOpenAI, OpenAI

from ..utils.config import Config


class OpenAIClient:
    """OpenAI client wrapper for Skwaq.
    
    This class provides a configured OpenAI client instance with proper
    authentication and retry logic for use in the Skwaq system.

    Args:
        config: Configuration object containing OpenAI settings
        async_mode: Whether to use async client. Defaults to False.
    
    Attributes:
        client: The underlying OpenAI client instance
        model: The default model to use for completions
    """

    def __init__(self, config: Config, async_mode: bool = False) -> None:
        """Initialize the OpenAI client.
        
        Args:
            config: Configuration object containing OpenAI settings
            async_mode: Whether to use async client. Defaults to False.
        """
        client_cls = AsyncOpenAI if async_mode else OpenAI
        self.client = client_cls(
            api_key=config.openai_api_key,
            organization=config.openai_org_id,
        )
        self.model = config.openai_model or "gpt-4-turbo-preview"

    async def get_completion(
        self,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> str:
        """Get a completion from the OpenAI API.
        
        Args:
            prompt: The prompt to send to the model
            temperature: Sampling temperature, higher means more random
            max_tokens: Maximum number of tokens to generate
            stop_sequences: Sequences that will stop generation
        
        Returns:
            The generated completion text
        
        Raises:
            OpenAIError: If the API request fails
        """
        response = await self.client.chat.completions.create(
            model=self.model,
            messages=[{"role": "user", "content": prompt}],
            temperature=temperature,
            max_tokens=max_tokens,
            stop=stop_sequences,
        )
        return response.choices[0].message.content