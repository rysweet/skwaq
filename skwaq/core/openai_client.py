"""OpenAI client implementation for Skwaq.

This module provides a wrapper around the OpenAI API client with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

from typing import Dict, List, Optional, Union

from openai import AsyncAzureOpenAI, AsyncOpenAI, AzureOpenAI, OpenAI

from ..utils.config import Config, get_config
from ..utils.logging import get_logger

logger = get_logger(__name__)


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
        # Determine API type (Azure or standard OpenAI)
        api_type = config.get("openai", {}).get("api_type", "azure").lower()
        
        if api_type == "azure":
            # Azure OpenAI setup
            client_cls = AsyncAzureOpenAI if async_mode else AzureOpenAI
            self.client = client_cls(
                api_key=config.openai_api_key,
                api_version=config.get("openai", {}).get("api_version", "2023-05-15"),
                azure_endpoint=config.get("openai", {}).get("endpoint", 
                                         "https://skwaq-openai.openai.azure.com/"),
            )
            self.model = config.get("openai", {}).get("chat_model", "gpt4o")
            logger.info(f"Initialized Azure OpenAI client with model {self.model}")
        else:
            # Standard OpenAI setup
            client_cls = AsyncOpenAI if async_mode else OpenAI
            self.client = client_cls(
                api_key=config.openai_api_key,
                organization=config.openai_org_id,
            )
            self.model = config.openai_model or "gpt-4-turbo-preview"
            logger.info(f"Initialized OpenAI client with model {self.model}")

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
        logger.debug(f"Requesting completion with temperature={temperature}")
        try:
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=temperature,
                max_tokens=max_tokens,
                stop=stop_sequences,
            )
            completion = response.choices[0].message.content
            logger.debug(f"Received completion of length {len(completion)}")
            return completion
        except Exception as e:
            logger.error(f"OpenAI API request failed: {e}")
            raise
            
    async def get_embedding(
        self,
        text: str,
    ) -> List[float]:
        """Get an embedding vector for the given text.
        
        Args:
            text: The text to embed
            
        Returns:
            List of float values representing the embedding vector
            
        Raises:
            OpenAIError: If the API request fails
        """
        try:
            embedding_model = get_config().get("openai", {}).get(
                "embedding_model", "text-embedding-ada-002"
            )
            response = await self.client.embeddings.create(
                model=embedding_model,
                input=text,
            )
            return response.data[0].embedding
        except Exception as e:
            logger.error(f"OpenAI embedding request failed: {e}")
            raise


# Global client instances
_sync_client: Optional[OpenAIClient] = None
_async_client: Optional[OpenAIClient] = None


def get_openai_client(async_mode: bool = False) -> OpenAIClient:
    """Get the global OpenAI client instance.
    
    Args:
        async_mode: Whether to return an async client
        
    Returns:
        OpenAI client instance
    """
    global _sync_client, _async_client
    
    if async_mode:
        if _async_client is None:
            _async_client = OpenAIClient(get_config(), async_mode=True)
        return _async_client
    else:
        if _sync_client is None:
            _sync_client = OpenAIClient(get_config(), async_mode=False)
        return _sync_client