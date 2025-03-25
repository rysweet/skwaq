"""OpenAI client implementation for Skwaq using autogen-core.
This module provides a wrapper around the autogen-core OpenAI functionality with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

from typing import Dict, List, Optional, Union
import json
import autogen
from autogen.core import chat_complete_tokens
from ..utils.config import Config, get_config
from ..utils.logging import get_logger

logger = get_logger(__name__)


class OpenAIClient:
    """OpenAI client wrapper for Skwaq using autogen-core.

    This class provides a configured OpenAI client instance using autogen-core
    with proper authentication and retry logic for the Skwaq system.

    Args:
        config: Configuration object containing OpenAI settings
        async_mode: Whether to use async client. Defaults to False.

    Attributes:
        config_list: The autogen config list for model inference
        model: The default model to use for completions
    """

    def __init__(self, config: Config, async_mode: bool = False) -> None:
        """Initialize the OpenAI client with autogen-core.

        Args:
            config: Configuration object containing OpenAI settings
            async_mode: Whether to use async client. Defaults to False.
        """
        api_type = config.get("openai", {}).get("api_type", "azure").lower()

        # Set up autogen config based on API type
        if api_type == "azure":
            self.config_list = [
                {
                    "model": config.get("openai", {}).get("chat_model", "gpt4o"),
                    "api_type": "azure",
                    "api_key": config.openai_api_key,
                    "api_version": config.get("openai", {}).get("api_version", "2023-05-15"),
                    "base_url": config.get("openai", {}).get(
                        "endpoint", "https://skwaq-openai.openai.azure.com/"
                    ),
                }
            ]
            self.model = config.get("openai", {}).get("chat_model", "gpt4o")
        else:
            self.config_list = [
                {
                    "model": config.openai_model or "gpt-4-turbo-preview",
                    "api_key": config.openai_api_key,
                    "api_type": "openai",
                }
            ]
            self.model = config.openai_model or "gpt-4-turbo-preview"

        if config.openai_org_id:
            self.config_list[0]["organization"] = config.openai_org_id

        logger.info(f"Initialized autogen-core OpenAI client with model {self.model}")

    async def get_completion(
        self,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> str:
        """Get a completion using autogen-core's completion management.

        Args:
            prompt: The prompt to send to the model
            temperature: Sampling temperature, higher means more random
            max_tokens: Maximum number of tokens to generate
            stop_sequences: Optional list of sequences where the API will stop generating

        Returns:
            The generated completion text
        """
        messages = [{"role": "user", "content": prompt}]

        response = await chat_complete_tokens(
            messages,
            is_async=True,
            config_list=self.config_list,
            temperature=temperature,
            max_tokens=max_tokens,
            stop=stop_sequences,
        )

        if not response or not response.get("choices"):
            raise ValueError("No completion received from the model")

        return response["choices"][0]["message"]["content"]

    async def get_embeddings(
        self, texts: List[str], model: Optional[str] = None
    ) -> List[List[float]]:
        """Get embeddings for a list of texts using autogen-core.

        Args:
            texts: List of texts to get embeddings for
            model: Optional specific model to use for embeddings

        Returns:
            List of embedding vectors
        """
        embeddings_config = self.config_list[0].copy()
        embeddings_config["model"] = model or "text-embedding-ada-002"

        results = []
        for text in texts:
            response = await autogen.core.embeddings(
                input=[text], is_async=True, config_list=[embeddings_config]
            )
            if response and response.get("data"):
                results.append(response["data"][0]["embedding"])

        return results

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Get a chat completion using autogen-core.

        Args:
            messages: List of message dictionaries with role and content
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stop_sequences: Optional stop sequences

        Returns:
            The response message as a dictionary with role and content
        """
        response = await chat_complete_tokens(
            messages,
            is_async=True,
            config_list=self.config_list,
            temperature=temperature,
            max_tokens=max_tokens,
            stop=stop_sequences,
        )

        if not response or not response.get("choices"):
            raise ValueError("No completion received from the model")

        return response["choices"][0]["message"]


# Global client instances
_sync_client: Optional[OpenAIClient] = None
_async_client: Optional[OpenAIClient] = None


def get_openai_client(async_mode: bool = False) -> OpenAIClient:
    """Get the global OpenAI client instance.

    Args:
        async_mode: Whether to return an async client

    Returns:
        OpenAI client instance configured with autogen-core
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
