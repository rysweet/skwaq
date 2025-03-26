"""OpenAI client implementation for Skwaq using autogen-core.
This module provides a wrapper around the autogen-core OpenAI functionality with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

from typing import Dict, List, Optional, Union
import json
import autogen_core as autogen
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
                    "api_version": config.get("openai", {}).get(
                        "api_version", "2023-05-15"
                    ),
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
        """Get a completion using autogen-core's chat client.

        Args:
            prompt: The prompt to send to the model
            temperature: Sampling temperature, higher means more random
            max_tokens: Maximum number of tokens to generate
            stop_sequences: Optional list of sequences where the API will stop generating

        Returns:
            The generated completion text
        """
        messages = [{"role": "user", "content": prompt}]
        chat_client = autogen.core.ChatCompletionClient(
            config_list=self.config_list, is_async=True
        )
        response = await chat_client.generate(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stop=stop_sequences,
        )
        if not response or not response.choices:
            raise ValueError("No completion received from the model")
        return response.choices[0].message["content"]

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
        """Get a chat completion using autogen-core's chat client.

        Args:
            messages: List of message dictionaries with role and content
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stop_sequences: Optional stop sequences

        Returns:
            The response message as a dictionary with role and content
        """
        chat_client = autogen.core.ChatCompletionClient(
            config_list=self.config_list, is_async=True
        )
        response = await chat_client.generate(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stop=stop_sequences,
        )
        if not response or not response.choices:
            raise ValueError("No completion received from the model")
        return response.choices[0].message


# Use a client registry instead of global instances
_client_registry: Dict[str, OpenAIClient] = {}


def get_openai_client(
    config: Optional[Config] = None,
    async_mode: bool = False,
    registry_key: Optional[str] = None,
) -> OpenAIClient:
    """Get an OpenAI client instance from the registry or create a new one.

    This function provides backward compatibility with the previous singleton pattern
    while allowing for proper dependency injection and testing.

    Args:
        config: Optional configuration object. If None, the global config will be used.
        async_mode: Whether to return an async client
        registry_key: Key to use for storing the client in the registry.
                     If None, defaults to "sync" or "async" based on async_mode.

    Returns:
        OpenAI client instance configured with autogen-core
    """
    global _client_registry

    if registry_key is None:
        registry_key = "async" if async_mode else "sync"

    if registry_key in _client_registry:
        return _client_registry[registry_key]

    if config is None:
        config = get_config()

    client = OpenAIClient(config, async_mode=async_mode)
    _client_registry[registry_key] = client
    return client


def reset_client_registry() -> None:
    """Reset the client registry - primarily for testing.

    This function clears all stored client instances from the registry.
    """
    global _client_registry
    _client_registry.clear()
