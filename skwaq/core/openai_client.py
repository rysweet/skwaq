"""OpenAI client implementation for Skwaq using Azure OpenAI API directly.
This module provides a wrapper around the Azure OpenAI API with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

import asyncio
from typing import Dict, List, Optional

# Direct OpenAI imports
from openai import AzureOpenAI, OpenAI

from ..utils.config import Config, get_config
from ..utils.logging import get_logger

try:
    from azure.identity import (
        ClientSecretCredential,
        DefaultAzureCredential,
        get_bearer_token_provider,
    )

    HAS_AZURE_IDENTITY = True
except ImportError:
    HAS_AZURE_IDENTITY = False

logger = get_logger(__name__)


class OpenAIClient:
    """OpenAI client wrapper for Skwaq using Azure OpenAI API directly.

    This class provides a configured OpenAI client instance using the modern OpenAI
    Python client with proper authentication and retry logic for the Skwaq system.

    Args:
        config: Configuration object containing OpenAI settings
        async_mode: Whether to use async client. Defaults to False.

    Attributes:
        client: The OpenAI client instance (AzureOpenAI or OpenAI)
        model: The default model to use for completions
    """

    def __init__(self, config: Config, async_mode: bool = False) -> None:
        """Initialize the OpenAI client with the modern OpenAI SDK.

        Args:
            config: Configuration object containing OpenAI settings
            async_mode: Whether to use async client. Defaults to False.
        """
        api_type = config.get("openai", {}).get("api_type", "azure").lower()
        openai_config = config.get("openai", {})
        use_entra_id = openai_config.get("use_entra_id", False)

        # Get model configuration
        model_deployments = openai_config.get("model_deployments", {})
        default_chat_model = model_deployments.get("chat", "gpt4o")

        # Set up the client instance
        if api_type == "azure":
            # For Azure OpenAI
            endpoint = openai_config.get("endpoint")
            if not endpoint:
                raise ValueError(
                    "Azure OpenAI endpoint is required but not provided in configuration"
                )

            api_version = openai_config.get("api_version", "2023-05-15")

            if use_entra_id:
                # Use Azure AD authentication
                if not HAS_AZURE_IDENTITY:
                    raise ImportError(
                        "The 'azure-identity' package is required for Entra ID authentication. "
                        "Install it with 'pip install azure-identity'."
                    )

                logger.info(
                    "Using Microsoft Entra ID (Azure AD) authentication for Azure OpenAI"
                )

                # Create credentials for authentication
                if (
                    "auth_method" in openai_config
                    and openai_config["auth_method"] == "bearer_token"
                ):
                    try:
                        credential = DefaultAzureCredential()
                        scope = openai_config.get(
                            "token_scope",
                            "https://cognitiveservices.azure.com/.default",
                        )

                        token_provider = get_bearer_token_provider(credential, scope)
                        logger.info(
                            f"Using bearer token authentication with scope: {scope}"
                        )

                        self.client = AzureOpenAI(
                            azure_endpoint=endpoint,
                            api_version=api_version,
                            azure_ad_token_provider=token_provider,
                        )
                    except (ImportError, AttributeError) as e:
                        logger.error(
                            f"Bearer token authentication requires newer azure-identity version: {e}"
                        )
                        raise ImportError(
                            "Bearer token authentication requires azure-identity>=1.15.0. "
                            "Please upgrade with 'pip install azure-identity>=1.15.0'."
                        )
                elif "client_id" in openai_config and "tenant_id" in openai_config:
                    tenant_id = openai_config["tenant_id"]
                    client_id = openai_config["client_id"]

                    if "client_secret" in openai_config:
                        # Use service principal authentication
                        client_secret = openai_config["client_secret"]
                        credential = ClientSecretCredential(
                            tenant_id=tenant_id,
                            client_id=client_id,
                            client_secret=client_secret,
                        )
                        scope = openai_config.get(
                            "token_scope",
                            "https://cognitiveservices.azure.com/.default",
                        )
                        token_provider = get_bearer_token_provider(credential, scope)

                        logger.info(
                            "Using service principal authentication with tenant, client ID and secret"
                        )

                        self.client = AzureOpenAI(
                            azure_endpoint=endpoint,
                            api_version=api_version,
                            azure_ad_token_provider=token_provider,
                        )
                    else:
                        # Use managed identity or default authentication
                        credential = DefaultAzureCredential()
                        scope = openai_config.get(
                            "token_scope",
                            "https://cognitiveservices.azure.com/.default",
                        )
                        token_provider = get_bearer_token_provider(credential, scope)

                        logger.info(
                            "Using DefaultAzureCredential (managed identity or environment)"
                        )

                        self.client = AzureOpenAI(
                            azure_endpoint=endpoint,
                            api_version=api_version,
                            azure_ad_token_provider=token_provider,
                        )
                else:
                    # Use default authentication methods
                    credential = DefaultAzureCredential()
                    scope = openai_config.get(
                        "token_scope", "https://cognitiveservices.azure.com/.default"
                    )
                    token_provider = get_bearer_token_provider(credential, scope)

                    logger.info(
                        "Using DefaultAzureCredential (managed identity or environment)"
                    )

                    self.client = AzureOpenAI(
                        azure_endpoint=endpoint,
                        api_version=api_version,
                        azure_ad_token_provider=token_provider,
                    )
            else:
                # Use API key authentication for Azure
                if not config.openai_api_key:
                    raise ValueError(
                        "OpenAI API key is required but not provided in configuration"
                    )

                logger.info("Using API key authentication for Azure OpenAI")

                self.client = AzureOpenAI(
                    azure_endpoint=endpoint,
                    api_version=api_version,
                    api_key=config.openai_api_key,
                )
        else:
            # Regular OpenAI API
            if not config.openai_api_key:
                raise ValueError(
                    "OpenAI API key is required but not provided in configuration"
                )

            logger.info("Using API key authentication for OpenAI")

            client_kwargs = {
                "api_key": config.openai_api_key,
            }

            # Add organization ID if available
            if config.openai_org_id:
                client_kwargs["organization"] = config.openai_org_id

            self.client = OpenAI(**client_kwargs)

        # Store model information
        if api_type == "azure":
            self.model = openai_config.get("chat_model", default_chat_model)
            # For Azure, we set the deployment to the same value as the model by default
            self.deployment = openai_config.get("deployment", self.model)
        else:
            self.model = config.openai_model or "gpt-4-turbo-preview"
            self.deployment = None  # Not used for regular OpenAI API

        logger.info(f"Initialized OpenAI client with model {self.model}")

    async def get_completion(
        self,
        prompt: str,
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> str:
        """Get a completion using the OpenAI API directly.

        Args:
            prompt: The prompt to send to the model
            temperature: Sampling temperature, higher means more random
            max_tokens: Maximum number of tokens to generate
            stop_sequences: Optional list of sequences where the API will stop generating

        Returns:
            The generated completion text
        """
        messages = [{"role": "user", "content": prompt}]
        response = await self.chat_completion(
            messages=messages,
            temperature=temperature,
            max_tokens=max_tokens,
            stop_sequences=stop_sequences,
        )
        return response.get("content", "")

    async def get_embeddings(
        self, texts: List[str], model: Optional[str] = None
    ) -> List[List[float]]:
        """Get embeddings for a list of texts using the OpenAI embeddings API.

        Args:
            texts: List of texts to get embeddings for
            model: Optional specific model to use for embeddings

        Returns:
            List of embedding vectors
        """
        embedding_model = model or "text-embedding-ada-002"

        results = []
        # Process texts in batches of 10 to avoid overloading the API
        batch_size = 10
        for i in range(0, len(texts), batch_size):
            batch = texts[i : i + batch_size]
            try:
                response = await self.client.embeddings.create(
                    input=batch,
                    model=embedding_model,
                )

                for embedding_data in response.data:
                    results.append(embedding_data.embedding)
            except Exception as e:
                logger.error(f"Error getting embeddings: {e}")
                # Add None for each failed embedding
                results.extend([None] * len(batch))

        return results

    async def chat_completion(
        self,
        messages: List[Dict[str, str]],
        *,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop_sequences: Optional[List[str]] = None,
    ) -> Dict[str, str]:
        """Get a chat completion using the OpenAI API directly.

        Args:
            messages: List of message dictionaries with role and content
            temperature: Sampling temperature
            max_tokens: Maximum tokens to generate
            stop_sequences: Optional stop sequences

        Returns:
            The response message as a dictionary with role and content
        """
        try:
            # Prepare the arguments
            kwargs = {
                "messages": messages,
            }

            # Handle Azure vs regular OpenAI API parameters
            is_azure = hasattr(self, "deployment") and self.deployment is not None

            # For Azure OpenAI, we need to specify the deployment
            if is_azure:
                kwargs["model"] = self.deployment

                # Azure OpenAI API uses different parameter names for different models
                if max_tokens is not None:
                    # For o1 model, use max_completion_tokens instead of max_tokens
                    if self.deployment == "o1" or self.model == "o1":
                        kwargs["max_completion_tokens"] = max_tokens
                    else:
                        kwargs["max_tokens"] = max_tokens

                # Only include temperature if not using o1 model (which doesn't support it)
                if self.deployment != "o1" and self.model != "o1":
                    kwargs["temperature"] = temperature
            else:
                # Regular OpenAI
                kwargs["model"] = self.model

                if max_tokens is not None:
                    kwargs["max_tokens"] = max_tokens

                kwargs["temperature"] = temperature

            # Stop sequences work the same for both APIs
            if stop_sequences is not None:
                kwargs["stop"] = stop_sequences

            logger.debug(f"Chat completion parameters: {kwargs}")

            # Make the API call
            try:
                if hasattr(self.client.chat.completions, "create"):
                    # Check if the create method is async or not
                    if asyncio.iscoroutinefunction(self.client.chat.completions.create):
                        response = await self.client.chat.completions.create(**kwargs)
                    else:
                        # Handle non-async create method
                        response = self.client.chat.completions.create(**kwargs)
                else:
                    # Fallback to directly accessing the attribute
                    response = self.client.chat.completions(**kwargs)
            except Exception as api_error:
                # If there's an error with temperature in Azure, retry without it
                if is_azure and "temperature" in str(api_error).lower():
                    logger.warning(
                        f"Temperature parameter issue detected: {api_error}. Retrying without temperature parameter."
                    )
                    kwargs.pop("temperature", None)
                    if hasattr(self.client.chat.completions, "create"):
                        if asyncio.iscoroutinefunction(self.client.chat.completions.create):
                            response = await self.client.chat.completions.create(**kwargs)
                        else:
                            response = self.client.chat.completions.create(**kwargs)
                    else:
                        response = self.client.chat.completions(**kwargs)
                else:
                    raise  # Re-raise if it's not a temperature issue or not Azure

            if not response:
                raise ValueError("No completion received from the model")

            # Handle different response formats
            if hasattr(response, 'choices'):
                if len(response.choices) == 0:
                    raise ValueError("No choices in completion response")
                
                # Get the message based on response structure
                if hasattr(response.choices[0], 'message'):
                    message = response.choices[0].message
                    if hasattr(message, 'role') and hasattr(message, 'content'):
                        return {"role": message.role, "content": message.content}
                    elif hasattr(message, 'get'):
                        # Dictionary-like structure
                        return {
                            "role": message.get("role", "assistant"),
                            "content": message.get("content", "")
                        }
                elif hasattr(response.choices[0], 'text'):
                    # Completion API response
                    return {"role": "assistant", "content": response.choices[0].text}
                elif hasattr(response.choices[0], 'get'):
                    # Dictionary-like choice
                    choice = response.choices[0]
                    if choice.get('message'):
                        msg = choice.get('message')
                        return {
                            "role": msg.get("role", "assistant"),
                            "content": msg.get("content", "")
                        }
                    elif choice.get('text'):
                        return {"role": "assistant", "content": choice.get('text', "")}
            
            # Handle dictionary response format
            if isinstance(response, dict):
                if 'choices' in response:
                    choices = response['choices']
                    if choices and isinstance(choices, list) and len(choices) > 0:
                        choice = choices[0]
                        if isinstance(choice, dict):
                            if 'message' in choice:
                                msg = choice['message']
                                return {
                                    "role": msg.get("role", "assistant"),
                                    "content": msg.get("content", "")
                                }
                            elif 'text' in choice:
                                return {"role": "assistant", "content": choice.get('text', "")}
            
            # Fallback if we can't parse the response structure
            logger.warning(f"Unexpected response format: {type(response)}. Attempting to extract content.")
            try:
                # Try to convert to string and return
                return {"role": "assistant", "content": str(response)}
            except Exception as e:
                logger.error(f"Failed to extract content from response: {e}")
                return {"role": "assistant", "content": "Error: Unable to parse response"}

        except Exception as e:
            logger.error(f"Error in chat_completion: {e}")
            # Return a fallback response with error message
            return {"role": "assistant", "content": f"Error: {str(e)}"}


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


async def test_openai_connection() -> bool:
    """Test the connection to the OpenAI API.

    This function attempts to make a simple API call to test if the
    OpenAI configuration is correct and the connection works.

    Returns:
        True if connection is successful, False otherwise
    """
    try:
        client = get_openai_client(async_mode=True)

        # Make a minimal API call to test connection
        test_prompt = "Return only the word 'OK' if you can see this message."
        response = await client.get_completion(test_prompt, temperature=0.0)

        # Check if we got a reasonable response
        if response and "OK" in response:
            logger.info("OpenAI API connection test successful")
            return True
        else:
            logger.warning(
                f"OpenAI API responded but with unexpected content: {response[:100]}"
            )
            return False

    except Exception as e:
        logger.error(f"OpenAI API connection test failed: {e}")
        return False
