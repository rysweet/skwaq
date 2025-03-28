"""OpenAI client implementation for Skwaq using autogen-core.
This module provides a wrapper around the autogen-core OpenAI functionality with configuration
specific to the Skwaq vulnerability assessment copilot.
"""

from typing import Dict, List, Optional, Union
import json

# Import autogen_core directly
import autogen_core
from ..utils.config import Config, get_config
from ..utils.logging import get_logger

try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential

    HAS_AZURE_IDENTITY = True
except ImportError:
    HAS_AZURE_IDENTITY = False

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
        openai_config = config.get("openai", {})
        use_entra_id = openai_config.get("use_entra_id", False)

        # Get model configuration
        model_deployments = openai_config.get("model_deployments", {})
        default_chat_model = model_deployments.get("chat", "gpt4o")

        # Set up base configuration
        base_config = {
            "api_type": api_type,
            "api_version": openai_config.get("api_version", "2023-05-15"),
        }

        # Add API endpoint
        if api_type == "azure":
            endpoint = openai_config.get("endpoint")
            if not endpoint:
                raise ValueError(
                    "Azure OpenAI endpoint is required but not provided in configuration"
                )
            base_config["base_url"] = endpoint

        # Configure authentication based on method
        if api_type == "azure" and use_entra_id:
            if not HAS_AZURE_IDENTITY:
                raise ImportError(
                    "The 'azure-identity' package is required for Entra ID authentication. "
                    "Install it with 'pip install azure-identity'."
                )

            # Set up Azure AD authentication
            logger.info(
                "Using Microsoft Entra ID (Azure AD) authentication for Azure OpenAI"
            )

            # Create credentials for authentication
            if (
                "auth_method" in openai_config
                and openai_config["auth_method"] == "bearer_token"
            ):
                try:
                    from azure.identity import get_bearer_token_provider

                    credential = DefaultAzureCredential()
                    scope = openai_config.get(
                        "token_scope", "https://cognitiveservices.azure.com/.default"
                    )

                    base_config["azure_ad_token_provider"] = get_bearer_token_provider(
                        credential, scope
                    )
                    logger.info(
                        f"Using bearer token authentication with scope: {scope}"
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
                    base_config["azure_ad_token_provider"] = ClientSecretCredential(
                        tenant_id=tenant_id,
                        client_id=client_id,
                        client_secret=client_secret,
                    )
                    logger.info(
                        "Using service principal authentication with tenant, client ID and secret"
                    )
                else:
                    # Use managed identity or default authentication
                    base_config["azure_ad_token_provider"] = DefaultAzureCredential()
                    logger.info(
                        "Using DefaultAzureCredential (managed identity or environment)"
                    )
            else:
                # Use default authentication methods
                base_config["azure_ad_token_provider"] = DefaultAzureCredential()
                logger.info(
                    "Using DefaultAzureCredential (managed identity or environment)"
                )

            # For Azure AD auth, we don't set api_key
            self.config_list = [
                {
                    "model": openai_config.get("chat_model", default_chat_model),
                    **base_config,
                }
            ]
        else:
            # Use API key authentication
            if not config.openai_api_key:
                raise ValueError(
                    "OpenAI API key is required but not provided in configuration"
                )

            logger.info("Using API key authentication for OpenAI")

            if api_type == "azure":
                self.config_list = [
                    {
                        "model": openai_config.get("chat_model", default_chat_model),
                        "api_key": config.openai_api_key,
                        **base_config,
                    }
                ]
            else:
                self.config_list = [
                    {
                        "model": config.openai_model or "gpt-4-turbo-preview",
                        "api_key": config.openai_api_key,
                        "api_type": "openai",
                    }
                ]

        # Set the model based on configuration
        if api_type == "azure":
            self.model = openai_config.get("chat_model", default_chat_model)
        else:
            self.model = config.openai_model or "gpt-4-turbo-preview"

        # Add organization ID if available
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
        chat_client = autogen_core.ChatCompletionClient(
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
            response = await autogen_core.embeddings(
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
        try:
            chat_client = autogen_core.ChatCompletionClient(
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
            
            # Handle different response formats based on autogen_core version
            message = response.choices[0].message
            
            # If message is already a dict with 'content', return it directly
            if isinstance(message, dict) and "content" in message:
                return message
                
            # If message is an object with attributes, convert to dict
            if hasattr(message, "content"):
                return {"role": "assistant", "content": message.content}
                
            # If message is a string, wrap it in a dict
            if isinstance(message, str):
                return {"role": "assistant", "content": message}
                
            # If it's some other unexpected format, try to convert to dict
            if hasattr(message, "__dict__"):
                message_dict = dict(message.__dict__)
                if "content" not in message_dict and "message" in message_dict:
                    message_dict["content"] = message_dict["message"]
                return message_dict
                
            # Last resort fallback
            logger.warning(f"Unexpected message format from autogen_core: {type(message)}")
            return {"role": "assistant", "content": str(message)}
            
        except Exception as e:
            logger.error(f"Error in chat_completion: {e}")
            raise


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
