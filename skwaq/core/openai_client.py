"""OpenAI client module for the Skwaq vulnerability assessment copilot.

This module provides a wrapper around the OpenAI API client, with support
for Azure OpenAI services.
"""

import os
from typing import Any, Dict, List, Optional, Union

import openai
from openai import AzureOpenAI, OpenAI

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


class OpenAIClient:
    """Client for OpenAI API requests.
    
    This class provides a unified interface to OpenAI models, with
    support for both OpenAI and Azure OpenAI endpoints.
    """

    def __init__(self):
        """Initialize the OpenAI client.
        
        Configuration is loaded from the global configuration.
        """
        self._config = get_config()
        self._openai_config = self._config.openai
        self._client = None
        
        # Initialize the client
        self._initialize_client()
    
    def _initialize_client(self) -> None:
        """Initialize the appropriate OpenAI client based on configuration."""
        api_type = self._openai_config.get("api_type", "openai")
        
        if api_type == "azure":
            logger.info("Initializing Azure OpenAI client")
            if not all(k in self._openai_config for k in ["api_key", "endpoint", "api_version"]):
                error_msg = "Missing required Azure OpenAI configuration"
                logger.error(error_msg)
                raise ValueError(error_msg)
            
            # Set up Azure OpenAI client
            self._client = AzureOpenAI(
                api_key=self._openai_config.get("api_key"),
                api_version=self._openai_config.get("api_version"),
                azure_endpoint=self._openai_config.get("endpoint")
            )
            
            logger.info(f"Azure OpenAI client initialized with endpoint: {self._openai_config.get('endpoint')}")
        elif api_type == "openai":
            logger.info("Initializing OpenAI client")
            if "api_key" not in self._openai_config:
                # Try to get from environment variable
                if not os.environ.get("OPENAI_API_KEY"):
                    error_msg = "OpenAI API key not found in config or environment variables"
                    logger.error(error_msg)
                    raise ValueError(error_msg)
            
            # Set up OpenAI client
            self._client = OpenAI(
                api_key=self._openai_config.get("api_key") or os.environ.get("OPENAI_API_KEY")
            )
            logger.info("OpenAI client initialized")
        else:
            error_msg = f"Unsupported OpenAI API type: {api_type}"
            logger.error(error_msg)
            raise ValueError(error_msg)
    
    @property
    def client(self) -> Union[OpenAI, AzureOpenAI]:
        """Get the underlying OpenAI client.
        
        Returns:
            The OpenAI client instance
        """
        if not self._client:
            self._initialize_client()
        return self._client
    
    def get_chat_completion(
        self,
        messages: List[Dict[str, str]],
        model: Optional[str] = None,
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stream: bool = False,
        **kwargs: Any
    ) -> Any:
        """Get a completion from the chat model.
        
        Args:
            messages: List of message objects with 'role' and 'content'
            model: Model to use (defaults to configuration)
            temperature: Sampling temperature (0-1)
            max_tokens: Maximum tokens to generate
            stream: Whether to stream the response
            **kwargs: Additional parameters to pass to the API
            
        Returns:
            Completion response from the API
        """
        # Determine model to use
        if not model:
            api_type = self._openai_config.get("api_type", "openai")
            model = self._openai_config.get("chat_model", "gpt-4o" if api_type == "azure" else "gpt-4o")
        
        # Log request (with truncated content for privacy/verbosity)
        logger.debug(f"Sending chat completion request to model: {model}")
        logger.debug(f"Temperature: {temperature}, Max tokens: {max_tokens}")
        
        for idx, msg in enumerate(messages):
            content = msg.get("content", "")
            if content and len(content) > 100:
                content = content[:97] + "..."
            logger.debug(f"Message {idx}: {msg.get('role')} - {content}")
        
        try:
            # Create the model parameters
            params = {
                "model": model,
                "messages": messages,
                "temperature": temperature,
                **kwargs
            }
            
            if max_tokens is not None:
                params["max_tokens"] = max_tokens
            
            # Make the API call
            if stream:
                response = self.client.chat.completions.create(**params, stream=True)
                return response
            else:
                response = self.client.chat.completions.create(**params)
                
                # Log response (truncated for privacy/verbosity)
                content = response.choices[0].message.content
                if content and len(content) > 100:
                    log_content = content[:97] + "..."
                else:
                    log_content = content
                logger.debug(f"Response: {log_content}")
                
                # Calculate token usage if available
                if hasattr(response, "usage") and response.usage:
                    prompt_tokens = response.usage.prompt_tokens
                    completion_tokens = response.usage.completion_tokens
                    total_tokens = response.usage.total_tokens
                    logger.debug(f"Token usage - Prompt: {prompt_tokens}, Completion: {completion_tokens}, Total: {total_tokens}")
                
                return response
        except Exception as e:
            logger.error(f"Error making OpenAI API request: {e}")
            raise
    
    def get_embeddings(
        self,
        texts: List[str],
        model: Optional[str] = None
    ) -> List[List[float]]:
        """Get embeddings for a list of texts.
        
        Args:
            texts: List of text strings to embed
            model: Embedding model to use (defaults to configuration)
            
        Returns:
            List of embedding vectors
        """
        # Determine model to use
        if not model:
            api_type = self._openai_config.get("api_type", "openai")
            model = self._openai_config.get(
                "embedding_model", 
                "text-embedding-ada-002" if api_type == "azure" else "text-embedding-3-small"
            )
        
        logger.debug(f"Getting embeddings for {len(texts)} texts using model {model}")
        
        try:
            response = self.client.embeddings.create(
                model=model,
                input=texts
            )
            
            embeddings = [item.embedding for item in response.data]
            logger.debug(f"Generated {len(embeddings)} embeddings")
            
            # Calculate token usage if available
            if hasattr(response, "usage") and response.usage:
                total_tokens = response.usage.total_tokens
                logger.debug(f"Token usage: {total_tokens}")
            
            return embeddings
        except Exception as e:
            logger.error(f"Error getting embeddings: {e}")
            raise


# Global client instance
_client: Optional[OpenAIClient] = None


def get_openai_client() -> OpenAIClient:
    """Get the global OpenAI client instance.
    
    Returns:
        The global OpenAIClient instance
    """
    global _client
    if _client is None:
        _client = OpenAIClient()
    return _client