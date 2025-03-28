"""Tests for OpenAI client module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from openai import AzureOpenAI, OpenAI

from skwaq.core.openai_client import (
    OpenAIClient,
    reset_client_registry,
    get_openai_client,
)
from skwaq.utils.config import Config


@pytest.fixture
def mock_config():
    """Fixture providing a mock configuration."""
    config = Config(
        openai_api_key="test-key",
        openai_org_id="test-org",
        openai_model="gpt-4-turbo-preview",
    )
    # Override the openai config section for tests
    config.openai = {
        "api_type": "openai",  # Use openai instead of azure for tests
        "chat_model": "gpt-4-turbo-preview",  # Use this model for tests
    }
    return config


@patch("openai.OpenAI")
def test_openai_client_initialization(mock_openai, mock_config):
    """Test OpenAI client initialization."""
    mock_instance = MagicMock()
    mock_openai.return_value = mock_instance
    
    client = OpenAIClient(mock_config)
    # The client now uses OpenAI directly
    assert hasattr(client, "client")
    assert client.model == "gpt-4-turbo-preview"
    assert client.deployment is None  # Not used for OpenAI API
    
    # Verify OpenAI was initialized with correct parameters
    mock_openai.assert_called_once_with(api_key="test-key", organization="test-org")


@patch("openai.OpenAI")
def test_openai_client_async_initialization(mock_openai, mock_config):
    """Test async OpenAI client initialization."""
    mock_instance = MagicMock()
    mock_openai.return_value = mock_instance
    
    client = OpenAIClient(mock_config, async_mode=True)
    # Async mode doesn't affect initialization now, only usage
    assert hasattr(client, "client")
    assert client.model == "gpt-4-turbo-preview"
    
    # Verify OpenAI was initialized with correct parameters
    mock_openai.assert_called_once_with(api_key="test-key", organization="test-org")


@pytest.mark.asyncio
async def test_get_completion():
    """Test getting completions from OpenAI with proper mocking."""
    # Mock a client with chat_completion method
    with patch("openai.OpenAI") as mock_openai_class:
        # Setup the mock client
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        
        # Set up the return value for chat.completions.create
        mock_completion = MagicMock()
        mock_choice = MagicMock()
        mock_message = MagicMock()
        mock_message.content = "Test completion"
        mock_message.role = "assistant"
        mock_choice.message = mock_message
        mock_completion.choices = [mock_choice]
        
        # Set up the completion method
        mock_chat = MagicMock()
        mock_chat.completions = MagicMock()
        mock_chat.completions.create = AsyncMock(return_value=mock_completion)
        mock_client.chat = mock_chat
        
        # Create a config for the client
        config = Config(
            openai_api_key="test-key",
            openai_org_id="test-org",
            openai_model="gpt-4-turbo-preview",
            openai={
                "api_type": "openai",  # Regular OpenAI, not Azure
            }
        )

        # Create the client
        client = OpenAIClient(config, async_mode=True)
        
        # Test get_completion
        result = await client.get_completion("Test prompt")
        
        # Verify the result
        assert result == "Test completion"
        
        # Verify the API was called with correct parameters
        mock_chat.completions.create.assert_called_once()
        call_args = mock_chat.completions.create.call_args
        assert call_args[1]["messages"] == [{"role": "user", "content": "Test prompt"}]
        assert call_args[1]["temperature"] == 0.7
        assert call_args[1]["model"] == "gpt-4-turbo-preview"


@pytest.mark.asyncio
async def test_chat_completion_formats():
    """Test chat_completion method handles different response formats correctly."""
    with patch("openai.OpenAI") as mock_openai_class:
        # Setup the mock client
        mock_client = MagicMock()
        mock_openai_class.return_value = mock_client
        
        # Create test cases with different message formats
        test_cases = [
            # Standard response
            {
                "message_content": "Standard response",
                "message_role": "assistant",
                "expected": {"role": "assistant", "content": "Standard response"}
            },
            # Error handling test
            {
                "raises_exception": True,
                "exception_message": "API error",
                "expected": {"role": "assistant", "content": "Error: API error"}
            }
        ]
        
        for i, test_case in enumerate(test_cases):
            # Configure mock chat completions
            mock_chat = MagicMock()
            mock_client.chat = mock_chat
            mock_completions = MagicMock()
            mock_chat.completions = mock_completions
            
            if test_case.get("raises_exception", False):
                # Set up the mock to raise an exception
                mock_completions.create = AsyncMock(
                    side_effect=Exception(test_case["exception_message"])
                )
            else:
                # Set up a normal response
                mock_completion = MagicMock()
                mock_choice = MagicMock()
                mock_message = MagicMock()
                mock_message.content = test_case["message_content"]
                mock_message.role = test_case["message_role"]
                mock_choice.message = mock_message
                mock_completion.choices = [mock_choice]
                mock_completions.create = AsyncMock(return_value=mock_completion)
            
            # Create a test config
            config = Config(
                openai_api_key="test-key",
                openai_model="gpt-4-turbo-preview",
                openai={"api_type": "openai"}
            )
            
            # Create the client
            client = OpenAIClient(config)
            
            # Call the method
            result = await client.chat_completion(
                messages=[{"role": "user", "content": f"Test message {i}"}]
            )
            
            # Verify the result matches expected format
            assert result["role"] == test_case["expected"]["role"]
            assert result["content"] == test_case["expected"]["content"]


@patch("openai.AzureOpenAI")
def test_azure_api_key_auth(mock_azure_openai):
    """Test initialization with Azure API key authentication."""
    # Create a mock config with Azure settings
    config = Config(
        openai_api_key="test-api-key",
        openai_org_id="test-org-id",
        openai={
            "api_type": "azure",
            "endpoint": "https://test.openai.azure.com/",
            "api_version": "2023-05-15",
        },
    )

    # Setup the mock
    mock_client = MagicMock()
    mock_azure_openai.return_value = mock_client

    # Initialize client
    client = OpenAIClient(config)

    # Verify client was initialized correctly
    assert client.client == mock_client
    assert client.model is not None
    
    # Verify AzureOpenAI was initialized with correct parameters
    mock_azure_openai.assert_called_once_with(
        azure_endpoint="https://test.openai.azure.com/",
        api_version="2023-05-15",
        api_key="test-api-key",
    )


@pytest.mark.skipif(
    not hasattr(OpenAIClient, "HAS_AZURE_IDENTITY")
    or not OpenAIClient.HAS_AZURE_IDENTITY,
    reason="Azure Identity package not installed",
)
@patch("openai.AzureOpenAI")
@patch("azure.identity.DefaultAzureCredential")
@patch("azure.identity.get_bearer_token_provider")
def test_azure_entra_id_auth(mock_token_provider, mock_credential, mock_azure_openai):
    """Test initialization with Azure Entra ID authentication."""
    # Mock credential instance
    mock_credential.return_value = MagicMock(name="default_credential")
    
    # Mock token provider
    token_provider_instance = MagicMock(name="token_provider")
    mock_token_provider.return_value = token_provider_instance
    
    # Mock OpenAI client
    mock_client = MagicMock(name="azure_openai_client")
    mock_azure_openai.return_value = mock_client

    # Create a mock config with Entra ID settings
    config = Config(
        openai_api_key="",  # Empty API key
        openai_org_id="test-org-id",
        openai={
            "api_type": "azure",
            "endpoint": "https://test.openai.azure.com/",
            "api_version": "2023-05-15",
            "use_entra_id": True,
            "tenant_id": "test-tenant-id",
            "client_id": "test-client-id",
        },
    )

    # Initialize client
    client = OpenAIClient(config)

    # Verify client was initialized correctly
    assert client.client == mock_client
    
    # Verify AzureOpenAI was initialized with token provider
    mock_azure_openai.assert_called_once_with(
        azure_endpoint="https://test.openai.azure.com/",
        api_version="2023-05-15",
        azure_ad_token_provider=token_provider_instance,
    )


@pytest.mark.skipif(
    not hasattr(OpenAIClient, "HAS_AZURE_IDENTITY")
    or not OpenAIClient.HAS_AZURE_IDENTITY,
    reason="Azure Identity package not installed",
)
@patch("openai.AzureOpenAI")
@patch("azure.identity.DefaultAzureCredential")
@patch("azure.identity.get_bearer_token_provider")
def test_azure_bearer_token_auth(mock_get_token_provider, mock_credential, mock_azure_openai):
    """Test initialization with Azure bearer token authentication."""
    # Mock credential and token provider instances
    mock_credential.return_value = MagicMock(name="default_credential")
    mock_token_provider = MagicMock(name="token_provider")
    mock_get_token_provider.return_value = mock_token_provider
    
    # Mock Azure OpenAI client
    mock_client = MagicMock(name="azure_openai_client")
    mock_azure_openai.return_value = mock_client

    # Create a mock config with bearer token settings
    config = Config(
        openai_api_key="",  # Empty API key
        openai_org_id="test-org-id",
        openai={
            "api_type": "azure",
            "endpoint": "https://test.openai.azure.com/",
            "api_version": "2023-05-15",
            "use_entra_id": True,
            "auth_method": "bearer_token",
            "token_scope": "https://cognitiveservices.azure.com/.default",
        },
    )

    # Initialize client
    client = OpenAIClient(config)

    # Verify the client was initialized correctly
    assert client.client == mock_client
    
    # Verify the AzureOpenAI client was initialized with token provider
    mock_azure_openai.assert_called_once_with(
        azure_endpoint="https://test.openai.azure.com/",
        api_version="2023-05-15",
        azure_ad_token_provider=mock_token_provider,
    )

    # Verify the token provider was created with the correct scope
    mock_get_token_provider.assert_called_once_with(
        mock_credential.return_value, "https://cognitiveservices.azure.com/.default"
    )


@patch("openai.AzureOpenAI")
def test_client_registry(mock_azure_openai):
    """Test the OpenAI client registry."""
    # Setup mocks
    mock_client1 = MagicMock(name="azure_client1")
    mock_client2 = MagicMock(name="azure_client2")
    mock_azure_openai.side_effect = [mock_client1, mock_client2]
    
    # Reset registry to start with a clean state
    reset_client_registry()

    # Create a config
    config = Config(
        openai_api_key="test-api-key",
        openai_org_id="test-org-id",
        openai={"api_type": "azure", "endpoint": "https://test.openai.azure.com/"},
    )

    # Get client from registry
    client1 = get_openai_client(config)

    # Get client again - should be the same instance
    client2 = get_openai_client(config)

    # Verify it's the same instance
    assert client1 is client2
    # Verify the Azure client was only created once
    assert mock_azure_openai.call_count == 1

    # Get a client with a different registry key
    client3 = get_openai_client(config, registry_key="test")

    # Should be a different instance
    assert client1 is not client3
    # Verify the Azure client was created again
    assert mock_azure_openai.call_count == 2

    # Reset registry
    reset_client_registry()

    # Mock one more client instance
    mock_client3 = MagicMock(name="azure_client3")
    mock_azure_openai.side_effect = [mock_client3]
    
    # Get client again - should be a new instance
    client4 = get_openai_client(config)

    # Verify it's a different instance
    assert client1 is not client4
    # Verify the Azure client was created again
    assert mock_azure_openai.call_count == 3
