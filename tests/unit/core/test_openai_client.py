"""Tests for OpenAI client module."""

import pytest
from openai import AsyncOpenAI, OpenAI

from skwaq.core.openai_client import OpenAIClient
from skwaq.utils.config import Config


@pytest.fixture
def mock_config():
    """Fixture providing a mock configuration."""
    return Config(
        openai_api_key="test-key",
        openai_org_id="test-org",
        openai_model="gpt-4-turbo-preview",
    )


def test_openai_client_initialization(mock_config):
    """Test OpenAI client initialization."""
    client = OpenAIClient(mock_config)
    assert isinstance(client.client, OpenAI)
    assert client.model == "gpt-4-turbo-preview"


def test_openai_client_async_initialization(mock_config):
    """Test async OpenAI client initialization."""
    client = OpenAIClient(mock_config, async_mode=True)
    assert isinstance(client.client, AsyncOpenAI)


@pytest.mark.asyncio
async def test_get_completion(mock_config, mocker):
    """Test getting completions from OpenAI."""
    mock_response = mocker.Mock()
    mock_response.choices = [mocker.Mock(message=mocker.Mock(content="Test completion"))]

    mock_create = mocker.AsyncMock(return_value=mock_response)
    mock_chat = mocker.Mock(completions=mocker.Mock(create=mock_create))
    mock_client = mocker.Mock(chat=mock_chat)

    client = OpenAIClient(mock_config, async_mode=True)
    client.client = mock_client

    result = await client.get_completion("Test prompt")
    assert result == "Test completion"

    mock_create.assert_called_once_with(
        model="gpt-4-turbo-preview",
        messages=[{"role": "user", "content": "Test prompt"}],
        temperature=0.7,
        max_tokens=None,
        stop=None,
    )
