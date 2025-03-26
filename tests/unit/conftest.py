"""Pytest fixtures for unit tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock


@pytest.fixture
def mock_connector():
    """Mock Neo4j connector."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []
    return connector


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    client = AsyncMock()
    client.get_completion.return_value = "Mock completion"
    return client


@pytest.fixture
def mock_config():
    """Mock configuration."""
    config = MagicMock()
    config.get.return_value = None  # Default return value
    
    # Return different values for specific keys
    def mock_get(key, default=None):
        config_values = {
            "openai.model": "gpt-4-32k",
            "neo4j.uri": "bolt://localhost:7687",
            "neo4j.username": "neo4j",
            "neo4j.password": "password",
            "logging.level": "INFO",
            "telemetry.enabled": True,
        }
        return config_values.get(key, default)
    
    config.get.side_effect = mock_get
    return config