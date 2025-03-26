"""Test configuration for pytest.

This module provides fixtures and configuration for testing.
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, patch
import importlib

# List of modules to mock
MOCK_MODULES = [
    "autogen",
    "autogen.core",
    "autogen_core",
    "autogen_core.agent",
    "autogen_core.event",
    "autogen_core.code_utils",
    "autogen_core.memory",
]


def pytest_sessionstart(session):
    """Set up mocks for external dependencies before test collection begins."""
    # Create mock modules
    for mod_name in MOCK_MODULES:
        sys.modules[mod_name] = MagicMock()
    
    # Set up autogen_core modules with required classes
    if "autogen_core" in sys.modules:
        sys.modules["autogen_core"].agent = MagicMock()
        sys.modules["autogen_core"].event = MagicMock()
        sys.modules["autogen_core"].code_utils = MagicMock()
        sys.modules["autogen_core"].memory = MagicMock()
        
        # Add required classes
        sys.modules["autogen_core"].agent.Agent = MagicMock()
        sys.modules["autogen_core"].agent.ChatAgent = MagicMock()
        sys.modules["autogen_core"].event.BaseEvent = MagicMock()
        sys.modules["autogen_core"].event.Event = MagicMock()
        sys.modules["autogen_core"].event.EventHook = MagicMock()
        sys.modules["autogen_core"].event.register_hook = MagicMock()
        sys.modules["autogen_core"].memory.MemoryRecord = MagicMock()
    
    # Set up autogen.core
    if "autogen.core" in sys.modules:
        sys.modules["autogen.core"].chat_complete_tokens = MagicMock()


@pytest.fixture(autouse=True)
def reset_singletons(monkeypatch):
    """Reset all singleton instances before each test and enhance mocking.
    
    This fixture ensures that tests don't interfere with each other by
    resetting all singleton instances between tests and enforcing proper mocking.
    """
    # Store original module values
    neo4j_connector_module = importlib.import_module("skwaq.db.neo4j_connector")
    openai_client_module = importlib.import_module("skwaq.core.openai_client")
    
    # Reset singleton instances
    neo4j_connector_module._connector = None
    openai_client_module._sync_client = None
    openai_client_module._async_client = None
    
    # Create mock objects
    mock_neo4j_connector = MagicMock()
    mock_neo4j_connector.create_node.return_value = 1
    mock_neo4j_connector.create_relationship.return_value = True
    mock_neo4j_connector.run_query.return_value = []
    
    mock_openai_client = MagicMock()
    mock_openai_client.get_completion.return_value = "Mock response"
    
    # Patch the get_* functions to ensure consistent mocking
    def mock_get_connector():
        return mock_neo4j_connector
    
    def mock_get_openai_client(async_mode=False):
        return mock_openai_client
    
    # Patch the module functions
    monkeypatch.setattr("skwaq.db.neo4j_connector.get_connector", mock_get_connector)
    monkeypatch.setattr("skwaq.core.openai_client.get_openai_client", mock_get_openai_client)
    
    # Run the test
    yield
    
    # Reset singletons again to prevent test interference
    neo4j_connector_module._connector = None
    openai_client_module._sync_client = None
    openai_client_module._async_client = None


@pytest.fixture
def mock_connector():
    """Mock Neo4j connector."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []
    
    with patch("skwaq.db.neo4j_connector.get_connector", return_value=connector):
        yield connector


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    client = MagicMock()
    client.get_completion = MagicMock(return_value="Mock response")
    
    with patch("skwaq.core.openai_client.get_openai_client", return_value=client):
        yield client


@pytest.fixture
def mock_config():
    """Mock configuration."""
    config = MagicMock()
    
    with patch("skwaq.utils.config.get_config", return_value=config):
        yield config