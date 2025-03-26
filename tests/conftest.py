"""Test configuration for pytest.

This module provides fixtures and configuration for testing.
"""

import sys
import os
import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import importlib
from pathlib import Path

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
def reset_registries(monkeypatch):
    """Reset all service registries before each test and enhance mocking.

    This fixture ensures that tests don't interfere with each other by
    resetting all service registries between tests and enforcing proper mocking.
    It also handles Path.exists mocking that can cause test interference.
    """
    # Import the modules that have registries
    neo4j_connector_module = importlib.import_module("skwaq.db.neo4j_connector")
    openai_client_module = importlib.import_module("skwaq.core.openai_client")
    code_ingestion_module = importlib.import_module("skwaq.ingestion.code_ingestion")
    patterns_registry_module = importlib.import_module("skwaq.code_analysis.patterns.registry")
    
    # Keep track of any global instances of CodeAnalyzer
    try:
        analyzer_module = importlib.import_module("skwaq.code_analysis.analyzer")
        if hasattr(analyzer_module, "CodeAnalyzer") and hasattr(analyzer_module.CodeAnalyzer, "_instance"):
            analyzer_module.CodeAnalyzer._instance = None
    except (ImportError, AttributeError):
        pass
    
    # Reset all known registries before the test
    neo4j_connector_module.reset_connector_registry()
    openai_client_module.reset_client_registry()
    
    # Reset any global state in other modules
    if hasattr(patterns_registry_module, "reset_registry"):
        patterns_registry_module.reset_registry()
    
    # Create mock objects for global usage
    mock_neo4j_connector = MagicMock()
    mock_neo4j_connector.create_node.return_value = 1
    mock_neo4j_connector.create_relationship.return_value = True
    mock_neo4j_connector.run_query.return_value = []

    mock_openai_client = MagicMock()
    mock_openai_client.get_completion = MagicMock(return_value="Mock repository summary")
    # For async tests
    mock_async_openai_client = MagicMock()
    mock_async_openai_client.get_completion = AsyncMock(return_value="Mock repository summary")

    # Override the get_* functions to return consistent mocks for 'default' keys
    original_get_connector = neo4j_connector_module.get_connector
    original_get_openai_client = openai_client_module.get_openai_client

    def mock_get_connector(uri=None, user=None, password=None, registry_key="default"):
        if registry_key == "default":
            return mock_neo4j_connector
        return original_get_connector(uri, user, password, registry_key)

    def mock_get_openai_client(config=None, async_mode=False, registry_key=None):
        if registry_key is None:
            registry_key = "async" if async_mode else "sync"
        if registry_key == "sync":
            return mock_openai_client
        elif registry_key == "async":
            return mock_async_openai_client
        return original_get_openai_client(config, async_mode, registry_key)

    # Apply the patches for the registry functions
    monkeypatch.setattr("skwaq.db.neo4j_connector.get_connector", mock_get_connector)
    monkeypatch.setattr("skwaq.core.openai_client.get_openai_client", mock_get_openai_client)
    
    # Save original Path.exists to restore it after tests
    from pathlib import Path
    original_path_exists = Path.exists
    
    def safe_path_exists(self):
        """A safe default implementation that allows basic path checks.
        
        This allows Path.exists('/real/path') to work normally
        but returns True for common test paths like '/path/to/repo'.
        """
        # Common test paths that should return True
        test_paths = {
            "/path/to/repo", 
            "/tmp/mock_repo",
            "/tmp/mock_temp_dir",
            "/test/path"
        }
        
        if str(self) in test_paths:
            return True
            
        # Fall back to the actual implementation for real paths
        return original_path_exists(self)
    
    # Apply Path.exists patch
    monkeypatch.setattr(Path, "exists", safe_path_exists)

    # Run the test
    yield

    # Reset registries after the test
    neo4j_connector_module.reset_connector_registry()
    openai_client_module.reset_client_registry()
    
    # Reset other global state as needed
    if hasattr(patterns_registry_module, "reset_registry"):
        patterns_registry_module.reset_registry()
        
    # Reset any CodeAnalyzer instance
    try:
        analyzer_module = importlib.import_module("skwaq.code_analysis.analyzer")
        if hasattr(analyzer_module, "CodeAnalyzer") and hasattr(analyzer_module.CodeAnalyzer, "_instance"):
            analyzer_module.CodeAnalyzer._instance = None
    except (ImportError, AttributeError):
        pass


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
    client.get_completion = MagicMock(return_value="Mock repository summary")

    with patch("skwaq.core.openai_client.get_openai_client", return_value=client):
        yield client


@pytest.fixture
def mock_config():
    """Mock configuration."""
    config = MagicMock()

    with patch("skwaq.utils.config.get_config", return_value=config):
        yield config
