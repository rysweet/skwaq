"""Pytest fixtures for isolated testing of the ingestion module."""

import sys
import importlib
import pytest
from unittest.mock import MagicMock, AsyncMock


@pytest.fixture(scope="function", autouse=True)
def reset_ingestion_modules():
    """Reset the ingestion modules before and after each test.
    
    This fixture ensures that each test has a clean import state for
    the ingestion modules. It is marked as autouse=True to ensure
    it runs for every test in this directory.
    """
    # Save original modules
    original_modules = dict(sys.modules)
    
    # Store keys to be removed after test
    ingestion_modules = [key for key in sys.modules.keys() 
                      if key.startswith('skwaq.ingestion')]
    
    # Clear module cache for ingestion modules and reload
    for module in ingestion_modules:
        if module in sys.modules:
            del sys.modules[module]
    
    # Let the test run
    yield
    
    # Restore original module state after test
    for module in ingestion_modules:
        if module in original_modules:
            sys.modules[module] = original_modules[module]
        elif module in sys.modules:
            del sys.modules[module]


@pytest.fixture
def mock_connector():
    """Mock Neo4j connector for ingestion tests."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []
    return connector


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client for ingestion tests."""
    client = AsyncMock()
    client.get_completion.return_value = "Mock repository summary"
    return client


@pytest.fixture
def mock_github_client():
    """Mock GitHub client for ingestion tests."""
    client = MagicMock()
    # Set up basic rate limiting response
    client.get_rate_limit.return_value = MagicMock()
    return client


@pytest.fixture
def mock_github_repo():
    """Mock GitHub Repository object for tests."""
    repo = MagicMock()
    repo.name = "test-repo"
    repo.full_name = "user/test-repo"
    repo.description = "Test repository"
    repo.stargazers_count = 10
    repo.forks_count = 5
    repo.default_branch = "main"
    repo.size = 1024
    repo.private = False
    repo.created_at = None
    repo.updated_at = None
    repo.clone_url = "https://github.com/user/test-repo.git"
    repo.ssh_url = "git@github.com:user/test-repo.git"
    repo.html_url = "https://github.com/user/test-repo"
    repo.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
    return repo


@pytest.fixture
def isolated_test_environment(mock_connector, mock_openai_client, mock_github_client):
    """Create a completely isolated test environment.
    
    This fixture returns a dictionary with mocked dependencies for isolated tests.
    It's designed to create a completely independent test environment where each
    test run is completely isolated from others.
    """
    # Store mocked dependencies in a single dictionary
    env = {
        "connector": mock_connector,
        "openai_client": mock_openai_client,
        "github_client": mock_github_client,
    }
    
    # Mock github module
    github_mock = MagicMock()
    github_instance = MagicMock()
    github_instance.get_rate_limit = MagicMock(return_value=MagicMock())
    github_instance.get_repo = MagicMock(return_value=MagicMock())
    
    # Set up repo mock
    repo_mock = github_instance.get_repo.return_value
    repo_mock.name = "test-repo"
    repo_mock.full_name = "test-user/test-repo"
    repo_mock.description = "Test repository for unit tests"
    repo_mock.stargazers_count = 10
    repo_mock.forks_count = 5
    repo_mock.default_branch = "main"
    repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
    repo_mock.html_url = "https://github.com/test-user/test-repo"
    repo_mock.clone_url = "https://github.com/test-user/test-repo.git"
    repo_mock.ssh_url = "git@github.com:test-user/test-repo.git"
    
    # Set up GitHub class in the module
    github_mock.Github = MagicMock(return_value=github_instance)
    github_mock.Auth = MagicMock()
    github_mock.Auth.Token = MagicMock()
    github_mock.GithubException = type("GithubException", (Exception,), {})
    
    # Store the original modules
    original_github = sys.modules.get("github", None)
    
    # Replace with mocks
    sys.modules["github"] = github_mock
    
    yield env
    
    # Restore original modules if they existed
    if original_github:
        sys.modules["github"] = original_github
    elif "github" in sys.modules:
        del sys.modules["github"]