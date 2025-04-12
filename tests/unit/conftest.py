"""Pytest fixtures for unit tests."""

import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest


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


@pytest.fixture(scope="session", autouse=True)
def mock_global_modules():
    """Mock global modules that might cause issues in tests."""
    # Create mock modules to avoid import errors
    mock_modules = {
        "github": MagicMock(),
        "github.Auth": MagicMock(),
        "github.Repository": MagicMock(),
        "github.Repository.Repository": MagicMock(),
        "github.GithubException": MagicMock(),
        "git": MagicMock(),
        "git.Repo": MagicMock(),
        "git.GitCommandError": MagicMock(),
        "pygit2": MagicMock(),
        "blarify": MagicMock(),
        "codeql": MagicMock(),
    }

    # Apply patching to sys.modules
    with patch.dict(sys.modules, mock_modules):
        yield


@pytest.fixture
def mock_github_repo():
    """Mock GitHub repository object."""
    repo = MagicMock()
    repo.name = "test-repo"
    repo.full_name = "test-user/test-repo"
    repo.description = "Test repository for unit tests"
    repo.stargazers_count = 10
    repo.forks_count = 5
    repo.default_branch = "main"
    repo.size = 1024  # KB
    repo.private = False
    repo.clone_url = "https://github.com/test-user/test-repo.git"
    repo.ssh_url = "git@github.com:test-user/test-repo.git"
    repo.html_url = "https://github.com/test-user/test-repo"

    # Mock dates
    from datetime import datetime

    repo.created_at = datetime.now()
    repo.updated_at = datetime.now()

    # Mock languages
    repo.get_languages.return_value = {"Python": 1000, "JavaScript": 500}

    return repo


@pytest.fixture
def mock_github_client(mock_github_repo):
    """Mock GitHub client."""
    github_client = MagicMock()
    github_client.get_repo.return_value = mock_github_repo
    github_client.get_rate_limit.return_value = MagicMock()
    return github_client


@pytest.fixture
def mock_repository_ingestor(mock_connector, mock_openai_client, mock_github_client):
    """Create a properly mocked RepositoryIngestor instance."""
    # Create a simple MagicMock instead of using spec which causes problems
    ingestor = MagicMock()

    # Initialize with the mock dependencies
    ingestor.connector = mock_connector
    ingestor.openai_client = mock_openai_client
    ingestor.github_client = mock_github_client
    ingestor.github_token = "test_token"
    ingestor.max_workers = 2
    ingestor.show_progress = False
    ingestor.excluded_dirs = {".git", "node_modules", "__pycache__"}
    ingestor.temp_dir = None

    # Mock the important methods
    ingestor._init_github_client.return_value = mock_github_client
    ingestor._get_timestamp.return_value = "2023-01-01T00:00:00"
    ingestor._generate_repo_summary = AsyncMock(return_value="Test repository summary")
    ingestor._parse_github_url.return_value = ("test-user", "test-repo")

    # Mock the high-level methods
    mock_ingest_result = {
        "repository_id": 1,
        "repository_name": "test-repo",
        "file_count": 10,
        "directory_count": 5,
        "code_files_processed": 7,
        "processing_time_seconds": 0.1,
        "summary": "Test repository summary",
    }

    mock_github_result = {
        "repository_id": 1,
        "repository_name": "test-repo",
        "metadata": {"name": "test-repo", "owner": "test-user", "stars": 10},
        "content_ingested": False,
    }

    ingestor.ingest_from_path = AsyncMock(return_value=mock_ingest_result)
    ingestor.ingest_from_github = AsyncMock(return_value=mock_github_result)

    return ingestor
