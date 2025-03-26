"""Pytest fixtures specific to ingestion tests."""

import pytest
import os
import tempfile
from unittest.mock import MagicMock, AsyncMock, patch
from pathlib import Path


@pytest.fixture
def mock_path_exists():
    """Mock Path.exists to always return True for any path."""
    original_path_exists = Path.exists
    
    def mock_path_exists_fn(self):
        return True
    
    Path.exists = mock_path_exists_fn
    yield
    Path.exists = original_path_exists


@pytest.fixture
def mock_github_api():
    """Mock GitHub API for testing."""
    github_mock = MagicMock()
    repo_mock = MagicMock()
    
    # Mock repository properties
    repo_mock.name = "test-repo"
    repo_mock.full_name = "test-user/test-repo"
    repo_mock.description = "Test repository for unit tests"
    repo_mock.stargazers_count = 10
    repo_mock.forks_count = 5
    repo_mock.default_branch = "main"
    repo_mock.size = 1024  # KB
    repo_mock.private = False
    repo_mock.clone_url = "https://github.com/test-user/test-repo.git"
    repo_mock.ssh_url = "git@github.com:test-user/test-repo.git"
    repo_mock.html_url = "https://github.com/test-user/test-repo"
    
    # Mock dates
    from datetime import datetime
    
    repo_mock.created_at = datetime.now()
    repo_mock.updated_at = datetime.now()
    
    # Mock languages
    repo_mock.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
    
    # Set up the GitHub client mock
    github_mock.get_repo.return_value = repo_mock
    github_mock.get_rate_limit.return_value = MagicMock()
    
    with patch("github.Github", return_value=github_mock):
        yield github_mock


@pytest.fixture
def mock_git_repo():
    """Mock GitPython Repo for testing."""
    git_repo_mock = MagicMock()
    branch_mock = MagicMock()
    commit_mock = MagicMock()
    
    # Mock branch properties
    branch_mock.name = "main"
    git_repo_mock.active_branch = branch_mock
    
    # Mock commit properties
    commit_mock.hexsha = "abc123def456"
    commit_mock.author.name = "Test User"
    commit_mock.author.email = "test@example.com"
    commit_mock.committed_date = 1616161616  # Unix timestamp
    commit_mock.message = "Test commit message"
    
    # Link commit to repo
    git_repo_mock.head.commit = commit_mock
    
    with patch("git.Repo", return_value=git_repo_mock):
        with patch("git.Repo.clone_from") as clone_mock:
            clone_mock.return_value = git_repo_mock
            yield git_repo_mock


@pytest.fixture
def isolated_repository_ingestor(mock_connector, mock_openai_client, monkeypatch):
    """Create an isolated RepositoryIngestor instance with proper mocks.
    
    This fixture is designed to be completely isolated from the global state and
    other tests, ensuring that tests using this fixture will not interfere with
    other tests running before or after them.
    """
    # Important: Import all modules within the fixture to prevent global state issues
    import sys
    
    # First, mock external dependencies that might cause test failures
    mock_modules = {
        "github": MagicMock(),
        "github.Auth": MagicMock(),
        "github.Repository": MagicMock(),
        "github.Repository.Repository": MagicMock(),
        "github.GithubException": type("GithubException", (Exception,), {}),
        "git": MagicMock(),
        "git.Repo": MagicMock(),
        "git.GitCommandError": type("GitCommandError", (Exception,), {}),
    }
    
    # Apply module mocking
    with patch.dict(sys.modules, mock_modules):
        from skwaq.ingestion.code_ingestion import RepositoryIngestor
        
        # Mock essential dependencies - use direct imports instead of string paths to avoid monkeypatch issues
        from skwaq.db.neo4j_connector import get_connector
        from skwaq.core.openai_client import get_openai_client
        import skwaq.ingestion.code_ingestion as code_ingestion_module
        
        # Use direct patching to avoid string path issues
        monkeypatch.setattr(code_ingestion_module, "get_connector", lambda: mock_connector)
        monkeypatch.setattr(code_ingestion_module, "get_openai_client", lambda async_mode=False: mock_openai_client)
        
        # Create a safe Path.exists implementation
        original_path_exists = Path.exists
        
        def safe_path_exists(self):
            # Common test paths that should return True
            test_paths = {
                "/path/to/repo", 
                "/tmp/mock_repo",
                "/tmp/mock_temp_dir",
                "/test/path",
                "/test/repo"
            }
            
            if str(self) in test_paths:
                return True
            
            # Fall back to actual implementation for real paths
            return original_path_exists(self)
        
        # Apply the patch
        monkeypatch.setattr(Path, "exists", safe_path_exists)
        
        # Ensure no instances exist before creating ours
        if hasattr(RepositoryIngestor, "_instance"):
            RepositoryIngestor._instance = None
        
        # Create the ingestor with mocked dependencies
        ingestor = RepositoryIngestor(
            github_token="test_token",
            max_workers=2,
            progress_bar=False,
            connector=mock_connector,
            openai_client=mock_openai_client
        )
        
        # Set up GitHub client mock
        github_client = MagicMock()
        repo_mock = MagicMock()
        
        # Mock repository properties
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
        repo_mock.size = 1024
        
        # Set up the GitHub client
        github_client.get_repo.return_value = repo_mock
        github_client.get_rate_limit.return_value = MagicMock()
        
        # Set the GitHub client on the ingestor
        ingestor.github_client = github_client
        
        # Mock internal methods
        ingestor._get_timestamp = MagicMock(return_value="2023-01-01T00:00:00")
        ingestor._generate_repo_summary = AsyncMock(return_value="Mock repository summary")
        ingestor._generate_code_summary = AsyncMock(return_value="Mock code summary")
        ingestor._process_filesystem = AsyncMock(return_value={
            "file_count": 5,
            "directory_count": 3,
            "code_files_processed": 4
        })
        ingestor._parse_github_url = MagicMock(return_value=("test-user", "test-repo"))
        ingestor._get_github_repo_info = MagicMock(return_value={
            "name": "test-repo",
            "full_name": "test-user/test-repo",
            "description": "Test repository",
            "owner": "test-user",
            "stars": 10,
            "forks": 5,
            "default_branch": "main",
            "languages": {"Python": 1000, "JavaScript": 500},
            "size": 1024,
            "private": False,
            "created_at": None,
            "updated_at": None,
            "clone_url": "https://github.com/test-user/test-repo.git",
            "ssh_url": "git@github.com:test-user/test-repo.git",
            "html_url": "https://github.com/test-user/test-repo"
        })
        
        # Mock high-level methods for testing
        mock_ingest_result = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "file_count": 5,
            "directory_count": 3,
            "code_files_processed": 4,
            "processing_time_seconds": 0.1,
            "summary": "Test repository summary"
        }
        
        mock_github_result = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "metadata": {
                "name": "test-repo",
                "owner": "test-user",
                "stars": 10,
                "languages": {"Python": 1000, "JavaScript": 500}
            },
            "content_ingested": False
        }
        
        ingestor.ingest_from_path = AsyncMock(return_value=mock_ingest_result)
        ingestor.ingest_from_github = AsyncMock(return_value=mock_github_result)
        
        yield ingestor
        
        # Clean up after the test to prevent test interference
        if hasattr(RepositoryIngestor, "_instance"):
            RepositoryIngestor._instance = None