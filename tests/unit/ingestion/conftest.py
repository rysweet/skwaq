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