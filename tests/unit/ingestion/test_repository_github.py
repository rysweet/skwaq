"""Tests for GitHub integration in the repository module."""

import os
import tempfile
import pytest
from unittest.mock import MagicMock

from skwaq.ingestion.repository import RepositoryHandler
from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.ingestion.exceptions import RepositoryError

# Test against a small, real, public repo
TEST_REPO_URL = "https://github.com/pallets/flask"


@pytest.mark.github
def test_clone_real_repository():
    """Test cloning a real repository from GitHub."""
    handler = RepositoryHandler()

    try:
        # Clone the repository with depth=1 to save time
        repo_path = handler.clone_repository(TEST_REPO_URL, depth=1)

        # Verify that the repository was cloned successfully
        assert os.path.exists(repo_path)
        assert os.path.isdir(repo_path)
        assert os.path.isdir(os.path.join(repo_path, ".git"))

        # List files in the repository to verify it was cloned
        files = os.listdir(repo_path)
        assert len(files) > 0  # There should be at least some files

        # Assert that .git directory exists and contains expected files
        git_dir = os.path.join(repo_path, ".git")
        git_files = os.listdir(git_dir)
        assert "HEAD" in git_files  # Every Git repo has a HEAD file

    finally:
        # Clean up
        handler.cleanup()


@pytest.mark.github
def test_get_repository_metadata():
    """Test extracting metadata from a real repository."""
    handler = RepositoryHandler()

    try:
        # Clone the repository with minimal depth for speed
        repo_path = handler.clone_repository(TEST_REPO_URL, depth=1)

        # Get metadata
        metadata = handler.get_repository_metadata(repo_path, TEST_REPO_URL)

        # Check basic metadata
        assert metadata["name"] == "flask"
        assert "commit_hash" in metadata
        assert "branch" in metadata
        assert "commit_date" in metadata
        assert "commit_author" in metadata
        assert "commit_message" in metadata

    finally:
        # Clean up
        handler.cleanup()


@pytest.mark.github
def test_get_repository_stats():
    """Test generating statistics for a real repository."""
    handler = RepositoryHandler()

    try:
        # Clone the repository with minimal depth for speed
        repo_path = handler.clone_repository(TEST_REPO_URL, depth=1)

        # Get stats
        stats = handler.get_repository_stats(repo_path)

        # Check stats
        assert stats["file_count"] > 0
        assert stats["directory_count"] > 0
        assert stats["total_size_bytes"] > 0

        # There should be at least some file extensions
        assert len(stats["extension_counts"]) > 0

    finally:
        # Clean up
        handler.cleanup()


@pytest.mark.github
@pytest.mark.parametrize(
    "repo_url", ["https://github.com/nonexistent/repository", "invalid_url"]
)
def test_clone_repository_errors(repo_url):
    """Test error handling when cloning invalid repositories."""
    handler = RepositoryHandler()

    with pytest.raises(RepositoryError) as excinfo:
        handler.clone_repository(repo_url)

    assert excinfo.value.repo_url == repo_url

    # Clean up any temporary directories that might have been created
    handler.cleanup()


@pytest.mark.skipif(
    not os.environ.get("GITHUB_TOKEN"),
    reason="GITHUB_TOKEN environment variable not set",
)
@pytest.mark.github
def test_github_api():
    """Test GitHub API integration with a token."""
    # Only run this test if a GitHub token is available
    token = os.environ.get("GITHUB_TOKEN")
    handler = RepositoryHandler(github_token=token)

    # Get GitHub repo
    github_repo = handler.get_github_repo(TEST_REPO_URL)

    # Verify repo data
    assert github_repo is not None
    assert github_repo.name == "flask"
    assert "Python" in github_repo.get_languages()

    # Get repository metadata with GitHub info
    metadata = handler.get_repository_metadata(os.getcwd(), TEST_REPO_URL)

    # Check GitHub-specific metadata
    assert "github_id" in metadata
    assert "github_full_name" in metadata
    assert "stars" in metadata
    assert "languages" in metadata
