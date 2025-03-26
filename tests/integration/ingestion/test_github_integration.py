"""Integration tests for GitHub repository ingestion functionality."""

import os
import pytest
from unittest.mock import MagicMock, patch, PropertyMock
from pathlib import Path

from skwaq.ingestion.code_ingestion import (
    RepositoryIngestor,
    ingest_repository,
    get_github_repository_info,
)


@pytest.mark.github
@pytest.mark.skipif(
    not os.environ.get("GITHUB_TOKEN"), reason="GitHub token not available"
)
class TestGitHubIntegration:
    """Tests for GitHub integration functionality.

    These tests require GitHub access and are marked to be skipped if a token is not available.
    Run these tests with:
    GITHUB_TOKEN=your_token pytest tests/integration/ingestion/test_github_integration.py -v
    """

    def test_github_repository_info(self):
        """Test fetching GitHub repository information.

        This test uses a real GitHub token to fetch information from the GitHub API.
        """
        # Create clean connector and client
        mock_connector = MagicMock()
        mock_openai_client = MagicMock()

        # Create ingestor with real GitHub token but mock other dependencies
        ingestor = RepositoryIngestor(
            github_token=os.environ.get("GITHUB_TOKEN"),
            connector=mock_connector,
            openai_client=mock_openai_client,
        )

        # Get repository info for a public repository
        repo_info = ingestor._get_github_repo_info("anthropics", "anthropic-cookbook")

        # Verify essential information was retrieved
        assert repo_info["name"] == "anthropic-cookbook"
        assert repo_info["full_name"] == "anthropics/anthropic-cookbook"
        assert repo_info["owner"] == "anthropics"
        assert isinstance(repo_info["stars"], int)
        assert isinstance(repo_info["languages"], dict)

    @pytest.mark.asyncio
    async def test_github_metadata_only(self):
        """Test fetching GitHub repository metadata without cloning."""
        # Create clean connector and client
        mock_connector = MagicMock()
        mock_openai_client = MagicMock()

        # Get repository info for a public repository
        result = await get_github_repository_info(
            github_url="https://github.com/anthropics/anthropic-cookbook",
            github_token=os.environ.get("GITHUB_TOKEN"),
            connector=mock_connector,
            openai_client=mock_openai_client,
        )

        # Verify essential metadata was retrieved
        assert "repository_name" in result
        assert result["repository_name"] == "anthropic-cookbook"


# For non-integration tests that mock GitHub API
class TestGitHubMocks:
    """Tests for GitHub functionality using mocks.

    These tests don't require GitHub access and can be run without a token.
    """

    def test_github_repository_info_mocked(self):
        """Test fetching GitHub repository information with mocked GitHub API."""
        # Create clean dependencies
        mock_connector = MagicMock()
        mock_openai_client = MagicMock()

        # Mock GitHub dependencies
        with (
            patch("skwaq.ingestion.code_ingestion.Auth") as mock_auth,
            patch("skwaq.ingestion.code_ingestion.Github") as mock_github,
        ):

            # Set up Auth token
            mock_auth_token = MagicMock()
            mock_auth.Token.return_value = mock_auth_token

            # Mock repository
            mock_repo = MagicMock()
            mock_repo.name = "test-repo"
            mock_repo.full_name = "user/test-repo"
            mock_repo.description = "Test repository"
            mock_repo.stargazers_count = 10
            mock_repo.forks_count = 5
            mock_repo.default_branch = "main"
            mock_repo.size = 1024
            mock_repo.private = False
            mock_repo.clone_url = "https://github.com/user/test-repo.git"
            mock_repo.ssh_url = "git@github.com:user/test-repo.git"
            mock_repo.html_url = "https://github.com/user/test-repo"

            # Mock dates as properties
            type(mock_repo).created_at = PropertyMock(return_value=None)
            type(mock_repo).updated_at = PropertyMock(return_value=None)

            # Mock languages
            mock_repo.get_languages.return_value = {"Python": 1000, "JavaScript": 500}

            # Set up the GitHub client mock
            mock_github_instance = MagicMock()
            mock_github_instance.get_repo.return_value = mock_repo
            mock_github_instance.get_rate_limit.return_value = MagicMock()
            mock_github.return_value = mock_github_instance

            # Initialize the ingestor with mocks
            ingestor = RepositoryIngestor(
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client,
            )
            ingestor.github_client = mock_github_instance  # Skip initialization

            # Get repository info
            repo_info = ingestor._get_github_repo_info("user", "test-repo")

            # Verify the GitHub client was used properly
            mock_github_instance.get_repo.assert_called_once_with("user/test-repo")

            # Verify the repository info
            assert repo_info["name"] == "test-repo"
            assert repo_info["full_name"] == "user/test-repo"
            assert repo_info["description"] == "Test repository"
            assert repo_info["owner"] == "user"
            assert repo_info["stars"] == 10
            assert repo_info["forks"] == 5
            assert repo_info["default_branch"] == "main"
            assert repo_info["languages"] == {"Python": 1000, "JavaScript": 500}
            assert repo_info["size"] == 1024
            assert repo_info["private"] is False
            assert repo_info["clone_url"] == "https://github.com/user/test-repo.git"
            assert repo_info["ssh_url"] == "git@github.com:user/test-repo.git"
            assert repo_info["html_url"] == "https://github.com/user/test-repo"
