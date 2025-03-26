"""Unit tests for the high-level functions in the code_ingestion module."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from skwaq.ingestion.code_ingestion import (
    ingest_repository,
    get_github_repository_info,
    list_repositories,
)


@pytest.mark.asyncio
class TestIngestionFunctions:
    """Tests for high-level ingestion functions."""

    async def test_ingest_repository_local(self):
        """Test ingesting a repository from a local path."""
        # Mock logger to avoid log errors
        with patch("skwaq.ingestion.code_ingestion.logger") as mock_logger, \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_cls, \
             patch("skwaq.ingestion.code_ingestion.get_connector") as mock_get_connector, \
             patch("skwaq.ingestion.code_ingestion.get_openai_client") as mock_get_openai_client:
            
            # Set up mock dependencies
            mock_get_connector.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            
            # Set up the mock ingestor
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_path = AsyncMock(
                return_value={
                    "repository_id": 1,
                    "repository_name": "test-repo",
                    "file_count": 10,
                    "directory_count": 5,
                    "code_files_processed": 7,
                    "summary": "Test repository summary",
                }
            )
            mock_ingestor_cls.return_value = mock_ingestor
            
            # Mock path exists
            with patch("pathlib.Path.exists", return_value=True):
                # Call the function with local path
                result = await ingest_repository(
                    repo_path_or_url="/path/to/repo",
                    is_github_url=False,
                    include_patterns=["*.py"],
                    exclude_patterns=["*test*"],
                    max_workers=8,
                    show_progress=False,
                )
                
                # Verify the ingestor was created with correct parameters
                mock_ingestor_cls.assert_called_once_with(
                    github_token=None,
                    max_workers=8,
                    progress_bar=False,
                )
                
                # Verify ingest_from_path was called with correct parameters
                mock_ingestor.ingest_from_path.assert_called_once_with(
                    "/path/to/repo",
                    None,
                    ["*.py"],
                    ["*test*"],
                )
                
                # Verify the result
                assert result["repository_name"] == "test-repo"
                assert result["file_count"] == 10
                assert result["code_files_processed"] == 7

    async def test_ingest_repository_github(self):
        """Test ingesting a repository from a GitHub URL."""
        # Mock dependencies
        with patch("skwaq.ingestion.code_ingestion.logger") as mock_logger, \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_cls, \
             patch("skwaq.ingestion.code_ingestion.get_connector") as mock_get_connector, \
             patch("skwaq.ingestion.code_ingestion.get_openai_client") as mock_get_openai_client:
            
            # Set up mock dependencies
            mock_get_connector.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            
            # Set up the mock ingestor
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_github = AsyncMock(
                return_value={
                    "repository_id": 1,
                    "repository_name": "test-repo",
                    "github_url": "https://github.com/user/test-repo",
                    "github_metadata": {"name": "test-repo"},
                    "branch": "main",
                    "file_count": 10,
                    "directory_count": 5,
                    "code_files_processed": 7,
                    "summary": "Test repository summary",
                }
            )
            mock_ingestor_cls.return_value = mock_ingestor
            
            # Call the function with GitHub URL
            result = await ingest_repository(
                repo_path_or_url="https://github.com/user/test-repo",
                is_github_url=True,
                include_patterns=["*.py"],
                exclude_patterns=["*test*"],
                github_token="test_token",
                branch="develop",
                max_workers=8,
                show_progress=False,
            )
            
            # Verify the ingestor was created with correct parameters
            mock_ingestor_cls.assert_called_once_with(
                github_token="test_token",
                max_workers=8,
                progress_bar=False,
            )
            
            # Verify ingest_from_github was called with correct parameters
            mock_ingestor.ingest_from_github.assert_called_once_with(
                "https://github.com/user/test-repo",
                ["*.py"],
                ["*test*"],
                branch="develop",
                metadata_only=False,
            )
            
            # Verify the result
            assert result["repository_name"] == "test-repo"
            assert result["github_url"] == "https://github.com/user/test-repo"
            assert result["branch"] == "main"

    async def test_ingest_repository_auto_detect_github(self):
        """Test auto-detection of GitHub URLs."""
        # Mock dependencies
        with patch("skwaq.ingestion.code_ingestion.logger") as mock_logger, \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_cls, \
             patch("skwaq.ingestion.code_ingestion.get_connector") as mock_get_connector, \
             patch("skwaq.ingestion.code_ingestion.get_openai_client") as mock_get_openai_client:
            
            # Set up mock dependencies
            mock_get_connector.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            
            # Set up the mock ingestor
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_github = AsyncMock(
                return_value={"repository_name": "test-repo"}
            )
            mock_ingestor.ingest_from_path = AsyncMock()
            mock_ingestor_cls.return_value = mock_ingestor
            
            # Call the function with GitHub URL (without specifying is_github_url)
            await ingest_repository(
                repo_path_or_url="https://github.com/user/test-repo",
            )
            
            # Verify ingest_from_github was called (auto-detected)
            mock_ingestor.ingest_from_github.assert_called_once()
            mock_ingestor.ingest_from_path.assert_not_called()

    async def test_get_github_repository_info(self):
        """Test getting GitHub repository info without ingesting."""
        # Mock dependencies
        with patch("skwaq.ingestion.code_ingestion.logger") as mock_logger, \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_cls, \
             patch("skwaq.ingestion.code_ingestion.get_connector") as mock_get_connector, \
             patch("skwaq.ingestion.code_ingestion.get_openai_client") as mock_get_openai_client:
            
            # Set up mock dependencies
            mock_get_connector.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            
            # Set up the mock ingestor
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_github = AsyncMock(
                return_value={
                    "repository_id": 1,
                    "repository_name": "test-repo",
                    "metadata": {
                        "name": "test-repo",
                        "description": "Test repository",
                        "stars": 10,
                    },
                    "content_ingested": False,
                }
            )
            mock_ingestor_cls.return_value = mock_ingestor
            
            # Call the function
            result = await get_github_repository_info(
                github_url="https://github.com/user/test-repo",
                github_token="test_token",
            )
            
            # Verify the ingestor was created with correct parameters
            mock_ingestor_cls.assert_called_once_with(github_token="test_token")
            
            # Verify ingest_from_github was called with correct parameters
            mock_ingestor.ingest_from_github.assert_called_once_with(
                "https://github.com/user/test-repo",
                metadata_only=True,
            )
            
            # Verify the result
            assert result["repository_name"] == "test-repo"
            assert "metadata" in result
            assert result["content_ingested"] is False

    async def test_list_repositories(self):
        """Test listing repositories."""
        # Mock dependencies
        with patch("skwaq.ingestion.code_ingestion.logger") as mock_logger, \
             patch("skwaq.ingestion.code_ingestion.get_connector") as mock_connector_fn:
            
            # Set up the mock connector
            mock_connector = MagicMock()
            mock_connector.run_query.return_value = [
                {
                    "id": 1,
                    "name": "repo1",
                    "path": "/path/to/repo1",
                    "url": "https://github.com/user/repo1",
                    "ingested_at": "2023-01-01T00:00:00",
                    "files": 10,
                    "code_files": 7,
                    "summary": "Test repository 1",
                    "labels": ["Repository", "GitHubRepository"],
                },
                {
                    "id": 2,
                    "name": "repo2",
                    "path": "/path/to/repo2",
                    "url": None,
                    "ingested_at": "2023-01-02T00:00:00",
                    "files": 20,
                    "code_files": 15,
                    "summary": "Test repository 2",
                    "labels": ["Repository"],
                },
            ]
            mock_connector_fn.return_value = mock_connector
            
            # Call the function
            result = await list_repositories()
            
            # Verify the connector was used properly
            mock_connector.run_query.assert_called_once()
            query = mock_connector.run_query.call_args[0][0]
            assert "MATCH (r:Repository)" in query
            
            # Verify the result
            assert len(result) == 2
            assert result[0]["name"] == "repo1"
            assert result[0]["id"] == 1
            assert result[1]["name"] == "repo2"
            assert result[1]["id"] == 2