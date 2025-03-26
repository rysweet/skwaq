"""Unit tests for the high-level functions in the code_ingestion module."""

import os
import tempfile
import shutil
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

from skwaq.ingestion.code_ingestion import (
    ingest_repository,
    get_github_repository_info,
    list_repositories,
    RepositoryIngestor,
)


@pytest.fixture
def test_repo_path():
    """Create a test repository structure."""
    temp_dir = tempfile.mkdtemp(prefix="skwaq_test_repo_")

    # Create a basic repository structure
    (Path(temp_dir) / "src").mkdir()
    (Path(temp_dir) / "docs").mkdir()
    (Path(temp_dir) / "tests").mkdir()

    # Create some mock files
    (Path(temp_dir) / "src" / "main.py").write_text("print('Hello, world!')")
    (Path(temp_dir) / "src" / "utils.py").write_text("def add(a, b): return a + b")
    (Path(temp_dir) / "docs" / "README.md").write_text("# Test Repository")
    (Path(temp_dir) / "tests" / "test_main.py").write_text("def test_main(): pass")

    # Create a .git directory to simulate a git repository
    (Path(temp_dir) / ".git").mkdir()
    (Path(temp_dir) / ".git" / "HEAD").write_text("ref: refs/heads/main")

    yield temp_dir

    # Clean up
    shutil.rmtree(temp_dir)


@pytest.mark.asyncio
class TestIngestionFunctions:
    """Tests for high-level ingestion functions."""

    async def test_ingest_repository_local(self, mock_connector, mock_openai_client, test_repo_path, mock_path_exists):
        """Test ingesting a repository from a local path."""
        # Mock the RepositoryIngestor class with our own implementation
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class:
            # Create a mock ingestor with the expected return value
            mock_ingest_result = {
                "repository_id": 1,
                "repository_name": Path(test_repo_path).name,
                "file_count": 4,
                "directory_count": 3,
                "code_files_processed": 3,
                "processing_time_seconds": 0.1,
                "summary": "Test repository summary"
            }
            
            # Set up the mock instance with properly defined ingest_from_path method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_path = AsyncMock(return_value=mock_ingest_result)
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the function
            result = await ingest_repository(
                repo_path_or_url=test_repo_path,
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify the result
            assert result == mock_ingest_result
            
            # Verify the ingestor was created with the right args
            mock_ingestor_class.assert_called_once()
            # Verify ingest_from_path was called with the right args
            mock_ingestor_instance.ingest_from_path.assert_called_once_with(
                test_repo_path,
                None,  # Use directory name
                None,  # No include patterns
                None,  # No exclude patterns
            )

    async def test_ingest_repository_github(self, mock_connector, mock_openai_client, mock_path_exists):
        """Test ingesting a repository from a GitHub URL."""
        github_url = "https://github.com/user/test-repo"
        
        # Mock the RepositoryIngestor class with our own implementation
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class:
            # Create a mock ingestor with the expected return value
            mock_ingest_result = {
                "repository_id": 1,
                "repository_name": "test-repo",
                "github_url": github_url,
                "github_metadata": {
                    "name": "test-repo",
                    "owner": "user",
                    "stars": 10
                },
                "branch": "main",
                "file_count": 10,
                "code_files_processed": 5
            }
            
            # Set up the mock instance with properly defined ingest_from_github method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_github = AsyncMock(return_value=mock_ingest_result)
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the function
            result = await ingest_repository(
                repo_path_or_url=github_url,
                is_github_url=True,
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify the result
            assert result == mock_ingest_result
            
            # Verify the ingestor was created with the right args
            mock_ingestor_class.assert_called_once_with(
                github_token="test_token",
                max_workers=4,  # Default
                progress_bar=True,  # Default
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify ingest_from_github was called with the right args
            mock_ingestor_instance.ingest_from_github.assert_called_once_with(
                github_url,
                None,  # No include patterns
                None,  # No exclude patterns
                branch=None,
                metadata_only=False
            )

    async def test_ingest_repository_auto_detect_github(self, mock_connector, mock_openai_client, mock_path_exists):
        """Test auto-detection of GitHub URLs."""
        github_url = "https://github.com/user/test-repo"
        
        # Mock the RepositoryIngestor class and logger
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class, \
             patch("skwaq.ingestion.code_ingestion.logger") as mock_logger:
            
            # Create a mock ingestor with the expected return value
            mock_ingest_result = {
                "repository_id": 1,
                "repository_name": "test-repo",
                "github_url": github_url
            }
            
            # Set up the mock instance with properly defined ingest_from_github method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_github = AsyncMock(return_value=mock_ingest_result)
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the function with auto-detection
            result = await ingest_repository(
                repo_path_or_url=github_url,
                # Don't explicitly say it's a GitHub URL
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify URL was auto-detected
            mock_logger.info.assert_any_call(f"Automatically detected GitHub URL: {github_url}")
            
            # Verify the result
            assert result == mock_ingest_result
            
            # Verify ingest_from_github was called
            mock_ingestor_instance.ingest_from_github.assert_called_once()

    async def test_get_github_repository_info(self, mock_connector, mock_openai_client, mock_path_exists):
        """Test getting GitHub repository info without ingesting."""
        github_url = "https://github.com/user/test-repo"
        
        # Mock the RepositoryIngestor class
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class:
            # Create a mock ingestor with the expected return value
            mock_metadata_result = {
                "repository_id": 1,
                "repository_name": "test-repo",
                "metadata": {
                    "name": "test-repo",
                    "owner": "user",
                    "stars": 10,
                    "languages": {"Python": 1000}
                },
                "content_ingested": False
            }
            
            # Set up the mock instance with properly defined ingest_from_github method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_github = AsyncMock(return_value=mock_metadata_result)
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the function
            result = await get_github_repository_info(
                github_url=github_url,
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify the result
            assert result == mock_metadata_result
            
            # Verify the ingestor was created with the right args
            mock_ingestor_class.assert_called_once_with(
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify ingest_from_github was called with metadata_only=True
            mock_ingestor_instance.ingest_from_github.assert_called_once_with(
                github_url,
                metadata_only=True
            )

    async def test_list_repositories(self, mock_connector):
        """Test listing repositories."""
        # Define mock query result
        mock_query_result = [
            {
                "id": 1,
                "name": "repo1",
                "path": "/path/to/repo1",
                "url": "https://github.com/user/repo1",
                "ingested_at": "2023-01-01T00:00:00",
                "files": 10,
                "code_files": 7,
                "summary": "Test repository 1",
                "labels": ["Repository", "GitHubRepository"]
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
                "labels": ["Repository"]
            }
        ]
        
        # Configure the mock connector
        mock_connector.run_query.return_value = mock_query_result
        
        # Call the function
        result = await list_repositories(connector=mock_connector)
        
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
