"""Isolated tests for GitHub integration that avoid import issues."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import sys
import tempfile
from pathlib import Path


@pytest.mark.asyncio
@pytest.mark.isolated
class TestIsolatedGitHubIntegration:
    """Tests for GitHub integration functionality in isolation."""

    async def test_ingest_from_github_metadata_only(self):
        """Test fetching GitHub repository metadata without cloning."""
        # Setup all mocks directly within the test to avoid module import issues
        with patch.dict(sys.modules, {
            "github": MagicMock(),
            "github.Repository": MagicMock(),
            "github.Auth": MagicMock(),
            "git": MagicMock(),
        }):
            # Now import the code
            from skwaq.ingestion.code_ingestion import RepositoryIngestor
            
            # Mock connector
            mock_connector = MagicMock()
            mock_connector.create_node.return_value = 1
            mock_connector.create_relationship.return_value = True
            mock_connector.run_query.return_value = []
            
            # Mock openai client
            mock_openai_client = MagicMock()
            mock_openai_client.get_completion = AsyncMock(return_value="Test summary")
            
            # Setup GitHub client mock
            mock_github = MagicMock()
            repo_mock = MagicMock()
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
            mock_github.get_repo.return_value = repo_mock
            
            # Mock ingestor
            with patch.object(RepositoryIngestor, "_init_github_client", return_value=mock_github):
                # Create test ingestor
                ingestor = RepositoryIngestor(
                    github_token="fake_token",
                    connector=mock_connector,
                    openai_client=mock_openai_client
                )
                
                # Mock internal methods
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
                ingestor._get_timestamp = MagicMock(return_value="2023-01-01T00:00:00")
                
                # Test metadata-only ingestion
                result = await ingestor.ingest_from_github(
                    "https://github.com/test-user/test-repo",
                    metadata_only=True
                )
                
                # Verify result
                assert "repository_id" in result
                assert result["repository_name"] == "test-repo"
                assert "metadata" in result
                assert result["metadata"]["name"] == "test-repo"
                assert result["content_ingested"] is False
    
    async def test_high_level_ingest(self):
        """Test the high-level ingest_repository function with GitHub URL."""
        # Setup all mocks directly within the test to avoid module import issues
        with patch.dict(sys.modules, {
            "github": MagicMock(),
            "github.Repository": MagicMock(),
            "github.Auth": MagicMock(),
            "git": MagicMock(),
        }):
            # Now import the code
            from skwaq.ingestion.code_ingestion import ingest_repository, RepositoryIngestor
            
            # Mock connector
            mock_connector = MagicMock()
            mock_connector.create_node.return_value = 1
            
            # Mock openai client
            mock_openai_client = MagicMock()
            
            # Mock RepositoryIngestor class
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_github = AsyncMock(return_value={
                "repository_id": 1,
                "repository_name": "test-repo",
                "metadata": {
                    "name": "test-repo",
                    "full_name": "test-user/test-repo",
                    "description": "Test repository"
                },
                "content_ingested": False
            })
            
            # Patch components
            with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor", return_value=mock_ingestor):
                with patch("skwaq.ingestion.code_ingestion.logger", MagicMock()):
                    # Test the function
                    result = await ingest_repository(
                        repo_path_or_url="https://github.com/test-user/test-repo",
                        is_github_url=True,
                        github_token="fake_token",
                        connector=mock_connector,
                        openai_client=mock_openai_client,
                        github_metadata_only=True
                    )
                    
                    # Verify result
                    assert result["repository_id"] == 1
                    assert result["repository_name"] == "test-repo"
                    assert "metadata" in result
                    assert result["content_ingested"] is False
                    
                    # Verify ingest_from_github was called with the right parameters
                    mock_ingestor.ingest_from_github.assert_called_once_with(
                        "https://github.com/test-user/test-repo",
                        None,  # include_patterns
                        None,  # exclude_patterns
                        branch=None,
                        metadata_only=True
                    )
    
    async def test_high_level_ingest_auto_detection(self):
        """Test that the high-level function automatically detects GitHub URLs."""
        # Setup all mocks directly within the test to avoid module import issues
        with patch.dict(sys.modules, {
            "github": MagicMock(),
            "github.Repository": MagicMock(),
            "github.Auth": MagicMock(),
            "git": MagicMock(),
        }):
            # Now import the code
            from skwaq.ingestion.code_ingestion import ingest_repository, RepositoryIngestor
            
            # Mock connector
            mock_connector = MagicMock()
            
            # Mock openai client
            mock_openai_client = MagicMock()
            
            # Mock RepositoryIngestor and its methods
            mock_ingestor = MagicMock()
            mock_ingestor.ingest_from_github = AsyncMock(return_value={
                "repository_id": 1,
                "repository_name": "test-repo",
                "content_ingested": False
            })
            
            # Create a mock logger to verify it was called
            mock_logger = MagicMock()
            
            # Patch components
            with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor", return_value=mock_ingestor):
                with patch("skwaq.ingestion.code_ingestion.logger", mock_logger):
                    # Test auto-detection
                    result = await ingest_repository(
                        repo_path_or_url="https://github.com/user/test-repo",
                        is_github_url=False,  # Not explicitly specified as GitHub
                        connector=mock_connector,
                        openai_client=mock_openai_client
                    )
                    
                    # Verify GitHub URL was auto-detected
                    mock_logger.info.assert_any_call("Automatically detected GitHub URL: https://github.com/user/test-repo")
                    
                    # Verify ingest_from_github was called
                    mock_ingestor.ingest_from_github.assert_called_once()
                    
                    # Verify result
                    assert result["repository_id"] == 1
                    assert result["repository_name"] == "test-repo"
                    assert result["content_ingested"] is False
                    
    async def test_list_repositories(self):
        """Test listing repositories."""
        # Mock the imports
        with patch.dict(sys.modules, {
            "github": MagicMock(),
            "github.Repository": MagicMock(),
            "github.Auth": MagicMock(),
            "git": MagicMock(),
        }):
            # Now import the function we need
            from skwaq.ingestion.code_ingestion import list_repositories
            
            # Mock connector
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
            
            # Test the function
            result = await list_repositories(connector=mock_connector)
            
            # Verify results
            assert len(result) == 2
            assert result[0]["name"] == "repo1"
            assert result[0]["id"] == 1
            assert result[1]["name"] == "repo2"
            assert result[1]["id"] == 2