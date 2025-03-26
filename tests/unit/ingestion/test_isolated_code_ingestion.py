"""Isolated tests for the code_ingestion module.

These tests use isolated instances of the RepositoryIngestor class to avoid
test interference with global mocking.

IMPORTANT: These tests should only be run directly, not as part of the full test suite.
Example: python -m pytest tests/unit/ingestion/test_isolated_code_ingestion.py -v
"""

import pytest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

from skwaq.ingestion.code_ingestion import RepositoryIngestor, ingest_repository


@pytest.fixture
def local_mock_connector():
    """Mock Neo4j connector specifically for code_ingestion tests."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []
    return connector


@pytest.fixture
def local_mock_openai_client():
    """Mock OpenAI client specifically for code_ingestion tests."""
    client = AsyncMock()
    client.get_completion.return_value = "Mock repository summary"
    return client


@pytest.mark.isolated
class TestIsolatedRepositoryIngestor:
    """Tests for the RepositoryIngestor class with isolation."""

    def test_initialization(self, local_mock_connector, local_mock_openai_client):
        """Test RepositoryIngestor initialization directly."""
        # Test the initialization using direct dependency injection
        ingestor = RepositoryIngestor(
            github_token="test_token", 
            max_workers=8, 
            progress_bar=False,
            connector=local_mock_connector,
            openai_client=local_mock_openai_client,
        )
        
        # Verify initialization
        assert ingestor.github_token == "test_token"
        assert ingestor.max_workers == 8
        assert ingestor.show_progress is False
        assert ingestor.temp_dir is None
        assert isinstance(ingestor.excluded_dirs, set)
        assert ".git" in ingestor.excluded_dirs
        assert "node_modules" in ingestor.excluded_dirs
        
        # Verify dependency injection worked correctly
        assert ingestor.connector is local_mock_connector
        assert ingestor.openai_client is local_mock_openai_client
        assert ingestor.github_client is None  # Should be initialized later

    def test_github_client_initialization(self, local_mock_connector, local_mock_openai_client):
        """Test GitHub client initialization directly."""
        # Use standard mocking approach
        with (
            patch("skwaq.ingestion.code_ingestion.Auth") as mock_auth,
            patch("skwaq.ingestion.code_ingestion.Github") as mock_github,
            patch("skwaq.ingestion.code_ingestion.logger") as mock_logger,
        ):
            # Set up Auth token and Github instance mocks
            mock_auth_token = MagicMock()
            mock_auth.Token.return_value = mock_auth_token
            
            mock_github_instance = MagicMock()
            mock_github.return_value = mock_github_instance
            mock_github_instance.get_rate_limit.return_value = MagicMock()
            
            # Create ingestor with explicit dependencies
            ingestor = RepositoryIngestor(
                github_token="test_token",
                connector=local_mock_connector,
                openai_client=local_mock_openai_client,
            )
            
            # Call the method
            client = ingestor._init_github_client()
            
            # Check that the auth was created with token
            mock_auth.Token.assert_called_once_with("test_token")
            
            # Check that the client was initialized
            mock_github.assert_called_once_with(auth=mock_auth_token)
            
            # Verify rate limit check
            mock_github_instance.get_rate_limit.assert_called_once()
            
            # Verify success logging occurred
            mock_logger.info.assert_called_with("Successfully authenticated with GitHub API")
            
            # Check that the client was returned
            assert client == mock_github_instance
            
            # Verify that github_client was stored in the ingestor
            assert ingestor.github_client == mock_github_instance
            
            # Test the caching behavior (subsequent calls should return the cached client)
            mock_github.reset_mock()
            mock_auth.Token.reset_mock()
            
            # Call the method again
            cached_client = ingestor._init_github_client()
            
            # Verify no new client was created
            mock_github.assert_not_called()
            mock_auth.Token.assert_not_called()
            
            # Verify the same client was returned
            assert cached_client == mock_github_instance


@pytest.mark.isolated
class TestIsolatedGitHubIntegration:
    """Tests for GitHub integration functionality with isolation."""

    @pytest.mark.asyncio
    async def test_ingest_from_github_metadata_only(self, local_mock_connector, local_mock_openai_client):
        """Test fetching GitHub repository metadata without cloning."""
        # Mock the necessary GitHub components
        with (
            patch("skwaq.ingestion.code_ingestion.Auth") as mock_auth,
            patch("skwaq.ingestion.code_ingestion.Github") as mock_github_class,
            patch("skwaq.ingestion.code_ingestion.logger") as mock_logger,
        ):
            # Mock Auth token
            mock_auth_token = MagicMock()
            mock_auth.Token.return_value = mock_auth_token
            
            # Mock GitHub instance and its rate_limit method
            mock_github = MagicMock()
            mock_github.get_rate_limit.return_value = MagicMock()
            mock_github_class.return_value = mock_github
            
            # Mock repo object with all necessary properties
            mock_repo = MagicMock()
            mock_repo.name = "test-repo"
            mock_repo.full_name = "user/test-repo"
            mock_repo.description = "Test repository"
            mock_repo.stargazers_count = 10
            mock_repo.forks_count = 5
            mock_repo.default_branch = "main"
            mock_repo.size = 1024
            mock_repo.private = False
            mock_repo.created_at = None
            mock_repo.updated_at = None
            mock_repo.clone_url = "https://github.com/user/test-repo.git"
            mock_repo.ssh_url = "git@github.com:user/test-repo.git"
            mock_repo.html_url = "https://github.com/user/test-repo"
            mock_repo.get_languages.return_value = {"Python": 1000, "JavaScript": 500}
            
            # Set up GitHub client to return our mock repo
            mock_github.get_repo.return_value = mock_repo
            
            # Create ingestor with mocked dependencies
            with patch.object(RepositoryIngestor, "_parse_github_url", return_value=("user", "test-repo")):
                ingestor = RepositoryIngestor(
                    github_token="test_token",
                    connector=local_mock_connector,
                    openai_client=local_mock_openai_client
                )
                
                # Mock the _get_github_repo_info method to return predefined data
                with patch.object(
                    RepositoryIngestor, 
                    "_get_github_repo_info", 
                    return_value={
                        "name": "test-repo",
                        "full_name": "user/test-repo",
                        "description": "Test repository",
                        "owner": "user",
                        "stars": 10,
                        "forks": 5,
                        "default_branch": "main",
                        "languages": {"Python": 1000, "JavaScript": 500},
                        "size": 1024,
                        "private": False,
                        "created_at": None,
                        "updated_at": None,
                        "clone_url": "https://github.com/user/test-repo.git",
                        "ssh_url": "git@github.com:user/test-repo.git",
                        "html_url": "https://github.com/user/test-repo"
                    }
                ):
                    # Call the method we're testing
                    result = await ingestor.ingest_from_github(
                        github_url="https://github.com/user/test-repo",
                        metadata_only=True,
                    )
                    
                    # Verify the result
                    assert result["repository_id"] == 1  # From mock_connector.create_node
                    assert result["repository_name"] == "test-repo"
                    assert result["content_ingested"] is False
                    assert "metadata" in result
                    
                    # Verify that expected properties were added to the Neo4j node
                    metadata = result["metadata"]
                    assert metadata["name"] == "test-repo"
                    assert metadata["full_name"] == "user/test-repo"
                    assert metadata["description"] == "Test repository"
                    assert metadata["stars"] == 10
                    assert metadata["owner"] == "user"
                    
                    # Verify that connector was used to create a node with the right labels
                    local_mock_connector.create_node.assert_called_once()
                    call_args = local_mock_connector.create_node.call_args
                    assert call_args[1]["labels"] == ["Repository", "GitHubRepository"]
                    
                    # Verify that no clone was attempted
                    assert ingestor.temp_dir is None
                    
                    # Verify logging
                    mock_logger.info.assert_any_call("Ingesting repository from GitHub URL: https://github.com/user/test-repo")
    
    @pytest.mark.asyncio
    async def test_high_level_ingest(self, local_mock_connector, local_mock_openai_client):
        """Test the high-level ingest_repository function with GitHub URL."""
        # Result to be returned by the ingestor
        expected_result = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "metadata": {
                "name": "test-repo",
                "full_name": "user/test-repo",
                "description": "Test repository"
            },
            "content_ingested": False
        }
        
        # Create an async method that returns the expected result
        async def mock_ingest_from_github(*args, **kwargs):
            return expected_result
        
        # Mock the isolated class
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class:
            # Set up the mock instance with async method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_github = mock_ingest_from_github
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the high-level function
            result = await ingest_repository(
                repo_path_or_url="https://github.com/user/test-repo",
                is_github_url=True,
                github_token="test_token",
                connector=local_mock_connector,
                openai_client=local_mock_openai_client,
                github_metadata_only=True
            )
            
            # Verify the ingestor was created correctly
            mock_ingestor_class.assert_called_once_with(
                github_token="test_token",
                max_workers=4,  # Default
                progress_bar=True,  # Default
                connector=local_mock_connector,
                openai_client=local_mock_openai_client
            )
            
            # Since we're using a real function and not a mock, we can't assert on calls
            # But we can verify the result
            assert result == expected_result
    
    @pytest.mark.asyncio
    async def test_high_level_ingest_auto_detection(self, local_mock_connector, local_mock_openai_client):
        """Test that the high-level function automatically detects GitHub URLs."""
        # Expected result
        expected_result = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "content_ingested": False
        }
        
        # Create an async method that returns the expected result
        async def mock_ingest_from_github(*args, **kwargs):
            return expected_result
        
        # Mock the ingest_repository function, isolated class, and logger
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor") as mock_ingestor_class, \
             patch("skwaq.ingestion.code_ingestion.logger") as mock_logger:
            
            # Set up the mock instance with async method
            mock_ingestor_instance = MagicMock()
            mock_ingestor_instance.ingest_from_github = mock_ingest_from_github
            mock_ingestor_class.return_value = mock_ingestor_instance
            
            # Call the function with auto-detection
            result = await ingest_repository(
                repo_path_or_url="https://github.com/user/test-repo",
                is_github_url=False,  # Not explicitly specified as GitHub
                connector=local_mock_connector,
                openai_client=local_mock_openai_client
            )
            
            # Verify URL was auto-detected
            mock_logger.info.assert_any_call("Automatically detected GitHub URL: https://github.com/user/test-repo")
            
            # Since we're using a real function and not a mock, we can't assert on calls
            # But we can verify the result
            assert result == expected_result