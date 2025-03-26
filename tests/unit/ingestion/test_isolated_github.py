"""Isolated tests for GitHub integration."""

import os
import pytest
import tempfile
import sys
from unittest.mock import AsyncMock, MagicMock, patch
from pathlib import Path

import importlib
from copy import deepcopy

# Import everything in a safe way
@pytest.fixture
def setup_clean_imports():
    """Set up clean imports for isolated tests."""
    # Save the original state of imported modules
    original_modules = {}
    modules_to_save = [
        "skwaq.ingestion.code_ingestion",
        "skwaq.db.neo4j_connector",
        "skwaq.core.openai_client",
        "github",
        "github.Auth",
        "github.Repository",
        "git"
    ]
    
    for module_name in modules_to_save:
        if module_name in sys.modules:
            original_modules[module_name] = sys.modules[module_name]
    
    # Force reimport for clean tests
    for module_name in modules_to_save:
        if module_name in sys.modules:
            del sys.modules[module_name]
    
    # Create mock modules
    mock_modules = {
        "github": MagicMock(),
        "github.Auth": MagicMock(),
        "github.Repository": MagicMock(),
        "github.GithubException": type("GithubException", (Exception,), {}),
        "git": MagicMock(),
    }
    
    # Apply mock modules
    for mod_name, mock_mod in mock_modules.items():
        sys.modules[mod_name] = mock_mod
    
    # Set up GitHub mock functionality
    sys.modules["github"].Github = MagicMock()
    sys.modules["github"].Auth = MagicMock()
    sys.modules["github"].Auth.Token = MagicMock()
    
    # Yield control back to the test
    yield
    
    # Restore original modules after test completes
    for module_name, module in original_modules.items():
        sys.modules[module_name] = module
    
    # Remove any added modules
    for module_name in mock_modules:
        if module_name in sys.modules and module_name not in original_modules:
            del sys.modules[module_name]


@pytest.fixture
def mock_repository():
    """Create a mock GitHub repository object."""
    repo = MagicMock()
    repo.name = "test-repo"
    repo.full_name = "test-user/test-repo"
    repo.description = "Test repository for unit tests"
    repo.stargazers_count = 10
    repo.forks_count = 5
    repo.default_branch = "main"
    repo.size = 1024
    repo.private = False
    
    # Important: we need to return a real dict, not a MagicMock
    languages_dict = {"Python": 1000, "JavaScript": 500}
    repo.get_languages.return_value = languages_dict
    repo.clone_url = "https://github.com/test-user/test-repo.git"
    repo.ssh_url = "git@github.com:test-user/test-repo.git"
    repo.html_url = "https://github.com/test-user/test-repo"
    
    content_mock = MagicMock()
    content_mock.path = "test_file.py"
    content_mock.type = "file"
    content_mock.decoded_content = b"# Test content"
    repo.get_contents.return_value = [content_mock]
    
    return repo


@pytest.fixture
def mock_github_client(mock_repository):
    """Create a mock GitHub client object."""
    client = MagicMock()
    client.get_repo.return_value = mock_repository
    client.get_rate_limit.return_value = MagicMock()
    return client


@pytest.fixture
def patched_functions(setup_clean_imports, mock_github_client, mock_connector, mock_openai_client):
    """Patch all required functions for GitHub tests."""
    # Now safely import the modules we need
    from skwaq.ingestion.code_ingestion import get_github_repository_info, ingest_repository
    
    # Create a dictionary of patches that will be applied
    patches = {}
    
    # Create mock timestamp function
    timestamp_mock = MagicMock(return_value="2023-01-01T00:00:00")
    
    # Create all the patches
    patches["github"] = patch("github.Github", return_value=mock_github_client)
    patches["github_auth"] = patch("github.Auth.Token", return_value=MagicMock())
    patches["connector"] = patch("skwaq.ingestion.code_ingestion.get_connector", return_value=mock_connector)
    patches["openai"] = patch("skwaq.ingestion.code_ingestion.get_openai_client", return_value=mock_openai_client)
    patches["timestamp"] = patch("skwaq.ingestion.code_ingestion.RepositoryIngestor._get_timestamp", timestamp_mock)
    patches["path_exists"] = patch.object(Path, "exists", lambda self: True)
    
    # Start all patches
    for p in patches.values():
        p.start()
    
    # Return the imported, patched functions
    yield {
        "get_github_repository_info": get_github_repository_info,
        "ingest_repository": ingest_repository
    }
    
    # Stop all patches
    for p in patches.values():
        p.stop()


class TestIsolatedGitHubIntegration:
    """Tests for GitHub integration functionality in isolation."""

    @pytest.mark.asyncio
    async def test_ingest_from_github_metadata_only(self, setup_clean_imports, mock_connector, mock_openai_client):
        """Test GitHub repository metadata retrieval with a completely isolated approach."""
        # Fresh imports after clean setup
        from skwaq.ingestion.code_ingestion import get_github_repository_info, ingest_repository
        
        # Create expected results and mock functions
        expected_result = {
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
        
        # Create a MockRepositoryIngestor class with async methods
        class MockRepositoryIngestor:
            def __init__(self, github_token=None, connector=None, openai_client=None, **kwargs):
                self.github_token = github_token
                self.connector = connector
                self.openai_client = openai_client
                
            async def ingest_from_github(self, github_url, **kwargs):
                return expected_result
            
        # Patch the repository ingestor class
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor", MockRepositoryIngestor):
            # Call the function we're testing
            result = await get_github_repository_info(
                github_url="https://github.com/test-user/test-repo",
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify result structure and content
            assert result["repository_id"] == 1
            assert result["repository_name"] == "test-repo"
            assert result["content_ingested"] is False
            
            # Verify metadata fields
            assert result["metadata"]["name"] == "test-repo"
            assert result["metadata"]["owner"] == "test-user"
            assert result["metadata"]["stars"] == 10
            assert result["metadata"]["languages"] == {"Python": 1000, "JavaScript": 500}

    @pytest.mark.asyncio
    async def test_high_level_ingest(self, patched_functions, mock_github_client, mock_connector, mock_openai_client):
        """Test the high-level ingest_repository function with GitHub URL."""
        # Get the patched function
        ingest_repository = patched_functions["ingest_repository"]
        
        # Apply additional patches specific to this test
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor._init_github_client", return_value=mock_github_client), \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor.ingest_from_github") as mock_ingest_from_github:
            
            # Set up the expected result
            expected_result = {
                "repository_id": 1,
                "repository_name": "test-repo",
                "metadata": {
                    "name": "test-repo",
                    "full_name": "test-user/test-repo",
                    "description": "Test repository"
                },
                "content_ingested": False
            }
            
            # Mock ingest_from_github to return our expected result
            mock_ingest_from_github.return_value = expected_result
            
            # Call the function we're testing
            result = await ingest_repository(
                repo_path_or_url="https://github.com/test-user/test-repo",
                is_github_url=True,
                github_token="test_token",
                connector=mock_connector,
                openai_client=mock_openai_client,
                github_metadata_only=True
            )
            
            # Verify the result
            assert result["repository_id"] == 1
            assert result["repository_name"] == "test-repo"
            assert result["content_ingested"] is False
            
            # Verify ingest_from_github was called with correct parameters
            mock_ingest_from_github.assert_called_once()

    @pytest.mark.asyncio
    async def test_high_level_ingest_auto_detection(self, patched_functions, mock_github_client, mock_connector, mock_openai_client):
        """Test that the high-level function automatically detects GitHub URLs."""
        # Get the patched function
        ingest_repository = patched_functions["ingest_repository"]
        
        # Apply additional patches specific to this test
        with patch("skwaq.ingestion.code_ingestion.RepositoryIngestor._init_github_client", return_value=mock_github_client), \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor.ingest_from_github") as mock_ingest_from_github, \
             patch("skwaq.ingestion.code_ingestion.RepositoryIngestor.ingest_from_path") as mock_ingest_from_path, \
             patch("skwaq.ingestion.code_ingestion.logger") as mock_logger:
            
            # Set up the expected result
            expected_result = {
                "repository_id": 1,
                "repository_name": "test-repo",
                "metadata": {
                    "name": "test-repo",
                    "owner": "test-user",
                },
                "content_ingested": False
            }
            
            # Mock ingest_from_github to return our expected result
            mock_ingest_from_github.return_value = expected_result
            
            # Call the function with auto-detection
            result = await ingest_repository(
                repo_path_or_url="https://github.com/test-user/test-repo",
                is_github_url=False,  # Not explicitly specified as GitHub
                connector=mock_connector,
                openai_client=mock_openai_client
            )
            
            # Verify ingest_from_github was called
            mock_ingest_from_github.assert_called_once()
            
            # Verify ingest_from_path was not called
            mock_ingest_from_path.assert_not_called()

    @pytest.mark.asyncio
    async def test_list_repositories(self, setup_clean_imports):
        """Test listing available repositories."""
        # Create a fresh mock connector
        mock_connector = MagicMock()
        
        # Import the module after clean setup
        from skwaq.ingestion.code_ingestion import list_repositories
            
        # Mock the Neo4j query response
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
        
        # Call the function we're testing without path param
        repositories = await list_repositories(connector=mock_connector)
        
        # Verify the connector was called correctly
        mock_connector.run_query.assert_called_once()
        
        # Verify the results
        assert len(repositories) == 2
        
        # Check the contents of the repositories
        assert repositories[0]["name"] == "repo1"
        assert repositories[0]["id"] == 1
        assert repositories[0]["path"] == "/path/to/repo1"
        
        assert repositories[1]["name"] == "repo2"
        assert repositories[1]["id"] == 2
        assert repositories[1]["path"] == "/path/to/repo2"