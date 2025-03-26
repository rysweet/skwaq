"""Unit tests for the code_ingestion module."""

import os
import pytest
import tempfile
import shutil
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch, PropertyMock

from skwaq.ingestion.code_ingestion import RepositoryIngestor


@pytest.fixture
def mock_connector():
    """Mock Neo4j connector."""
    connector = MagicMock()
    connector.create_node.return_value = 1  # Return a fake node ID
    connector.create_relationship.return_value = True
    connector.run_query.return_value = []
    
    with patch("skwaq.ingestion.code_ingestion.get_connector", return_value=connector):
        yield connector


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client."""
    client = AsyncMock()
    client.get_completion.return_value = "Mock repository summary"
    
    with patch("skwaq.ingestion.code_ingestion.get_openai_client", return_value=client):
        yield client


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


class TestRepositoryIngestor:
    """Tests for the RepositoryIngestor class."""

    def test_initialization(self):
        """Test RepositoryIngestor initialization."""
        ingestor = RepositoryIngestor(github_token="test_token", max_workers=8, progress_bar=False)
        
        assert ingestor.github_token == "test_token"
        assert ingestor.max_workers == 8
        assert ingestor.show_progress is False
        assert ingestor.temp_dir is None
        assert isinstance(ingestor.excluded_dirs, set)
        assert ".git" in ingestor.excluded_dirs
        assert "node_modules" in ingestor.excluded_dirs

    def test_github_client_initialization(self):
        """Test GitHub client initialization."""
        with patch("skwaq.ingestion.code_ingestion.Github") as mock_github:
            mock_github_instance = MagicMock()
            mock_github.return_value = mock_github_instance
            
            ingestor = RepositoryIngestor(github_token="test_token")
            
            # Call the method
            client = ingestor._init_github_client()
            
            # Check that the client was initialized with the token
            mock_github.assert_called_once()
            assert client == mock_github_instance

    def test_parse_github_url(self):
        """Test parsing GitHub URLs."""
        ingestor = RepositoryIngestor()
        
        # Test standard URL
        owner, repo = ingestor._parse_github_url("https://github.com/user/repo")
        assert owner == "user"
        assert repo == "repo"
        
        # Test URL with .git suffix
        owner, repo = ingestor._parse_github_url("https://github.com/user/repo.git")
        assert owner == "user"
        assert repo == "repo"
        
        # Test URL with trailing slash
        owner, repo = ingestor._parse_github_url("https://github.com/user/repo/")
        assert owner == "user"
        assert repo == "repo"
        
        # Test invalid URL
        with pytest.raises(ValueError):
            ingestor._parse_github_url("https://example.com/user/repo")

    def test_is_code_file(self):
        """Test code file detection."""
        ingestor = RepositoryIngestor()
        
        # Test code files
        assert ingestor._is_code_file(Path("test.py")) is True
        assert ingestor._is_code_file(Path("test.js")) is True
        assert ingestor._is_code_file(Path("test.java")) is True
        assert ingestor._is_code_file(Path("test.c")) is True
        
        # Test non-code files
        assert ingestor._is_code_file(Path("test.txt")) is False
        assert ingestor._is_code_file(Path("test.pdf")) is False
        assert ingestor._is_code_file(Path("test.png")) is False

    def test_detect_language(self):
        """Test language detection."""
        ingestor = RepositoryIngestor()
        
        # Test language detection
        assert ingestor._detect_language(Path("test.py")) == "Python"
        assert ingestor._detect_language(Path("test.js")) == "JavaScript"
        assert ingestor._detect_language(Path("test.java")) == "Java"
        assert ingestor._detect_language(Path("test.c")) == "C"
        
        # Test unknown extension
        assert ingestor._detect_language(Path("test.unknown")) is None

    def test_get_timestamp(self):
        """Test timestamp generation."""
        ingestor = RepositoryIngestor()
        
        # Test that the timestamp is a string in ISO format
        timestamp = ingestor._get_timestamp()
        assert isinstance(timestamp, str)
        
        # Basic format check (not exhaustive)
        assert "T" in timestamp  # ISO 8601 separator
        assert ":" in timestamp  # Time separator

    @pytest.mark.asyncio
    async def test_generate_repo_summary(self, mock_openai_client):
        """Test repository summary generation."""
        ingestor = RepositoryIngestor()
        ingestor.openai_client = mock_openai_client
        
        # Create a temporary directory
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create a test file
            Path(temp_dir, "test.py").write_text("print('Hello, world!')")
            
            # Generate summary
            summary = await ingestor._generate_repo_summary(temp_dir, "test-repo")
            
            # Verify that OpenAI was called
            mock_openai_client.get_completion.assert_called_once()
            
            # Verify the summary
            assert summary == "Mock repository summary"

    @pytest.mark.asyncio
    async def test_ingest_from_path_basic(self, test_repo_path, mock_connector, mock_openai_client):
        """Test basic repository ingestion from path."""
        # Initialize with mocked dependencies
        ingestor = RepositoryIngestor()
        ingestor.connector = mock_connector
        ingestor.openai_client = mock_openai_client
        
        # Process repository
        result = await ingestor.ingest_from_path(test_repo_path)
        
        # Verify results
        assert result["repository_name"] == Path(test_repo_path).name
        assert "file_count" in result
        assert "directory_count" in result
        assert "code_files_processed" in result
        assert "summary" in result
        
        # Verify connector calls
        assert mock_connector.create_node.call_count > 0
        assert mock_connector.create_relationship.call_count > 0
        
        # Verify OpenAI client call for summary generation
        mock_openai_client.get_completion.assert_called()


@pytest.mark.asyncio
class TestGitHubIntegration:
    """Tests for GitHub integration functionality."""
    
    async def test_github_repository_info(self, mock_connector):
        """Test fetching GitHub repository information."""
        # Mock GitHub API responses
        with patch("skwaq.ingestion.code_ingestion.Github") as mock_github:
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
            mock_github.return_value = mock_github_instance
            
            # Initialize the ingestor with mocks
            ingestor = RepositoryIngestor(github_token="test_token")
            ingestor.connector = mock_connector
            
            # Get repository info
            repo_info = await ingestor._get_github_repo_info("user", "test-repo")
            
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

    async def test_ingest_from_github_metadata_only(self, mock_connector):
        """Test fetching GitHub repository metadata without cloning."""
        # Mock GitHub API and clone operations
        with patch("skwaq.ingestion.code_ingestion.Github") as mock_github, \
             patch("git.Repo.clone_from") as mock_clone:
            
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
            mock_github.return_value = mock_github_instance
            
            # Initialize the ingestor with mocks
            ingestor = RepositoryIngestor(github_token="test_token")
            ingestor.connector = mock_connector
            
            # Ingest from GitHub (metadata only)
            result = await ingestor.ingest_from_github(
                "https://github.com/user/test-repo",
                metadata_only=True
            )
            
            # Verify the GitHub client was used properly
            mock_github_instance.get_repo.assert_called_once_with("user/test-repo")
            
            # Verify that clone was not called
            mock_clone.assert_not_called()
            
            # Verify the result
            assert result["repository_name"] == "test-repo"
            assert "metadata" in result
            assert result["content_ingested"] is False
            assert result["repository_id"] is not None