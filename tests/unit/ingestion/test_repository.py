"""Tests for the repository module of the ingestion system."""

import os
import pytest
from unittest.mock import MagicMock, patch, mock_open
import tempfile
import git

from skwaq.ingestion.repository import RepositoryHandler, RepositoryManager
from skwaq.ingestion.exceptions import RepositoryError, DatabaseError
from skwaq.db.schema import NodeLabels


def test_repository_handler_init():
    """Test initializing a RepositoryHandler instance."""
    handler = RepositoryHandler()
    assert handler._temp_dirs == []


@pytest.mark.parametrize("branch", [None, "develop"])
def test_clone_repository(branch, monkeypatch):
    """Test cloning a repository with and without a branch specified."""
    handler = RepositoryHandler()
    
    # Use monkeypatch to avoid actual git commands
    mock_clone_from = MagicMock()
    monkeypatch.setattr(git.Repo, 'clone_from', mock_clone_from)
    
    # Use a real temporary directory to avoid mocking
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock only the tempfile.TemporaryDirectory to return our controlled directory
        mock_temp_dir_class = MagicMock()
        mock_temp_dir_instance = MagicMock()
        mock_temp_dir_instance.name = temp_dir
        mock_temp_dir_class.return_value = mock_temp_dir_instance
        monkeypatch.setattr('tempfile.TemporaryDirectory', mock_temp_dir_class)
        
        # Test cloning
        repo_url = "https://github.com/user/repo.git"
        path = handler.clone_repository(repo_url, branch)
        
        # Extract expected repo name from URL
        repo_name = "repo"  # Extracted from "repo.git"
        expected_path = os.path.join(temp_dir, repo_name)
        
        # Check result path
        assert path == expected_path
        
        # Check that temp directory was recorded
        assert temp_dir in handler._temp_dirs
        
        # Check git.Repo.clone_from was called with correct parameters
        expected_kwargs = {
            "url": repo_url,
            "to_path": expected_path,
            "progress": None,
        }
        
        if branch:
            expected_kwargs["branch"] = branch
            
        mock_clone_from.assert_called_once_with(**expected_kwargs)


def test_clone_repository_git_error(monkeypatch):
    """Test handling GitCommandError during repository cloning."""
    handler = RepositoryHandler()
    
    # Use a real temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock TemporaryDirectory to return a controlled instance
        mock_temp_dir_class = MagicMock()
        mock_temp_dir_instance = MagicMock()
        mock_temp_dir_instance.name = temp_dir
        mock_temp_dir_class.return_value = mock_temp_dir_instance
        monkeypatch.setattr('tempfile.TemporaryDirectory', mock_temp_dir_class)
        
        # Create a proper GitCommandError instance
        git_error = git.GitCommandError("git clone", 1, "Repository not found")
        
        # Make git.Repo.clone_from raise GitCommandError
        mock_clone_from = MagicMock(side_effect=git_error)
        monkeypatch.setattr(git.Repo, 'clone_from', mock_clone_from)
        
        # Test that RepositoryError is raised
        with pytest.raises(RepositoryError) as excinfo:
            handler.clone_repository("https://github.com/user/repo.git", "main")
        
        # Check error message and properties
        assert "Git error" in str(excinfo.value)
        assert excinfo.value.repo_url == "https://github.com/user/repo.git"
        assert excinfo.value.branch == "main"
        assert "git_error" in excinfo.value.details


def test_clone_repository_other_error(monkeypatch):
    """Test handling other errors during repository cloning."""
    handler = RepositoryHandler()
    
    # Use a real temporary directory
    with tempfile.TemporaryDirectory() as temp_dir:
        # Mock TemporaryDirectory to return a controlled instance
        mock_temp_dir_class = MagicMock()
        mock_temp_dir_instance = MagicMock()
        mock_temp_dir_instance.name = temp_dir
        mock_temp_dir_class.return_value = mock_temp_dir_instance
        monkeypatch.setattr('tempfile.TemporaryDirectory', mock_temp_dir_class)
        
        # Make git.Repo.clone_from raise a generic exception
        generic_error = Exception("Random error")
        mock_clone_from = MagicMock(side_effect=generic_error)
        monkeypatch.setattr(git.Repo, 'clone_from', mock_clone_from)
        
        # Test that RepositoryError is raised
        with pytest.raises(RepositoryError) as excinfo:
            handler.clone_repository("https://github.com/user/repo.git")
        
        # Check error message and properties
        assert "Failed to clone repository" in str(excinfo.value)
        assert excinfo.value.repo_url == "https://github.com/user/repo.git"
        assert excinfo.value.branch is None
        assert "error_type" in excinfo.value.details
        assert excinfo.value.details["error_type"] == "Exception"


def test_get_repository_metadata_with_git(monkeypatch):
    """Test extracting metadata from a Git repository."""
    handler = RepositoryHandler()
    
    # Create a mock repository
    mock_repo = MagicMock()
    
    # Configure active branch
    mock_branch = MagicMock()
    mock_branch.name = "main"
    mock_repo.active_branch = mock_branch
    
    # Configure head commit
    mock_commit = MagicMock()
    mock_commit.hexsha = "abc123"
    mock_author = MagicMock()
    mock_author.name = "Test User"
    mock_author.email = "test@example.com"
    mock_commit.author = mock_author
    mock_commit.committed_date = 1646834400  # 2022-03-09 12:00:00 UTC
    mock_commit.message = "Test commit message"
    
    mock_head = MagicMock()
    mock_head.commit = mock_commit
    mock_head.is_valid.return_value = True
    mock_repo.head = mock_head
    
    # Configure remotes
    mock_origin = MagicMock()
    mock_origin.url = "https://github.com/user/repo.git"
    mock_remotes = MagicMock()
    mock_remotes.origin = mock_origin
    mock_repo.remotes = mock_remotes
    
    # Mock git.Repo to return our prepared mock
    mock_repo_constructor = MagicMock(return_value=mock_repo)
    monkeypatch.setattr(git, 'Repo', mock_repo_constructor)
    
    # Test getting metadata
    metadata = handler.get_repository_metadata("/path/to/repo")
    
    # Check the metadata
    assert metadata["name"] == "repo"
    assert metadata["branch"] == "main"
    assert metadata["commit_hash"] == "abc123"
    assert "Test User" in metadata["commit_author"]
    assert "test@example.com" in metadata["commit_author"]
    assert "commit_date" in metadata
    assert metadata["commit_message"] == "Test commit message"
    assert metadata["remote_url"] == "https://github.com/user/repo.git"


def test_get_repository_metadata_no_git():
    """Test extracting metadata from a non-Git directory."""
    handler = RepositoryHandler()
    
    with patch("git.Repo", side_effect=git.InvalidGitRepositoryError):
        # Test getting metadata from a non-Git directory
        metadata = handler.get_repository_metadata("/path/to/repo")
        
        # Check that basic metadata is still available
        assert metadata["name"] == "repo"
        assert "ingestion_timestamp" in metadata
        
        # Check that Git-specific metadata is not available
        assert "commit_hash" not in metadata
        assert "branch" not in metadata


def test_get_repository_metadata_detached_head():
    """Test extracting metadata from a Git repository with a detached HEAD."""
    handler = RepositoryHandler()
    
    with patch("git.Repo") as mock_repo_cls:
        # Create a mock repository
        mock_repo = MagicMock()
        mock_repo_cls.return_value = mock_repo
        
        # Configure active branch to raise TypeError (detached HEAD)
        # This is tricky - we need to patch the property to raise an exception
        mock_active_branch = MagicMock()
        # Define a property that raises TypeError when accessed
        
        def name_property_raiser(self):
            raise TypeError("detached HEAD")
        
        # Apply the property to the mock
        type(mock_active_branch).__getattribute__ = MagicMock(side_effect=lambda x: 
                                                               name_property_raiser(None) if x == 'name' else MagicMock())
        
        mock_repo.active_branch = mock_active_branch
        
        # Configure head commit
        mock_commit = MagicMock()
        mock_commit.hexsha = "abc123"
        mock_head = MagicMock()
        mock_head.commit = mock_commit
        mock_head.is_valid.return_value = True
        mock_repo.head = mock_head
        
        # Test getting metadata
        metadata = handler.get_repository_metadata("/path/to/repo")
        
        # Check the branch is reported as detached
        assert metadata["branch"] == "HEAD detached"


def test_cleanup():
    """Test cleaning up temporary directories."""
    handler = RepositoryHandler()
    
    # Create a real temporary directory
    temp_dir = tempfile.mkdtemp()
    handler._temp_dirs.append(temp_dir)
    
    # Add a non-existent directory to test error handling
    handler._temp_dirs.append("/non/existent/dir")
    
    # Run cleanup
    with patch("shutil.rmtree") as mock_rmtree:
        handler.cleanup()
        
        # Check that rmtree was called for the real directory
        mock_rmtree.assert_called_with(temp_dir)
        
        # Check that _temp_dirs is empty
        assert handler._temp_dirs == []


def test_repository_manager():
    """Test the repository manager."""
    mock_connector = MagicMock()
    # Setup return values
    mock_connector.create_node.return_value = 123
    mock_connector.run_query.return_value = None
    
    manager = RepositoryManager(mock_connector)
    
    # Test creating a repository node
    node_id = manager.create_repository_node(
        ingestion_id="test-ingestion",
        codebase_path="/path/to/repo",
        repo_url="https://github.com/user/repo.git",
        metadata={"branch": "main", "commit_hash": "abc123"}
    )
    
    # Check the returned node ID
    assert node_id == 123
    
    # Check that create_node was called with the correct parameters
    mock_connector.create_node.assert_called_once()
    args, kwargs = mock_connector.create_node.call_args
    assert args[0] == NodeLabels.REPOSITORY
    assert kwargs["properties"]["ingestion_id"] == "test-ingestion"
    assert kwargs["properties"]["path"] == "/path/to/repo"
    assert kwargs["properties"]["url"] == "https://github.com/user/repo.git"
    assert kwargs["properties"]["branch"] == "main"
    assert kwargs["properties"]["commit_hash"] == "abc123"
    
    # Test error when create_node returns None
    mock_connector.create_node.return_value = None
    with pytest.raises(DatabaseError) as excinfo:
        manager.create_repository_node("test", "/path")
    assert "Failed to create repository node" in str(excinfo.value)
    assert "ingestion_id" in excinfo.value.details
    assert "codebase_path" in excinfo.value.details
    
    # Test exception during create_node
    mock_connector.create_node.side_effect = Exception("Database connection error")
    with pytest.raises(DatabaseError) as excinfo:
        manager.create_repository_node("test", "/path")
    assert "Database error while creating repository node" in str(excinfo.value)
    assert excinfo.value.db_error == "Database connection error"
    assert "error_type" in excinfo.value.details
    
    # Test updating status
    mock_connector.create_node.side_effect = None  # Reset side effect
    mock_connector.create_node.return_value = 123  # Reset return value
    manager.update_status(
        repo_node_id=123,
        status_data={"state": "completed", "progress": 100.0}
    )
    
    # Check that run_query was called with the correct parameters
    assert mock_connector.run_query.call_count >= 1
    args, kwargs = mock_connector.run_query.call_args
    assert "repo_id" in kwargs["params"]
    assert kwargs["params"]["repo_id"] == 123
    assert "status" in kwargs["params"]
    assert kwargs["params"]["status"]["state"] == "completed"
    assert kwargs["params"]["status"]["progress"] == 100.0
    assert "last_updated" in kwargs["params"]
    
    # Test exception during update_status
    mock_connector.run_query.side_effect = Exception("Query execution failed")
    with pytest.raises(DatabaseError) as excinfo:
        manager.update_status(456, {"state": "failed"})
    assert "Failed to update repository status" in str(excinfo.value)
    assert excinfo.value.db_error == "Query execution failed"
    assert "repo_node_id" in excinfo.value.details
    assert excinfo.value.details["repo_node_id"] == 456