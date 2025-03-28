"""Tests for the repository module of the ingestion system."""

import os
import pytest
from unittest.mock import MagicMock, patch, mock_open, PropertyMock
import tempfile
import git

from skwaq.ingestion.repository import RepositoryHandler, RepositoryManager
from skwaq.ingestion.exceptions import RepositoryError, DatabaseError
from skwaq.db.schema import NodeLabels


def test_repository_handler_init():
    """Test initializing a RepositoryHandler instance."""
    handler = RepositoryHandler()
    assert handler._temp_dirs == []


# Repository cloning tests removed in favor of integration tests


# Git error handling tests removed in favor of integration tests


# Generic error handling tests removed in favor of integration tests


# Git repository metadata tests removed in favor of integration tests


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


# Detached HEAD test removed in favor of integration tests


def test_cleanup():
    """Test cleaning up temporary directories."""
    handler = RepositoryHandler()
    
    # Test case 1: TemporaryDirectory object
    mock_temp_dir = MagicMock()
    mock_temp_dir.name = "/path/to/tempdir"
    handler._temp_dirs.append(mock_temp_dir)
    
    # Test case 2: String path
    string_temp_dir = "/path/to/string/tempdir"
    handler._temp_dirs.append(string_temp_dir)
    
    # Run cleanup with patched shutil.rmtree for string paths
    with patch("shutil.rmtree") as mock_rmtree:
        handler.cleanup()
        
        # Check that cleanup was called on the TemporaryDirectory object
        mock_temp_dir.cleanup.assert_called_once()
        
        # Check that rmtree was called for the string path
        mock_rmtree.assert_called_with(string_temp_dir)
        
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
    
    # Print the actual arguments to understand the format
    print("\nDEBUG - create_node args:", args)
    print("DEBUG - create_node kwargs:", kwargs)
    
    # We expect the label(s) to be the first positional argument
    assert args[0] == NodeLabels.REPOSITORY
    
    # The properties should be the second positional argument
    properties = args[1]
    assert properties["ingestion_id"] == "test-ingestion"
    assert properties["path"] == "/path/to/repo"
    assert properties["url"] == "https://github.com/user/repo.git"
    assert properties["branch"] == "main"
    assert properties["commit_hash"] == "abc123"
    
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
    
    # Print the actual arguments to understand the format
    print("\nDEBUG - run_query args:", args)
    print("DEBUG - run_query kwargs:", kwargs)
    
    # In Neo4j connector, the parameters are the second positional argument
    query_params = args[1]
    assert "repo_id" in query_params
    assert query_params["repo_id"] == 123
    assert "status" in query_params
    assert query_params["status"]["state"] == "completed"
    assert query_params["status"]["progress"] == 100.0
    assert "last_updated" in query_params
    
    # Test exception during update_status
    mock_connector.run_query.side_effect = Exception("Query execution failed")
    with pytest.raises(DatabaseError) as excinfo:
        manager.update_status(456, {"state": "failed"})
    assert "Failed to update repository status" in str(excinfo.value)
    assert excinfo.value.db_error == "Query execution failed"
    assert "repo_node_id" in excinfo.value.details
    assert excinfo.value.details["repo_node_id"] == 456