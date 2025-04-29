"""Tests for the AST to filesystem mapper module."""


import pytest

from skwaq.db.schema import RelationshipTypes
from skwaq.ingestion.ast_mapper import ASTFileMapper


@pytest.mark.asyncio
async def test_map_ast_to_files(mock_connector):
    """Test mapping AST nodes to file nodes."""
    # Create test data
    repo_node_id = 1
    file_paths = {
        "/path/to/repo/src/main.py": 10,
        "/path/to/repo/src/utils/helpers.py": 11,
        "/path/to/repo/tests/test_main.py": 12,
    }

    # Set up mock query result
    mock_connector.run_query.return_value = [
        {"node_id": 100, "file_path": "src/main.py"},
        {"node_id": 101, "file_path": "src/utils/helpers.py"},
        {"node_id": 102, "file_path": "tests/test_main.py"},
        {"node_id": 103, "file_path": "unknown_file.py"},  # This one won't match
    ]

    # Create the mapper
    mapper = ASTFileMapper(mock_connector)

    # Call the mapping function
    result = await mapper.map_ast_to_files(repo_node_id, file_paths)

    # Check the result
    assert result["ast_nodes_found"] == 4
    assert result["mapped_nodes"] > 0
    assert result["unmapped_nodes"] > 0

    # At least 3 relationships should have been created
    assert mock_connector.create_relationship.call_count >= 3

    # Check that the correct relationship type was used
    for call_args in mock_connector.create_relationship.call_args_list:
        args, kwargs = call_args
        assert args[2] == RelationshipTypes.DEFINES


@pytest.mark.asyncio
async def test_map_ast_to_files_with_normalization(mock_connector):
    """Test mapping AST nodes to file nodes with path normalization."""
    # Create test data
    repo_node_id = 1
    file_paths = {
        "/path/to/repo/src/main.py": 10,
    }

    # Set up mock query results with different path formats
    mock_connector.run_query.return_value = [
        {"node_id": 100, "file_path": "src/main.py"},  # Relative path
        {"node_id": 101, "file_path": "/path/to/repo/src/main.py"},  # Absolute path
        {"node_id": 102, "file_path": "src\\main.py"},  # Windows-style path
        {"node_id": 103, "file_path": "main.py"},  # Just filename
    ]

    # Create the mapper
    mapper = ASTFileMapper(mock_connector)

    # Call the mapping function
    result = await mapper.map_ast_to_files(repo_node_id, file_paths)

    # Check the result - all nodes should be mapped
    assert result["ast_nodes_found"] == 4
    assert result["mapped_nodes"] > 0

    # At least 4 relationships should have been created
    assert mock_connector.create_relationship.call_count > 0


@pytest.mark.asyncio
async def test_map_ast_to_files_no_nodes(mock_connector):
    """Test mapping when no AST nodes are found."""
    # Create test data
    repo_node_id = 1
    file_paths = {
        "/path/to/repo/src/main.py": 10,
    }

    # Set up mock query result with no nodes
    mock_connector.run_query.return_value = []

    # Create the mapper
    mapper = ASTFileMapper(mock_connector)

    # Call the mapping function
    result = await mapper.map_ast_to_files(repo_node_id, file_paths)

    # Check the result
    assert result["ast_nodes_found"] == 0
    assert result["mapped_nodes"] == 0
    assert result["unmapped_nodes"] == 0

    # No relationships should have been created
    assert mock_connector.create_relationship.call_count == 0


@pytest.mark.asyncio
async def test_map_ast_to_files_relationship_failure(mock_connector):
    """Test mapping when creating relationships fails."""
    # Create test data
    repo_node_id = 1
    file_paths = {
        "/path/to/repo/src/main.py": 10,
    }

    # Set up mock query result
    mock_connector.run_query.return_value = [
        {"node_id": 100, "file_path": "src/main.py"},
    ]

    # Make relationship creation fail
    mock_connector.create_relationship.return_value = False

    # Create the mapper
    mapper = ASTFileMapper(mock_connector)

    # Call the mapping function
    result = await mapper.map_ast_to_files(repo_node_id, file_paths)

    # Check the result
    assert result["ast_nodes_found"] == 1
    assert result["mapped_nodes"] == 0  # No mappings should have succeeded
    assert result["unmapped_nodes"] == 1  # All nodes should be unmapped

    # Relationship creation should have been attempted
    assert mock_connector.create_relationship.call_count > 0
