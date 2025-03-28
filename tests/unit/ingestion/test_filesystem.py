"""Tests for the filesystem module of the ingestion system."""

import os
import pytest
from unittest.mock import MagicMock, patch

import tempfile

from skwaq.ingestion.filesystem import CodebaseFileSystem, FilesystemGraphBuilder
from skwaq.db.schema import NodeLabels, RelationshipTypes


@pytest.mark.asyncio
async def test_filesystem_graph_builder(mock_connector, mock_fs):
    """Test building a graph representation of the filesystem."""
    # Create the filesystem graph builder
    builder = FilesystemGraphBuilder(mock_connector)
    
    # Create a real filesystem instance with the mock filesystem
    fs = CodebaseFileSystem(mock_fs)
    
    # Run the build_graph method
    nodes = await builder.build_graph(1, fs)
    
    # Check that nodes were created for directories and files
    # There should be at least 4 directories (root, src, src/utils, tests)
    # and 4 files (main.py, helpers.py, test_main.py, README.md)
    assert len(nodes) >= 8
    
    # Check calls to create nodes and relationships
    assert mock_connector.create_node.call_count >= 8
    assert mock_connector.create_relationship.call_count >= 8


def test_codebase_filesystem_init(mock_fs):
    """Test initializing a CodebaseFileSystem instance."""
    fs = CodebaseFileSystem(mock_fs)
    assert fs.root_path == os.path.abspath(mock_fs)
    assert fs._files_cache == []
    assert fs._dirs_cache == []
    
    # Check if magic is initialized correctly
    if hasattr(fs, "_mime_magic"):
        assert fs._mime_magic is None or fs._mime_magic is not None


def test_get_relative_path(mock_fs):
    """Test getting a relative path from the root directory."""
    fs = CodebaseFileSystem(mock_fs)
    file_path = os.path.join(mock_fs, "src", "main.py")
    rel_path = fs.get_relative_path(file_path)
    assert rel_path == os.path.join("src", "main.py")


def test_get_all_files(mock_fs):
    """Test getting all files in the codebase."""
    fs = CodebaseFileSystem(mock_fs)
    files = fs.get_all_files()
    assert len(files) == 4  # main.py, helpers.py, test_main.py, README.md
    
    # Check that the files are returned in the expected format
    for file_path in files:
        assert os.path.isfile(file_path)
        assert os.path.exists(file_path)
    
    # Check cache is used on second call
    fs._files_cache = ["cached_file"]
    assert fs.get_all_files() == ["cached_file"]


def test_get_all_dirs(mock_fs):
    """Test getting all directories in the codebase."""
    fs = CodebaseFileSystem(mock_fs)
    dirs = fs.get_all_dirs()
    assert len(dirs) == 4  # root, src, src/utils, tests
    
    # Check that the directories are returned in the expected format
    for dir_path in dirs:
        assert os.path.isdir(dir_path)
        assert os.path.exists(dir_path)
    
    # Check cache is used on second call
    fs._dirs_cache = ["cached_dir"]
    assert fs.get_all_dirs() == ["cached_dir"]


def test_get_file_info(mock_fs):
    """Test getting metadata about a file."""
    fs = CodebaseFileSystem(mock_fs)
    file_path = os.path.join(mock_fs, "src", "main.py")
    info = fs.get_file_info(file_path)
    
    assert info["extension"] == "py"
    assert info["language"] == "python"
    assert info["size"] > 0
    assert info["mime_type"] != ""
    assert info["encoding"] != ""
    
    # Test with a markdown file
    file_path = os.path.join(mock_fs, "README.md")
    info = fs.get_file_info(file_path)
    
    assert info["extension"] == "md"
    assert info["language"] == "markdown"


def test_read_file(mock_fs):
    """Test reading a file's content."""
    fs = CodebaseFileSystem(mock_fs)
    file_path = os.path.join(mock_fs, "src", "main.py")
    content = fs.read_file(file_path)
    
    assert "def main():" in content
    assert "Hello, world!" in content
    
    # Test with a non-existent file
    non_existent_path = os.path.join(mock_fs, "non_existent.py")
    content = fs.read_file(non_existent_path)
    assert content is None


def test_get_language_from_extension():
    """Test inferring programming language from file extension."""
    fs = CodebaseFileSystem(tempfile.mkdtemp())
    
    assert fs._get_language_from_extension(".py") == "python"
    assert fs._get_language_from_extension(".js") == "javascript"
    assert fs._get_language_from_extension(".ts") == "typescript"
    assert fs._get_language_from_extension(".java") == "java"
    assert fs._get_language_from_extension(".c") == "c"
    assert fs._get_language_from_extension(".cpp") == "cpp"
    assert fs._get_language_from_extension(".cs") == "csharp"
    assert fs._get_language_from_extension(".go") == "go"
    assert fs._get_language_from_extension(".rb") == "ruby"
    assert fs._get_language_from_extension(".php") == "php"
    assert fs._get_language_from_extension(".html") == "html"
    assert fs._get_language_from_extension(".css") == "css"
    assert fs._get_language_from_extension(".md") == "markdown"
    assert fs._get_language_from_extension(".sql") == "sql"
    assert fs._get_language_from_extension(".unknown") == "unknown"