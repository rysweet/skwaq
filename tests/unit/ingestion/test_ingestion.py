"""Tests for the main ingestion module."""

import asyncio
import os
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import uuid
import time

from skwaq.ingestion.ingestion import Ingestion, IngestionStatus
from skwaq.ingestion.filesystem import CodebaseFileSystem, FilesystemGraphBuilder
from skwaq.ingestion.repository import RepositoryHandler, RepositoryManager
from skwaq.ingestion.ast_mapper import ASTFileMapper
from skwaq.ingestion.documentation import DocumentationProcessor


def test_ingestion_init():
    """Test initializing an Ingestion instance."""
    # Test with local path
    ingestion = Ingestion(local_path="/path/to/local")
    assert ingestion.local_path == "/path/to/local"
    assert ingestion.repo is None
    assert ingestion.branch is None
    assert ingestion.model_client is None
    
    # Test with repo URL
    ingestion = Ingestion(repo="https://github.com/user/repo.git", branch="main")
    assert ingestion.local_path is None
    assert ingestion.repo == "https://github.com/user/repo.git"
    assert ingestion.branch == "main"
    
    # Test with additional parameters
    model_client = MagicMock()
    ingestion = Ingestion(
        local_path="/path/to/local",
        model_client=model_client,
        max_parallel=5,
        doc_path="/path/to/docs",
        doc_uri="https://example.com/docs",
        context_token_limit=30000,
        parse_only=True,
    )
    assert ingestion.model_client is model_client
    assert ingestion.max_parallel == 5
    assert ingestion.doc_path == "/path/to/docs"
    assert ingestion.doc_uri == "https://example.com/docs"
    assert ingestion.context_token_limit == 30000
    assert ingestion.parse_only is True
    
    # Test with invalid input (neither local_path nor repo)
    with pytest.raises(ValueError) as excinfo:
        Ingestion()
    assert "Either local_path or repo must be provided" in str(excinfo.value)
    
    # Test with invalid input (both local_path and repo)
    with pytest.raises(ValueError) as excinfo:
        Ingestion(local_path="/path/to/local", repo="https://github.com/user/repo.git")
    assert "Only one of local_path or repo can be provided" in str(excinfo.value)


@pytest.mark.asyncio
async def test_ingest():
    """Test the ingest method."""
    # Create a mock UUID to use for testing
    test_uuid = "12345678-1234-5678-1234-567812345678"
    
    with patch("uuid.uuid4", return_value=uuid.UUID(test_uuid)):
        ingestion = Ingestion(local_path="/path/to/local")
        
        # Mock _run_ingestion to prevent it from running
        with patch.object(ingestion, "_run_ingestion", AsyncMock()) as mock_run:
            # Call ingest
            ingestion_id = await ingestion.ingest()
            
            # Check the returned ID
            assert ingestion_id == test_uuid
            
            # Check that the status was created
            assert ingestion_id in ingestion._active_ingestions
            assert ingestion._active_ingestions[ingestion_id].id == test_uuid
            assert ingestion._active_ingestions[ingestion_id].state == "initializing"
            
            # Check that _run_ingestion was called with the correct ID
            mock_run.assert_called_once_with(test_uuid)


@pytest.mark.asyncio
async def test_get_status():
    """Test the get_status method."""
    ingestion = Ingestion(local_path="/path/to/local")
    
    # Create a test status
    test_id = "test-id"
    test_status = IngestionStatus(id=test_id, state="processing", progress=50.0)
    ingestion._active_ingestions[test_id] = test_status
    
    # Test getting an active status
    status = await ingestion.get_status(test_id)
    assert status is test_status
    assert status.id == test_id
    assert status.state == "processing"
    assert status.progress == 50.0
    
    # Test getting a non-existent status
    with patch.object(ingestion, "_load_status_from_db", return_value=None):
        with pytest.raises(ValueError) as excinfo:
            await ingestion.get_status("non-existent-id")
        assert "Ingestion ID not found" in str(excinfo.value)
    
    # Test getting a status from the database
    db_status = {
        "state": "completed",
        "progress": 100.0,
        "start_time": 1000.0,
        "end_time": 2000.0,
        "error": None,
        "files_processed": 10,
        "total_files": 10,
        "errors": [],
        "message": "Completed successfully",
    }
    with patch.object(ingestion, "_load_status_from_db", return_value=db_status):
        status = await ingestion.get_status("db-id")
        assert status.id == "db-id"
        assert status.state == "completed"
        assert status.progress == 100.0
        assert status.start_time == 1000.0
        assert status.end_time == 2000.0
        assert status.files_processed == 10
        assert status.total_files == 10


@pytest.mark.asyncio
async def test_run_ingestion_local_path(
    mock_repo_handler, mock_repo_manager, mock_connector, mock_filesystem,
    mock_parser, mock_summarizer, mock_ast_mapper, mock_async_model_client
):
    """Test running ingestion with a local path."""
    # Create an Ingestion instance with the necessary mocks
    ingestion = Ingestion(local_path="/path/to/local", model_client=mock_async_model_client)
    
    # Replace real components with mocks
    ingestion.repo_handler = mock_repo_handler
    ingestion.repo_manager = mock_repo_manager
    ingestion.db_connector = mock_connector
    
    # Mock other components that would be created
    with patch("skwaq.ingestion.ingestion.CodebaseFileSystem", return_value=mock_filesystem), \
         patch("skwaq.ingestion.ingestion.FilesystemGraphBuilder") as mock_fs_builder_cls, \
         patch("skwaq.ingestion.ingestion.get_parser", return_value=mock_parser), \
         patch("skwaq.ingestion.ingestion.get_summarizer", return_value=mock_summarizer), \
         patch("skwaq.ingestion.ingestion.ASTFileMapper", return_value=mock_ast_mapper), \
         patch("skwaq.ingestion.ingestion.DocumentationProcessor") as mock_doc_processor_cls:
        
        # Setup mock filesystem graph builder
        mock_fs_builder = MagicMock()
        mock_fs_builder.build_graph = AsyncMock(return_value={"file1.py": 1, "file2.py": 2})
        mock_fs_builder_cls.return_value = mock_fs_builder
        
        # Setup mock documentation processor
        mock_doc_processor = MagicMock()
        mock_doc_processor.process_local_docs = AsyncMock(return_value={"files_processed": 2})
        mock_doc_processor.process_remote_docs = AsyncMock(return_value={"files_processed": 1})
        mock_doc_processor_cls.return_value = mock_doc_processor
        
        # Setup ingestion status
        test_id = "test-ingestion-id"
        status = IngestionStatus(id=test_id)
        ingestion._active_ingestions[test_id] = status
        
        # Run the ingestion process
        await ingestion._run_ingestion(test_id)
        
        # Check that the status was updated correctly
        assert status.state == "completed"
        assert status.progress == 100.0
        assert status.end_time is not None
        
        # Verify that the correct components were used
        mock_fs_builder.build_graph.assert_called_once()
        mock_parser.parse.assert_called_once()
        mock_ast_mapper.map_ast_to_files.assert_called_once()
        mock_summarizer.configure.assert_called_once()
        mock_summarizer.summarize_files.assert_called_once()
        mock_repo_manager.update_status.assert_called()


@pytest.mark.asyncio
async def test_run_ingestion_git_repo(
    mock_repo_handler, mock_repo_manager, mock_connector, mock_filesystem,
    mock_parser, mock_summarizer, mock_ast_mapper, mock_async_model_client
):
    """Test running ingestion with a Git repository."""
    # Create an Ingestion instance with the necessary mocks
    ingestion = Ingestion(
        repo="https://github.com/user/repo.git",
        branch="main",
        model_client=mock_async_model_client
    )
    
    # Replace real components with mocks
    ingestion.repo_handler = mock_repo_handler
    ingestion.repo_manager = mock_repo_manager
    ingestion.db_connector = mock_connector
    
    # Mock other components that would be created
    with patch("skwaq.ingestion.ingestion.CodebaseFileSystem", return_value=mock_filesystem), \
         patch("skwaq.ingestion.ingestion.FilesystemGraphBuilder") as mock_fs_builder_cls, \
         patch("skwaq.ingestion.ingestion.get_parser", return_value=mock_parser), \
         patch("skwaq.ingestion.ingestion.get_summarizer", return_value=mock_summarizer), \
         patch("skwaq.ingestion.ingestion.ASTFileMapper", return_value=mock_ast_mapper), \
         patch("skwaq.ingestion.ingestion.DocumentationProcessor") as mock_doc_processor_cls:
        
        # Setup mock filesystem graph builder
        mock_fs_builder = MagicMock()
        mock_fs_builder.build_graph = AsyncMock(return_value={"file1.py": 1, "file2.py": 2})
        mock_fs_builder_cls.return_value = mock_fs_builder
        
        # Setup mock documentation processor
        mock_doc_processor = MagicMock()
        mock_doc_processor.process_local_docs = AsyncMock(return_value={"files_processed": 2})
        mock_doc_processor.process_remote_docs = AsyncMock(return_value={"files_processed": 1})
        mock_doc_processor_cls.return_value = mock_doc_processor
        
        # Setup ingestion status
        test_id = "test-ingestion-id"
        status = IngestionStatus(id=test_id)
        ingestion._active_ingestions[test_id] = status
        
        # Run the ingestion process
        await ingestion._run_ingestion(test_id)
        
        # Check that the status was updated correctly
        assert status.state == "completed"
        assert status.progress == 100.0
        assert status.end_time is not None
        
        # Verify that the repository was cloned
        mock_repo_handler.clone_repository.assert_called_once_with(
            "https://github.com/user/repo.git", "main"
        )
        
        # Verify that the correct components were used
        mock_fs_builder.build_graph.assert_called_once()
        mock_parser.parse.assert_called_once()
        mock_ast_mapper.map_ast_to_files.assert_called_once()
        mock_summarizer.configure.assert_called_once()
        mock_summarizer.summarize_files.assert_called_once()
        mock_repo_manager.update_status.assert_called()


@pytest.mark.asyncio
async def test_run_ingestion_with_documentation(
    mock_repo_handler, mock_repo_manager, mock_connector, mock_filesystem,
    mock_parser, mock_summarizer, mock_ast_mapper, mock_async_model_client
):
    """Test running ingestion with documentation."""
    # Create an Ingestion instance with the necessary mocks
    ingestion = Ingestion(
        local_path="/path/to/local",
        model_client=mock_async_model_client,
        doc_path="/path/to/docs",
        doc_uri="https://example.com/docs"
    )
    
    # Replace real components with mocks
    ingestion.repo_handler = mock_repo_handler
    ingestion.repo_manager = mock_repo_manager
    ingestion.db_connector = mock_connector
    
    # Mock other components that would be created
    with patch("skwaq.ingestion.ingestion.CodebaseFileSystem", return_value=mock_filesystem), \
         patch("skwaq.ingestion.ingestion.FilesystemGraphBuilder") as mock_fs_builder_cls, \
         patch("skwaq.ingestion.ingestion.get_parser", return_value=mock_parser), \
         patch("skwaq.ingestion.ingestion.get_summarizer", return_value=mock_summarizer), \
         patch("skwaq.ingestion.ingestion.ASTFileMapper", return_value=mock_ast_mapper), \
         patch("skwaq.ingestion.ingestion.DocumentationProcessor") as mock_doc_processor_cls:
        
        # Setup mock filesystem graph builder
        mock_fs_builder = MagicMock()
        mock_fs_builder.build_graph = AsyncMock(return_value={"file1.py": 1, "file2.py": 2})
        mock_fs_builder_cls.return_value = mock_fs_builder
        
        # Setup mock documentation processor
        mock_doc_processor = MagicMock()
        mock_doc_processor.process_local_docs = AsyncMock(return_value={"files_processed": 2})
        mock_doc_processor.process_remote_docs = AsyncMock(return_value={"files_processed": 1})
        mock_doc_processor_cls.return_value = mock_doc_processor
        
        # Setup ingestion status
        test_id = "test-ingestion-id"
        status = IngestionStatus(id=test_id)
        ingestion._active_ingestions[test_id] = status
        
        # Run the ingestion process
        await ingestion._run_ingestion(test_id)
        
        # Check that the documentation was processed
        mock_doc_processor.process_local_docs.assert_called_once_with("/path/to/docs", 1)
        mock_doc_processor.process_remote_docs.assert_called_once_with("https://example.com/docs", 1)


@pytest.mark.asyncio
async def test_run_ingestion_parse_only(
    mock_repo_handler, mock_repo_manager, mock_connector, mock_filesystem,
    mock_parser, mock_summarizer, mock_ast_mapper, mock_async_model_client
):
    """Test running ingestion with parse_only flag."""
    # Create an Ingestion instance with the necessary mocks
    ingestion = Ingestion(
        local_path="/path/to/local",
        model_client=mock_async_model_client,
        parse_only=True
    )
    
    # Replace real components with mocks
    ingestion.repo_handler = mock_repo_handler
    ingestion.repo_manager = mock_repo_manager
    ingestion.db_connector = mock_connector
    
    # Mock other components that would be created
    with patch("skwaq.ingestion.ingestion.CodebaseFileSystem", return_value=mock_filesystem), \
         patch("skwaq.ingestion.ingestion.FilesystemGraphBuilder") as mock_fs_builder_cls, \
         patch("skwaq.ingestion.ingestion.get_parser", return_value=mock_parser), \
         patch("skwaq.ingestion.ingestion.get_summarizer", return_value=mock_summarizer), \
         patch("skwaq.ingestion.ingestion.ASTFileMapper", return_value=mock_ast_mapper), \
         patch("skwaq.ingestion.ingestion.DocumentationProcessor") as mock_doc_processor_cls:
        
        # Setup mock filesystem graph builder
        mock_fs_builder = MagicMock()
        mock_fs_builder.build_graph = AsyncMock(return_value={"file1.py": 1, "file2.py": 2})
        mock_fs_builder_cls.return_value = mock_fs_builder
        
        # Setup ingestion status
        test_id = "test-ingestion-id"
        status = IngestionStatus(id=test_id)
        ingestion._active_ingestions[test_id] = status
        
        # Run the ingestion process
        await ingestion._run_ingestion(test_id)
        
        # Check that the code summarizer was not used
        mock_summarizer.configure.assert_not_called()
        mock_summarizer.summarize_files.assert_not_called()


@pytest.mark.asyncio
async def test_run_ingestion_error(
    mock_repo_handler, mock_repo_manager, mock_connector, mock_filesystem,
    mock_ast_mapper, mock_async_model_client
):
    """Test error handling in the ingestion process."""
    # Create an Ingestion instance with the necessary mocks
    ingestion = Ingestion(local_path="/path/to/local", model_client=mock_async_model_client)
    
    # Replace real components with mocks
    ingestion.repo_handler = mock_repo_handler
    ingestion.repo_manager = mock_repo_manager
    ingestion.db_connector = mock_connector
    
    # Create a test ID and status
    test_id = "test-ingestion-id"
    status = IngestionStatus(id=test_id)
    ingestion._active_ingestions[test_id] = status
    
    # Mock components and make one raise an exception
    with patch("skwaq.ingestion.ingestion.CodebaseFileSystem", return_value=mock_filesystem), \
         patch("skwaq.ingestion.ingestion.FilesystemGraphBuilder") as mock_fs_builder_cls, \
         patch("skwaq.ingestion.ingestion.get_parser", return_value=None), \
         patch("skwaq.ingestion.ingestion.ASTFileMapper", return_value=mock_ast_mapper):
         
        # Setup mock filesystem graph builder
        mock_fs_builder = MagicMock()
        mock_fs_builder.build_graph = AsyncMock(return_value={"file1.py": 1, "file2.py": 2})
        mock_fs_builder_cls.return_value = mock_fs_builder
        
        # Run the ingestion process
        await ingestion._run_ingestion(test_id)
        
        # Check that the status was updated with an error
        assert status.state == "failed"
        assert status.error is not None
        assert "Blarify parser not found" in status.message
        assert status.end_time is not None
        
        # Check that repo status was updated with the error
        mock_repo_manager.update_status.assert_called_once()


def test_ingestion_status():
    """Test the IngestionStatus class."""
    # Create a status
    status = IngestionStatus(id="test-id")
    
    # Check default values
    assert status.id == "test-id"
    assert status.state == "initializing"
    assert status.progress == 0.0
    assert status.end_time is None
    assert status.error is None
    assert status.files_processed == 0
    assert status.total_files == 0
    assert status.errors == []
    assert status.message == "Initializing ingestion process"
    
    # Check time_elapsed property - make it deterministic for testing
    current_time = time.time()
    
    # Test with no end time (in progress)
    status.start_time = current_time - 10  # 10 seconds ago
    with patch("time.time", return_value=current_time):
        assert status.time_elapsed == 10.0
    
    # Test with end time (completed)
    status.end_time = current_time - 5  # 5 seconds after start
    assert status.time_elapsed == 5.0
    
    # Check to_dict method
    status_dict = status.to_dict()
    assert status_dict["id"] == "test-id"
    assert status_dict["state"] == "initializing"
    assert status_dict["progress"] == 0.0
    assert status_dict["start_time"] == current_time - 10
    assert status_dict["end_time"] == current_time - 5
    assert status_dict["time_elapsed"] == 5.0