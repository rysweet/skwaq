"""Tests for the documentation processor module."""

import os
import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import aiohttp
import tempfile

from skwaq.ingestion.documentation import DocumentationProcessor
from skwaq.db.schema import NodeLabels, RelationshipTypes


@pytest.fixture
def mock_doc_dir():
    """Create a temporary directory with documentation files."""
    temp_dir = tempfile.mkdtemp()
    
    # Create some documentation files
    with open(os.path.join(temp_dir, "README.md"), "w") as f:
        f.write("# Test Project\n\nThis is a test project documentation.")
    
    with open(os.path.join(temp_dir, "API.md"), "w") as f:
        f.write("# API Reference\n\n## Functions\n\n- `test()`: Test function")
    
    # Create a subdirectory
    os.makedirs(os.path.join(temp_dir, "guides"))
    
    with open(os.path.join(temp_dir, "guides", "getting-started.md"), "w") as f:
        f.write("# Getting Started\n\nThis is a getting started guide.")
    
    yield temp_dir
    
    # Cleanup
    import shutil
    shutil.rmtree(temp_dir)


class MockResponse:
    """Mock aiohttp response."""
    
    def __init__(self, text, status=200):
        self._text = text
        self.status = status
        
    async def text(self):
        return self._text
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


class MockClientSession:
    """Mock aiohttp ClientSession."""
    
    def __init__(self, response):
        self.response = response
        
    async def get(self, url):
        return self.response
        
    async def __aenter__(self):
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        pass


@pytest.mark.asyncio
async def test_process_local_docs(mock_connector, mock_async_model_client, mock_doc_dir):
    """Test processing local documentation files."""
    # Create a DocumentationProcessor
    processor = DocumentationProcessor(mock_async_model_client, mock_connector)
    
    # Process the documentation
    result = await processor.process_local_docs(mock_doc_dir, repo_node_id=1)
    
    # Check the result
    assert result["files_processed"] > 0
    assert "errors" in result
    
    # Check that nodes were created for the documentation files
    assert mock_connector.create_node.call_count >= 3  # At least 3 doc files
    
    # Check that relationships were created
    assert mock_connector.create_relationship.call_count >= 3
    
    # Check that the LLM was used to generate summaries
    assert mock_async_model_client.get_completion.call_count >= 3


@pytest.mark.asyncio
async def test_process_local_docs_nonexistent_path(mock_connector, mock_async_model_client):
    """Test processing a nonexistent documentation path."""
    # Create a DocumentationProcessor
    processor = DocumentationProcessor(mock_async_model_client, mock_connector)
    
    # Try to process a nonexistent path
    with pytest.raises(ValueError) as excinfo:
        await processor.process_local_docs("/nonexistent/path", repo_node_id=1)
    
    # Check the error message
    assert "does not exist" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_remote_docs(mock_connector, mock_async_model_client):
    """Test processing remote documentation."""
    # Create a DocumentationProcessor
    processor = DocumentationProcessor(mock_async_model_client, mock_connector)
    
    # Mock the aiohttp ClientSession
    mock_response = MockResponse("# Remote Documentation\n\nThis is remote documentation.")
    mock_session = MockClientSession(mock_response)
    
    # Patch aiohttp.ClientSession to return our mock
    with patch("aiohttp.ClientSession", return_value=mock_session):
        # Process remote documentation
        result = await processor.process_remote_docs("https://example.com/docs.md", repo_node_id=1)
    
    # Check the result
    assert result["files_processed"] == 1
    assert result["errors"] == 0
    
    # Check that a node was created for the documentation
    assert mock_connector.create_node.call_count >= 1
    
    # Check that a relationship was created
    assert mock_connector.create_relationship.call_count >= 1
    
    # Check that the LLM was used to generate a summary
    assert mock_async_model_client.get_completion.call_count >= 1


@pytest.mark.asyncio
async def test_process_remote_docs_error(mock_connector, mock_async_model_client):
    """Test processing remote documentation with an error."""
    # Create a DocumentationProcessor
    processor = DocumentationProcessor(mock_async_model_client, mock_connector)
    
    # Mock the aiohttp ClientSession with an error response
    mock_response = MockResponse("Error", status=404)
    mock_session = MockClientSession(mock_response)
    
    # Patch aiohttp.ClientSession to return our mock
    with patch("aiohttp.ClientSession", return_value=mock_session):
        # Process remote documentation which will fail
        with pytest.raises(ValueError) as excinfo:
            await processor.process_remote_docs("https://example.com/docs.md", repo_node_id=1)
    
    # Check the error message
    assert "Failed to download documentation" in str(excinfo.value)


@pytest.mark.asyncio
async def test_process_doc_content(mock_connector, mock_async_model_client):
    """Test processing documentation content using LLM."""
    # Create a DocumentationProcessor
    processor = DocumentationProcessor(mock_async_model_client, mock_connector)
    
    # Call the _process_doc_content method directly
    doc_node_id = 1
    content = "# Test Document\n\nThis is a test document."
    doc_name = "test.md"
    
    await processor._process_doc_content(doc_node_id, content, doc_name)
    
    # Check that the LLM was used to generate a summary
    assert mock_async_model_client.get_completion.call_count >= 1
    
    # Check that the summary was stored in the database
    mock_connector.run_query.assert_called()
    args, kwargs = mock_connector.run_query.call_args
    assert "doc_id" in kwargs
    assert kwargs["doc_id"] == doc_node_id
    assert "summary" in kwargs
    

@pytest.mark.asyncio
async def test_process_doc_content_no_model(mock_connector):
    """Test processing documentation content without an LLM model."""
    # Create a DocumentationProcessor without a model client
    processor = DocumentationProcessor(None, mock_connector)
    
    # Call the _process_doc_content method directly
    doc_node_id = 1
    content = "# Test Document\n\nThis is a test document."
    doc_name = "test.md"
    
    # This should not raise an exception, but log a warning
    await processor._process_doc_content(doc_node_id, content, doc_name)
    
    # No database updates should have been made
    mock_connector.run_query.assert_not_called()