"""Tests for the ingestion exceptions module."""


from skwaq.ingestion.exceptions import (
    ASTMapperError,
    ConfigurationError,
    DatabaseError,
    DocumentationError,
    FileSystemError,
    IngestionError,
    IngestionTimeoutError,
    ParallelProcessingError,
    ParserError,
    RepositoryError,
    SummarizerError,
)


def test_ingestion_error_basic():
    """Test basic behavior of the IngestionError class."""
    # Create a simple error
    error = IngestionError("Test error message")
    assert str(error) == "Test error message"
    assert error.message == "Test error message"
    assert error.details == {}

    # Create an error with details
    error_with_details = IngestionError(
        "Error with details", details={"error_code": 123, "severity": "high"}
    )
    assert error_with_details.message == "Error with details"
    assert error_with_details.details == {"error_code": 123, "severity": "high"}


def test_repository_error():
    """Test the RepositoryError class."""
    # Create a basic repository error
    error = RepositoryError("Failed to clone repository")
    assert error.message == "Failed to clone repository"
    assert error.repo_url is None
    assert error.branch is None

    # Create a detailed repository error
    error = RepositoryError(
        message="Failed to clone repository",
        repo_url="https://github.com/example/repo.git",
        branch="main",
        details={"error_type": "network"},
    )
    assert error.message == "Failed to clone repository"
    assert error.repo_url == "https://github.com/example/repo.git"
    assert error.branch == "main"
    assert error.details == {
        "repo_url": "https://github.com/example/repo.git",
        "branch": "main",
        "error_type": "network",
    }


def test_filesystem_error():
    """Test the FileSystemError class."""
    # Create a basic filesystem error
    error = FileSystemError("Failed to read file")
    assert error.message == "Failed to read file"
    assert error.path is None
    assert error.file_type is None

    # Create a detailed filesystem error
    error = FileSystemError(
        message="Failed to read file",
        path="/path/to/file.py",
        file_type="python",
        details={"error_type": "permission"},
    )
    assert error.message == "Failed to read file"
    assert error.path == "/path/to/file.py"
    assert error.file_type == "python"
    assert error.details == {
        "path": "/path/to/file.py",
        "file_type": "python",
        "error_type": "permission",
    }


def test_parser_error():
    """Test the ParserError class."""
    # Create a basic parser error
    error = ParserError("Failed to parse file")
    assert error.message == "Failed to parse file"
    assert error.parser_name is None
    assert error.file_path is None
    assert error.language is None

    # Create a detailed parser error
    error = ParserError(
        message="Invalid syntax in file",
        parser_name="blarify",
        file_path="/path/to/file.py",
        language="python",
        details={"line": 42, "column": 10},
    )
    assert error.message == "Invalid syntax in file"
    assert error.parser_name == "blarify"
    assert error.file_path == "/path/to/file.py"
    assert error.language == "python"
    assert error.details == {
        "parser_name": "blarify",
        "file_path": "/path/to/file.py",
        "language": "python",
        "line": 42,
        "column": 10,
    }


def test_summarizer_error():
    """Test the SummarizerError class."""
    # Create a basic summarizer error
    error = SummarizerError("Failed to summarize file")
    assert error.message == "Failed to summarize file"
    assert error.summarizer_name is None
    assert error.file_path is None
    assert error.model_error is None

    # Create a detailed summarizer error
    error = SummarizerError(
        message="Model generation error",
        summarizer_name="llm",
        file_path="/path/to/file.py",
        model_error="Context length exceeded",
        details={"token_count": 4096},
    )
    assert error.message == "Model generation error"
    assert error.summarizer_name == "llm"
    assert error.file_path == "/path/to/file.py"
    assert error.model_error == "Context length exceeded"
    assert error.details == {
        "summarizer_name": "llm",
        "file_path": "/path/to/file.py",
        "model_error": "Context length exceeded",
        "token_count": 4096,
    }


def test_documentation_error():
    """Test the DocumentationError class."""
    # Create a basic documentation error
    error = DocumentationError("Failed to process documentation")
    assert error.message == "Failed to process documentation"
    assert error.doc_path is None
    assert error.doc_uri is None

    # Create a detailed documentation error
    error = DocumentationError(
        message="Invalid documentation format",
        doc_path="/path/to/docs",
        doc_uri="https://example.com/docs",
        details={"format": "markdown", "issue": "missing frontmatter"},
    )
    assert error.message == "Invalid documentation format"
    assert error.doc_path == "/path/to/docs"
    assert error.doc_uri == "https://example.com/docs"
    assert error.details == {
        "doc_path": "/path/to/docs",
        "doc_uri": "https://example.com/docs",
        "format": "markdown",
        "issue": "missing frontmatter",
    }


def test_ast_mapper_error():
    """Test the ASTMapperError class."""
    # Create a basic AST mapper error
    error = ASTMapperError("Failed to map AST to file")
    assert error.message == "Failed to map AST to file"
    assert error.ast_node_id is None
    assert error.file_node_id is None

    # Create a detailed AST mapper error
    error = ASTMapperError(
        message="Node mismatch",
        ast_node_id=123,
        file_node_id=456,
        details={"error_type": "path_mismatch", "severity": "warning"},
    )
    assert error.message == "Node mismatch"
    assert error.ast_node_id == 123
    assert error.file_node_id == 456
    assert error.details == {
        "ast_node_id": 123,
        "file_node_id": 456,
        "error_type": "path_mismatch",
        "severity": "warning",
    }


def test_database_error():
    """Test the DatabaseError class."""
    # Create a basic database error
    error = DatabaseError("Database query failed")
    assert error.message == "Database query failed"
    assert error.query is None
    assert error.db_error is None

    # Create a detailed database error
    query = "MATCH (n:Node) WHERE n.id = $id RETURN n"
    error = DatabaseError(
        message="Neo4j query failed",
        query=query,
        db_error="Syntax error in Cypher statement",
        details={"params": {"id": 123}},
    )
    assert error.message == "Neo4j query failed"
    assert error.query == query
    assert error.db_error == "Syntax error in Cypher statement"
    assert error.details == {
        "query": query,
        "db_error": "Syntax error in Cypher statement",
        "params": {"id": 123},
    }


def test_configuration_error():
    """Test the ConfigurationError class."""
    # Create a basic configuration error
    error = ConfigurationError("Invalid configuration")
    assert error.message == "Invalid configuration"
    assert error.param_name is None
    assert error.param_value is None

    # Create a detailed configuration error
    error = ConfigurationError(
        message="Invalid parameter value",
        param_name="max_parallel",
        param_value=-1,
        details={"valid_range": "1-10"},
    )
    assert error.message == "Invalid parameter value"
    assert error.param_name == "max_parallel"
    assert error.param_value == -1
    assert error.details == {
        "param_name": "max_parallel",
        "param_value": "-1",
        "valid_range": "1-10",
    }


def test_parallel_processing_error():
    """Test the ParallelProcessingError class."""
    # Create a basic parallel processing error
    error = ParallelProcessingError("Parallel processing failed")
    assert error.message == "Parallel processing failed"
    assert error.task_name is None
    assert error.task_errors == []

    # Create a detailed parallel processing error
    task_errors = [
        {"task_id": 1, "error": "Timeout", "file": "file1.py"},
        {"task_id": 2, "error": "Permission denied", "file": "file2.py"},
    ]
    error = ParallelProcessingError(
        message="Multiple tasks failed",
        task_name="file_processing",
        task_errors=task_errors,
        details={"failed_count": 2, "total_count": 5},
    )
    assert error.message == "Multiple tasks failed"
    assert error.task_name == "file_processing"
    assert error.task_errors == task_errors
    assert error.details == {
        "task_name": "file_processing",
        "task_errors": task_errors,
        "failed_count": 2,
        "total_count": 5,
    }


def test_ingestion_timeout_error():
    """Test the IngestionTimeoutError class."""
    # Create a basic timeout error
    error = IngestionTimeoutError("Operation timed out")
    assert error.message == "Operation timed out"
    assert error.timeout is None
    assert error.operation is None

    # Create a detailed timeout error
    error = IngestionTimeoutError(
        message="Repository cloning timed out",
        timeout=300.0,
        operation="git_clone",
        details={"repo_size": "large", "network_speed": "slow"},
    )
    assert error.message == "Repository cloning timed out"
    assert error.timeout == 300.0
    assert error.operation == "git_clone"
    assert error.details == {
        "timeout": 300.0,
        "operation": "git_clone",
        "repo_size": "large",
        "network_speed": "slow",
    }
