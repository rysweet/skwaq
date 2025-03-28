"""Custom exceptions for the ingestion module.

This module defines custom exceptions for the ingestion process to provide
more detailed error information and improve error handling.
"""

from typing import Optional, Dict, Any, List


class IngestionError(Exception):
    """Base exception for all ingestion-related errors."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        """Initialize the exception.

        Args:
            message: Human-readable error message
            details: Additional error details as a dictionary
        """
        self.message = message
        self.details = details or {}
        super().__init__(message)


class RepositoryError(IngestionError):
    """Exception for errors related to repository operations."""

    def __init__(
        self, 
        message: str, 
        repo_url: Optional[str] = None, 
        branch: Optional[str] = None, 
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the repository error.

        Args:
            message: Human-readable error message
            repo_url: URL of the repository that caused the error
            branch: Branch name that caused the error
            details: Additional error details as a dictionary
        """
        self.repo_url = repo_url
        self.branch = branch
        
        # Add repo info to details
        error_details = details or {}
        if repo_url:
            error_details["repo_url"] = repo_url
        if branch:
            error_details["branch"] = branch
            
        super().__init__(message, error_details)


class FileSystemError(IngestionError):
    """Exception for errors related to filesystem operations."""

    def __init__(
        self, 
        message: str, 
        path: Optional[str] = None,
        file_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the filesystem error.

        Args:
            message: Human-readable error message
            path: Path to the file or directory that caused the error
            file_type: Type of file that caused the error (if applicable)
            details: Additional error details as a dictionary
        """
        self.path = path
        self.file_type = file_type
        
        # Add path info to details
        error_details = details or {}
        if path:
            error_details["path"] = path
        if file_type:
            error_details["file_type"] = file_type
            
        super().__init__(message, error_details)


class ParserError(IngestionError):
    """Exception for errors related to code parsing."""

    def __init__(
        self, 
        message: str, 
        parser_name: Optional[str] = None,
        file_path: Optional[str] = None,
        language: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the parser error.

        Args:
            message: Human-readable error message
            parser_name: Name of the parser that encountered the error
            file_path: Path to the file that caused the error
            language: Programming language of the file
            details: Additional error details as a dictionary
        """
        self.parser_name = parser_name
        self.file_path = file_path
        self.language = language
        
        # Add parser info to details
        error_details = details or {}
        if parser_name:
            error_details["parser_name"] = parser_name
        if file_path:
            error_details["file_path"] = file_path
        if language:
            error_details["language"] = language
            
        super().__init__(message, error_details)


class SummarizerError(IngestionError):
    """Exception for errors related to code summarization."""

    def __init__(
        self, 
        message: str, 
        summarizer_name: Optional[str] = None,
        file_path: Optional[str] = None,
        model_error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the summarizer error.

        Args:
            message: Human-readable error message
            summarizer_name: Name of the summarizer that encountered the error
            file_path: Path to the file that caused the error
            model_error: Specific error from the LLM model if applicable
            details: Additional error details as a dictionary
        """
        self.summarizer_name = summarizer_name
        self.file_path = file_path
        self.model_error = model_error
        
        # Add summarizer info to details
        error_details = details or {}
        if summarizer_name:
            error_details["summarizer_name"] = summarizer_name
        if file_path:
            error_details["file_path"] = file_path
        if model_error:
            error_details["model_error"] = model_error
            
        super().__init__(message, error_details)


class DocumentationError(IngestionError):
    """Exception for errors related to documentation processing."""

    def __init__(
        self, 
        message: str, 
        doc_path: Optional[str] = None,
        doc_uri: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the documentation error.

        Args:
            message: Human-readable error message
            doc_path: Path to the documentation that caused the error
            doc_uri: URI of the documentation that caused the error
            details: Additional error details as a dictionary
        """
        self.doc_path = doc_path
        self.doc_uri = doc_uri
        
        # Add documentation info to details
        error_details = details or {}
        if doc_path:
            error_details["doc_path"] = doc_path
        if doc_uri:
            error_details["doc_uri"] = doc_uri
            
        super().__init__(message, error_details)


class ASTMapperError(IngestionError):
    """Exception for errors related to AST mapping."""

    def __init__(
        self, 
        message: str, 
        ast_node_id: Optional[int] = None,
        file_node_id: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the AST mapper error.

        Args:
            message: Human-readable error message
            ast_node_id: ID of the AST node that caused the error
            file_node_id: ID of the file node that caused the error
            details: Additional error details as a dictionary
        """
        self.ast_node_id = ast_node_id
        self.file_node_id = file_node_id
        
        # Add mapping info to details
        error_details = details or {}
        if ast_node_id:
            error_details["ast_node_id"] = ast_node_id
        if file_node_id:
            error_details["file_node_id"] = file_node_id
            
        super().__init__(message, error_details)


class DatabaseError(IngestionError):
    """Exception for errors related to database operations."""

    def __init__(
        self, 
        message: str, 
        query: Optional[str] = None,
        db_error: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the database error.

        Args:
            message: Human-readable error message
            query: Database query that caused the error
            db_error: Original database error message
            details: Additional error details as a dictionary
        """
        self.query = query
        self.db_error = db_error
        
        # Add database info to details
        error_details = details or {}
        if query:
            error_details["query"] = query
        if db_error:
            error_details["db_error"] = db_error
            
        super().__init__(message, error_details)


class ConfigurationError(IngestionError):
    """Exception for errors related to ingestion configuration."""

    def __init__(
        self, 
        message: str, 
        param_name: Optional[str] = None,
        param_value: Optional[Any] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the configuration error.

        Args:
            message: Human-readable error message
            param_name: Name of the configuration parameter that caused the error
            param_value: Value of the configuration parameter that caused the error
            details: Additional error details as a dictionary
        """
        self.param_name = param_name
        self.param_value = param_value
        
        # Add configuration info to details
        error_details = details or {}
        if param_name:
            error_details["param_name"] = param_name
        if param_value is not None:
            error_details["param_value"] = str(param_value)
            
        super().__init__(message, error_details)


class ParallelProcessingError(IngestionError):
    """Exception for errors related to parallel processing."""

    def __init__(
        self, 
        message: str, 
        task_name: Optional[str] = None,
        task_errors: Optional[List[Dict[str, Any]]] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the parallel processing error.

        Args:
            message: Human-readable error message
            task_name: Name of the task that failed
            task_errors: List of errors from parallel tasks
            details: Additional error details as a dictionary
        """
        self.task_name = task_name
        self.task_errors = task_errors or []
        
        # Add task info to details
        error_details = details or {}
        if task_name:
            error_details["task_name"] = task_name
        if task_errors:
            error_details["task_errors"] = task_errors
            
        super().__init__(message, error_details)


class IngestionTimeoutError(IngestionError):
    """Exception for timeout errors during ingestion."""

    def __init__(
        self, 
        message: str, 
        timeout: Optional[float] = None,
        operation: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None
    ):
        """Initialize the timeout error.

        Args:
            message: Human-readable error message
            timeout: Timeout value in seconds
            operation: Name of the operation that timed out
            details: Additional error details as a dictionary
        """
        self.timeout = timeout
        self.operation = operation
        
        # Add timeout info to details
        error_details = details or {}
        if timeout is not None:
            error_details["timeout"] = timeout
        if operation:
            error_details["operation"] = operation
            
        super().__init__(message, error_details)