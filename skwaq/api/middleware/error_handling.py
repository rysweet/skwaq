"""Error handling middleware for the Flask API."""

from typing import Dict, Any, Tuple, Optional, Union

from flask import Flask, jsonify, Response

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class APIError(Exception):
    """Base class for API errors."""
    
    def __init__(self, message: str, status_code: int = 500, details: Optional[Dict[str, Any]] = None):
        """Initialize an API error.
        
        Args:
            message: Error message
            status_code: HTTP status code
            details: Additional error details
        """
        self.message = message
        self.status_code = status_code
        self.details = details
        super().__init__(self.message)


class NotFoundError(APIError):
    """Resource not found error."""
    
    def __init__(self, message: str = "Resource not found", details: Optional[Dict[str, Any]] = None):
        """Initialize a not found error.
        
        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message, 404, details)


class BadRequestError(APIError):
    """Bad request error."""
    
    def __init__(self, message: str = "Bad request", details: Optional[Dict[str, Any]] = None):
        """Initialize a bad request error.
        
        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message, 400, details)


class UnauthorizedError(APIError):
    """Unauthorized error."""
    
    def __init__(self, message: str = "Authentication required", details: Optional[Dict[str, Any]] = None):
        """Initialize an unauthorized error.
        
        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message, 401, details)


class ForbiddenError(APIError):
    """Forbidden error."""
    
    def __init__(self, message: str = "Permission denied", details: Optional[Dict[str, Any]] = None):
        """Initialize a forbidden error.
        
        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message, 403, details)


class ConflictError(APIError):
    """Conflict error."""
    
    def __init__(self, message: str = "Resource conflict", details: Optional[Dict[str, Any]] = None):
        """Initialize a conflict error.
        
        Args:
            message: Error message
            details: Additional error details
        """
        super().__init__(message, 409, details)


def init_app(app: Flask) -> None:
    """Initialize error handling for the Flask app.
    
    Args:
        app: Flask application
    """
    @app.errorhandler(APIError)
    def handle_api_error(error: APIError) -> Response:
        """Handle API errors.
        
        Args:
            error: API error
            
        Returns:
            JSON response with error details
        """
        response = {
            'error': error.message
        }
        
        if error.details:
            response['details'] = error.details
            
        return jsonify(response), error.status_code
    
    @app.errorhandler(404)
    def handle_not_found(error: Any) -> Response:
        """Handle 404 errors.
        
        Args:
            error: Error object
            
        Returns:
            JSON response for not found errors
        """
        return jsonify({'error': 'Resource not found'}), 404
    
    @app.errorhandler(500)
    def handle_server_error(error: Any) -> Response:
        """Handle 500 errors.
        
        Args:
            error: Error object
            
        Returns:
            JSON response for server errors
        """
        logger.error(f"Internal server error: {str(error)}")
        return jsonify({'error': 'Internal server error'}), 500
