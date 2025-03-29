"""CORS middleware for the Flask API."""

from flask import Flask


def init_app(app: Flask) -> None:
    """Initialize CORS headers for all responses.
    
    Args:
        app: Flask application
    """
    @app.after_request
    def add_cors_headers(response):
        """Add CORS headers to all responses.
        
        Args:
            response: Flask response
            
        Returns:
            Modified response with CORS headers
        """
        response.headers['Access-Control-Allow-Origin'] = '*'
        response.headers['Access-Control-Allow-Headers'] = 'Content-Type,Authorization'
        response.headers['Access-Control-Allow-Methods'] = 'GET,PUT,POST,DELETE,OPTIONS'
        return response
