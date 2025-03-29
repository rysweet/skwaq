"""Flask application entry point for API server."""

import os
from flask import Flask, jsonify, request, g
from flask_cors import CORS

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


def create_app(test_config=None):
    """Create and configure the Flask app.
    
    Args:
        test_config: Configuration for testing (optional)
        
    Returns:
        Flask application
    """
    app = Flask(__name__, instance_relative_config=True)

    # Enable CORS for frontend development
    CORS(
        app,
        resources={r"/api/*": {"origins": "*"}},
        supports_credentials=True,
        allow_headers=["Content-Type", "Authorization", "X-Requested-With"]
    )
    
    # Set default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev"),
        JWT_SECRET=os.environ.get("JWT_SECRET", "dev-jwt-secret"),
        JWT_EXPIRATION=3600,  # 1 hour token expiration
        JWT_ALGORITHM="HS256",
    )

    if test_config is None:
        # Load the instance config, if it exists, when not testing
        app.config.from_pyfile("config.py", silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(test_config)

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Register middleware
    from skwaq.api.middleware import cors, error_handling
    cors.init_app(app)
    error_handling.init_app(app)
    
    # Register error handlers for our custom exceptions
    from skwaq.api.middleware.error_handling import APIError, NotFoundError, BadRequestError, UnauthorizedError, ForbiddenError, ConflictError
    
    @app.errorhandler(APIError)
    def handle_api_error(error):
        response = {
            'error': error.message
        }
        
        if error.details:
            response['details'] = error.details
            
        return jsonify(response), error.status_code
    
    # Add a health check endpoint
    @app.route("/api/health")
    def health_check():
        return jsonify({"status": "healthy"})
    
    # Register blueprints
    from skwaq.api.routes import auth
    app.register_blueprint(auth.bp)
    
    # Additional blueprints will be registered as they are implemented
    
    return app
