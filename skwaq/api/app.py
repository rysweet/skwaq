"""Flask application entry point for API server."""

import os
import traceback
import datetime
from flask import Flask, jsonify, request, g
import json
import neo4j.time
from flask_cors import CORS

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class CustomJSONEncoder(json.JSONEncoder):
    """Custom JSON encoder to handle Neo4j data types."""
    
    def default(self, obj):
        if isinstance(obj, neo4j.time.DateTime):
            return obj.to_native().isoformat()
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        return super().default(obj)


def create_app(test_config=None):
    """Create and configure the Flask app.
    
    Args:
        test_config: Configuration for testing (optional)
        
    Returns:
        Flask application
    """
    app = Flask(__name__, instance_relative_config=True)
    app.json_encoder = CustomJSONEncoder

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
        try:
            # Check database connection
            from skwaq.db.neo4j_connector import get_connector
            
            db_status = {
                "connected": False,
                "message": "Database not checked"
            }
            
            try:
                connector = get_connector()
                # Test query to verify database connection
                if connector.is_connected():
                    result = connector.run_query("MATCH (n) RETURN count(n) AS count LIMIT 1")
                    if result and len(result) > 0:
                        node_count = result[0]["count"]
                        db_status = {
                            "connected": True,
                            "message": f"Database connected, found {node_count} nodes"
                        }
                    else:
                        db_status["message"] = "Database query returned no results"
                else:
                    db_status["message"] = "Failed to connect to database"
            except Exception as db_err:
                db_status["message"] = f"Database error: {str(db_err)}"
                
            return jsonify({
                "status": "healthy" if db_status["connected"] else "degraded",
                "api_version": "1.0.0",
                "database": db_status,
                "timestamp": datetime.datetime.now().isoformat()
            })
        except Exception as e:
            # Catch all other errors and return unhealthy status
            logger.error(f"Health check failed: {str(e)}")
            return jsonify({
                "status": "unhealthy",
                "error": str(e),
                "details": {
                    "traceback": traceback.format_exc(),
                    "timestamp": datetime.datetime.now().isoformat()
                }
            }), 500
    
    # Register blueprints
    from skwaq.api.routes import auth, repositories, events, workflows, chat, investigations, knowledge_graph
    app.register_blueprint(auth.bp)
    app.register_blueprint(repositories.bp)
    app.register_blueprint(events.bp)
    app.register_blueprint(workflows.bp)
    app.register_blueprint(chat.bp)
    app.register_blueprint(investigations.bp)
    app.register_blueprint(knowledge_graph.bp)
    
    # Additional blueprints will be registered as they are implemented
    
    return app
