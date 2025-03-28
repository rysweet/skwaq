"""Skwaq API module for the web interface."""

import os
from flask import Flask, jsonify, request
from flask_cors import CORS


def create_app(test_config=None):
    """Create and configure the Flask app."""
    app = Flask(__name__, instance_relative_config=True)

    # Enable CORS for frontend development with proper support for credentials
    CORS(app, supports_credentials=True)

    # Set default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "dev"),
        DATABASE=os.path.join(app.instance_path, "skwaq.sqlite"),
        JWT_EXPIRATION=3600,  # 1 hour token expiration
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

    # Register authentication blueprint
    from . import auth

    app.register_blueprint(auth.bp)

    # Register event stream blueprint for real-time updates
    from . import events

    app.register_blueprint(events.bp)

    # Register blueprints for API routes
    from . import repositories

    app.register_blueprint(repositories.bp)

    from . import knowledge_graph

    app.register_blueprint(knowledge_graph.bp)

    from . import chat

    app.register_blueprint(chat.bp)

    from . import settings

    app.register_blueprint(settings.bp)

    # Add a simple route for testing
    @app.route("/api/healthcheck")
    def healthcheck():
        return {"status": "healthy"}

    # Add CSRF protection
    @app.before_request
    def csrf_protect():
        """Check for CSRF token on state-changing requests."""
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # Skip CSRF check for login endpoint and event streams
            if request.path == "/api/auth/login" or request.path.startswith(
                "/api/events/"
            ):
                return

            # Check for CSRF token in header
            csrf_token = request.headers.get("X-CSRF-Token")
            if not csrf_token:
                return jsonify({"error": "CSRF token missing"}), 403

            # In a real implementation, we would validate the token here
            # For this implementation, we'll just check that it exists

    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"error": "Resource not found"}), 404

    @app.errorhandler(500)
    def server_error(e):
        return jsonify({"error": "Internal server error"}), 500

    return app
