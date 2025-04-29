#!/usr/bin/env python3
"""Run a test version of the Skwaq API server for integration testing."""

import argparse
import logging
import os
import signal
import sys

# Add parent directory to path so we can import skwaq modules
sys.path.append(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from flask import Flask
from flask_cors import CORS

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler()],
)
logger = logging.getLogger(__name__)

# Flag to track if we're supposed to be running
running = True


def signal_handler(sig, frame):
    """Handle termination signals gracefully."""
    global running
    logger.info(f"Received signal {sig}. Shutting down API server...")
    running = False
    sys.exit(0)


def create_test_app():
    """Create a test version of the app with authentication disabled."""
    app = Flask(__name__, instance_relative_config=True)

    # Enable CORS for testing
    CORS(app, supports_credentials=True)

    # Set default configuration
    app.config.from_mapping(
        SECRET_KEY="test",
        DATABASE=os.path.join(app.instance_path, "test_skwaq.sqlite"),
        JWT_EXPIRATION=3600,  # 1 hour token expiration
        TESTING=True,  # Enable testing mode
    )

    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass

    # Register authentication blueprint
    from skwaq.api import auth

    app.register_blueprint(auth.bp)

    # Register event stream blueprint for real-time updates
    from skwaq.api import events

    app.register_blueprint(events.bp)

    # Register blueprints for API routes
    from skwaq.api import repositories

    app.register_blueprint(repositories.bp)

    from skwaq.api import investigations

    app.register_blueprint(investigations.bp)

    from skwaq.api import knowledge_graph

    app.register_blueprint(knowledge_graph.bp)

    from skwaq.api import chat

    app.register_blueprint(chat.bp)

    from skwaq.api import settings

    app.register_blueprint(settings.bp)

    from skwaq.api import workflows

    app.register_blueprint(workflows.bp)

    # Add a simple route for testing
    @app.route("/api/healthcheck")
    def healthcheck():
        return {"status": "healthy"}

    # Register error handlers
    @app.errorhandler(404)
    def not_found(e):
        return {"error": "Resource not found"}, 404

    @app.errorhandler(500)
    def server_error(e):
        return {"error": "Internal server error"}, 500

    # Disable authentication for testing
    @app.before_request
    def disable_auth():
        """Set fake authentication data for testing."""
        from flask import g

        g.user_id = "test-user"
        g.username = "testuser"
        g.roles = ["admin"]

    return app


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    parser = argparse.ArgumentParser(
        description="Run a test version of the Skwaq API server"
    )
    parser.add_argument(
        "--host", default="localhost", help="Host to bind to (default: localhost)"
    )
    parser.add_argument(
        "--port", type=int, default=5000, help="Port to bind to (default: 5000)"
    )
    parser.add_argument("--debug", action="store_true", help="Run in debug mode")
    parser.add_argument("--pid-file", help="File to write PID to")

    args = parser.parse_args()

    # Write PID to file if requested
    if args.pid_file:
        with open(args.pid_file, "w") as f:
            f.write(str(os.getpid()))
        logger.info(f"PID {os.getpid()} written to {args.pid_file}")

    if args.debug:
        logger.info("Running in debug mode")

    app = create_test_app()
    logger.info(f"Starting TEST API server at http://{args.host}:{args.port}")
    try:
        app.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logger.info("API server stopped by keyboard interrupt")
    except Exception as e:
        logger.error(f"API server error: {e}")
    finally:
        # Remove PID file if it exists
        if args.pid_file and os.path.exists(args.pid_file):
            os.remove(args.pid_file)
        logger.info("API server shutdown complete")
