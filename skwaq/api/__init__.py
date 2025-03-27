"""Skwaq API module for the web interface."""

import os
from flask import Flask
from flask_cors import CORS

def create_app(test_config=None):
    """Create and configure the Flask app."""
    app = Flask(__name__, instance_relative_config=True)
    
    # Enable CORS for frontend development
    CORS(app)
    
    # Set default configuration
    app.config.from_mapping(
        SECRET_KEY=os.environ.get('SECRET_KEY', 'dev'),
        DATABASE=os.path.join(app.instance_path, 'skwaq.sqlite'),
    )
    
    if test_config is None:
        # Load the instance config, if it exists, when not testing
        app.config.from_pyfile('config.py', silent=True)
    else:
        # Load the test config if passed in
        app.config.from_mapping(test_config)
    
    # Ensure the instance folder exists
    try:
        os.makedirs(app.instance_path)
    except OSError:
        pass
    
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
    @app.route('/api/healthcheck')
    def healthcheck():
        return {'status': 'healthy'}
    
    return app