"""Pytest fixtures for API unit tests."""

import pytest
import json
import uuid
from unittest.mock import MagicMock, patch
from flask.testing import FlaskClient
from datetime import datetime

from skwaq.api import create_app


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    # Create test configuration
    test_config = {
        'TESTING': True,
        'SECRET_KEY': 'test'
    }
    
    # Create the app with test config
    app = create_app(test_config)
    
    @app.before_request
    def disable_auth_for_testing():
        """Set fake authentication data for testing."""
        from flask import g
        # Only set these values if they're not already set
        if not hasattr(g, 'user_id'):
            g.user_id = "test-user"
            g.username = "testuser"
            g.roles = ["admin"]
    
    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def mock_get_investigations():
    """Mock the get_investigations_from_db function."""
    with patch('skwaq.api.investigations.get_investigations_from_db') as mock:
        # Set up the mock to return test data
        mock.return_value = [
            {
                "id": f"inv-test-{uuid.uuid4()}",
                "title": "Test Investigation 1",
                "repository_id": "repo-123",
                "repository_name": "Test Repository 1",
                "creation_date": datetime.utcnow().isoformat(),
                "status": "new",
                "findings_count": 2,
                "vulnerabilities_count": 1,
                "description": "This is test investigation 1"
            },
            {
                "id": f"inv-test-{uuid.uuid4()}",
                "title": "Test Investigation 2",
                "repository_id": "repo-456",
                "repository_name": "Test Repository 2",
                "creation_date": datetime.utcnow().isoformat(),
                "status": "completed",
                "findings_count": 0,
                "vulnerabilities_count": 0,
                "description": "This is test investigation 2"
            }
        ]
        yield mock


@pytest.fixture
def mock_get_investigation():
    """Mock the get_investigation_by_id function."""
    with patch('skwaq.api.investigations.get_investigation_by_id') as mock:
        # Create a test investigation ID
        investigation_id = f"inv-test-{uuid.uuid4()}"
        
        # Set up the mock to return test data for the specific ID
        def get_investigation_side_effect(id):
            if id == investigation_id:
                return {
                    "id": investigation_id,
                    "title": "Test Investigation",
                    "repository_id": "repo-123",
                    "repository_name": "Test Repository",
                    "creation_date": datetime.utcnow().isoformat(),
                    "status": "new",
                    "findings_count": 1,
                    "vulnerabilities_count": 1,
                    "description": "This is a test investigation"
                }
            elif id == "inv-not-found":
                return None
            else:
                return {
                    "id": id,
                    "title": f"Investigation {id}",
                    "repository_id": "repo-999",
                    "repository_name": "Test Repository",
                    "creation_date": datetime.utcnow().isoformat(),
                    "status": "new",
                    "findings_count": 0,
                    "vulnerabilities_count": 0,
                    "description": f"This is investigation {id}"
                }
        
        mock.side_effect = get_investigation_side_effect
        
        # Return both the mock and the test ID for tests to use
        yield mock, investigation_id


@pytest.fixture
def mock_neo4j_connector():
    """Mock the Neo4j connector."""
    with patch('skwaq.api.investigations.get_connector') as mock_get_connector:
        connector = MagicMock()
        connector.connect.return_value = True
        connector.is_connected.return_value = True
        connector.run_query.return_value = []
        
        mock_get_connector.return_value = connector
        
        yield connector