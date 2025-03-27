"""Tests for Milestone G2: GUI Backend Integration."""

import json
import pytest
import jwt
from unittest.mock import patch, MagicMock

from skwaq.api import create_app
from skwaq.security.authentication import (
    AuthenticationManager, 
    UserCredentials, 
    AuthRole
)
from skwaq.security.authorization import Permission


@pytest.fixture
def app():
    """Create a Flask app for testing."""
    app = create_app({
        'TESTING': True,
        'SECRET_KEY': 'test_secret_key',
    })
    return app


@pytest.fixture
def client(app):
    """Create a test client for the app."""
    with app.test_client() as client:
        yield client


@pytest.fixture
def auth_manager():
    """Create a mocked authentication manager for testing."""
    with patch('skwaq.api.auth.authenticate_user') as mock_auth:
        # Set up mocked user
        test_user = UserCredentials(
            username="testuser",
            password_hash="hash",
            salt="salt",
            roles={AuthRole.USER, AuthRole.ADMIN},
            user_id="test123"
        )
        mock_auth.return_value = test_user
        
        # Set up mocked token
        with patch('skwaq.api.auth.authenticate_token') as mock_token:
            mock_token.return_value = {
                'sub': 'test123',
                'username': 'testuser',
                'roles': ['user', 'admin']
            }
            
            # Set up mocked token generation
            with patch('skwaq.api.auth.generate_token') as mock_gen:
                mock_gen.return_value = "mocked.jwt.token"
                
                # Set up mocked authorization
                with patch('skwaq.api.auth.require_permission', lambda p: lambda f: f):
                    yield


class TestG2Milestone:
    """Test cases for the G2 milestone: GUI Backend Integration."""

    def test_rest_api_endpoints(self, client):
        """Test that the REST API endpoints are correctly implemented."""
        # Test the health check endpoint
        response = client.get('/api/healthcheck')
        assert response.status_code == 200
        assert response.json['status'] == 'healthy'
        
        # Test the auth endpoints exist
        response = client.get('/api/auth/login')
        assert response.status_code != 404, "Auth login endpoint not found"
        
        # Test the repositories endpoints exist
        response = client.get('/api/repositories')
        assert response.status_code != 404, "Repositories endpoint not found"
        
        # Test the events endpoint exists
        response = client.get('/api/events/repository/connect')
        assert response.status_code != 404, "Events endpoint not found"

    def test_authentication_flow(self, client, auth_manager):
        """Test that the authentication flow works correctly."""
        # Test login
        response = client.post(
            '/api/auth/login', 
            json={'username': 'testuser', 'password': 'testpass'}
        )
        assert response.status_code == 200
        assert 'token' in response.json
        assert response.json['user']['username'] == 'testuser'
        
        # Test protected endpoint with token
        response = client.get(
            '/api/repositories',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code != 401, "Authentication failed"
        
        # Test me endpoint
        response = client.get(
            '/api/auth/me',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 200
        assert response.json['user']['username'] == 'testuser'
        
        # Test refresh token
        response = client.post(
            '/api/auth/refresh',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 200
        assert 'token' in response.json

    def test_csrf_protection(self, client, auth_manager):
        """Test that CSRF protection is working."""
        # Without CSRF token, POST should fail
        response = client.post(
            '/api/repositories',
            json={'url': 'https://example.com/repo'},
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 403
        assert 'CSRF token missing' in response.json.get('error', '')
        
        # With CSRF token, POST should work
        response = client.post(
            '/api/repositories',
            json={'url': 'https://example.com/repo'},
            headers={
                'Authorization': f'Bearer mocked.jwt.token',
                'X-CSRF-Token': 'test-csrf-token'
            }
        )
        assert response.status_code != 403, "CSRF protection failed"

    @patch('skwaq.api.events.publish_repository_event')
    def test_realtime_updates(self, mock_publish, client, auth_manager):
        """Test that real-time updates for long-running processes work correctly."""
        # Ensure event publishing is called when adding a repository
        response = client.post(
            '/api/repositories',
            json={'url': 'https://example.com/repo'},
            headers={
                'Authorization': f'Bearer mocked.jwt.token',
                'X-CSRF-Token': 'test-csrf-token'
            }
        )
        assert response.status_code == 201
        mock_publish.assert_called_once()
        
        # Check SSE connection endpoint
        response = client.get('/api/events/repository/connect')
        assert response.status_code == 200
        assert response.mimetype == 'text/event-stream'

    @patch('skwaq.api.repositories.get_repositories_from_db')
    @patch('skwaq.api.repositories.get_repository_by_id')
    def test_repository_api(self, mock_get_by_id, mock_get_all, client, auth_manager):
        """Test that the repository API endpoints work correctly."""
        # Mock repository data
        mock_repos = [
            {
                'id': 'repo1',
                'name': 'test/repo',
                'description': 'Test repository',
                'status': 'Analyzed',
                'vulnerabilities': 5,
                'lastAnalyzed': '2025-03-25T12:00:00Z',
                'url': 'https://github.com/test/repo'
            }
        ]
        mock_get_all.return_value = mock_repos
        mock_get_by_id.return_value = mock_repos[0]
        
        # Test listing repositories
        response = client.get(
            '/api/repositories',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 200
        assert len(response.json) == 1
        assert response.json[0]['id'] == 'repo1'
        
        # Test getting a specific repository
        response = client.get(
            '/api/repositories/repo1',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 200
        assert response.json['id'] == 'repo1'
        
        # Test getting vulnerabilities
        response = client.get(
            '/api/repositories/repo1/vulnerabilities',
            headers={'Authorization': f'Bearer mocked.jwt.token'}
        )
        assert response.status_code == 200
        assert len(response.json) > 0