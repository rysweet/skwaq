"""Tests for the repository routes."""

import pytest
import json
import asyncio
from unittest.mock import patch, MagicMock, Mock
from typing import Dict, Any, List

from skwaq.api import create_app


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app({
        'TESTING': True,
        'JWT_SECRET': 'test-jwt-secret',
        'JWT_ALGORITHM': 'HS256',
    })
    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def auth_token(client):
    """Get authentication token for testing."""
    response = client.post(
        '/api/auth/login',
        json={'username': 'admin', 'password': 'admin'}
    )
    data = json.loads(response.data)
    return data['token']


# Mock repository data
MOCK_REPOSITORIES = [
    {
        "id": "repo-123",
        "name": "test-repo",
        "description": "Test repository",
        "status": "Analyzed",
        "vulnerabilities": 5,
        "lastAnalyzed": "2025-03-28T12:00:00Z",
        "url": "https://github.com/test/repo",
    },
    {
        "id": "repo-456",
        "name": "another-repo",
        "description": "Another test repository",
        "status": "Analyzing",
        "vulnerabilities": None,
        "lastAnalyzed": None,
        "url": "https://github.com/test/another-repo",
    }
]

# Mock repository by ID
MOCK_REPOSITORY = {
    "id": "repo-123",
    "name": "test-repo",
    "description": "Test repository",
    "status": "Analyzed",
    "progress": 100,
    "vulnerabilities": 5,
    "lastAnalyzed": "2025-03-28T12:00:00Z",
    "fileCount": 100,
    "url": "https://github.com/test/repo",
}

# Mock vulnerabilities
MOCK_VULNERABILITIES = [
    {
        "id": "vuln1",
        "name": "SQL Injection",
        "type": "Injection",
        "severity": "High",
        "file": "src/auth.py",
        "line": 42,
        "description": "Unsanitized user input used in SQL query",
        "cweId": "CWE-89",
        "remediation": "Use parameterized queries or prepared statements",
    },
    {
        "id": "vuln2",
        "name": "Cross-Site Scripting",
        "type": "XSS",
        "severity": "Medium",
        "file": "src/templates/index.html",
        "line": 23,
        "description": "Unescaped user data rendered in HTML",
        "cweId": "CWE-79",
        "remediation": "Use context-aware escaping for user data",
    },
]


# Mock asyncio.run
@pytest.fixture(autouse=True)
def mock_asyncio_run():
    """Mock asyncio.run to handle the async service functions."""
    with patch('asyncio.run') as mock:
        # Make mock return the coroutine's result
        mock.side_effect = lambda coroutine: coroutine
        yield mock


# Mock get_all_repositories function
@pytest.fixture
def mock_get_all_repositories():
    """Mock the get_all_repositories function."""
    with patch('skwaq.api.services.repository_service.get_all_repositories') as mock:
        mock.return_value = MOCK_REPOSITORIES
        yield mock


# Mock get_repository_by_id function
@pytest.fixture
def mock_get_repository_by_id():
    """Mock the get_repository_by_id function."""
    with patch('skwaq.api.services.repository_service.get_repository_by_id') as mock:
        mock.return_value = MOCK_REPOSITORY
        yield mock


# Mock get_repository_vulnerabilities function
@pytest.fixture
def mock_get_repository_vulnerabilities():
    """Mock the get_repository_vulnerabilities function."""
    with patch('skwaq.api.services.repository_service.get_repository_vulnerabilities') as mock:
        mock.return_value = MOCK_VULNERABILITIES
        yield mock


# Mock add_repository function
@pytest.fixture
def mock_add_repository():
    """Mock the add_repository function."""
    with patch('skwaq.api.services.repository_service.add_repository') as mock:
        mock.return_value = {
            "id": "new-repo-123",
            "name": "new-repo",
            "description": "Repository from https://github.com/test/new-repo",
            "status": "Initializing",
            "progress": 0,
            "vulnerabilities": None,
            "lastAnalyzed": None,
            "url": "https://github.com/test/new-repo",
        }
        yield mock


# Mock delete_repository function
@pytest.fixture
def mock_delete_repository():
    """Mock the delete_repository function."""
    with patch('skwaq.api.services.repository_service.delete_repository') as mock:
        mock.return_value = True
        yield mock


# Helper class for creating async mocks
class AsyncMock(MagicMock):
    """Mock class that works with async/await."""
    
    async def __call__(self, *args, **kwargs):
        return super(AsyncMock, self).__call__(*args, **kwargs)


def test_get_repositories(client, auth_token, mock_get_all_repositories):
    """Test getting all repositories."""
    response = client.get(
        '/api/repositories',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]['id'] == 'repo-123'
    assert data[1]['id'] == 'repo-456'


def test_get_repository(client, auth_token, mock_get_repository_by_id):
    """Test getting a repository by ID."""
    response = client.get(
        '/api/repositories/repo-123',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['id'] == 'repo-123'
    assert data['name'] == 'test-repo'
    assert data['status'] == 'Analyzed'


def test_get_repository_not_found(client, auth_token, mock_get_repository_by_id):
    """Test getting a repository that doesn't exist."""
    # Configure mock to return None
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(None)
    
    response = client.get(
        '/api/repositories/nonexistent',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data


def test_add_repository(client, auth_token, mock_add_repository):
    """Test adding a new repository."""
    response = client.post(
        '/api/repositories',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={
            'url': 'https://github.com/test/new-repo',
            'options': {
                'deepAnalysis': True,
                'includeDependencies': False
            }
        }
    )
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data['id'] == 'new-repo-123'
    assert data['name'] == 'new-repo'
    assert data['status'] == 'Initializing'


def test_add_repository_missing_url(client, auth_token):
    """Test adding a repository without a URL."""
    response = client.post(
        '/api/repositories',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={
            'options': {
                'deepAnalysis': True
            }
        }
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_delete_repository(client, auth_token, mock_get_repository_by_id, mock_delete_repository):
    """Test deleting a repository."""
    response = client.delete(
        '/api/repositories/repo-123',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 204
    assert response.data == b''


def test_delete_repository_not_found(client, auth_token, mock_get_repository_by_id):
    """Test deleting a repository that doesn't exist."""
    # Configure mock to return None
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(None)
    
    response = client.delete(
        '/api/repositories/nonexistent',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 404
    data = json.loads(response.data)
    assert 'error' in data


def test_get_vulnerabilities(client, auth_token, mock_get_repository_by_id, mock_get_repository_vulnerabilities):
    """Test getting vulnerabilities for a repository."""
    response = client.get(
        '/api/repositories/repo-123/vulnerabilities',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]['id'] == 'vuln1'
    assert data[0]['name'] == 'SQL Injection'
    assert data[1]['id'] == 'vuln2'
    assert data[1]['name'] == 'Cross-Site Scripting'


def test_analyze_repository(client, auth_token, mock_get_repository_by_id):
    """Test starting analysis for a repository."""
    # Set up mock to return a repository with status not "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository['status'] = 'Analyzed'
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(repository)
    
    response = client.post(
        '/api/repositories/repo-123/analyze',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={
            'deepAnalysis': True,
            'includeDependencies': False
        }
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert 'repository' in data
    assert 'task' in data
    assert data['repository']['status'] == 'Analyzing'
    assert data['task']['status'] == 'running'


def test_analyze_repository_already_analyzing(client, auth_token, mock_get_repository_by_id):
    """Test starting analysis for a repository that's already being analyzed."""
    # Set up mock to return a repository with status "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository['status'] = 'Analyzing'
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(repository)
    
    response = client.post(
        '/api/repositories/repo-123/analyze',
        headers={'Authorization': f'Bearer {auth_token}'},
        json={}
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_cancel_analysis(client, auth_token, mock_get_repository_by_id):
    """Test cancelling analysis for a repository."""
    # Set up mock to return a repository with status "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository['status'] = 'Analyzing'
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(repository)
    
    response = client.post(
        '/api/repositories/repo-123/cancel',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 204
    assert response.data == b''


def test_cancel_analysis_not_analyzing(client, auth_token, mock_get_repository_by_id):
    """Test cancelling analysis for a repository that's not being analyzed."""
    # Set up mock to return a repository with status not "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository['status'] = 'Analyzed'
    mock_get_repository_by_id.return_value = asyncio.Future()
    mock_get_repository_by_id.return_value.set_result(repository)
    
    response = client.post(
        '/api/repositories/repo-123/cancel',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_get_analysis_status(client, auth_token, mock_get_repository_by_id):
    """Test getting analysis status for a repository."""
    response = client.get(
        '/api/repositories/repo-123/analysis/status',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data['repoId'] == 'repo-123'
    assert data['status'] == 'Analyzed'
    assert data['analysis'] is None