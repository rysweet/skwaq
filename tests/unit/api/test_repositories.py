"""Tests for the repository routes."""

import pytest
import json
from unittest.mock import patch, MagicMock

from skwaq.api import create_app


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app(
        {
            "TESTING": True,
            "JWT_SECRET": "test-jwt-secret",
            "JWT_ALGORITHM": "HS256",
        }
    )
    yield app


@pytest.fixture
def client(app):
    """A test client for the app."""
    return app.test_client()


@pytest.fixture
def auth_token(client):
    """Get authentication token for testing."""
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    data = json.loads(response.data)
    return data["token"]


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
    },
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

# Add repository response
MOCK_NEW_REPOSITORY = {
    "id": "new-repo-123",
    "name": "new-repo",
    "description": "Repository from https://github.com/test/new-repo",
    "status": "Initializing",
    "progress": 0,
    "vulnerabilities": None,
    "lastAnalyzed": None,
    "url": "https://github.com/test/new-repo",
}


@patch("skwaq.api.services.repository_service.get_all_repositories")
def test_get_repositories(mock_repos, client, auth_token):
    """Test getting all repositories."""
    # Setup the mock
    mock_repos.return_value = MOCK_REPOSITORIES

    # Call the route that uses asyncio.run(repository_service.get_all_repositories())
    with patch(
        "skwaq.api.routes.repositories.asyncio.run", return_value=MOCK_REPOSITORIES
    ):
        response = client.get(
            "/api/repositories", headers={"Authorization": f"Bearer {auth_token}"}
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == "repo-123"
    assert data[1]["id"] == "repo-456"


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_get_repository(mock_repo, client, auth_token):
    """Test getting a repository by ID."""
    # Setup the mock
    mock_repo.return_value = MOCK_REPOSITORY

    # Call the route
    with patch(
        "skwaq.api.routes.repositories.asyncio.run", return_value=MOCK_REPOSITORY
    ):
        response = client.get(
            "/api/repositories/repo-123",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "repo-123"
    assert data["name"] == "test-repo"
    assert data["status"] == "Analyzed"


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_get_repository_not_found(mock_repo, client, auth_token):
    """Test getting a repository that doesn't exist."""
    # Configure mock to return None
    mock_repo.return_value = None

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=None):
        response = client.get(
            "/api/repositories/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.repository_service.add_repository")
def test_add_repository(mock_add, client, auth_token):
    """Test adding a new repository."""
    # Setup the mock
    mock_add.return_value = MOCK_NEW_REPOSITORY

    # Call the route
    with patch(
        "skwaq.api.routes.repositories.asyncio.run", return_value=MOCK_NEW_REPOSITORY
    ):
        response = client.post(
            "/api/repositories",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={
                "url": "https://github.com/test/new-repo",
                "options": {"deepAnalysis": True, "includeDependencies": False},
            },
        )

    # Check the response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == "new-repo-123"
    assert data["name"] == "new-repo"
    assert data["status"] == "Initializing"


def test_add_repository_missing_url(client, auth_token):
    """Test adding a repository without a URL."""
    response = client.post(
        "/api/repositories",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={"options": {"deepAnalysis": True}},
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.repository_service.get_repository_by_id")
@patch("skwaq.api.services.repository_service.delete_repository")
def test_delete_repository(mock_delete, mock_get, client, auth_token):
    """Test deleting a repository."""
    # Setup the mocks
    mock_get.return_value = MOCK_REPOSITORY
    mock_delete.return_value = True

    # Call the route
    with patch(
        "skwaq.api.routes.repositories.asyncio.run", side_effect=[MOCK_REPOSITORY, True]
    ):
        response = client.delete(
            "/api/repositories/repo-123",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 204
    assert response.data == b""


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_delete_repository_not_found(mock_get, client, auth_token):
    """Test deleting a repository that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=None):
        response = client.delete(
            "/api/repositories/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.repository_service.get_repository_by_id")
@patch("skwaq.api.services.repository_service.get_repository_vulnerabilities")
def test_get_vulnerabilities(mock_vulns, mock_repo, client, auth_token):
    """Test getting vulnerabilities for a repository."""
    # Setup the mocks
    mock_repo.return_value = MOCK_REPOSITORY
    mock_vulns.return_value = MOCK_VULNERABILITIES

    # Call the route
    with patch(
        "skwaq.api.routes.repositories.asyncio.run",
        side_effect=[MOCK_REPOSITORY, MOCK_VULNERABILITIES],
    ):
        response = client.get(
            "/api/repositories/repo-123/vulnerabilities",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 2
    assert data[0]["id"] == "vuln1"
    assert data[0]["name"] == "SQL Injection"
    assert data[1]["id"] == "vuln2"
    assert data[1]["name"] == "Cross-Site Scripting"


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_analyze_repository(mock_repo, client, auth_token):
    """Test starting analysis for a repository."""
    # Set up mock to return a repository with status not "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository["status"] = "Analyzed"
    mock_repo.return_value = repository

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=repository):
        response = client.post(
            "/api/repositories/repo-123/analyze",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"deepAnalysis": True, "includeDependencies": False},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "repository" in data
    assert "task" in data
    assert data["repository"]["status"] == "Analyzing"
    assert data["task"]["status"] == "running"


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_analyze_repository_already_analyzing(mock_repo, client, auth_token):
    """Test starting analysis for a repository that's already being analyzed."""
    # Set up mock to return a repository with status "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository["status"] = "Analyzing"
    mock_repo.return_value = repository

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=repository):
        response = client.post(
            "/api/repositories/repo-123/analyze",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={},
        )

    # Check the response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_cancel_analysis(mock_repo, client, auth_token):
    """Test cancelling analysis for a repository."""
    # Set up mock to return a repository with status "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository["status"] = "Analyzing"
    mock_repo.return_value = repository

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=repository):
        response = client.post(
            "/api/repositories/repo-123/cancel",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 204
    assert response.data == b""


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_cancel_analysis_not_analyzing(mock_repo, client, auth_token):
    """Test cancelling analysis for a repository that's not being analyzed."""
    # Set up mock to return a repository with status not "Analyzing"
    repository = MOCK_REPOSITORY.copy()
    repository["status"] = "Analyzed"
    mock_repo.return_value = repository

    # Call the route
    with patch("skwaq.api.routes.repositories.asyncio.run", return_value=repository):
        response = client.post(
            "/api/repositories/repo-123/cancel",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.repository_service.get_repository_by_id")
def test_get_analysis_status(mock_repo, client, auth_token):
    """Test getting analysis status for a repository."""
    # Call the route
    with patch(
        "skwaq.api.routes.repositories.asyncio.run", return_value=MOCK_REPOSITORY
    ):
        response = client.get(
            "/api/repositories/repo-123/analysis/status",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["repoId"] == "repo-123"
    assert data["status"] == "Analyzed"
    assert data["analysis"] is None
