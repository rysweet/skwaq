"""Tests for the authentication routes."""

import json

import jwt
import pytest

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


def test_health_check(client):
    """Test the health check endpoint."""
    response = client.get("/api/health")
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["status"] == "healthy"


def test_login_success(client):
    """Test successful login."""
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data
    assert "user" in data
    assert data["user"]["username"] == "admin"
    assert "admin" in data["user"]["roles"]

    # Verify token
    token = data["token"]
    payload = jwt.decode(
        token,
        "test-jwt-secret",
        algorithms=["HS256"],
        options={
            "verify_exp": False,
            "verify_iat": False,
        },  # Disable time validation for testing
    )
    assert payload["username"] == "admin"
    assert "admin" in payload["roles"]


def test_login_missing_credentials(client):
    """Test login with missing credentials."""
    response = client.post("/api/auth/login", json={"username": "admin"})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data

    response = client.post("/api/auth/login", json={"password": "admin"})
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


def test_login_invalid_credentials(client):
    """Test login with invalid credentials."""
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "wrong-password"}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data

    response = client.post(
        "/api/auth/login",
        json={"username": "non-existent-user", "password": "password"},
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data


def test_logout(client):
    """Test logout endpoint."""
    # First, login to get a token
    login_response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert login_response.status_code == 200
    login_data = json.loads(login_response.data)
    token = login_data["token"]

    # Then, try to logout
    response = client.post(
        "/api/auth/logout", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "message" in data
    assert data["message"] == "Successfully logged out"


def test_me(client):
    """Test me endpoint."""
    # First, login to get a token
    login_response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert login_response.status_code == 200
    login_data = json.loads(login_response.data)
    token = login_data["token"]

    # Then, get user info
    response = client.get("/api/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "user" in data
    assert data["user"]["username"] == "admin"
    assert "admin" in data["user"]["roles"]


def test_refresh(client):
    """Test refresh endpoint."""
    # First, login to get a token
    login_response = client.post(
        "/api/auth/login", json={"username": "admin", "password": "admin"}
    )
    assert login_response.status_code == 200
    login_data = json.loads(login_response.data)
    token = login_data["token"]

    # Then, refresh the token
    response = client.post(
        "/api/auth/refresh", headers={"Authorization": f"Bearer {token}"}
    )
    assert response.status_code == 200
    data = json.loads(response.data)
    assert "token" in data
    assert "user" in data
    assert data["user"]["username"] == "admin"
    assert "admin" in data["user"]["roles"]

    # Verify the new token
    new_token = data["token"]
    assert new_token != token
    payload = jwt.decode(
        new_token,
        "test-jwt-secret",
        algorithms=["HS256"],
        options={
            "verify_exp": False,
            "verify_iat": False,
        },  # Disable time validation for testing
    )
    assert payload["username"] == "admin"
    assert "admin" in payload["roles"]


def test_protected_route_without_token(client):
    """Test protected routes without a token."""
    response = client.get("/api/auth/me")
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data

    response = client.post("/api/auth/logout")
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data

    response = client.post("/api/auth/refresh")
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data


def test_protected_route_with_invalid_token(client):
    """Test protected routes with an invalid token."""
    response = client.get(
        "/api/auth/me", headers={"Authorization": "Bearer invalid-token"}
    )
    assert response.status_code == 401
    data = json.loads(response.data)
    assert "error" in data
