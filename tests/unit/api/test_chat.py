"""Tests for the chat routes."""

import pytest
import json
from unittest.mock import patch, MagicMock
import time
from datetime import datetime

from skwaq.api import create_app
from skwaq.api.services import chat_service


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

    # Clear conversations after tests
    chat_service.CONVERSATIONS = {}
    chat_service.MESSAGES = {}


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


# Mock conversation data
MOCK_CONVERSATION = {
    "id": "conv-123",
    "title": "Test Conversation",
    "userId": "user-001",
    "createdAt": "2025-03-28T12:00:00Z",
    "updatedAt": "2025-03-28T12:15:00Z",
    "context": {},
    "messages": [
        {
            "id": "msg-1",
            "conversationId": "conv-123",
            "userId": "system",
            "sender": "system",
            "content": "Welcome to the conversation",
            "timestamp": "2025-03-28T12:00:00Z",
        },
        {
            "id": "msg-2",
            "conversationId": "conv-123",
            "userId": "user-001",
            "sender": "user",
            "content": "Hello system",
            "timestamp": "2025-03-28T12:05:00Z",
        },
        {
            "id": "msg-3",
            "conversationId": "conv-123",
            "userId": "assistant",
            "sender": "assistant",
            "content": "Hello! How can I help you?",
            "timestamp": "2025-03-28T12:05:10Z",
        },
    ],
    "messageCount": 3,
    "lastMessageTime": "2025-03-28T12:05:10Z",
}

MOCK_MESSAGES = [
    {
        "id": "msg-1",
        "conversationId": "conv-123",
        "userId": "system",
        "sender": "system",
        "content": "Welcome to the conversation",
        "timestamp": "2025-03-28T12:00:00Z",
    },
    {
        "id": "msg-2",
        "conversationId": "conv-123",
        "userId": "user-001",
        "sender": "user",
        "content": "Hello system",
        "timestamp": "2025-03-28T12:05:00Z",
    },
    {
        "id": "msg-3",
        "conversationId": "conv-123",
        "userId": "assistant",
        "sender": "assistant",
        "content": "Hello! How can I help you?",
        "timestamp": "2025-03-28T12:05:10Z",
    },
]

MOCK_USER_MESSAGE = {
    "id": "msg-4",
    "conversationId": "conv-123",
    "userId": "user-001",
    "sender": "user",
    "content": "I need help with security analysis",
    "timestamp": "2025-03-28T12:10:00Z",
}


@patch("skwaq.api.services.chat_service.get_conversations")
def test_get_conversations(mock_get, client, auth_token):
    """Test getting all conversations."""
    # Setup the mock
    mock_get.return_value = [MOCK_CONVERSATION]

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=[MOCK_CONVERSATION]):
        response = client.get(
            "/api/chat/conversations", headers={"Authorization": f"Bearer {auth_token}"}
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 1
    assert data[0]["id"] == "conv-123"
    assert data[0]["title"] == "Test Conversation"
    assert data[0]["messageCount"] == 3


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
def test_get_conversation(mock_get, client, auth_token):
    """Test getting a conversation by ID."""
    # Setup the mock
    mock_get.return_value = MOCK_CONVERSATION

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=MOCK_CONVERSATION):
        response = client.get(
            "/api/chat/conversations/conv-123",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "conv-123"
    assert data["title"] == "Test Conversation"
    assert len(data["messages"]) == 3


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
def test_get_conversation_not_found(mock_get, client, auth_token):
    """Test getting a conversation that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=None):
        response = client.get(
            "/api/chat/conversations/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.chat_service.create_conversation")
def test_create_conversation(mock_create, client, auth_token):
    """Test creating a new conversation."""
    # Setup the mock
    new_conversation = MOCK_CONVERSATION.copy()
    new_conversation["id"] = "conv-new"
    new_conversation["title"] = "New Test Conversation"
    mock_create.return_value = new_conversation

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=new_conversation):
        response = client.post(
            "/api/chat/conversations",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"title": "New Test Conversation"},
        )

    # Check the response
    assert response.status_code == 201
    data = json.loads(response.data)
    assert data["id"] == "conv-new"
    assert data["title"] == "New Test Conversation"


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
@patch("skwaq.api.services.chat_service.delete_conversation")
def test_delete_conversation(mock_delete, mock_get, client, auth_token):
    """Test deleting a conversation."""
    # Setup the mocks
    mock_get.return_value = MOCK_CONVERSATION
    mock_delete.return_value = True

    # Call the route
    with patch(
        "skwaq.api.routes.chat.asyncio.run", side_effect=[MOCK_CONVERSATION, True]
    ):
        response = client.delete(
            "/api/chat/conversations/conv-123",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 204
    assert response.data == b""


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
def test_delete_conversation_not_found(mock_get, client, auth_token):
    """Test deleting a conversation that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=None):
        response = client.delete(
            "/api/chat/conversations/nonexistent",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
@patch("skwaq.api.services.chat_service.get_messages")
def test_get_messages(mock_messages, mock_get, client, auth_token):
    """Test getting all messages for a conversation."""
    # Setup the mocks
    mock_get.return_value = MOCK_CONVERSATION
    mock_messages.return_value = MOCK_MESSAGES

    # Call the route
    with patch(
        "skwaq.api.routes.chat.asyncio.run",
        side_effect=[MOCK_CONVERSATION, MOCK_MESSAGES],
    ):
        response = client.get(
            "/api/chat/conversations/conv-123/messages",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert isinstance(data, list)
    assert len(data) == 3
    assert data[0]["id"] == "msg-1"
    assert data[1]["id"] == "msg-2"
    assert data[2]["id"] == "msg-3"


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
def test_get_messages_conversation_not_found(mock_get, client, auth_token):
    """Test getting messages for a conversation that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=None):
        response = client.get(
            "/api/chat/conversations/nonexistent/messages",
            headers={"Authorization": f"Bearer {auth_token}"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
@patch("skwaq.api.services.chat_service.send_message")
def test_send_message(mock_send, mock_get, client, auth_token):
    """Test sending a message in a conversation."""
    # Setup the mocks
    mock_get.return_value = MOCK_CONVERSATION
    mock_send.return_value = MOCK_USER_MESSAGE

    # Call the route
    with patch(
        "skwaq.api.routes.chat.asyncio.run",
        side_effect=[MOCK_CONVERSATION, MOCK_USER_MESSAGE],
    ):
        response = client.post(
            "/api/chat/conversations/conv-123/messages",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"content": "I need help with security analysis"},
        )

    # Check the response
    assert response.status_code == 200
    data = json.loads(response.data)
    assert data["id"] == "msg-4"
    assert data["content"] == "I need help with security analysis"
    assert data["sender"] == "user"


def test_send_message_missing_content(client, auth_token):
    """Test sending a message without content."""
    response = client.post(
        "/api/chat/conversations/conv-123/messages",
        headers={"Authorization": f"Bearer {auth_token}"},
        json={},
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert "error" in data


@patch("skwaq.api.services.chat_service.get_conversation_by_id")
def test_send_message_conversation_not_found(mock_get, client, auth_token):
    """Test sending a message to a conversation that doesn't exist."""
    # Configure mock to return None
    mock_get.return_value = None

    # Call the route
    with patch("skwaq.api.routes.chat.asyncio.run", return_value=None):
        response = client.post(
            "/api/chat/conversations/nonexistent/messages",
            headers={"Authorization": f"Bearer {auth_token}"},
            json={"content": "Test message"},
        )

    # Check the response
    assert response.status_code == 404
    data = json.loads(response.data)
    assert "error" in data
