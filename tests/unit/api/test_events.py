"""Tests for the event streaming routes."""

import pytest
import json
import queue
from unittest.mock import patch, MagicMock

from skwaq.api import create_app
from skwaq.api.services import event_service


@pytest.fixture
def app():
    """Create and configure a Flask app for testing."""
    app = create_app({
        'TESTING': True,
        'JWT_SECRET': 'test-jwt-secret',
        'JWT_ALGORITHM': 'HS256',
    })
    yield app
    
    # Reset event queues after each test
    event_service.event_queues = {
        "repository": {},
        "analysis": {},
        "chat": {},
        "system": {},
    }


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


def test_invalid_channel(client, auth_token):
    """Test connecting to an invalid channel."""
    response = client.get(
        '/api/events/invalid-channel/connect',
        headers={'Authorization': f'Bearer {auth_token}'}
    )
    assert response.status_code == 400
    data = json.loads(response.data)
    assert 'error' in data


def test_publish_event(client, auth_token):
    """Test publishing an event to a channel."""
    # First connect to the channel
    # Note: We can't actually test streaming responses in a unit test easily,
    # so we'll focus on testing the underlying service functions
    
    # Create a test client queue
    client_id = 'test-client'
    channel = 'repository'
    client_queue = event_service.get_client_queue(channel, client_id)
    
    # Publish an event
    test_data = {'message': 'Test event'}
    event_service.publish_repository_event('test_event', test_data)
    
    # Check that the event was added to the queue
    event = client_queue.get(timeout=1)
    assert event['type'] == 'test_event'
    assert event['data'] == test_data
    
    # Queue should be empty now
    assert client_queue.empty()


def test_disconnect_client():
    """Test disconnecting a client."""
    # Create a test client queue
    client_id = 'test-client'
    channel = 'repository'
    event_service.get_client_queue(channel, client_id)
    
    # Check that the client is in the event queues
    assert client_id in event_service.event_queues[channel]
    
    # Disconnect the client
    event_service.disconnect_client(channel, client_id)
    
    # Check that the client is no longer in the event queues
    assert client_id not in event_service.event_queues[channel]


def test_publish_to_specific_channels():
    """Test publishing events to specific channels."""
    # Create test client queues for different channels
    client_id = 'test-client'
    repository_queue = event_service.get_client_queue('repository', client_id)
    analysis_queue = event_service.get_client_queue('analysis', client_id)
    chat_queue = event_service.get_client_queue('chat', client_id)
    system_queue = event_service.get_client_queue('system', client_id)
    
    # Publish events to each channel
    event_service.publish_repository_event('repo_event', {'channel': 'repository'})
    event_service.publish_analysis_event('analysis_event', {'channel': 'analysis'})
    event_service.publish_chat_event('chat_event', {'channel': 'chat'})
    event_service.publish_system_event('system_event', {'channel': 'system'})
    
    # Check that each queue received the correct event
    repo_event = repository_queue.get(timeout=1)
    assert repo_event['type'] == 'repo_event'
    assert repo_event['data']['channel'] == 'repository'
    
    analysis_event = analysis_queue.get(timeout=1)
    assert analysis_event['type'] == 'analysis_event'
    assert analysis_event['data']['channel'] == 'analysis'
    
    chat_event = chat_queue.get(timeout=1)
    assert chat_event['type'] == 'chat_event'
    assert chat_event['data']['channel'] == 'chat'
    
    system_event = system_queue.get(timeout=1)
    assert system_event['type'] == 'system_event'
    assert system_event['data']['channel'] == 'system'
    
    # All queues should be empty now
    assert repository_queue.empty()
    assert analysis_queue.empty()
    assert chat_queue.empty()
    assert system_queue.empty()


def test_publish_to_multiple_clients():
    """Test publishing an event to multiple clients on the same channel."""
    # Create test client queues for different clients
    client1_id = 'client1'
    client2_id = 'client2'
    client1_queue = event_service.get_client_queue('repository', client1_id)
    client2_queue = event_service.get_client_queue('repository', client2_id)
    
    # Publish an event to the channel
    event_data = {'message': 'Multi-client event'}
    event_service.publish_repository_event('multi_client', event_data)
    
    # Check that both queues received the event
    client1_event = client1_queue.get(timeout=1)
    assert client1_event['type'] == 'multi_client'
    assert client1_event['data'] == event_data
    
    client2_event = client2_queue.get(timeout=1)
    assert client2_event['type'] == 'multi_client'
    assert client2_event['data'] == event_data
    
    # Both queues should be empty now
    assert client1_queue.empty()
    assert client2_queue.empty()