"""Unit tests for the system_events module."""

import json
from unittest.mock import MagicMock, patch

from skwaq.events.system_events import (
    AnalysisEvent,
    EventBus,
    EventSubscriber,
    EventType,
    RepositoryEvent,
    SystemEvent,
    SystemStatusEvent,
    UserInteractionEvent,
)


class TestSystemEvent:
    """Tests for the SystemEvent class."""

    def test_initialization(self):
        """Test event initialization."""
        event = SystemEvent(
            sender="test_sender",
            message="test message",
            target="test_target",
            metadata={"key": "value"},
        )

        assert event.sender == "test_sender"
        assert event.message == "test message"
        assert event.target == "test_target"
        assert event.metadata == {"key": "value"}
        assert isinstance(event.timestamp, float)
        assert isinstance(event.event_id, str)

    def test_serialization(self):
        """Test event serialization."""
        event = SystemEvent(
            sender="test_sender",
            message="test message",
            target="test_target",
            metadata={"key": "value"},
        )

        serialized = event.to_json()
        assert isinstance(serialized, str)

        data = json.loads(serialized)
        assert data["sender"] == "test_sender"
        assert data["message"] == "test message"
        assert data["target"] == "test_target"
        assert data["metadata"] == {"key": "value"}
        assert "timestamp" in data
        assert "event_id" in data
        assert "event_type" in data

    def test_from_json(self):
        """Test event deserialization."""
        event = SystemEvent(
            sender="test_sender",
            message="test message",
            target="test_target",
            metadata={"key": "value"},
        )

        serialized = event.to_json()
        deserialized = SystemEvent.from_json(serialized)

        assert deserialized.sender == event.sender
        assert deserialized.message == event.message
        assert deserialized.target == event.target
        assert deserialized.metadata == event.metadata
        assert deserialized.timestamp == event.timestamp
        assert deserialized.event_id == event.event_id

    def test_str_representation(self):
        """Test string representation of an event."""
        event = SystemEvent(
            sender="test_sender",
            message="test message",
        )

        str_repr = str(event)
        assert "SystemEvent" in str_repr
        assert "test_sender" in str_repr
        assert "test message" in str_repr


class TestEventBus:
    """Tests for the EventBus class."""

    def test_singleton(self):
        """Test EventBus singleton pattern."""
        bus1 = EventBus()
        bus2 = EventBus()

        assert bus1 is bus2

    def test_subscribe_unsubscribe(self):
        """Test subscribing and unsubscribing from events."""
        bus = EventBus()

        # Clear any existing subscriptions from previous tests
        bus._subscribers = {}

        # Define a test handler
        def test_handler(event):
            pass

        # Subscribe to an event
        subscriber_id = bus.subscribe(SystemEvent, test_handler)

        # Check subscription
        assert SystemEvent in bus._subscribers
        assert subscriber_id in bus._subscribers[SystemEvent]

        # Unsubscribe
        bus.unsubscribe(subscriber_id)

        # Check unsubscription
        assert subscriber_id not in bus._subscribers[SystemEvent]

    def test_publish(self):
        """Test publishing events."""
        bus = EventBus()

        # Clear any existing subscriptions from previous tests
        bus._subscribers = {}

        # Create a mock handler
        mock_handler = MagicMock()

        # Subscribe to an event
        bus.subscribe(SystemEvent, mock_handler)

        # Create and publish an event
        event = SystemEvent(sender="test_sender", message="test message")
        bus.publish(event)

        # Verify the handler was called
        mock_handler.assert_called_once_with(event)

    def test_get_subscribers(self):
        """Test getting subscribers for an event type."""
        bus = EventBus()

        # Clear any existing subscriptions from previous tests
        bus._subscribers = {}

        # Define test handlers
        def handler1(event):
            pass

        def handler2(event):
            pass

        # Subscribe to events
        id1 = bus.subscribe(SystemEvent, handler1)
        id2 = bus.subscribe(SystemEvent, handler2)

        # Get subscribers
        subscribers = bus.get_subscribers(SystemEvent)

        assert len(subscribers) == 2
        assert id1 in subscribers
        assert id2 in subscribers


class TestEventSubscriber:
    """Tests for the EventSubscriber class."""

    def test_subscriber_initialization(self):
        """Test subscriber initialization."""
        subscriber = EventSubscriber(name="test_subscriber")

        assert subscriber.name == "test_subscriber"
        assert subscriber.subscriptions == {}

    def test_subscribe(self):
        """Test subscribing to events."""
        with patch("skwaq.events.system_events.EventBus") as mock_bus_cls:
            mock_bus = MagicMock()
            mock_bus.subscribe.return_value = "subscription_id"
            mock_bus_cls.return_value = mock_bus

            subscriber = EventSubscriber(name="test_subscriber")

            # Define a test handler
            def test_handler(event):
                pass

            # Subscribe to an event
            subscriber.subscribe(SystemEvent, test_handler)

            # Verify EventBus.subscribe was called
            mock_bus.subscribe.assert_called_once_with(SystemEvent, test_handler)

            # Check subscription was stored
            assert SystemEvent in subscriber.subscriptions
            assert subscriber.subscriptions[SystemEvent] == "subscription_id"

    def test_unsubscribe(self):
        """Test unsubscribing from events."""
        with patch("skwaq.events.system_events.EventBus") as mock_bus_cls:
            mock_bus = MagicMock()
            mock_bus.subscribe.return_value = "subscription_id"
            mock_bus_cls.return_value = mock_bus

            subscriber = EventSubscriber(name="test_subscriber")

            # Define a test handler
            def test_handler(event):
                pass

            # Subscribe to an event
            subscriber.subscribe(SystemEvent, test_handler)

            # Unsubscribe from the event
            subscriber.unsubscribe(SystemEvent)

            # Verify EventBus.unsubscribe was called
            mock_bus.unsubscribe.assert_called_once_with("subscription_id")

            # Check subscription was removed
            assert SystemEvent not in subscriber.subscriptions

    def test_unsubscribe_all(self):
        """Test unsubscribing from all events."""
        with patch("skwaq.events.system_events.EventBus") as mock_bus_cls:
            mock_bus = MagicMock()
            mock_bus.subscribe.side_effect = ["id1", "id2"]
            mock_bus_cls.return_value = mock_bus

            subscriber = EventSubscriber(name="test_subscriber")

            # Define test handlers
            def handler1(event):
                pass

            def handler2(event):
                pass

            # Subscribe to events
            subscriber.subscribe(SystemEvent, handler1)
            subscriber.subscribe(RepositoryEvent, handler2)

            # Unsubscribe from all events
            subscriber.unsubscribe_all()

            # Verify EventBus.unsubscribe was called for each subscription
            assert mock_bus.unsubscribe.call_count == 2

            # Check all subscriptions were removed
            assert subscriber.subscriptions == {}


class TestRepositoryEvent:
    """Tests for the RepositoryEvent class."""

    def test_repository_event(self):
        """Test RepositoryEvent initialization and properties."""
        event = RepositoryEvent(
            sender="test_sender",
            repository_id="repo123",
            repository_name="test-repo",
            action="clone",
            message="Repository cloned",
            metadata={"path": "/path/to/repo"},
        )

        assert event.sender == "test_sender"
        assert event.repository_id == "repo123"
        assert event.repository_name == "test-repo"
        assert event.action == "clone"
        assert event.message == "Repository cloned"
        assert event.metadata == {"path": "/path/to/repo"}
        assert event.event_type == EventType.REPOSITORY


class TestAnalysisEvent:
    """Tests for the AnalysisEvent class."""

    def test_analysis_event(self):
        """Test AnalysisEvent initialization and properties."""
        event = AnalysisEvent(
            sender="test_sender",
            repository_id="repo123",
            finding_id="find456",
            severity="high",
            confidence=0.85,
            message="Vulnerability found",
            metadata={"line": 42, "file": "main.py"},
        )

        assert event.sender == "test_sender"
        assert event.repository_id == "repo123"
        assert event.finding_id == "find456"
        assert event.severity == "high"
        assert event.confidence == 0.85
        assert event.message == "Vulnerability found"
        assert event.metadata == {"line": 42, "file": "main.py"}
        assert event.event_type == EventType.ANALYSIS


class TestUserInteractionEvent:
    """Tests for the UserInteractionEvent class."""

    def test_user_interaction_event(self):
        """Test UserInteractionEvent initialization and properties."""
        event = UserInteractionEvent(
            sender="test_sender",
            interaction_type="command",
            command="analyze",
            message="User requested analysis",
            metadata={"args": ["--repo", "test-repo"]},
        )

        assert event.sender == "test_sender"
        assert event.interaction_type == "command"
        assert event.command == "analyze"
        assert event.message == "User requested analysis"
        assert event.metadata == {"args": ["--repo", "test-repo"]}
        assert event.event_type == EventType.USER_INTERACTION


class TestSystemStatusEvent:
    """Tests for the SystemStatusEvent class."""

    def test_system_status_event(self):
        """Test SystemStatusEvent initialization and properties."""
        event = SystemStatusEvent(
            sender="test_sender",
            status="starting",
            component="analyzer",
            message="Analyzer starting",
            metadata={"version": "1.0.0"},
        )

        assert event.sender == "test_sender"
        assert event.status == "starting"
        assert event.component == "analyzer"
        assert event.message == "Analyzer starting"
        assert event.metadata == {"version": "1.0.0"}
        assert event.event_type == EventType.SYSTEM_STATUS
