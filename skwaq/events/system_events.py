"""Event system for Skwaq.

This module provides the event system implementation for the Skwaq
vulnerability assessment copilot, allowing components to communicate
through a publish-subscribe pattern.
"""

from typing import Dict, List, Type, Callable, Optional, Any, Set
import time
import uuid
import json
from datetime import datetime
from enum import Enum

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class EventType(Enum):
    """Event types for system events."""

    SYSTEM = "system"
    CONFIG = "config"
    TELEMETRY = "telemetry"
    LOGGING = "logging"
    REPOSITORY = "repository"
    ANALYSIS = "analysis"
    USER_INTERACTION = "user_interaction"
    SYSTEM_STATUS = "system_status"
    AGENT_LIFECYCLE = "agent_lifecycle"


class SystemEvent:
    """Base class for all system events in Skwaq."""

    def __init__(
        self,
        sender: str,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a system event.

        Args:
            sender: The component that sent the event
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        self.sender = sender
        self.message = message
        self.target = target
        self.metadata = metadata or {}
        self.timestamp = time.time()
        self.event_id = str(uuid.uuid4())
        self.event_type = EventType.SYSTEM

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to a dictionary.

        Returns:
            Dictionary representation of the event
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "sender": self.sender,
            "timestamp": self.timestamp,
            "message": self.message,
            "target": self.target,
            "metadata": self.metadata,
        }

    def to_json(self) -> str:
        """Convert event to a JSON string.

        Returns:
            JSON string representation of the event
        """
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, json_str: str) -> "SystemEvent":
        """Create an event from a JSON string.

        Args:
            json_str: JSON string representation of the event

        Returns:
            An instance of the appropriate event class
        """
        data = json.loads(json_str)
        return cls.from_dict(data)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemEvent":
        """Create an event from a dictionary.

        Args:
            data: Dictionary with event data

        Returns:
            An instance of the appropriate event class
        """
        event_type = data.pop("event_type", cls.__name__)

        # Get the appropriate event class
        event_class = EVENT_TYPES.get(event_type, cls)

        # Create the instance
        event = event_class(
            sender=data.pop("sender"),
            message=data.pop("message", None),
            target=data.pop("target", None),
            metadata=data.pop("metadata", {}),
        )

        # Set any additional attributes
        for key, value in data.items():
            setattr(event, key, value)

        return event

    def __str__(self) -> str:
        """Return a string representation of the event.

        Returns:
            String representation
        """
        return (
            f"{self.__class__.__name__}(sender={self.sender}, message={self.message})"
        )


class ConfigEvent(SystemEvent):
    """Event emitted when configuration changes."""

    def __init__(
        self,
        sender: str,
        key: str,
        value: Any,
        old_value: Optional[Any] = None,
        component: Optional[str] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a configuration change event.

        Args:
            sender: The component that sent the event
            key: The configuration key that changed
            value: The new configuration value
            old_value: The previous configuration value
            component: Optional component name affected by the change
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"Configuration changed: {key}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.CONFIG
        self.key = key
        self.value = value
        self.old_value = old_value
        self.component = component


class TelemetryEvent(SystemEvent):
    """Event emitted for telemetry data collection."""

    def __init__(
        self,
        sender: str,
        event_name: str,
        event_data: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
        session_id: Optional[str] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a telemetry event.

        Args:
            sender: The component that sent the event
            event_name: Name of the telemetry event
            event_data: Optional event data
            user_id: Optional user identifier
            session_id: Optional session identifier
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"Telemetry event: {event_name}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.TELEMETRY
        self.event_name = event_name
        self.event_data = event_data or {}
        self.user_id = user_id
        self.session_id = session_id


class LoggingEvent(SystemEvent):
    """Event emitted for logging."""

    def __init__(
        self,
        sender: str,
        level: str,
        log_message: str,
        context: Optional[Dict[str, Any]] = None,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a logging event.

        Args:
            sender: The component that sent the event
            level: Log level
            log_message: The log message
            context: Optional log context
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"Log event ({level}): {log_message}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.LOGGING
        self.level = level
        self.log_message = log_message
        self.context = context or {}


class RepositoryEvent(SystemEvent):
    """Event emitted when a repository action occurs."""

    def __init__(
        self,
        sender: str,
        repository_id: str,
        repository_name: str,
        action: str,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a repository event.

        Args:
            sender: The component that sent the event
            repository_id: ID of the repository
            repository_name: Name of the repository
            action: The action performed on the repository
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"Repository event: {action} on {repository_name}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.REPOSITORY
        self.repository_id = repository_id
        self.repository_name = repository_name
        self.action = action


class AnalysisEvent(SystemEvent):
    """Event emitted during code analysis."""

    def __init__(
        self,
        sender: str,
        repository_id: str,
        finding_id: str,
        severity: str,
        confidence: float,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an analysis event.

        Args:
            sender: The component that sent the event
            repository_id: ID of the repository
            finding_id: ID of the finding
            severity: Severity of the finding
            confidence: Confidence level (0-1)
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message
            or f"Analysis event: Finding {finding_id} with {severity} severity",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.ANALYSIS
        self.repository_id = repository_id
        self.finding_id = finding_id
        self.severity = severity
        self.confidence = confidence


class UserInteractionEvent(SystemEvent):
    """Event emitted during user interaction."""

    def __init__(
        self,
        sender: str,
        interaction_type: str,
        command: str,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a user interaction event.

        Args:
            sender: The component that sent the event
            interaction_type: Type of interaction
            command: Command issued by the user
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"User interaction: {interaction_type} - {command}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.USER_INTERACTION
        self.interaction_type = interaction_type
        self.command = command


class SystemStatusEvent(SystemEvent):
    """Event emitted when system status changes."""

    def __init__(
        self,
        sender: str,
        status: str,
        component: str,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a system status event.

        Args:
            sender: The component that sent the event
            status: Current status
            component: Component reporting status
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=sender,
            message=message or f"System status: {component} is {status}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.SYSTEM_STATUS
        self.status = status
        self.component = component


class AgentLifecycleState(Enum):
    """Lifecycle states for agents."""

    CREATED = "created"
    STARTING = "starting"
    STARTED = "started"
    RUNNING = "running"
    PAUSED = "paused"
    RESUMED = "resumed"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


class AgentLifecycleEvent(SystemEvent):
    """Event emitted when an agent's lifecycle state changes."""

    def __init__(
        self,
        agent_id: str,
        agent_name: str,
        state: AgentLifecycleState,
        message: Optional[str] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an agent lifecycle event.

        Args:
            agent_id: The ID of the agent
            agent_name: The name of the agent
            state: The new lifecycle state of the agent
            message: Optional message describing the event
            target: Optional target component for the event
            metadata: Optional additional metadata
        """
        super().__init__(
            sender=agent_name,
            message=message
            or f"Agent {agent_name} lifecycle state changed to {state.value}",
            target=target,
            metadata=metadata or {},
        )
        self.event_type = EventType.AGENT_LIFECYCLE
        self.agent_id = agent_id
        self.agent_name = agent_name
        self.state = state.value


# Map of event types to classes
EVENT_TYPES: Dict[str, Type[SystemEvent]] = {
    "SystemEvent": SystemEvent,
    "ConfigEvent": ConfigEvent,
    "TelemetryEvent": TelemetryEvent,
    "LoggingEvent": LoggingEvent,
    "RepositoryEvent": RepositoryEvent,
    "AnalysisEvent": AnalysisEvent,
    "UserInteractionEvent": UserInteractionEvent,
    "SystemStatusEvent": SystemStatusEvent,
    "AgentLifecycleEvent": AgentLifecycleEvent,
}


# Event handler type definition
EventHandler = Callable[[SystemEvent], None]


# EventBus singleton class
class EventBus:
    """Event bus for publishing and subscribing to events."""

    _instance = None

    def __new__(cls) -> "EventBus":
        """Create a singleton instance.

        Returns:
            Singleton instance
        """
        if cls._instance is None:
            cls._instance = super(EventBus, cls).__new__(cls)
            # Initialize the subscribers dictionary without type annotation in __new__
            cls._instance._subscribers = {}
        return cls._instance

    def __init__(self) -> None:
        """Initialize the event bus."""
        # Already initialized in __new__
        if not hasattr(self, "_subscribers"):
            self._subscribers: Dict[Type[SystemEvent], Dict[str, EventHandler]] = {}

    def subscribe(self, event_type: Type[SystemEvent], handler: EventHandler) -> str:
        """Subscribe to an event type.

        Args:
            event_type: The event type to subscribe to
            handler: The handler function to call when event occurs

        Returns:
            Subscriber ID for unsubscribing
        """
        subscriber_id = str(uuid.uuid4())

        if event_type not in self._subscribers:
            self._subscribers[event_type] = {}

        self._subscribers[event_type][subscriber_id] = handler
        logger.debug(
            f"Added subscriber {subscriber_id} to {event_type.name if hasattr(event_type, 'name') else str(event_type)}"
        )

        return subscriber_id

    def unsubscribe(self, subscriber_id: str) -> bool:
        """Unsubscribe using the subscriber ID.

        Args:
            subscriber_id: ID returned from subscribe()

        Returns:
            True if unsubscribed successfully, False otherwise
        """
        for event_type in self._subscribers:
            if subscriber_id in self._subscribers[event_type]:
                del self._subscribers[event_type][subscriber_id]
                logger.debug(
                    f"Removed subscriber {subscriber_id} from {event_type.__name__}"
                )
                return True

        return False

    def publish(self, event: SystemEvent) -> None:
        """Publish an event to all subscribers.

        Args:
            event: The event to publish
        """
        handlers_called = 0

        # Get all handlers for this event type and parent types
        for event_type, subscribers in self._subscribers.items():
            if isinstance(event, event_type):
                for subscriber_id, handler in subscribers.items():
                    try:
                        handler(event)
                        handlers_called += 1
                    except Exception as e:
                        logger.error(
                            f"Error in event handler for {event.event_type}: {e}"
                        )

        logger.debug(
            f"Published {event.event_type} event from {event.sender} to {handlers_called} handlers"
        )

    def get_subscribers(self, event_type: Type[SystemEvent]) -> Dict[str, EventHandler]:
        """Get all subscribers for an event type.

        Args:
            event_type: The event type

        Returns:
            Dictionary of subscriber IDs to handlers
        """
        return dict(self._subscribers.get(event_type, {}))


class EventSubscriber:
    """Class for subscribing to events."""

    def __init__(self, name: str):
        """Initialize a new subscriber.

        Args:
            name: Name of the subscriber
        """
        self.name = name
        self.bus = EventBus()
        self.subscriptions: Dict[Type[SystemEvent], str] = {}

    def subscribe(self, event_type: Type[SystemEvent], handler: EventHandler) -> None:
        """Subscribe to an event type.

        Args:
            event_type: The event type to subscribe to
            handler: The handler function to call when event occurs
        """
        subscriber_id = self.bus.subscribe(event_type, handler)
        self.subscriptions[event_type] = subscriber_id

    def unsubscribe(self, event_type: Type[SystemEvent]) -> bool:
        """Unsubscribe from an event type.

        Args:
            event_type: The event type to unsubscribe from

        Returns:
            True if unsubscribed successfully, False otherwise
        """
        if event_type in self.subscriptions:
            subscriber_id = self.subscriptions.pop(event_type)
            return self.bus.unsubscribe(subscriber_id)
        return False

    def unsubscribe_all(self) -> None:
        """Unsubscribe from all events."""
        for event_type in list(self.subscriptions.keys()):
            self.unsubscribe(event_type)


# For backward compatibility with existing code
def subscribe(event_type: Type[SystemEvent], handler: EventHandler) -> str:
    """Subscribe to an event type.

    Args:
        event_type: The event type to subscribe to
        handler: The handler function to call when event occurs

    Returns:
        Subscriber ID
    """
    bus = EventBus()
    return bus.subscribe(event_type, handler)


def unsubscribe(event_type: Type[SystemEvent], handler: EventHandler) -> bool:
    """Unsubscribe from an event type.

    Args:
        event_type: The event type to unsubscribe from
        handler: The handler function to remove

    Returns:
        True if handler was removed, False otherwise
    """
    # This is a simplified version that doesn't actually work with the new bus design
    # but is maintained for backward compatibility
    logger.warning("Using deprecated unsubscribe() function")
    return False


def publish(event: SystemEvent) -> None:
    """Publish an event to all subscribers.

    Args:
        event: The event to publish
    """
    bus = EventBus()
    bus.publish(event)


def get_subscribers() -> Dict[str, int]:
    """Get the current subscribers.

    Returns:
        Dictionary mapping event type names to subscriber counts
    """
    bus = EventBus()
    return {
        event_type.__name__: len(subscribers)
        for event_type, subscribers in bus._subscribers.items()
    }
