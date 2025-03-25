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

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


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
        self.event_type = self.__class__.__name__

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to a dictionary.

        Returns:
            Dictionary representation of the event
        """
        return {
            "event_id": self.event_id,
            "event_type": self.event_type,
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
        self.level = level
        self.log_message = log_message
        self.context = context or {}


# Map of event types to classes
EVENT_TYPES: Dict[str, Type[SystemEvent]] = {
    "SystemEvent": SystemEvent,
    "ConfigEvent": ConfigEvent,
    "TelemetryEvent": TelemetryEvent,
    "LoggingEvent": LoggingEvent,
}


# Event handler type definition
EventHandler = Callable[[SystemEvent], None]


# Subscribers dictionary mapping event types to handlers
_subscribers: Dict[Type[SystemEvent], List[EventHandler]] = {}


def subscribe(event_type: Type[SystemEvent], handler: EventHandler) -> None:
    """Subscribe to an event type.

    Args:
        event_type: The event type to subscribe to
        handler: The handler function to call when event occurs
    """
    if event_type not in _subscribers:
        _subscribers[event_type] = []

    if handler not in _subscribers[event_type]:
        _subscribers[event_type].append(handler)
        logger.debug(f"Subscribed handler to {event_type.__name__} events")


def unsubscribe(event_type: Type[SystemEvent], handler: EventHandler) -> None:
    """Unsubscribe from an event type.

    Args:
        event_type: The event type to unsubscribe from
        handler: The handler function to remove

    Returns:
        True if handler was removed, False otherwise
    """
    if event_type in _subscribers and handler in _subscribers[event_type]:
        _subscribers[event_type].remove(handler)
        logger.debug(f"Unsubscribed handler from {event_type.__name__} events")
        return True
    return False


def publish(event: SystemEvent) -> None:
    """Publish an event to all subscribers.

    Args:
        event: The event to publish
    """
    handlers_called = 0

    # Get all handlers for this event type and parent types
    for event_type, handlers in _subscribers.items():
        if isinstance(event, event_type):
            for handler in handlers:
                try:
                    handler(event)
                    handlers_called += 1
                except Exception as e:
                    logger.error(f"Error in event handler for {event.event_type}: {e}")

    logger.debug(
        f"Published {event.event_type} event from {event.sender} " f"to {handlers_called} handlers"
    )


def get_subscribers() -> Dict[str, int]:
    """Get the current subscribers.

    Returns:
        Dictionary mapping event type names to subscriber counts
    """
    return {event_type.__name__: len(handlers) for event_type, handlers in _subscribers.items()}
