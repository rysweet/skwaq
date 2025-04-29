"""Event service for the Flask API."""

import datetime
import queue
import time
import uuid
from typing import Any, Dict, List, Optional

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Store recent events for dashboard
recent_events: List[Dict[str, Any]] = []
MAX_RECENT_EVENTS = 50  # Maximum number of events to keep in memory

# Event queues for different channels
event_queues: Dict[str, Dict[str, queue.Queue]] = {
    "repository": {},  # client_id -> queue
    "analysis": {},  # client_id -> queue
    "chat": {},  # client_id -> queue
    "system": {},  # client_id -> queue
}


def get_client_queue(channel: str, client_id: str) -> queue.Queue:
    """Get or create a queue for a client.

    Args:
        channel: Event channel
        client_id: Client identifier

    Returns:
        Queue for the client
    """
    if channel not in event_queues:
        event_queues[channel] = {}

    if client_id not in event_queues[channel]:
        event_queues[channel][client_id] = queue.Queue()

    return event_queues[channel][client_id]


def publish_event(
    channel: str, event_type: str, data: Any, title: Optional[str] = None
) -> None:
    """Publish an event to all clients subscribed to a channel.

    Args:
        channel: Event channel
        event_type: Type of event
        data: Event data
        title: Optional event title for display
    """
    if channel not in event_queues:
        logger.warning(f"Invalid channel: {channel}")
        return

    # Generate event ID
    event_id = str(uuid.uuid4())
    timestamp = int(time.time() * 1000)

    # Create the event object
    event = {
        "id": event_id,
        "type": event_type,
        "data": data,
        "timestamp": timestamp,
    }

    # Add title if provided
    if title:
        event["title"] = title

    # Add event to recent events list for dashboard
    dashboard_event = {
        "id": event_id,
        "type": event_type,
        "title": title or event_type,
        "description": (
            data.get("message", str(data)) if isinstance(data, dict) else str(data)
        ),
        "timestamp": datetime.datetime.fromtimestamp(timestamp / 1000).isoformat(),
    }
    recent_events.insert(0, dashboard_event)

    # Trim recent events list if it's too long
    if len(recent_events) > MAX_RECENT_EVENTS:
        recent_events.pop()

    # Add to all client queues for this channel
    for client_id, q in event_queues[channel].items():
        q.put(event)

    logger.debug(
        f"Published event to {len(event_queues[channel])} clients: {event_type}"
    )


def disconnect_client(channel: str, client_id: str) -> None:
    """Disconnect a client from a channel.

    Args:
        channel: Event channel
        client_id: Client identifier
    """
    if channel in event_queues and client_id in event_queues[channel]:
        logger.debug(f"Disconnecting client {client_id} from {channel}")
        del event_queues[channel][client_id]


# Helper functions to publish to specific channels
def publish_repository_event(event_type: str, data: Any) -> None:
    """Publish repository event.

    Args:
        event_type: Type of event
        data: Event data
    """
    publish_event("repository", event_type, data)


def publish_analysis_event(event_type: str, data: Any) -> None:
    """Publish analysis event.

    Args:
        event_type: Type of event
        data: Event data
    """
    publish_event("analysis", event_type, data)


def publish_chat_event(event_type: str, data: Any) -> None:
    """Publish chat event.

    Args:
        event_type: Type of event
        data: Event data
    """
    publish_event("chat", event_type, data)


def publish_system_event(
    event_type: str, data: Any, title: Optional[str] = None
) -> None:
    """Publish system event.

    Args:
        event_type: Type of event
        data: Event data
        title: Optional event title for display
    """
    publish_event("system", event_type, data, title)


def get_recent_events(limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent events for the dashboard.

    Args:
        limit: Maximum number of events to return

    Returns:
        List of recent events
    """
    return recent_events[:limit]
