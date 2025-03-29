"""Event service for the Flask API."""

import uuid
import json
import time
import queue
from typing import Dict, Any, List, Optional, Callable

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

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


def publish_event(channel: str, event_type: str, data: Any) -> None:
    """Publish an event to all clients subscribed to a channel.

    Args:
        channel: Event channel
        event_type: Type of event
        data: Event data
    """
    if channel not in event_queues:
        logger.warning(f"Invalid channel: {channel}")
        return

    event = {
        "id": str(uuid.uuid4()),
        "type": event_type,
        "data": data,
        "timestamp": int(time.time() * 1000),
    }

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


def publish_system_event(event_type: str, data: Any) -> None:
    """Publish system event.

    Args:
        event_type: Type of event
        data: Event data
    """
    publish_event("system", event_type, data)