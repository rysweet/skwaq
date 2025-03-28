"""Server-Sent Events (SSE) for real-time updates."""

from typing import Dict, Any, List, Optional

from flask import Blueprint, Response, current_app, stream_with_context
import json
import time
import queue
import threading
import uuid

from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("events", __name__, url_prefix="/api/events")

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


def event_stream(channel: str, client_id: str) -> str:
    """Generate SSE stream for a client.

    Args:
        channel: Event channel
        client_id: Client identifier

    Yields:
        SSE formatted events
    """
    q = get_client_queue(channel, client_id)

    # Send initial connection established event
    yield f"event: connection\ndata: {json.dumps({'connected': True, 'channel': channel, 'clientId': client_id})}\n\n"

    try:
        while True:
            try:
                # Get event from queue with timeout
                event = q.get(timeout=30)
                event_json = json.dumps(event)

                # Format as SSE
                yield f"event: {event['type']}\ndata: {event_json}\n\n"

            except queue.Empty:
                # Send keep-alive
                yield f": keepalive {time.time()}\n\n"

    except GeneratorExit:
        # Client disconnected
        if channel in event_queues and client_id in event_queues[channel]:
            del event_queues[channel][client_id]
            logger.debug(f"Client disconnected: {client_id} from {channel}")


@bp.route("/<channel>/connect", methods=["GET"])
def connect(channel: str) -> Response:
    """Connect to an event stream.

    Args:
        channel: Event channel

    Returns:
        SSE stream response
    """
    client_id = str(uuid.uuid4())

    # Check if channel exists
    if channel not in ["repository", "analysis", "chat", "system"]:
        return Response(f"Invalid channel: {channel}", status=400)

    # Create event stream
    def generate():
        return event_stream(channel, client_id)

    logger.debug(f"Client connected: {client_id} to {channel}")

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",  # Disable buffering for nginx
        },
    )


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
