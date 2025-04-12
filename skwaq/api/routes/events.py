"""Event streaming routes for the Flask API."""

import datetime
import json
import queue
import time
import uuid
from typing import Generator

from flask import Blueprint, Response, jsonify, stream_with_context

from skwaq.api.middleware.auth import login_required
from skwaq.api.middleware.error_handling import BadRequestError
from skwaq.api.services import event_service
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("events", __name__, url_prefix="/api/events")


def event_stream(channel: str, client_id: str) -> Generator[str, None, None]:
    """Generate SSE stream for a client.

    Args:
        channel: Event channel
        client_id: Client identifier

    Yields:
        SSE formatted events
    """
    q = event_service.get_client_queue(channel, client_id)

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
        event_service.disconnect_client(channel, client_id)
        logger.debug(f"Client disconnected: {client_id} from {channel}")


@bp.route("/<channel>", methods=["GET"])
@login_required
def connect(channel: str) -> Response:
    """Connect to an event stream.

    Args:
        channel: Event channel

    Returns:
        SSE stream response

    Raises:
        BadRequestError: If channel is invalid
    """
    # Check if channel exists
    if channel not in ["repository", "analysis", "chat", "system"]:
        raise BadRequestError(f"Invalid channel: {channel}")

    # Check for token in query param (for browsers that don't support headers in EventSource)
    # The auth middleware already handled the main token validation

    # Generate a unique client ID
    client_id = str(uuid.uuid4())

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


# Alias the old connect endpoint for backwards compatibility
@bp.route("/<channel>/connect", methods=["GET"])
@login_required
def connect_old(channel: str) -> Response:
    """Legacy endpoint for connecting to an event stream."""
    return connect(channel)


@bp.route("/recent", methods=["GET"])
@login_required
def get_recent_events() -> Response:
    """Get recent events for the dashboard.

    Returns:
        A list of recent events
    """
    # Get recent events from the service
    recent_events = event_service.get_recent_events(limit=10)

    # If no events are available, create placeholder events
    if not recent_events:
        # Create sample events for the dashboard
        now = datetime.datetime.now()
        recent_events = [
            {
                "id": "event-1",
                "type": "system",
                "title": "API Server Active",
                "description": "The API server is running and ready for requests",
                "timestamp": now.isoformat(),
            },
            {
                "id": "event-2",
                "type": "repository",
                "title": "Ready for Analysis",
                "description": "Add a repository to start vulnerability assessment",
                "timestamp": (now - datetime.timedelta(hours=1)).isoformat(),
            },
            {
                "id": "event-3",
                "type": "workflow",
                "title": "Workflows Available",
                "description": "Security assessment workflows are ready to use",
                "timestamp": (now - datetime.timedelta(days=1)).isoformat(),
            },
        ]

    return jsonify(recent_events)
