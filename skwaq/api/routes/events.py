"""Event streaming routes for the Flask API."""

import uuid
import json
import queue
import time
from typing import Dict, Any, Generator, Optional

from flask import Blueprint, Response, request, stream_with_context

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


@bp.route("/<channel>/connect", methods=["GET"])
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