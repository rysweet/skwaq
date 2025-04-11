"""Chat routes for the Flask API."""

from flask import Blueprint, jsonify, request, Response
import asyncio
import uuid

from skwaq.api.middleware.auth import login_required
from skwaq.api.middleware.error_handling import APIError, NotFoundError, BadRequestError
from skwaq.api.services import chat_service, event_service
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("chat", __name__, url_prefix="/api/chat")


@bp.route("/conversations", methods=["GET"])
@login_required
def get_conversations() -> Response:
    """Get all chat conversations.

    Returns:
        JSON response with list of conversations
    """
    # Get user from auth token
    from flask import g

    user_id = g.user_id

    conversations = asyncio.run(chat_service.get_conversations(user_id))
    return jsonify(conversations)


@bp.route("/conversations/<conversation_id>", methods=["GET"])
@login_required
def get_conversation(conversation_id: str) -> Response:
    """Get a specific conversation by ID.

    Args:
        conversation_id: Conversation ID

    Returns:
        JSON response with conversation details and messages

    Raises:
        NotFoundError: If conversation is not found
    """
    conversation = asyncio.run(chat_service.get_conversation_by_id(conversation_id))
    if conversation is None:
        raise NotFoundError(f"Conversation {conversation_id} not found")

    return jsonify(conversation)


@bp.route("/conversations", methods=["POST"])
@login_required
def create_conversation() -> Response:
    """Create a new conversation.

    Returns:
        JSON response with new conversation details

    Raises:
        BadRequestError: If request is invalid
    """
    if not request.is_json:
        raise BadRequestError("Content-Type must be application/json")

    data = request.get_json()
    title = data.get("title", "New Conversation")
    context = data.get("context", {})

    # Get user from auth token
    from flask import g

    user_id = g.user_id

    conversation = asyncio.run(
        chat_service.create_conversation(user_id=user_id, title=title, context=context)
    )

    # Publish event for conversation created
    event_service.publish_event(
        "chat",
        "conversation_created",
        {"conversationId": conversation["id"], "title": conversation["title"]},
    )

    return jsonify(conversation), 201


@bp.route("/conversations/<conversation_id>", methods=["DELETE"])
@login_required
def delete_conversation(conversation_id: str) -> Response:
    """Delete a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        Empty response with 204 status code

    Raises:
        NotFoundError: If conversation is not found
    """
    conversation = asyncio.run(chat_service.get_conversation_by_id(conversation_id))
    if conversation is None:
        raise NotFoundError(f"Conversation {conversation_id} not found")

    success = asyncio.run(chat_service.delete_conversation(conversation_id))
    if not success:
        logger.warning(f"Error deleting conversation {conversation_id}, but continuing")

    # Publish event for conversation deleted
    event_service.publish_event(
        "chat", "conversation_deleted", {"conversationId": conversation_id}
    )

    return "", 204


@bp.route("/conversations/<conversation_id>/messages", methods=["GET"])
@login_required
def get_messages(conversation_id: str) -> Response:
    """Get all messages for a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        JSON response with list of messages

    Raises:
        NotFoundError: If conversation is not found
    """
    conversation = asyncio.run(chat_service.get_conversation_by_id(conversation_id))
    if conversation is None:
        raise NotFoundError(f"Conversation {conversation_id} not found")

    messages = asyncio.run(chat_service.get_messages(conversation_id))
    return jsonify(messages)


@bp.route("/conversations/<conversation_id>/messages", methods=["POST"])
@login_required
def send_message(conversation_id: str) -> Response:
    """Send a new message in a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        JSON response with message details

    Raises:
        NotFoundError: If conversation is not found
        BadRequestError: If request is invalid
    """
    if not request.is_json:
        raise BadRequestError("Content-Type must be application/json")

    data = request.get_json()
    content = data.get("content")

    if not content:
        raise BadRequestError("Message content is required")

    conversation = asyncio.run(chat_service.get_conversation_by_id(conversation_id))
    if conversation is None:
        raise NotFoundError(f"Conversation {conversation_id} not found")

    # Get user from auth token
    from flask import g

    user_id = g.user_id

    message = asyncio.run(
        chat_service.send_message(
            conversation_id=conversation_id, user_id=user_id, content=content
        )
    )

    # Publish event for message sent
    event_service.publish_event(
        "chat",
        "message_sent",
        {
            "conversationId": conversation_id,
            "messageId": message["id"],
            "sender": "user",
            "content": content,
        },
    )

    return jsonify(message)
