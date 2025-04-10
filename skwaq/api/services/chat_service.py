"""Chat service for the Flask API."""

import uuid
import threading
import time
from typing import Dict, Any, List, Optional
from datetime import datetime

from skwaq.utils.logging import get_logger
from skwaq.api.services.event_service import publish_event

logger = get_logger(__name__)

# In-memory conversation storage (will be replaced with database in production)
CONVERSATIONS: Dict[str, Dict[str, Any]] = {}
MESSAGES: Dict[str, List[Dict[str, Any]]] = {}


async def get_conversations(user_id: str) -> List[Dict[str, Any]]:
    """Get all conversations for a user.

    Args:
        user_id: User ID

    Returns:
        List of conversation dictionaries
    """
    try:
        # Filter conversations by user ID
        user_conversations = []
        for conversation in CONVERSATIONS.values():
            if conversation.get("userId") == user_id:
                # Include message count
                conversation_copy = conversation.copy()
                conversation_copy["messageCount"] = len(
                    MESSAGES.get(conversation["id"], [])
                )
                conversation_copy["lastMessageTime"] = get_latest_message_time(
                    conversation["id"]
                )
                user_conversations.append(conversation_copy)

        # Sort by last message time
        user_conversations.sort(
            key=lambda c: c.get("lastMessageTime", c.get("createdAt", "")), reverse=True
        )

        return user_conversations
    except Exception as e:
        logger.error(f"Error retrieving conversations for user {user_id}: {e}")
        return []


async def get_conversation_by_id(conversation_id: str) -> Optional[Dict[str, Any]]:
    """Get a conversation by ID.

    Args:
        conversation_id: Conversation ID

    Returns:
        Conversation dictionary if found, None otherwise
    """
    try:
        conversation = CONVERSATIONS.get(conversation_id)
        if not conversation:
            return None

        # Include messages
        conversation_copy = conversation.copy()
        conversation_copy["messages"] = MESSAGES.get(conversation_id, [])
        conversation_copy["messageCount"] = len(conversation_copy["messages"])
        conversation_copy["lastMessageTime"] = get_latest_message_time(conversation_id)

        return conversation_copy
    except Exception as e:
        logger.error(f"Error retrieving conversation {conversation_id}: {e}")
        return None


def get_latest_message_time(conversation_id: str) -> Optional[str]:
    """Get the timestamp of the latest message in a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        ISO formatted timestamp or None if no messages
    """
    messages = MESSAGES.get(conversation_id, [])
    if not messages:
        return None

    latest_message = max(messages, key=lambda m: m.get("timestamp", ""))
    return latest_message.get("timestamp")


async def create_conversation(
    user_id: str, title: str = "New Conversation", context: Dict[str, Any] = None
) -> Dict[str, Any]:
    """Create a new conversation.

    Args:
        user_id: User ID
        title: Conversation title
        context: Optional context information

    Returns:
        New conversation dictionary
    """
    try:
        conversation_id = f"conv-{str(uuid.uuid4())}"

        if context is None:
            context = {}

        now = datetime.now().isoformat()

        conversation = {
            "id": conversation_id,
            "title": title,
            "userId": user_id,
            "createdAt": now,
            "updatedAt": now,
            "context": context,
        }

        # Initialize empty message list
        MESSAGES[conversation_id] = []

        # Store conversation
        CONVERSATIONS[conversation_id] = conversation

        # Add system welcome message
        await send_system_message(
            conversation_id=conversation_id,
            content="Hello! I'm your vulnerability research assistant. How can I help you today?",
        )

        logger.info(f"Created conversation {conversation_id} for user {user_id}")

        # Return conversation with messages
        conversation_copy = conversation.copy()
        conversation_copy["messages"] = MESSAGES.get(conversation_id, [])
        conversation_copy["messageCount"] = len(conversation_copy["messages"])

        return conversation_copy
    except Exception as e:
        logger.error(f"Error creating conversation for user {user_id}: {e}")
        # Return an empty conversation to avoid breaking client
        return {
            "id": f"error-{str(uuid.uuid4())}",
            "title": "Error creating conversation",
            "userId": user_id,
            "createdAt": datetime.now().isoformat(),
            "updatedAt": datetime.now().isoformat(),
            "context": {},
            "messages": [],
            "messageCount": 0,
        }


async def delete_conversation(conversation_id: str) -> bool:
    """Delete a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        True if deleted successfully, False otherwise
    """
    try:
        if conversation_id not in CONVERSATIONS:
            return False

        # Remove conversation and messages
        del CONVERSATIONS[conversation_id]
        if conversation_id in MESSAGES:
            del MESSAGES[conversation_id]

        logger.info(f"Deleted conversation {conversation_id}")
        return True
    except Exception as e:
        logger.error(f"Error deleting conversation {conversation_id}: {e}")
        return False


async def get_messages(conversation_id: str) -> List[Dict[str, Any]]:
    """Get all messages for a conversation.

    Args:
        conversation_id: Conversation ID

    Returns:
        List of message dictionaries
    """
    try:
        return MESSAGES.get(conversation_id, [])
    except Exception as e:
        logger.error(
            f"Error retrieving messages for conversation {conversation_id}: {e}"
        )
        return []


async def send_message(
    conversation_id: str, user_id: str, content: str
) -> Dict[str, Any]:
    """Send a new message in a conversation.

    Args:
        conversation_id: Conversation ID
        user_id: User ID
        content: Message content

    Returns:
        New message dictionary
    """
    try:
        message_id = f"msg-{str(uuid.uuid4())}"
        now = datetime.now().isoformat()

        message = {
            "id": message_id,
            "conversationId": conversation_id,
            "userId": user_id,
            "sender": "user",
            "content": content,
            "timestamp": now,
        }

        # Add message to conversation
        if conversation_id in MESSAGES:
            MESSAGES[conversation_id].append(message)
        else:
            MESSAGES[conversation_id] = [message]

        # Update conversation timestamp
        if conversation_id in CONVERSATIONS:
            CONVERSATIONS[conversation_id]["updatedAt"] = now

        logger.info(f"Added message {message_id} to conversation {conversation_id}")

        # Generate AI response asynchronously
        threading.Thread(
            target=generate_response, args=(conversation_id, message)
        ).start()

        return message
    except Exception as e:
        logger.error(f"Error sending message in conversation {conversation_id}: {e}")
        # Return placeholder message
        return {
            "id": f"error-{str(uuid.uuid4())}",
            "conversationId": conversation_id,
            "userId": user_id,
            "sender": "user",
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
        }


async def send_system_message(conversation_id: str, content: str) -> Dict[str, Any]:
    """Send a system message in a conversation.

    Args:
        conversation_id: Conversation ID
        content: Message content

    Returns:
        New message dictionary
    """
    try:
        message_id = f"msg-{str(uuid.uuid4())}"
        now = datetime.now().isoformat()

        message = {
            "id": message_id,
            "conversationId": conversation_id,
            "userId": "system",
            "sender": "system",
            "content": content,
            "timestamp": now,
        }

        # Add message to conversation
        if conversation_id in MESSAGES:
            MESSAGES[conversation_id].append(message)
        else:
            MESSAGES[conversation_id] = [message]

        # Update conversation timestamp
        if conversation_id in CONVERSATIONS:
            CONVERSATIONS[conversation_id]["updatedAt"] = now

        logger.info(
            f"Added system message {message_id} to conversation {conversation_id}"
        )

        # Publish event for message sent
        publish_event(
            "chat",
            "message_sent",
            {
                "conversationId": conversation_id,
                "messageId": message_id,
                "sender": "system",
                "content": content,
            },
        )

        return message
    except Exception as e:
        logger.error(
            f"Error sending system message in conversation {conversation_id}: {e}"
        )
        return {
            "id": f"error-{str(uuid.uuid4())}",
            "conversationId": conversation_id,
            "userId": "system",
            "sender": "system",
            "content": content,
            "timestamp": datetime.now().isoformat(),
            "error": str(e),
        }


def generate_response(conversation_id: str, user_message: Dict[str, Any]) -> None:
    """Generate an AI response to a user message (runs in a separate thread).

    Args:
        conversation_id: Conversation ID
        user_message: User message dictionary
    """
    try:
        # First, send "thinking" message
        thinking_message_id = f"thinking-{str(uuid.uuid4())}"
        now = datetime.now().isoformat()

        thinking_message = {
            "id": thinking_message_id,
            "conversationId": conversation_id,
            "userId": "assistant",
            "sender": "assistant",
            "content": "...",
            "isTyping": True,
            "timestamp": now,
        }

        # Add thinking message to conversation
        if conversation_id in MESSAGES:
            MESSAGES[conversation_id].append(thinking_message)
        else:
            MESSAGES[conversation_id] = [thinking_message]

        # Publish event for thinking message
        publish_event(
            "chat",
            "message_sent",
            {
                "conversationId": conversation_id,
                "messageId": thinking_message_id,
                "sender": "assistant",
                "content": "...",
                "isTyping": True,
            },
        )

        # Simulate AI thinking time
        time.sleep(1)

        # In a real implementation, we would call an LLM here
        # For demo purposes, generate a simple response based on the user message
        user_content = user_message.get("content", "").lower()

        if "hello" in user_content or "hi" in user_content:
            response_content = (
                "Hello! How can I help you with your security research today?"
            )
        elif "vulnerable" in user_content or "vulnerability" in user_content:
            response_content = "I can help you analyze vulnerabilities in your code. Can you provide more details about what you're looking for?"
        elif "repository" in user_content:
            response_content = "I can scan repositories for security issues. Would you like me to help you analyze a specific repository?"
        elif "report" in user_content:
            response_content = "I can generate vulnerability reports for your repositories. Is there a specific format you'd like the report in?"
        else:
            response_content = "I understand you're interested in security research. Could you tell me more about what you're trying to accomplish, and I'll do my best to assist you?"

        # Remove the thinking message
        if conversation_id in MESSAGES:
            MESSAGES[conversation_id] = [
                msg
                for msg in MESSAGES[conversation_id]
                if msg["id"] != thinking_message_id
            ]

        # Create the actual response message
        message_id = f"msg-{str(uuid.uuid4())}"
        now = datetime.now().isoformat()

        message = {
            "id": message_id,
            "conversationId": conversation_id,
            "userId": "assistant",
            "sender": "assistant",
            "content": response_content,
            "timestamp": now,
        }

        # Add message to conversation
        if conversation_id in MESSAGES:
            MESSAGES[conversation_id].append(message)
        else:
            MESSAGES[conversation_id] = [message]

        # Update conversation timestamp
        if conversation_id in CONVERSATIONS:
            CONVERSATIONS[conversation_id]["updatedAt"] = now

        # Publish event for message sent
        publish_event(
            "chat",
            "message_sent",
            {
                "conversationId": conversation_id,
                "messageId": message_id,
                "sender": "assistant",
                "content": response_content,
            },
        )

        logger.info(f"Added AI response {message_id} to conversation {conversation_id}")

    except Exception as e:
        logger.error(
            f"Error generating AI response in conversation {conversation_id}: {e}"
        )
        # Send error message
        error_message_id = f"error-{str(uuid.uuid4())}"
        now = datetime.now().isoformat()

        error_message = {
            "id": error_message_id,
            "conversationId": conversation_id,
            "userId": "assistant",
            "sender": "assistant",
            "content": "I apologize, but I encountered an error while processing your request. Please try again.",
            "timestamp": now,
            "error": str(e),
        }

        # Add error message to conversation
        if conversation_id in MESSAGES:
            # Remove thinking message if it exists
            MESSAGES[conversation_id] = [
                msg
                for msg in MESSAGES[conversation_id]
                if msg.get("isTyping") is not True
            ]
            MESSAGES[conversation_id].append(error_message)
        else:
            MESSAGES[conversation_id] = [error_message]

        # Publish event for error message
        publish_event(
            "chat",
            "message_sent",
            {
                "conversationId": conversation_id,
                "messageId": error_message_id,
                "sender": "assistant",
                "content": error_message["content"],
                "error": str(e),
            },
        )
