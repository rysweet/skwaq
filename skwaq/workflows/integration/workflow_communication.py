"""Inter-workflow communication for data sharing and coordination.

This module provides mechanisms for workflows to communicate and share data
with each other, enabling coordinated execution and data passing.
"""

import asyncio
import uuid
from datetime import datetime
from enum import Enum
from typing import Any, Awaitable, Callable, Dict, List, Optional, Set

from autogen_core.event import Event

from ...utils.logging import get_logger

logger = get_logger(__name__)


class CommunicationChannel:
    """Communication channel between workflows.

    This class represents a communication channel that allows workflows
    to exchange messages and data with each other asynchronously.
    """

    def __init__(self, name: Optional[str] = None):
        """Initialize a communication channel.

        Args:
            name: Optional name for this channel
        """
        self.name = name or f"channel-{uuid.uuid4().hex[:8]}"
        self._queue: asyncio.Queue = asyncio.Queue()
        self._subscribers: Set[str] = set()

    async def send(self, message: Dict[str, Any], sender_id: str) -> None:
        """Send a message on this channel.

        Args:
            message: The message to send
            sender_id: ID of the sending workflow
        """
        # Add metadata to the message
        full_message = message.copy()
        full_message.update(
            {
                "timestamp": datetime.now().isoformat(),
                "sender": sender_id,
                "channel": self.name,
                "message_id": str(uuid.uuid4()),
            }
        )

        # Put the message in the queue
        await self._queue.put(full_message)

        logger.debug(f"Message sent on channel {self.name} by {sender_id}")

    async def receive(
        self, timeout: Optional[float] = None
    ) -> Optional[Dict[str, Any]]:
        """Receive a message from this channel.

        Args:
            timeout: Optional timeout in seconds

        Returns:
            The received message, or None if timeout occurs
        """
        try:
            if timeout is not None:
                # Use wait_for with timeout
                return await asyncio.wait_for(self._queue.get(), timeout=timeout)
            else:
                # Wait indefinitely
                return await self._queue.get()
        except asyncio.TimeoutError:
            logger.debug(f"Timeout waiting for message on channel {self.name}")
            return None

    def subscribe(self, workflow_id: str) -> None:
        """Subscribe a workflow to this channel.

        Args:
            workflow_id: ID of the subscribing workflow
        """
        self._subscribers.add(workflow_id)
        logger.debug(f"Workflow {workflow_id} subscribed to channel {self.name}")

    def unsubscribe(self, workflow_id: str) -> None:
        """Unsubscribe a workflow from this channel.

        Args:
            workflow_id: ID of the workflow to unsubscribe
        """
        if workflow_id in self._subscribers:
            self._subscribers.remove(workflow_id)
            logger.debug(
                f"Workflow {workflow_id} unsubscribed from channel {self.name}"
            )

    def get_subscribers(self) -> Set[str]:
        """Get all subscribers to this channel.

        Returns:
            Set of workflow IDs subscribed to this channel
        """
        return self._subscribers.copy()


class MessageType(Enum):
    """Types of messages exchanged between workflows."""

    DATA = "data"  # Data sharing
    NOTIFICATION = "notification"  # Event notification
    CONTROL = "control"  # Control messages (pause, resume, etc.)
    QUERY = "query"  # Information request
    RESPONSE = "response"  # Response to a query
    ERROR = "error"  # Error notification


class WorkflowMessage:
    """Message exchanged between workflows.

    This class represents a structured message that can be exchanged
    between workflows through communication channels.
    """

    def __init__(
        self,
        message_type: MessageType,
        content: Any,
        sender_id: str,
        recipient_id: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        """Initialize a workflow message.

        Args:
            message_type: The type of message
            content: The message content
            sender_id: ID of the sending workflow
            recipient_id: Optional ID of the recipient workflow
            correlation_id: Optional ID for message correlation
        """
        self.message_type = message_type
        self.content = content
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.timestamp = datetime.now().isoformat()
        self.message_id = str(uuid.uuid4())

    def to_dict(self) -> Dict[str, Any]:
        """Convert the message to a dictionary.

        Returns:
            Dictionary representation of the message
        """
        return {
            "message_type": self.message_type.value,
            "content": self.content,
            "sender_id": self.sender_id,
            "recipient_id": self.recipient_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "message_id": self.message_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "WorkflowMessage":
        """Create a message from a dictionary.

        Args:
            data: Dictionary representation of the message

        Returns:
            A WorkflowMessage object
        """
        message = cls(
            message_type=MessageType(data["message_type"]),
            content=data["content"],
            sender_id=data["sender_id"],
            recipient_id=data.get("recipient_id"),
            correlation_id=data.get("correlation_id"),
        )

        # Restore other fields
        message.timestamp = data.get("timestamp", datetime.now().isoformat())
        message.message_id = data.get("message_id", str(uuid.uuid4()))

        return message

    def __str__(self) -> str:
        """Get string representation of the message.

        Returns:
            String representation
        """
        recipient = self.recipient_id or "broadcast"
        return f"WorkflowMessage({self.message_type.value}, sender={self.sender_id}, to={recipient})"


class WorkflowCommunicationEvent(Event):
    """Event for workflow communication.

    This event is emitted when workflows communicate with each other,
    allowing for event-based communication in addition to direct messaging.
    """

    def __init__(
        self,
        sender: str,
        message_type: MessageType,
        content: Any,
        recipient: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ):
        """Initialize a workflow communication event.

        Args:
            sender: The sender identifier
            message_type: The type of message
            content: The message content
            recipient: Optional recipient identifier
            correlation_id: Optional correlation ID
        """
        super().__init__(
            sender=sender,
            relationship_type="COMMUNICATES_WITH",
            target_type=recipient or "broadcast",
            content={
                "message_type": message_type.value,
                "content": content,
                "correlation_id": correlation_id or str(uuid.uuid4()),
                "timestamp": datetime.now().isoformat(),
            },
        )


class WorkflowCommunicationManager:
    """Manages communication between workflows.

    This class provides a centralized system for workflow communication,
    managing channels, message routing, and coordination.
    """

    def __init__(self):
        """Initialize the communication manager."""
        self._channels: Dict[str, CommunicationChannel] = {}
        self._workflow_subscriptions: Dict[str, Set[str]] = {}
        self._message_handlers: Dict[str, Dict[MessageType, Callable]] = {}

    def create_channel(self, channel_name: str) -> CommunicationChannel:
        """Create a new communication channel.

        Args:
            channel_name: The name of the channel

        Returns:
            The created communication channel
        """
        if channel_name in self._channels:
            logger.warning(
                f"Channel {channel_name} already exists, returning existing channel"
            )
            return self._channels[channel_name]

        channel = CommunicationChannel(name=channel_name)
        self._channels[channel_name] = channel

        logger.info(f"Created communication channel: {channel_name}")
        return channel

    def get_channel(self, channel_name: str) -> Optional[CommunicationChannel]:
        """Get a communication channel by name.

        Args:
            channel_name: The name of the channel

        Returns:
            The channel, or None if not found
        """
        return self._channels.get(channel_name)

    def list_channels(self) -> List[str]:
        """List all available channels.

        Returns:
            List of channel names
        """
        return list(self._channels.keys())

    def subscribe_workflow(self, workflow_id: str, channel_name: str) -> bool:
        """Subscribe a workflow to a channel.

        Args:
            workflow_id: The ID of the workflow
            channel_name: The name of the channel

        Returns:
            True if successful, False otherwise
        """
        channel = self._channels.get(channel_name)
        if not channel:
            logger.warning(f"Cannot subscribe to non-existent channel: {channel_name}")
            return False

        # Subscribe to the channel
        channel.subscribe(workflow_id)

        # Update workflow subscriptions
        if workflow_id not in self._workflow_subscriptions:
            self._workflow_subscriptions[workflow_id] = set()
        self._workflow_subscriptions[workflow_id].add(channel_name)

        return True

    def unsubscribe_workflow(
        self, workflow_id: str, channel_name: Optional[str] = None
    ) -> None:
        """Unsubscribe a workflow from a channel or all channels.

        Args:
            workflow_id: The ID of the workflow
            channel_name: Optional channel name. If None, unsubscribe from all channels.
        """
        if channel_name:
            # Unsubscribe from a specific channel
            channel = self._channels.get(channel_name)
            if channel:
                channel.unsubscribe(workflow_id)

                # Update workflow subscriptions
                if workflow_id in self._workflow_subscriptions:
                    self._workflow_subscriptions[workflow_id].discard(channel_name)
        else:
            # Unsubscribe from all channels
            if workflow_id in self._workflow_subscriptions:
                for ch_name in self._workflow_subscriptions[workflow_id]:
                    channel = self._channels.get(ch_name)
                    if channel:
                        channel.unsubscribe(workflow_id)

                # Clear workflow subscriptions
                self._workflow_subscriptions[workflow_id] = set()

    async def broadcast_message(
        self, channel_name: str, message: WorkflowMessage
    ) -> None:
        """Broadcast a message to all subscribers of a channel.

        Args:
            channel_name: The name of the channel
            message: The message to broadcast
        """
        channel = self._channels.get(channel_name)
        if not channel:
            logger.warning(f"Cannot broadcast to non-existent channel: {channel_name}")
            return

        # Send the message on the channel
        await channel.send(message.to_dict(), message.sender_id)

        # Also emit an event for this communication
        Event.add(
            WorkflowCommunicationEvent(
                sender=message.sender_id,
                message_type=message.message_type,
                content=message.content,
                recipient="broadcast",
                correlation_id=message.correlation_id,
            )
        )

    async def send_direct_message(
        self,
        sender_workflow_id: str,
        recipient_workflow_id: str,
        message_type: MessageType,
        content: Any,
        correlation_id: Optional[str] = None,
    ) -> str:
        """Send a direct message to a specific workflow.

        Args:
            sender_workflow_id: The ID of the sending workflow
            recipient_workflow_id: The ID of the recipient workflow
            message_type: The type of message
            content: The message content
            correlation_id: Optional correlation ID

        Returns:
            The message ID
        """
        # Create a direct message
        message = WorkflowMessage(
            message_type=message_type,
            content=content,
            sender_id=sender_workflow_id,
            recipient_id=recipient_workflow_id,
            correlation_id=correlation_id,
        )

        # Create or get the direct channel
        direct_channel_name = f"direct_{sender_workflow_id}_{recipient_workflow_id}"
        if direct_channel_name not in self._channels:
            self.create_channel(direct_channel_name)

            # Subscribe both sender and recipient
            self.subscribe_workflow(sender_workflow_id, direct_channel_name)
            self.subscribe_workflow(recipient_workflow_id, direct_channel_name)

        # Send the message
        await self.broadcast_message(direct_channel_name, message)

        # Emit an event for this direct communication
        Event.add(
            WorkflowCommunicationEvent(
                sender=sender_workflow_id,
                message_type=message_type,
                content=content,
                recipient=recipient_workflow_id,
                correlation_id=correlation_id,
            )
        )

        return message.message_id

    def register_message_handler(
        self,
        workflow_id: str,
        message_type: MessageType,
        handler: Callable[[WorkflowMessage], Awaitable[None]],
    ) -> None:
        """Register a handler for a specific message type.

        Args:
            workflow_id: The ID of the workflow
            message_type: The type of message to handle
            handler: The handler function
        """
        if workflow_id not in self._message_handlers:
            self._message_handlers[workflow_id] = {}

        self._message_handlers[workflow_id][message_type] = handler

        logger.debug(
            f"Registered handler for {message_type.value} messages "
            f"for workflow {workflow_id}"
        )

    async def start_message_processing(
        self, workflow_id: str, polling_interval: float = 0.1
    ) -> asyncio.Task:
        """Start processing messages for a workflow.

        Args:
            workflow_id: The ID of the workflow
            polling_interval: The interval in seconds for polling channels

        Returns:
            An asyncio Task for the message processing loop
        """
        # Create a task for message processing
        task = asyncio.create_task(
            self._message_processing_loop(workflow_id, polling_interval)
        )

        logger.info(f"Started message processing for workflow {workflow_id}")
        return task

    async def _message_processing_loop(
        self, workflow_id: str, polling_interval: float
    ) -> None:
        """Message processing loop for a workflow.

        Args:
            workflow_id: The ID of the workflow
            polling_interval: The interval in seconds for polling channels
        """
        while True:
            try:
                # Get the channels this workflow is subscribed to
                subscriptions = self._workflow_subscriptions.get(workflow_id, set())

                # Check each channel for messages
                for channel_name in subscriptions:
                    channel = self._channels.get(channel_name)
                    if not channel:
                        continue

                    # Try to receive a message with a short timeout
                    message_dict = await channel.receive(timeout=polling_interval)
                    if message_dict:
                        # Process the message
                        await self._process_message(workflow_id, message_dict)

                # Short sleep to avoid busy waiting
                await asyncio.sleep(polling_interval)

            except asyncio.CancelledError:
                logger.info(f"Message processing loop for {workflow_id} cancelled")
                break
            except Exception as e:
                logger.error(f"Error in message processing loop for {workflow_id}: {e}")
                await asyncio.sleep(1)  # Longer sleep on error

    async def _process_message(
        self, workflow_id: str, message_dict: Dict[str, Any]
    ) -> None:
        """Process a received message.

        Args:
            workflow_id: The ID of the workflow
            message_dict: Dictionary representation of the message
        """
        try:
            # Convert to WorkflowMessage
            message = WorkflowMessage.from_dict(message_dict)

            # Skip processing if this message is from this workflow
            if message.sender_id == workflow_id:
                return

            # Skip if this message has a specific recipient that isn't this workflow
            if message.recipient_id and message.recipient_id != workflow_id:
                return

            # Check if there's a handler for this message type
            if workflow_id in self._message_handlers:
                handlers = self._message_handlers[workflow_id]
                handler = handlers.get(message.message_type)

                if handler:
                    # Call the handler
                    await handler(message)
                    logger.debug(
                        f"Handled {message.message_type.value} message "
                        f"for workflow {workflow_id}"
                    )

        except Exception as e:
            logger.error(f"Error processing message for {workflow_id}: {e}")


# Singleton instance
_communication_manager = None


def get_communication_manager() -> WorkflowCommunicationManager:
    """Get the singleton communication manager instance.

    Returns:
        The WorkflowCommunicationManager instance
    """
    global _communication_manager
    if _communication_manager is None:
        _communication_manager = WorkflowCommunicationManager()
    return _communication_manager
