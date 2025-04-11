"""Agent communication events for the Skwaq vulnerability assessment system.

This module defines the communication events used by agents to exchange
messages, task assignments, and results.
"""

from typing import Dict, Any, Optional
import time
from dataclasses import dataclass, field

from ..events.system_events import SystemEvent
from ..utils.logging import get_logger

# Define logging
logger = get_logger(__name__)


class AgentCommunicationEvent(SystemEvent):
    """Event for agent-to-agent communication."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        message: str,
        message_type: str = "text",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an agent communication event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            message: The content of the message
            message_type: Type of message (text, json, etc.)
            metadata: Optional metadata for the message
        """
        super().__init__(
            sender=sender_id,
            message=message,
            target=receiver_id,
            metadata=metadata or {},
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_type = message_type


class TaskAssignmentEvent(SystemEvent):
    """Event for task assignment between agents."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        task_id: str,
        task_type: str,
        task_description: str,
        task_parameters: Optional[Dict[str, Any]] = None,
        priority: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a task assignment event.

        Args:
            sender_id: ID of the agent assigning the task
            receiver_id: ID of the agent receiving the task
            task_id: Unique identifier for the task
            task_type: Type of task
            task_description: Description of the task
            task_parameters: Parameters for the task
            priority: Task priority (1-5, with 5 being highest)
            metadata: Optional metadata for the task
        """
        task_metadata = metadata or {}
        task_metadata.update(
            {
                "task_id": task_id,
                "task_type": task_type,
                "task_parameters": task_parameters or {},
                "priority": priority,
            }
        )

        super().__init__(
            sender=sender_id,
            message=task_description,
            target=receiver_id,
            metadata=task_metadata,
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.task_id = task_id
        self.task_type = task_type
        self.task_description = task_description
        self.task_parameters = task_parameters or {}
        self.priority = priority


class TaskResultEvent(SystemEvent):
    """Event for sending task results between agents."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        task_id: str,
        status: str,
        result: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a task result event.

        Args:
            sender_id: ID of the agent sending the result
            receiver_id: ID of the agent that assigned the task
            task_id: ID of the task this is a result for
            status: Status of the task (completed, failed, etc.)
            result: The result data
            metadata: Optional metadata for the result
        """
        result_metadata = metadata or {}
        result_metadata.update(
            {
                "task_id": task_id,
                "status": status,
                "result_summary": str(result)[
                    :100
                ],  # Include a summary in the metadata
            }
        )

        message = f"Task {task_id} {status}"

        super().__init__(
            sender=sender_id,
            message=message,
            target=receiver_id,
            metadata=result_metadata,
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.task_id = task_id
        self.status = status
        self.result = result


@dataclass
class Task:
    """Task model for agent task tracking."""

    task_id: str
    task_type: str
    task_description: str
    task_parameters: Dict[str, Any]
    priority: int
    sender_id: str
    receiver_id: str
    status: str = "pending"
    result: Any = None
    assigned_time: float = field(default_factory=time.time)
    completed_time: Optional[float] = None
