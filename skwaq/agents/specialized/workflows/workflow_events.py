"""Workflow event definitions for specialized agent orchestration.

This module provides event classes for workflow-related events in the
orchestration system.
"""

from typing import Dict, Any, Optional
import uuid
from datetime import datetime

from ...events import AgentCommunicationEvent
from ....events.system_events import EventBus, SystemEvent
from .workflow_types import WorkflowType, WorkflowStatus


class WorkflowEvent(AgentCommunicationEvent):
    """Event representing workflow status updates and results."""

    def __init__(
        self,
        sender_id: str,
        workflow_id: str,
        workflow_type: WorkflowType,
        status: WorkflowStatus,
        progress: float,
        results: Dict[str, Any],
        target: Optional[str] = None,
    ):
        """Initialize a workflow event.

        Args:
            sender_id: ID of the sender agent
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            status: Current status of the workflow
            progress: Progress as a float between 0 and 1
            results: Dictionary of workflow results
            target: Target agent ID, or None for broadcast
        """
        message = f"Workflow {workflow_id} status: {status.value}, progress: {progress}"
        metadata = {
            "workflow_id": workflow_id,
            "workflow_type": workflow_type.value,
            "status": status.value,
            "progress": progress,
            "event_type": "workflow_status",
            "results": results,
        }

        super().__init__(
            sender_id=sender_id,
            receiver_id=target or "broadcast",
            message=message,
            message_type="workflow_status",
            metadata=metadata,
        )

        self.workflow_id = workflow_id
        self.workflow_type = workflow_type
        self.status = status
        self.progress = progress
        self.results = results

        # Add metadata for event filtering
        self.metadata["workflow_id"] = workflow_id
        self.metadata["workflow_type"] = workflow_type.value
        self.metadata["status"] = status.value
        self.metadata["progress"] = progress

    @classmethod
    def create_initialization_event(
        cls,
        sender_id: str,
        workflow_id: str,
        workflow_type: WorkflowType,
        target: Optional[str] = None,
    ) -> "WorkflowEvent":
        """Create an initialization event for a workflow.

        Args:
            sender_id: ID of the sender agent
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            target: Target agent ID, or None for broadcast

        Returns:
            WorkflowEvent: Initialized workflow event
        """
        return cls(
            sender_id=sender_id,
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=WorkflowStatus.INITIALIZING,
            progress=0.0,
            results={"stage": "initialization"},
            target=target,
        )

    @classmethod
    def create_completion_event(
        cls,
        sender_id: str,
        workflow_id: str,
        workflow_type: WorkflowType,
        results: Dict[str, Any],
        target: Optional[str] = None,
    ) -> "WorkflowEvent":
        """Create a completion event for a workflow.

        Args:
            sender_id: ID of the sender agent
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            results: Dictionary of workflow results
            target: Target agent ID, or None for broadcast

        Returns:
            WorkflowEvent: Completion workflow event
        """
        return cls(
            sender_id=sender_id,
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=WorkflowStatus.COMPLETED,
            progress=1.0,
            results=results,
            target=target,
        )

    @classmethod
    def create_failure_event(
        cls,
        sender_id: str,
        workflow_id: str,
        workflow_type: WorkflowType,
        error: str,
        target: Optional[str] = None,
    ) -> "WorkflowEvent":
        """Create a failure event for a workflow.

        Args:
            sender_id: ID of the sender agent
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            error: Error message
            target: Target agent ID, or None for broadcast

        Returns:
            WorkflowEvent: Failure workflow event
        """
        return cls(
            sender_id=sender_id,
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=WorkflowStatus.FAILED,
            progress=0.0,
            results={"error": error},
            target=target,
        )
