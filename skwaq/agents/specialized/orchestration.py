"""Advanced Orchestration for the Skwaq vulnerability assessment system.

This module provides a backward-compatible import for the advanced orchestrator,
which has been refactored into a more modular structure.
"""

from .workflows.orchestrator import AdvancedOrchestrator
from .workflows.workflow_events import WorkflowEvent
from .workflows.workflow_execution import WorkflowExecution
from .workflows.workflow_types import WorkflowDefinition, WorkflowStatus, WorkflowType

__all__ = [
    "WorkflowType",
    "WorkflowStatus",
    "WorkflowDefinition",
    "WorkflowEvent",
    "WorkflowExecution",
    "AdvancedOrchestrator",
]
