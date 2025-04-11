"""Workflow execution logic for specialized agent orchestration.

This module provides the execution logic and data structures for workflow
execution in the orchestration system.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Set, Tuple, Union
from datetime import datetime
import time

from .workflow_types import WorkflowType, WorkflowStatus, WorkflowDefinition


@dataclass
class WorkflowExecution:
    """Execution state of a workflow."""

    workflow_id: str
    definition: WorkflowDefinition
    status: WorkflowStatus = WorkflowStatus.INITIALIZING
    current_stage: int = 0
    progress: float = 0.0
    start_time: Optional[int] = None  # Unix timestamp
    completion_time: Optional[int] = None  # Unix timestamp
    error: Optional[str] = None
    stage_results: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    artifacts: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Initialize default fields after initialization."""
        if self.start_time is None:
            self.start_time = int(time.time())

    def update_progress(self) -> None:
        """Update the progress based on current stage vs total stages."""
        total_stages = len(self.definition.stages)
        if total_stages > 0:
            self.progress = self.current_stage / total_stages
        else:
            self.progress = 0.0

    def mark_completed(self) -> None:
        """Mark the workflow as completed."""
        self.status = WorkflowStatus.COMPLETED
        self.completion_time = int(time.time())
        self.progress = 1.0

    def mark_failed(self, error: str) -> None:
        """Mark the workflow as failed.

        Args:
            error: Error message
        """
        self.status = WorkflowStatus.FAILED
        self.completion_time = int(time.time())
        self.error = error

    def add_stage_result(self, stage_index: int, result: Dict[str, Any]) -> None:
        """Add a result for a specific stage.

        Args:
            stage_index: Index of the stage
            result: Result dictionary
        """
        self.stage_results[stage_index] = result

    def add_artifact(self, key: str, value: Any) -> None:
        """Add an artifact to the workflow execution.

        Args:
            key: Artifact key
            value: Artifact value
        """
        self.artifacts[key] = value

    def get_execution_time(self) -> int:
        """Get the execution time in seconds.

        Returns:
            Execution time in seconds
        """
        if self.start_time is None:
            return 0

        if self.completion_time is not None:
            return self.completion_time - self.start_time

        return int(time.time()) - self.start_time
