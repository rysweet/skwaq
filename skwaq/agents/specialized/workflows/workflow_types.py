"""Workflow type definitions for specialized agent orchestration.

This module provides enums and basic data structures for workflow types
and workflow statuses used in the orchestration system.
"""

import enum
from dataclasses import dataclass, field
from typing import Any, Dict, List


class WorkflowType(enum.Enum):
    """Types of vulnerability assessment workflows."""

    GUIDED_ASSESSMENT = "guided_assessment"
    TARGETED_ANALYSIS = "targeted_analysis"
    EXPLOITATION_VERIFICATION = "exploitation_verification"
    REMEDIATION_PLANNING = "remediation_planning"
    POLICY_COMPLIANCE = "policy_compliance"
    COMPREHENSIVE = "comprehensive"


class WorkflowStatus(enum.Enum):
    """Status of workflow execution."""

    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class WorkflowDefinition:
    """Definition of a workflow with all required components."""

    workflow_id: str
    workflow_type: WorkflowType
    name: str
    description: str
    target_id: str
    target_type: str
    parameters: Dict[str, Any]
    agents: List[str]
    stages: List[Dict[str, Any]]
    communication_patterns: List[str]
    created_at: int  # Unix timestamp
    metadata: Dict[str, Any] = field(default_factory=dict)
