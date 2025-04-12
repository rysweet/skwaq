"""Main orchestrator for specialized agent workflows.

This module provides the main orchestrator class for managing and
executing specialized agent workflows.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional, Set

from ....events.system_events import EventBus
from ....utils.logging import get_logger
from ...base import AutogenChatAgent
from ...communication_patterns.chain_of_thought import ChainOfThoughtPattern
from ...communication_patterns.debate import DebatePattern
from ...communication_patterns.feedback_loop import FeedbackLoopPattern
from ...communication_patterns.parallel_reasoning import ParallelReasoningPattern
from ..exploitation_agent import ExploitabilityStatus, ExploitationVerificationAgent

# Import specialized agents
from ..guided_assessment_agent import GuidedAssessmentAgent
from ..policy_agent import SecurityPolicyAgent
from ..remediation_agent import (
    RemediationComplexity,
    RemediationPlanningAgent,
    RemediationPriority,
)
from .workflow_events import WorkflowEvent
from .workflow_execution import WorkflowExecution

# Import workflow-related classes
from .workflow_types import WorkflowDefinition, WorkflowStatus, WorkflowType

# Import utility functions
from .workflow_utils import create_workflow_id, validate_workflow_definition

logger = get_logger(__name__)


class AdvancedOrchestrator(AutogenChatAgent):
    """Advanced orchestrator for managing and executing specialized agent workflows."""

    def __init__(self, agent_id: Optional[str] = None):
        """Initialize the advanced orchestrator.

        Args:
            agent_id: Optional agent ID, generated if not provided
        """
        super().__init__(
            agent_id=agent_id or f"orchestrator_{uuid.uuid4().hex[:8]}",
            name="Advanced Workflow Orchestrator",
            system_message="""You are an advanced workflow orchestrator for 
            vulnerability assessment. Your role is to coordinate specialized agents 
            to execute complex workflows, assign tasks, collect results, and ensure 
            the completion of security assessments.""",
        )

        # Store workflow definitions and executions
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.workflow_executions: Dict[str, WorkflowExecution] = {}
        self.active_workflows: Set[str] = set()

        # Register for event bus
        self.event_bus = EventBus()

        # Register communication patterns
        self.communication_patterns = {
            "chain_of_thought": ChainOfThoughtPattern(),
            "debate": DebatePattern(),
            "feedback_loop": FeedbackLoopPattern(),
            "parallel_reasoning": ParallelReasoningPattern(),
        }

    async def create_workflow(
        self,
        workflow_type: WorkflowType,
        target_id: str,
        target_type: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Create a new workflow.

        Args:
            workflow_type: Type of workflow to create
            target_id: ID of the target (repository, file, etc.)
            target_type: Type of target (repository, file, etc.)
            name: Optional name for the workflow
            description: Optional description for the workflow
            parameters: Optional parameters for the workflow

        Returns:
            str: ID of the created workflow
        """
        workflow_id = create_workflow_id()

        # Generate name and description if not provided
        if name is None:
            name = f"{workflow_type.value.replace('_', ' ').title()} Workflow"

        if description is None:
            description = f"Workflow for {workflow_type.value.replace('_', ' ')} of {target_type} {target_id}"

        # Set default parameters if not provided
        if parameters is None:
            parameters = {"depth": "standard"}

        # Generate workflow components based on type
        components = await self._generate_workflow_components(
            workflow_type, target_type, parameters
        )

        # Create workflow definition
        workflow_def = WorkflowDefinition(
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            name=name,
            description=description,
            target_id=target_id,
            target_type=target_type,
            parameters=parameters,
            agents=components["agents"],
            stages=components["stages"],
            communication_patterns=components["communication_patterns"],
            created_at=int(datetime.now().timestamp()),
        )

        # Validate workflow definition
        validate_workflow_definition(workflow_def)

        # Store workflow definition
        self.workflow_definitions[workflow_id] = workflow_def

        logger.info(f"Created workflow: {workflow_id} of type {workflow_type.value}")

        return workflow_id

    async def execute_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Execute a workflow.

        Args:
            workflow_id: ID of the workflow to execute

        Returns:
            Dict[str, Any]: Workflow execution results

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow definition not found: {workflow_id}")

        # Get workflow definition
        workflow_def = self.workflow_definitions[workflow_id]

        # Create workflow execution
        workflow_exec = WorkflowExecution(
            workflow_id=workflow_id,
            definition=workflow_def,
            status=WorkflowStatus.INITIALIZING,
            current_stage=0,
            progress=0.0,
            start_time=int(datetime.now().timestamp()),
        )

        # Store workflow execution
        self.workflow_executions[workflow_id] = workflow_exec

        # Add to active workflows
        self.active_workflows.add(workflow_id)

        # Emit workflow initialization event
        await self._emit_workflow_event(
            workflow_id,
            workflow_def.workflow_type,
            WorkflowStatus.INITIALIZING,
            0.0,
            {"stage": "initialization"},
        )

        # Execute workflow
        try:
            await self._execute_workflow(workflow_id)

            # Compile and return results
            return self._compile_workflow_results(workflow_id)
        except Exception as e:
            logger.error(f"Error executing workflow {workflow_id}: {str(e)}")

            # Update workflow execution
            workflow_exec.status = WorkflowStatus.FAILED
            workflow_exec.error = str(e)
            workflow_exec.completion_time = int(datetime.now().timestamp())

            # Remove from active workflows
            if workflow_id in self.active_workflows:
                self.active_workflows.remove(workflow_id)

            # Emit workflow failure event
            await self._emit_workflow_event(
                workflow_id,
                workflow_def.workflow_type,
                WorkflowStatus.FAILED,
                workflow_exec.progress,
                {"error": str(e)},
            )

            return {
                "workflow_id": workflow_id,
                "status": WorkflowStatus.FAILED.value,
                "error": str(e),
            }

    async def _execute_workflow(self, workflow_id: str) -> WorkflowExecution:
        """Execute a workflow based on its definition.

        Args:
            workflow_id: ID of the workflow to execute

        Returns:
            WorkflowExecution: Updated workflow execution

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow definition not found: {workflow_id}")

        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow execution not found: {workflow_id}")

        # Get workflow definition and execution
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]

        # Update workflow status
        workflow_exec.status = WorkflowStatus.RUNNING

        # Emit workflow running event
        await self._emit_workflow_event(
            workflow_id,
            workflow_def.workflow_type,
            WorkflowStatus.RUNNING,
            workflow_exec.progress,
            {"stage": "running"},
        )

        # Execute each stage sequentially
        for i, stage in enumerate(workflow_def.stages):
            # Update current stage
            workflow_exec.current_stage = i
            workflow_exec.update_progress()

            # Emit stage start event
            await self._emit_workflow_event(
                workflow_id,
                workflow_def.workflow_type,
                WorkflowStatus.RUNNING,
                workflow_exec.progress,
                {"stage": stage["name"], "status": "starting"},
            )

            try:
                # Execute stage
                result = await self._execute_workflow_stage(workflow_id, i)

                # Store stage result
                workflow_exec.add_stage_result(i, result)

                # Emit stage completion event
                await self._emit_workflow_event(
                    workflow_id,
                    workflow_def.workflow_type,
                    WorkflowStatus.RUNNING,
                    workflow_exec.progress,
                    {"stage": stage["name"], "status": "completed", "result": result},
                )

            except Exception as e:
                logger.error(
                    f"Error executing workflow {workflow_id} stage {i}: {str(e)}"
                )

                # Update workflow execution
                workflow_exec.status = WorkflowStatus.FAILED
                workflow_exec.error = f"Error in stage {stage['name']}: {str(e)}"
                workflow_exec.completion_time = int(datetime.now().timestamp())

                # Emit stage failure event
                await self._emit_workflow_event(
                    workflow_id,
                    workflow_def.workflow_type,
                    WorkflowStatus.FAILED,
                    workflow_exec.progress,
                    {"stage": stage["name"], "status": "failed", "error": str(e)},
                )

                # Remove from active workflows
                if workflow_id in self.active_workflows:
                    self.active_workflows.remove(workflow_id)

                return workflow_exec

        # Mark workflow as completed
        workflow_exec.mark_completed()

        # Remove from active workflows
        if workflow_id in self.active_workflows:
            self.active_workflows.remove(workflow_id)

        # Emit workflow completion event
        await self._emit_workflow_event(
            workflow_id,
            workflow_def.workflow_type,
            WorkflowStatus.COMPLETED,
            1.0,
            self._compile_workflow_results(workflow_id),
        )

        return workflow_exec

    async def _execute_workflow_stage(
        self, workflow_id: str, stage_index: int
    ) -> Dict[str, Any]:
        """Execute a specific stage of a workflow.

        Args:
            workflow_id: ID of the workflow
            stage_index: Index of the stage to execute

        Returns:
            Dict[str, Any]: Stage execution results

        Raises:
            ValueError: If workflow ID is not found or stage index is invalid
        """
        from .workflow_implementation import execute_workflow_stage

        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow definition not found: {workflow_id}")

        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow execution not found: {workflow_id}")

        # Get workflow definition and execution
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]

        # Initialize agent instances if needed - this would be more sophisticated in production
        agent_instances = {
            "guided_assessment": GuidedAssessmentAgent(),
            "exploitation_verification": ExploitationVerificationAgent(),
            "remediation_planning": RemediationPlanningAgent(),
            "security_policy": SecurityPolicyAgent(),
        }

        # Execute the stage
        return await execute_workflow_stage(
            workflow_id,
            stage_index,
            workflow_def,
            workflow_exec,
            agent_instances,
            self.communication_patterns,
        )

    async def _generate_workflow_components(
        self, workflow_type: WorkflowType, target_type: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate workflow components based on type.

        Args:
            workflow_type: Type of workflow
            target_type: Type of target
            parameters: Workflow parameters

        Returns:
            Dict[str, Any]: Dictionary of workflow components
        """
        from .workflow_implementation import generate_workflow_components

        return await generate_workflow_components(
            workflow_type, target_type, parameters
        )

    async def _emit_workflow_event(
        self,
        workflow_id: str,
        workflow_type: WorkflowType,
        status: WorkflowStatus,
        progress: float,
        results: Dict[str, Any],
    ) -> None:
        """Emit a workflow event.

        Args:
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            status: Current status of the workflow
            progress: Progress as a float between 0 and 1
            results: Dictionary of workflow results
        """
        event = WorkflowEvent(
            sender_id=self.agent_id,
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=status,
            progress=progress,
            results=results,
        )

        await self.event_bus.emit(event)

    def _summarize_verifications(
        self, verifications: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Summarize verification results.

        Args:
            verifications: List of verification dictionaries

        Returns:
            Dict[str, Any]: Summary of verification results
        """
        if not verifications:
            return {
                "count": 0,
                "exploitable": 0,
                "potentially_exploitable": 0,
                "not_exploitable": 0,
                "undetermined": 0,
            }

        exploitable = sum(
            1
            for v in verifications
            if v.get("status") == ExploitabilityStatus.EXPLOITABLE.value
        )
        potentially = sum(
            1
            for v in verifications
            if v.get("status") == ExploitabilityStatus.POTENTIALLY_EXPLOITABLE.value
        )
        not_exploitable = sum(
            1
            for v in verifications
            if v.get("status") == ExploitabilityStatus.NOT_EXPLOITABLE.value
        )
        undetermined = sum(
            1
            for v in verifications
            if v.get("status") == ExploitabilityStatus.UNDETERMINED.value
        )

        return {
            "count": len(verifications),
            "exploitable": exploitable,
            "potentially_exploitable": potentially,
            "not_exploitable": not_exploitable,
            "undetermined": undetermined,
        }

    def _summarize_remediation_plans(
        self, remediation_plans: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Summarize remediation plans.

        Args:
            remediation_plans: List of remediation plan dictionaries

        Returns:
            Dict[str, Any]: Summary of remediation plans
        """
        if not remediation_plans:
            return {
                "count": 0,
                "high_priority": 0,
                "medium_priority": 0,
                "low_priority": 0,
                "simple_complexity": 0,
                "moderate_complexity": 0,
                "complex_complexity": 0,
            }

        high = sum(
            1
            for p in remediation_plans
            if p.get("priority") == RemediationPriority.HIGH.value
        )
        medium = sum(
            1
            for p in remediation_plans
            if p.get("priority") == RemediationPriority.MEDIUM.value
        )
        low = sum(
            1
            for p in remediation_plans
            if p.get("priority") == RemediationPriority.LOW.value
        )

        simple = sum(
            1
            for p in remediation_plans
            if p.get("complexity") == RemediationComplexity.SIMPLE.value
        )
        moderate = sum(
            1
            for p in remediation_plans
            if p.get("complexity") == RemediationComplexity.MODERATE.value
        )
        complex = sum(
            1
            for p in remediation_plans
            if p.get("complexity") == RemediationComplexity.COMPLEX.value
        )

        return {
            "count": len(remediation_plans),
            "high_priority": high,
            "medium_priority": medium,
            "low_priority": low,
            "simple_complexity": simple,
            "moderate_complexity": moderate,
            "complex_complexity": complex,
        }

    def _compile_workflow_results(self, workflow_id: str) -> Dict[str, Any]:
        """Compile comprehensive workflow results.

        Args:
            workflow_id: ID of the workflow

        Returns:
            Dict[str, Any]: Compiled workflow results

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow definition not found: {workflow_id}")

        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow execution not found: {workflow_id}")

        # Get workflow definition and execution
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]

        # Build basic result structure
        results = {
            "workflow_id": workflow_id,
            "workflow_type": workflow_def.workflow_type.value,
            "name": workflow_def.name,
            "description": workflow_def.description,
            "target_id": workflow_def.target_id,
            "target_type": workflow_def.target_type,
            "status": workflow_exec.status.value,
            "start_time": workflow_exec.start_time,
            "completion_time": workflow_exec.completion_time,
            "execution_time": workflow_exec.get_execution_time(),
            "error": workflow_exec.error,
        }

        # Add stage results
        stage_results = {}
        for i, stage in enumerate(workflow_def.stages):
            stage_name = stage["name"]
            if i in workflow_exec.stage_results:
                stage_results[stage_name] = workflow_exec.stage_results[i]
            else:
                stage_results[stage_name] = {"status": "not_executed"}

        results["stage_results"] = stage_results

        # Add findings if available
        if "findings" in workflow_exec.artifacts:
            results["findings"] = workflow_exec.artifacts["findings"]

            # Count findings by severity
            severity_counts = {}
            for finding in workflow_exec.artifacts["findings"]:
                severity = finding.get("severity", "unknown")
                severity_counts[severity] = severity_counts.get(severity, 0) + 1

            results["finding_counts"] = severity_counts

        # Add verification summary if available
        if "verifications" in workflow_exec.artifacts:
            results["verification_summary"] = self._summarize_verifications(
                workflow_exec.artifacts["verifications"]
            )

        # Add remediation summary if available
        if "remediation_plans" in workflow_exec.artifacts:
            results["remediation_summary"] = self._summarize_remediation_plans(
                workflow_exec.artifacts["remediation_plans"]
            )

        # Add policy evaluation if available
        if "policy_evaluation" in workflow_exec.artifacts:
            results["policy_evaluation"] = workflow_exec.artifacts["policy_evaluation"]

        # Include all artifacts
        results["artifacts"] = workflow_exec.artifacts

        return results
