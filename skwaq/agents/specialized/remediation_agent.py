"""Remediation Planning Agent for the Skwaq vulnerability assessment system.

This module defines a specialized workflow agent that develops detailed
remediation plans for addressing discovered vulnerabilities.
"""

import enum
import json
import time
import uuid
from typing import Any, Dict, List, Optional, Union

from ...events.system_events import SystemEvent
from ...shared.finding import Finding
from ...utils.logging import get_logger
from ..base import AutogenChatAgent
from ..events import Task, TaskAssignmentEvent, TaskResultEvent

logger = get_logger(__name__)


class RemediationPriority(enum.Enum):
    """Priority levels for vulnerability remediation."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class RemediationComplexity(enum.Enum):
    """Complexity levels for remediation implementation."""

    SIMPLE = "simple"
    MODERATE = "moderate"
    COMPLEX = "complex"
    ARCHITECTURAL = "architectural"


class RemediationPlanEvent(SystemEvent):
    """Event for communicating remediation plans."""

    def __init__(
        self,
        sender_id: str,
        finding_id: str,
        priority: RemediationPriority,
        complexity: RemediationComplexity,
        steps: List[Dict[str, Any]],
        code_changes: Optional[Dict[str, Any]] = None,
        estimated_effort: Optional[str] = None,
        plan_id: str = "",
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a remediation plan event.

        Args:
            sender_id: ID of the sending agent
            finding_id: ID of the finding being remediated
            priority: Remediation priority level
            complexity: Remediation complexity level
            steps: List of remediation steps
            code_changes: Optional specific code changes
            estimated_effort: Optional estimated effort for implementation
            plan_id: Unique identifier for this plan
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        plan_metadata = metadata or {}
        plan_metadata.update(
            {
                "finding_id": finding_id,
                "priority": priority.value,
                "complexity": complexity.value,
                "steps_count": len(steps),
                "plan_id": plan_id or str(uuid.uuid4()),
                "event_type": "remediation_plan",
            }
        )

        message = f"Remediation plan for finding {finding_id}: {priority.value} priority, {complexity.value} complexity"

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=plan_metadata,
        )
        self.sender_id = sender_id
        self.finding_id = finding_id
        self.priority = priority
        self.complexity = complexity
        self.steps = steps
        self.code_changes = code_changes or {}
        self.estimated_effort = estimated_effort
        self.plan_id = plan_metadata["plan_id"]


class RemediationPlanningAgent(AutogenChatAgent):
    """Specialized agent for creating vulnerability remediation plans.

    This agent analyzes vulnerability findings and creates detailed plans for
    remediation, including specific steps, code changes, and implementation
    considerations.
    """

    def __init__(
        self,
        name: str = "RemediationPlanningAgent",
        description: str = "Creates detailed remediation plans for vulnerabilities",
        config_key: str = "agents.remediation_planning",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the remediation planning agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are a Remediation Planning Agent for a vulnerability assessment system.
Your purpose is to analyze reported vulnerabilities and create detailed, actionable
plans for their remediation, prioritizing fixes based on risk and implementation complexity.

Your responsibilities include:
1. Analyzing vulnerabilities to understand their root causes
2. Developing detailed remediation steps for each vulnerability
3. Suggesting specific code changes to fix security issues
4. Prioritizing remediation efforts based on risk and impact
5. Estimating implementation complexity and effort
6. Identifying potential challenges or side effects of remediation
7. Providing best practice recommendations for long-term security

Your remediation plans should be practical, technically sound, and tailored to
the specific vulnerability and development context. For each vulnerability,
provide specific, actionable steps that developers can implement directly,
including code examples where appropriate.

Remember that your goal is to provide complete, accurate, and effective remediation
guidance that addresses the root cause of each vulnerability, not just the symptoms.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )

        # Set up remediation plan tracking
        self.remediation_plans: Dict[str, Dict[str, Any]] = {}
        self.remediation_tasks: Dict[str, Task] = {}

    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()

        # Register event handlers
        self.register_event_handler(
            RemediationPlanEvent, self._handle_remediation_plan_event
        )
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        self.register_event_handler(TaskResultEvent, self._handle_task_result)

    async def create_remediation_plan(
        self,
        finding: Union[Finding, Dict[str, Any]],
        context: Optional[Dict[str, Any]] = None,
        code_context: Optional[Dict[str, Any]] = None,
        plan_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a remediation plan for a vulnerability finding.

        Args:
            finding: The finding to remediate (can be Finding object or dict)
            context: Optional additional context about the environment
            code_context: Optional code context (surrounding code, related files)
            plan_id: Optional unique identifier for this plan

        Returns:
            Remediation plan details
        """
        # Generate plan ID if not provided
        plan_id = plan_id or f"remediation_{int(time.time())}_{str(uuid.uuid4())[:8]}"

        # Convert Finding to dict if needed
        if isinstance(finding, Finding):
            finding_dict = finding.to_dict()
            finding_id = finding.file_id
        else:
            finding_dict = finding
            finding_id = finding_dict.get(
                "file_id", finding_dict.get("finding_id", "unknown")
            )

        logger.info(f"Creating remediation plan for finding: {finding_id}")

        # Create remediation task
        remediation_task = Task(
            task_id=plan_id,
            task_type="remediation_planning",
            task_description=f"Create remediation plan for {finding_id}",
            task_parameters={
                "finding_id": finding_id,
                "context": context or {},
                "code_context": code_context or {},
            },
            priority=3,
            sender_id=self.agent_id,
            receiver_id=self.agent_id,
            status="in_progress",
        )

        self.remediation_tasks[plan_id] = remediation_task

        try:
            # Prepare the remediation plan record
            plan = {
                "plan_id": plan_id,
                "finding_id": finding_id,
                "finding": finding_dict,
                "context": context or {},
                "code_context": code_context or {},
                "timestamp": time.time(),
                "priority": None,
                "complexity": None,
                "steps": [],
                "code_changes": {},
                "estimated_effort": None,
            }

            # Generate the remediation plan
            plan_result = await self._generate_remediation_plan(
                finding_dict, context or {}, code_context or {}
            )

            # Update the plan with results
            plan.update(plan_result)

            # Store the remediation plan
            self.remediation_plans[plan_id] = plan

            # Update task status
            remediation_task.status = "completed"
            remediation_task.result = plan

            # Emit remediation plan event
            await self._emit_remediation_plan_event(plan)

            logger.info(
                f"Completed remediation plan with priority: {plan['priority']}, complexity: {plan['complexity']}"
            )

            return plan

        except Exception as e:
            logger.error(f"Error creating remediation plan: {e}")
            remediation_task.status = "failed"
            remediation_task.error = str(e)
            raise

    async def _generate_remediation_plan(
        self,
        finding: Dict[str, Any],
        context: Dict[str, Any],
        code_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a detailed remediation plan for a finding.

        Args:
            finding: Finding to remediate
            context: Additional context information
            code_context: Code context information

        Returns:
            Dictionary with remediation plan details
        """
        # Prepare prompt for remediation plan generation
        finding_str = json.dumps(finding, indent=2)
        context_str = json.dumps(context, indent=2)
        code_context_str = json.dumps(code_context, indent=2)

        # Build comprehensive prompt for the LLM
        remediation_prompt = (
            f"I need you to create a detailed remediation plan for the following vulnerability finding:\n\n"
            f"FINDING:\n{finding_str}\n\n"
            f"CONTEXT:\n{context_str}\n\n"
            f"CODE CONTEXT:\n{code_context_str}\n\n"
            f"Please analyze this vulnerability and create a comprehensive remediation plan with the following elements:\n"
            f"1. Remediation priority (critical, high, medium, low, informational)\n"
            f"2. Implementation complexity (simple, moderate, complex, architectural)\n"
            f"3. A list of detailed remediation steps with explanations\n"
            f"4. Specific code changes recommended to fix the issue\n"
            f"5. Estimated effort for implementation (hours/days)\n"
            f"6. Potential challenges or side effects of remediation\n"
            f"7. Best practices to prevent similar issues\n\n"
            f"Return your remediation plan in JSON format with the following fields:\n"
            f"- priority: One of the priority levels mentioned above\n"
            f"- complexity: One of the complexity levels mentioned above\n"
            f"- steps: Array of step objects with 'description' and 'explanation' fields\n"
            f"- code_changes: Object with 'before' and 'after' code examples\n"
            f"- estimated_effort: Estimated time for implementation\n"
            f"- challenges: Array of potential challenges\n"
            f"- best_practices: Array of best practice recommendations\n"
        )

        # Use the chat model to generate the remediation plan
        response = await self.openai_client.create_completion(
            prompt=remediation_prompt,
            model=self.model,
            temperature=0.2,
            max_tokens=2500,
            response_format={"type": "json"},
        )

        # Extract the text response
        response_text = response.get("choices", [{}])[0].get("text", "").strip()

        try:
            # Parse the JSON response
            plan = json.loads(response_text)

            # Ensure all required fields are present
            if "priority" not in plan:
                plan["priority"] = "medium"
            if "complexity" not in plan:
                plan["complexity"] = "moderate"
            if "steps" not in plan:
                plan["steps"] = []
            if "code_changes" not in plan:
                plan["code_changes"] = {}
            if "estimated_effort" not in plan:
                plan["estimated_effort"] = "Unknown"
            if "challenges" not in plan:
                plan["challenges"] = []
            if "best_practices" not in plan:
                plan["best_practices"] = []

            # Validate priority
            try:
                priority = RemediationPriority(plan["priority"])
                plan["priority"] = priority.value
            except ValueError:
                plan["priority"] = RemediationPriority.MEDIUM.value

            # Validate complexity
            try:
                complexity = RemediationComplexity(plan["complexity"])
                plan["complexity"] = complexity.value
            except ValueError:
                plan["complexity"] = RemediationComplexity.MODERATE.value

            return plan

        except json.JSONDecodeError:
            logger.error(f"Failed to parse remediation plan: {response_text}")
            # Return a default plan on parsing error
            return {
                "priority": RemediationPriority.MEDIUM.value,
                "complexity": RemediationComplexity.MODERATE.value,
                "steps": [
                    {
                        "description": "Review vulnerability details",
                        "explanation": "Analyze the finding to understand the underlying issue",
                    },
                    {
                        "description": "Implement fixes following secure coding practices",
                        "explanation": "Error creating detailed remediation plan; generic guidance provided",
                    },
                ],
                "code_changes": {},
                "estimated_effort": "Unknown (plan generation failed)",
                "challenges": ["Plan generation error"],
                "best_practices": ["Follow secure coding guidelines"],
            }

    async def _emit_remediation_plan_event(self, plan: Dict[str, Any]) -> None:
        """Emit a remediation plan event with results.

        Args:
            plan: Remediation plan to emit
        """
        try:
            # Convert priority and complexity strings to enums
            if isinstance(plan["priority"], str):
                try:
                    priority = RemediationPriority(plan["priority"])
                except ValueError:
                    priority = RemediationPriority.MEDIUM
            else:
                priority = plan["priority"]

            if isinstance(plan["complexity"], str):
                try:
                    complexity = RemediationComplexity(plan["complexity"])
                except ValueError:
                    complexity = RemediationComplexity.MODERATE
            else:
                complexity = plan["complexity"]

            # Create remediation plan event
            event = RemediationPlanEvent(
                sender_id=self.agent_id,
                finding_id=plan["finding_id"],
                priority=priority,
                complexity=complexity,
                steps=plan.get("steps", []),
                code_changes=plan.get("code_changes"),
                estimated_effort=plan.get("estimated_effort"),
                plan_id=plan["plan_id"],
            )

            # Emit the event
            self.emit_event(event)

        except Exception as e:
            logger.error(f"Error emitting remediation plan event: {e}")

    async def _handle_remediation_plan_event(self, event: RemediationPlanEvent) -> None:
        """Handle incoming remediation plan events.

        Args:
            event: Incoming remediation plan event
        """
        # Log the received plan
        logger.info(
            f"Received remediation plan event for finding {event.finding_id}: "
            f"{event.priority.value} priority, {event.complexity.value} complexity"
        )

        # Store the plan for reference
        self.remediation_plans[event.plan_id] = {
            "plan_id": event.plan_id,
            "finding_id": event.finding_id,
            "priority": event.priority.value,
            "complexity": event.complexity.value,
            "steps": event.steps,
            "code_changes": event.code_changes,
            "estimated_effort": event.estimated_effort,
            "sender_id": event.sender_id,
            "timestamp": time.time(),
        }

    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment events.

        Args:
            event: Task assignment event
        """
        if event.receiver_id != self.agent_id:
            return

        if event.task_type == "remediation_planning":
            # Extract finding information from task parameters
            params = event.task_parameters
            finding_id = params.get("finding_id")
            finding_data = params.get("finding")
            context = params.get("context", {})
            code_context = params.get("code_context", {})

            if not finding_id or not finding_data:
                logger.warning(
                    f"Received remediation planning task without finding data: {event.task_id}"
                )

                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing finding data"},
                )
                return

            # Begin remediation planning process
            try:
                result = await self.create_remediation_plan(
                    finding=finding_data,
                    context=context,
                    code_context=code_context,
                    plan_id=event.task_id,
                )

                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result,
                )

            except Exception as e:
                logger.error(f"Error in remediation planning task: {e}")

                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)},
                )

    async def _emit_task_result(
        self, task_id: str, sender_id: str, status: str, result: Any
    ) -> None:
        """Emit a task result event.

        Args:
            task_id: ID of the task
            sender_id: ID of the sender
            status: Status of the task
            result: Result of the task
        """
        event = TaskResultEvent(
            sender_id=self.agent_id,
            receiver_id=sender_id,
            task_id=task_id,
            status=status,
            result=result,
        )
        self.emit_event(event)

    async def _handle_task_result(self, event: TaskResultEvent) -> None:
        """Handle task result events.

        Args:
            event: Task result event
        """
        # Currently no specific handling needed for task results
        pass

    def get_remediation_plan(self, plan_id: str) -> Optional[Dict[str, Any]]:
        """Get a remediation plan by ID.

        Args:
            plan_id: ID of the plan to retrieve

        Returns:
            Remediation plan or None if not found
        """
        return self.remediation_plans.get(plan_id)

    def get_remediation_plans_by_finding(self, finding_id: str) -> List[Dict[str, Any]]:
        """Get all remediation plans for a specific finding.

        Args:
            finding_id: ID of the finding

        Returns:
            List of remediation plans for the finding
        """
        return [
            p
            for p in self.remediation_plans.values()
            if p.get("finding_id") == finding_id
        ]
