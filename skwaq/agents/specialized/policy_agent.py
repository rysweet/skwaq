"""Security Policy Agent for the Skwaq vulnerability assessment system.

This module defines a specialized workflow agent that evaluates findings against
security policies and compliance requirements, and generates policy recommendations.
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


class ComplianceStatus(enum.Enum):
    """Status of compliance with security policies."""

    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    REQUIRES_INVESTIGATION = "requires_investigation"
    NOT_APPLICABLE = "not_applicable"


class PolicyRecommendationType(enum.Enum):
    """Types of policy recommendations."""

    NEW_POLICY = "new_policy"
    POLICY_UPDATE = "policy_update"
    PROCESS_IMPROVEMENT = "process_improvement"
    CONTROL_IMPLEMENTATION = "control_implementation"
    TRAINING = "training"


class PolicyEvaluationEvent(SystemEvent):
    """Event for communicating policy evaluation results."""

    def __init__(
        self,
        sender_id: str,
        target_id: str,
        target_type: str,
        policy_references: List[Dict[str, Any]],
        compliance_status: ComplianceStatus,
        compliance_gaps: List[Dict[str, Any]],
        recommendations: List[Dict[str, Any]],
        evaluation_id: str = "",
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a policy evaluation event.

        Args:
            sender_id: ID of the sending agent
            target_id: ID of the target being evaluated (finding, repo, etc.)
            target_type: Type of the target (finding, repository, etc.)
            policy_references: List of relevant policy references
            compliance_status: Overall compliance status
            compliance_gaps: List of identified compliance gaps
            recommendations: List of policy recommendations
            evaluation_id: Unique identifier for this evaluation
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        eval_metadata = metadata or {}
        eval_metadata.update(
            {
                "target_id": target_id,
                "target_type": target_type,
                "compliance_status": compliance_status.value,
                "policy_count": len(policy_references),
                "gaps_count": len(compliance_gaps),
                "recommendations_count": len(recommendations),
                "evaluation_id": evaluation_id or str(uuid.uuid4()),
                "event_type": "policy_evaluation",
            }
        )

        message = f"Policy evaluation for {target_type} {target_id}: {compliance_status.value}"

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=eval_metadata,
        )
        self.sender_id = sender_id
        self.target_id = target_id
        self.target_type = target_type
        self.policy_references = policy_references
        self.compliance_status = compliance_status
        self.compliance_gaps = compliance_gaps
        self.recommendations = recommendations
        self.evaluation_id = eval_metadata["evaluation_id"]


class PolicyRecommendationEvent(SystemEvent):
    """Event for communicating policy recommendations."""

    def __init__(
        self,
        sender_id: str,
        recommendation_type: PolicyRecommendationType,
        title: str,
        description: str,
        justification: str,
        implementation_steps: List[str],
        policy_references: Optional[List[Dict[str, Any]]] = None,
        recommendation_id: str = "",
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a policy recommendation event.

        Args:
            sender_id: ID of the sending agent
            recommendation_type: Type of policy recommendation
            title: Short title of the recommendation
            description: Detailed description of the recommendation
            justification: Justification for this recommendation
            implementation_steps: Steps to implement the recommendation
            policy_references: Optional references to existing policies
            recommendation_id: Unique identifier for this recommendation
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        rec_metadata = metadata or {}
        rec_metadata.update(
            {
                "recommendation_type": recommendation_type.value,
                "implementation_steps_count": len(implementation_steps),
                "recommendation_id": recommendation_id or str(uuid.uuid4()),
                "event_type": "policy_recommendation",
            }
        )

        message = f"Policy recommendation: {title} ({recommendation_type.value})"

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=rec_metadata,
        )
        self.sender_id = sender_id
        self.recommendation_type = recommendation_type
        self.title = title
        self.description = description
        self.justification = justification
        self.implementation_steps = implementation_steps
        self.policy_references = policy_references or []
        self.recommendation_id = rec_metadata["recommendation_id"]


class SecurityPolicyAgent(AutogenChatAgent):
    """Specialized agent for evaluating security policies and compliance.

    This agent evaluates findings and repositories against security policies
    and compliance requirements, identifies gaps, and generates policy
    recommendations to improve security posture.
    """

    def __init__(
        self,
        name: str = "SecurityPolicyAgent",
        description: str = "Evaluates security policies and generates recommendations",
        config_key: str = "agents.security_policy",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the security policy agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are a Security Policy Agent for a vulnerability assessment system.
Your purpose is to evaluate findings and repositories against security policies
and compliance requirements, identify gaps, and generate policy recommendations.

Your responsibilities include:
1. Analyzing vulnerability findings for policy compliance
2. Identifying security policy violations and compliance gaps
3. Mapping findings to relevant security standards (NIST, CIS, OWASP, etc.)
4. Generating policy recommendations based on identified gaps
5. Suggesting process improvements to prevent future violations
6. Providing implementation guidance for security controls
7. Helping organizations align security practices with best practices

Your evaluations should be thorough, standards-based, and actionable. For each
finding or set of findings, identify relevant security policies, determine
compliance status, and provide specific recommendations for policy improvements
or new policy creation.

Remember that effective security policies balance protection with practicality.
Your recommendations should aim to improve security posture while being
implementable within reasonable constraints.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )

        # Set up policy evaluation tracking
        self.policy_evaluations: Dict[str, Dict[str, Any]] = {}
        self.policy_recommendations: Dict[str, Dict[str, Any]] = {}
        self.evaluation_tasks: Dict[str, Task] = {}

        # Initialize policy knowledge base
        self.policy_knowledge: Dict[str, Dict[str, Any]] = {
            "standards": {
                "NIST_800_53": {
                    "description": "NIST Special Publication 800-53 Security Controls"
                },
                "OWASP_ASVS": {
                    "description": "OWASP Application Security Verification Standard"
                },
                "CIS": {"description": "Center for Internet Security Benchmarks"},
                "ISO_27001": {
                    "description": "ISO/IEC 27001 Information Security Management"
                },
                "PCI_DSS": {
                    "description": "Payment Card Industry Data Security Standard"
                },
            },
            "categories": {
                "access_control": {
                    "description": "Controls for managing system access"
                },
                "authentication": {
                    "description": "Authentication mechanisms and policies"
                },
                "authorization": {"description": "Authorization controls and policies"},
                "data_protection": {
                    "description": "Data encryption and protection policies"
                },
                "secure_coding": {
                    "description": "Secure coding practices and requirements"
                },
                "logging_monitoring": {
                    "description": "Logging and monitoring requirements"
                },
                "incident_response": {"description": "Incident response procedures"},
                "configuration_management": {
                    "description": "Secure configuration requirements"
                },
            },
        }

    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()

        # Register event handlers
        self.register_event_handler(
            PolicyEvaluationEvent, self._handle_policy_evaluation_event
        )
        self.register_event_handler(
            PolicyRecommendationEvent, self._handle_policy_recommendation_event
        )
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        self.register_event_handler(TaskResultEvent, self._handle_task_result)

    async def evaluate_policy_compliance(
        self,
        target: Union[Finding, Dict[str, Any]],
        target_type: str,
        policy_context: Optional[Dict[str, Any]] = None,
        evaluation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Evaluate policy compliance for a finding or repository.

        Args:
            target: The target to evaluate (finding or repository)
            target_type: Type of target ('finding', 'repository', etc.)
            policy_context: Optional context about applicable policies
            evaluation_id: Optional unique identifier for this evaluation

        Returns:
            Policy evaluation results
        """
        # Generate evaluation ID if not provided
        evaluation_id = (
            evaluation_id or f"policy_eval_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        )

        # Convert Finding to dict if needed
        if isinstance(target, Finding):
            target_dict = target.to_dict()
            target_id = target.file_id
        else:
            target_dict = target
            target_id = target_dict.get(
                "file_id",
                target_dict.get("finding_id", target_dict.get("id", "unknown")),
            )

        logger.info(
            f"Starting policy compliance evaluation for {target_type} {target_id}"
        )

        # Create evaluation task
        evaluation_task = Task(
            task_id=evaluation_id,
            task_type="policy_evaluation",
            task_description=f"Evaluate policy compliance for {target_type} {target_id}",
            task_parameters={
                "target_id": target_id,
                "target_type": target_type,
                "policy_context": policy_context or {},
            },
            priority=2,
            sender_id=self.agent_id,
            receiver_id=self.agent_id,
            status="in_progress",
        )

        self.evaluation_tasks[evaluation_id] = evaluation_task

        try:
            # Prepare the evaluation record
            evaluation = {
                "evaluation_id": evaluation_id,
                "target_id": target_id,
                "target_type": target_type,
                "target": target_dict,
                "policy_context": policy_context or {},
                "timestamp": time.time(),
                "policy_references": [],
                "compliance_status": None,
                "compliance_gaps": [],
                "recommendations": [],
            }

            # Perform the policy evaluation
            evaluation_result = await self._analyze_policy_compliance(
                target_dict, target_type, policy_context or {}
            )

            # Update the evaluation with results
            evaluation.update(evaluation_result)

            # Store the evaluation
            self.policy_evaluations[evaluation_id] = evaluation

            # Update task status
            evaluation_task.status = "completed"
            evaluation_task.result = evaluation

            # Emit evaluation event
            await self._emit_policy_evaluation_event(evaluation)

            logger.info(
                f"Completed policy evaluation with status: {evaluation['compliance_status']}"
            )

            return evaluation

        except Exception as e:
            logger.error(f"Error evaluating policy compliance: {e}")
            evaluation_task.status = "failed"
            evaluation_task.error = str(e)
            raise

    async def generate_policy_recommendation(
        self,
        input_data: Dict[str, Any],
        recommendation_type: Optional[PolicyRecommendationType] = None,
        policy_context: Optional[Dict[str, Any]] = None,
        recommendation_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generate a security policy recommendation.

        Args:
            input_data: The input data for recommendation generation
            recommendation_type: Optional type of recommendation to generate
            policy_context: Optional context about existing policies
            recommendation_id: Optional unique identifier for this recommendation

        Returns:
            Policy recommendation details
        """
        # Generate recommendation ID if not provided
        recommendation_id = (
            recommendation_id
            or f"policy_rec_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        )

        logger.info(
            f"Generating policy recommendation of type {recommendation_type.value if recommendation_type else 'auto'}"
        )

        try:
            # Determine recommendation type if not specified
            if recommendation_type is None:
                recommendation_type = PolicyRecommendationType.POLICY_UPDATE

                # Try to infer type from input data
                if "gaps" in input_data and input_data.get("gaps", []):
                    if any(
                        "missing policy" in gap.get("description", "").lower()
                        for gap in input_data["gaps"]
                    ):
                        recommendation_type = PolicyRecommendationType.NEW_POLICY
                    elif any(
                        "implementation" in gap.get("description", "").lower()
                        for gap in input_data["gaps"]
                    ):
                        recommendation_type = (
                            PolicyRecommendationType.CONTROL_IMPLEMENTATION
                        )
                    elif any(
                        "process" in gap.get("description", "").lower()
                        for gap in input_data["gaps"]
                    ):
                        recommendation_type = (
                            PolicyRecommendationType.PROCESS_IMPROVEMENT
                        )
                    elif any(
                        "training" in gap.get("description", "").lower()
                        for gap in input_data["gaps"]
                    ):
                        recommendation_type = PolicyRecommendationType.TRAINING

            # Prepare the recommendation record
            recommendation = {
                "recommendation_id": recommendation_id,
                "recommendation_type": recommendation_type.value,
                "input_data": input_data,
                "policy_context": policy_context or {},
                "timestamp": time.time(),
                "title": "",
                "description": "",
                "justification": "",
                "implementation_steps": [],
                "policy_references": [],
            }

            # Generate the recommendation
            recommendation_result = await self._generate_recommendation(
                input_data, recommendation_type, policy_context or {}
            )

            # Update the recommendation with results
            recommendation.update(recommendation_result)

            # Store the recommendation
            self.policy_recommendations[recommendation_id] = recommendation

            # Emit recommendation event
            await self._emit_policy_recommendation_event(recommendation)

            logger.info(f"Generated policy recommendation: {recommendation['title']}")

            return recommendation

        except Exception as e:
            logger.error(f"Error generating policy recommendation: {e}")
            raise

    async def _analyze_policy_compliance(
        self, target: Dict[str, Any], target_type: str, policy_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Analyze policy compliance for a target.

        Args:
            target: Target to analyze
            target_type: Type of the target
            policy_context: Context about applicable policies

        Returns:
            Dictionary with policy compliance analysis
        """
        # Prepare prompt for policy compliance analysis
        target_str = json.dumps(target, indent=2)
        context_str = json.dumps(policy_context, indent=2)

        # Include known policy frameworks in the prompt
        policy_frameworks = json.dumps(self.policy_knowledge["standards"], indent=2)
        policy_categories = json.dumps(self.policy_knowledge["categories"], indent=2)

        # Build comprehensive prompt for the LLM
        policy_prompt = (
            f"I need you to evaluate the following {target_type} for security policy compliance:\n\n"
            f"TARGET ({target_type.upper()}):\n{target_str}\n\n"
            f"POLICY CONTEXT:\n{context_str}\n\n"
            f"AVAILABLE POLICY FRAMEWORKS:\n{policy_frameworks}\n\n"
            f"POLICY CATEGORIES:\n{policy_categories}\n\n"
            f"Please evaluate this {target_type} against relevant security policies and standards. "
            f"For your analysis, provide:\n"
            f"1. A list of relevant policy references (standards, controls, requirements)\n"
            f"2. An overall compliance status (compliant, non_compliant, partially_compliant, requires_investigation, not_applicable)\n"
            f"3. Identified compliance gaps with detailed descriptions\n"
            f"4. Policy recommendations to address the gaps\n\n"
            f"Return your analysis in JSON format with the following fields:\n"
            f"- policy_references: Array of objects with standard, control_id, and description fields\n"
            f"- compliance_status: One of the compliance statuses mentioned above\n"
            f"- compliance_gaps: Array of objects with category, description, and severity fields\n"
            f"- recommendations: Array of objects with type, title, and description fields\n"
        )

        # Use the chat model to analyze policy compliance
        response = await self.openai_client.create_completion(
            prompt=policy_prompt,
            model=self.model,
            temperature=0.2,
            max_tokens=2000,
            response_format={"type": "json"},
        )

        # Extract the text response
        response_text = response.get("choices", [{}])[0].get("text", "").strip()

        try:
            # Parse the JSON response
            evaluation = json.loads(response_text)

            # Ensure all required fields are present
            if "policy_references" not in evaluation:
                evaluation["policy_references"] = []
            if "compliance_status" not in evaluation:
                evaluation["compliance_status"] = "requires_investigation"
            if "compliance_gaps" not in evaluation:
                evaluation["compliance_gaps"] = []
            if "recommendations" not in evaluation:
                evaluation["recommendations"] = []

            # Validate compliance status
            try:
                status = ComplianceStatus(evaluation["compliance_status"])
                evaluation["compliance_status"] = status.value
            except ValueError:
                evaluation[
                    "compliance_status"
                ] = ComplianceStatus.REQUIRES_INVESTIGATION.value

            return evaluation

        except json.JSONDecodeError:
            logger.error(f"Failed to parse policy compliance analysis: {response_text}")
            # Return a default evaluation on parsing error
            return {
                "policy_references": [],
                "compliance_status": ComplianceStatus.REQUIRES_INVESTIGATION.value,
                "compliance_gaps": [
                    {
                        "category": "analysis_error",
                        "description": "Error analyzing policy compliance",
                        "severity": "medium",
                    }
                ],
                "recommendations": [
                    {
                        "type": "process_improvement",
                        "title": "Manual review needed",
                        "description": "Automated analysis failed, manual review recommended",
                    }
                ],
            }

    async def _generate_recommendation(
        self,
        input_data: Dict[str, Any],
        recommendation_type: PolicyRecommendationType,
        policy_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a policy recommendation based on input data.

        Args:
            input_data: Input data for recommendation generation
            recommendation_type: Type of recommendation to generate
            policy_context: Context about existing policies

        Returns:
            Dictionary with recommendation details
        """
        # Prepare prompt for recommendation generation
        input_str = json.dumps(input_data, indent=2)
        context_str = json.dumps(policy_context, indent=2)

        # Build comprehensive prompt for the LLM
        rec_prompt = (
            f"I need you to generate a detailed security policy recommendation "
            f"of type '{recommendation_type.value}' based on the following input:\n\n"
            f"INPUT DATA:\n{input_str}\n\n"
            f"POLICY CONTEXT:\n{context_str}\n\n"
            f"Please generate a comprehensive security policy recommendation that addresses "
            f"the identified issues and aligns with security best practices. "
            f"For your recommendation, provide:\n"
            f"1. A clear, concise title for the recommendation\n"
            f"2. A detailed description of the recommendation\n"
            f"3. A strong justification explaining why this recommendation is important\n"
            f"4. Specific implementation steps to put the recommendation into practice\n"
            f"5. References to relevant security standards or policies\n\n"
            f"Return your recommendation in JSON format with the following fields:\n"
            f"- title: A clear, concise title\n"
            f"- description: Detailed description of the recommendation\n"
            f"- justification: Explanation of why this recommendation is important\n"
            f"- implementation_steps: Array of specific steps to implement\n"
            f"- policy_references: Array of objects with standard, control_id, and description fields\n"
        )

        # Use the chat model to generate the recommendation
        response = await self.openai_client.create_completion(
            prompt=rec_prompt,
            model=self.model,
            temperature=0.3,
            max_tokens=2000,
            response_format={"type": "json"},
        )

        # Extract the text response
        response_text = response.get("choices", [{}])[0].get("text", "").strip()

        try:
            # Parse the JSON response
            recommendation = json.loads(response_text)

            # Ensure all required fields are present
            if "title" not in recommendation:
                recommendation[
                    "title"
                ] = f"Security {recommendation_type.value.replace('_', ' ').title()} Recommendation"
            if "description" not in recommendation:
                recommendation["description"] = "No description provided"
            if "justification" not in recommendation:
                recommendation["justification"] = "Addresses identified security gaps"
            if "implementation_steps" not in recommendation:
                recommendation["implementation_steps"] = [
                    "Review recommendation details",
                    "Develop implementation plan",
                ]
            if "policy_references" not in recommendation:
                recommendation["policy_references"] = []

            # Add recommendation type
            recommendation["recommendation_type"] = recommendation_type.value

            return recommendation

        except json.JSONDecodeError:
            logger.error(f"Failed to parse policy recommendation: {response_text}")
            # Return a default recommendation on parsing error
            return {
                "title": f"Security {recommendation_type.value.replace('_', ' ').title()} Recommendation",
                "description": "A security policy recommendation based on identified gaps",
                "justification": "Addresses security gaps and enhances compliance",
                "implementation_steps": [
                    "Review the identified security gaps",
                    "Develop a detailed implementation plan",
                    "Implement the recommended security controls",
                    "Verify implementation effectiveness",
                ],
                "policy_references": [],
                "recommendation_type": recommendation_type.value,
            }

    async def _emit_policy_evaluation_event(self, evaluation: Dict[str, Any]) -> None:
        """Emit a policy evaluation event with results.

        Args:
            evaluation: Policy evaluation result to emit
        """
        try:
            # Convert status string to enum
            if isinstance(evaluation["compliance_status"], str):
                try:
                    status = ComplianceStatus(evaluation["compliance_status"])
                except ValueError:
                    status = ComplianceStatus.REQUIRES_INVESTIGATION
            else:
                status = evaluation["compliance_status"]

            # Create policy evaluation event
            event = PolicyEvaluationEvent(
                sender_id=self.agent_id,
                target_id=evaluation["target_id"],
                target_type=evaluation["target_type"],
                policy_references=evaluation.get("policy_references", []),
                compliance_status=status,
                compliance_gaps=evaluation.get("compliance_gaps", []),
                recommendations=evaluation.get("recommendations", []),
                evaluation_id=evaluation["evaluation_id"],
            )

            # Emit the event
            self.emit_event(event)

        except Exception as e:
            logger.error(f"Error emitting policy evaluation event: {e}")

    async def _emit_policy_recommendation_event(
        self, recommendation: Dict[str, Any]
    ) -> None:
        """Emit a policy recommendation event.

        Args:
            recommendation: Policy recommendation to emit
        """
        try:
            # Convert type string to enum
            if isinstance(recommendation["recommendation_type"], str):
                try:
                    rec_type = PolicyRecommendationType(
                        recommendation["recommendation_type"]
                    )
                except ValueError:
                    rec_type = PolicyRecommendationType.POLICY_UPDATE
            else:
                rec_type = recommendation["recommendation_type"]

            # Create policy recommendation event
            event = PolicyRecommendationEvent(
                sender_id=self.agent_id,
                recommendation_type=rec_type,
                title=recommendation["title"],
                description=recommendation["description"],
                justification=recommendation["justification"],
                implementation_steps=recommendation.get("implementation_steps", []),
                policy_references=recommendation.get("policy_references", []),
                recommendation_id=recommendation["recommendation_id"],
            )

            # Emit the event
            self.emit_event(event)

        except Exception as e:
            logger.error(f"Error emitting policy recommendation event: {e}")

    async def _handle_policy_evaluation_event(
        self, event: PolicyEvaluationEvent
    ) -> None:
        """Handle incoming policy evaluation events.

        Args:
            event: Incoming policy evaluation event
        """
        # Log the received evaluation
        logger.info(
            f"Received policy evaluation event for {event.target_type} {event.target_id} "
            f"with status {event.compliance_status.value}"
        )

        # Store the evaluation for reference
        self.policy_evaluations[event.evaluation_id] = {
            "evaluation_id": event.evaluation_id,
            "target_id": event.target_id,
            "target_type": event.target_type,
            "policy_references": event.policy_references,
            "compliance_status": event.compliance_status.value,
            "compliance_gaps": event.compliance_gaps,
            "recommendations": event.recommendations,
            "sender_id": event.sender_id,
            "timestamp": time.time(),
        }

    async def _handle_policy_recommendation_event(
        self, event: PolicyRecommendationEvent
    ) -> None:
        """Handle incoming policy recommendation events.

        Args:
            event: Incoming policy recommendation event
        """
        # Log the received recommendation
        logger.info(
            f"Received policy recommendation event: {event.title} "
            f"({event.recommendation_type.value})"
        )

        # Store the recommendation for reference
        self.policy_recommendations[event.recommendation_id] = {
            "recommendation_id": event.recommendation_id,
            "recommendation_type": event.recommendation_type.value,
            "title": event.title,
            "description": event.description,
            "justification": event.justification,
            "implementation_steps": event.implementation_steps,
            "policy_references": event.policy_references,
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

        if event.task_type == "policy_evaluation":
            # Extract task parameters
            params = event.task_parameters
            target_id = params.get("target_id")
            target_type = params.get("target_type")
            target_data = params.get("target")
            policy_context = params.get("policy_context", {})

            if not target_id or not target_data:
                logger.warning(
                    f"Received policy evaluation task without target data: {event.task_id}"
                )

                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing target data"},
                )
                return

            # Begin policy evaluation
            try:
                result = await self.evaluate_policy_compliance(
                    target=target_data,
                    target_type=target_type,
                    policy_context=policy_context,
                    evaluation_id=event.task_id,
                )

                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result,
                )

            except Exception as e:
                logger.error(f"Error in policy evaluation task: {e}")

                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)},
                )

        elif event.task_type == "policy_recommendation":
            # Extract task parameters
            params = event.task_parameters
            input_data = params.get("input_data", {})
            recommendation_type_str = params.get("recommendation_type")
            policy_context = params.get("policy_context", {})

            if not input_data:
                logger.warning(
                    f"Received policy recommendation task without input data: {event.task_id}"
                )

                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing input data"},
                )
                return

            # Convert recommendation type string to enum if provided
            recommendation_type = None
            if recommendation_type_str:
                try:
                    recommendation_type = PolicyRecommendationType(
                        recommendation_type_str
                    )
                except ValueError:
                    logger.warning(
                        f"Invalid recommendation type: {recommendation_type_str}"
                    )

            # Begin recommendation generation
            try:
                result = await self.generate_policy_recommendation(
                    input_data=input_data,
                    recommendation_type=recommendation_type,
                    policy_context=policy_context,
                    recommendation_id=event.task_id,
                )

                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result,
                )

            except Exception as e:
                logger.error(f"Error in policy recommendation task: {e}")

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

    def get_policy_evaluation(self, evaluation_id: str) -> Optional[Dict[str, Any]]:
        """Get a policy evaluation result by ID.

        Args:
            evaluation_id: ID of the evaluation to retrieve

        Returns:
            Policy evaluation or None if not found
        """
        return self.policy_evaluations.get(evaluation_id)

    def get_policy_recommendation(
        self, recommendation_id: str
    ) -> Optional[Dict[str, Any]]:
        """Get a policy recommendation by ID.

        Args:
            recommendation_id: ID of the recommendation to retrieve

        Returns:
            Policy recommendation or None if not found
        """
        return self.policy_recommendations.get(recommendation_id)

    def get_evaluations_by_target(
        self, target_id: str, target_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get all policy evaluations for a specific target.

        Args:
            target_id: ID of the target
            target_type: Optional target type filter

        Returns:
            List of policy evaluations for the target
        """
        if target_type:
            return [
                e
                for e in self.policy_evaluations.values()
                if e.get("target_id") == target_id
                and e.get("target_type") == target_type
            ]
        else:
            return [
                e
                for e in self.policy_evaluations.values()
                if e.get("target_id") == target_id
            ]
