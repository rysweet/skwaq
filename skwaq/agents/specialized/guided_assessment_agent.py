"""Guided Assessment Agent for the Skwaq vulnerability assessment system.

This module defines a specialized workflow agent that provides a guided
approach to vulnerability assessment, helping users systematically
analyze repositories for security issues.
"""

from typing import Dict, List, Any, Optional, Set, Tuple, Union, cast
import asyncio
import json
import enum
import time
import uuid

from ..base import AutogenChatAgent
from ..events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task
from ...events.system_events import EventBus, SystemEvent
from ...utils.config import get_config
from ...utils.logging import get_logger
from ...shared.finding import Finding

logger = get_logger(__name__)


class AssessmentStage(enum.Enum):
    """Stages in a guided vulnerability assessment workflow."""

    INITIALIZATION = "initialization"
    REPOSITORY_SCAN = "repository_scan"
    THREAT_MODELING = "threat_modeling"
    DEPENDENCY_ANALYSIS = "dependency_analysis"
    CODE_REVIEW = "code_review"
    FINDING_VERIFICATION = "finding_verification"
    REPORT_GENERATION = "report_generation"
    COMPLETED = "completed"


class AssessmentPlanEvent(SystemEvent):
    """Event for the assessment plan creation."""

    def __init__(
        self,
        sender_id: str,
        repository_id: str,
        assessment_id: str,
        plan: Dict[str, Any],
        assessment_context: Dict[str, Any],
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an assessment plan event.

        Args:
            sender_id: ID of the sending agent
            repository_id: ID of the repository being assessed
            assessment_id: Unique identifier for this assessment
            plan: The assessment plan with stages and tasks
            assessment_context: Context information for the assessment
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        plan_metadata = metadata or {}
        plan_metadata.update(
            {
                "repository_id": repository_id,
                "assessment_id": assessment_id,
                "stages": len(plan.get("stages", [])),
                "event_type": "assessment_plan",
            }
        )

        message = f"Assessment plan created for repository {repository_id}"

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=plan_metadata,
        )
        self.sender_id = sender_id
        self.repository_id = repository_id
        self.assessment_id = assessment_id
        self.plan = plan
        self.assessment_context = assessment_context


class AssessmentStageEvent(SystemEvent):
    """Event for assessment stage transitions."""

    def __init__(
        self,
        sender_id: str,
        repository_id: str,
        assessment_id: str,
        stage: AssessmentStage,
        status: str,
        progress: float,
        results: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an assessment stage event.

        Args:
            sender_id: ID of the sending agent
            repository_id: ID of the repository being assessed
            assessment_id: Unique identifier for this assessment
            stage: The assessment stage
            status: Status of the stage (starting, in_progress, completed, failed)
            progress: Progress percentage for the stage (0-1)
            results: Optional results from the stage
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        stage_metadata = metadata or {}
        stage_metadata.update(
            {
                "repository_id": repository_id,
                "assessment_id": assessment_id,
                "stage": stage.value,
                "status": status,
                "progress": progress,
                "event_type": "assessment_stage",
            }
        )

        message = (
            f"Assessment stage {stage.value} {status} for repository {repository_id}"
        )

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=stage_metadata,
        )
        self.sender_id = sender_id
        self.repository_id = repository_id
        self.assessment_id = assessment_id
        self.stage = stage
        self.status = status
        self.progress = progress
        self.results = results or {}


class GuidedAssessmentAgent(AutogenChatAgent):
    """Guided assessment agent that provides a structured approach to vulnerability assessment.

    This agent orchestrates a step-by-step vulnerability assessment workflow,
    guiding the assessment process through different stages and delegating
    specialized tasks to other agents in the system.
    """

    def __init__(
        self,
        name: str = "GuidedAssessmentAgent",
        description: str = "Provides guided vulnerability assessment workflows",
        config_key: str = "agents.guided_assessment",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the guided assessment agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are a Guided Assessment Agent for a vulnerability assessment system.
Your purpose is to provide a structured, step-by-step approach to vulnerability assessment,
helping users thoroughly analyze repositories for security issues.

Your responsibilities include:
1. Creating comprehensive assessment plans tailored to the repository's characteristics
2. Guiding the assessment through different stages (initialization, threat modeling, code review, etc.)
3. Coordinating with other specialized agents for specific tasks
4. Tracking progress throughout the assessment process
5. Adapting the assessment strategy based on findings and context
6. Providing clear explanations and recommendations at each stage
7. Ensuring thorough coverage of the codebase and potential vulnerability classes

You should approach each assessment methodically, ensuring that the most critical security
concerns are addressed first, while still providing comprehensive coverage. Your guidance
helps ensure that vulnerability assessments are thorough, consistent, and effective.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )

        # Set up assessment tracking
        self.assessments: Dict[str, Dict[str, Any]] = {}
        self.active_stages: Dict[str, AssessmentStage] = {}
        self.stage_results: Dict[str, Dict[AssessmentStage, Any]] = {}

    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()

        # Register event handlers
        self.register_event_handler(
            AssessmentPlanEvent, self._handle_assessment_plan_event
        )
        self.register_event_handler(
            AssessmentStageEvent, self._handle_assessment_stage_event
        )
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        self.register_event_handler(TaskResultEvent, self._handle_task_result)

    async def create_assessment(
        self,
        repository_id: str,
        repository_info: Dict[str, Any],
        assessment_parameters: Optional[Dict[str, Any]] = None,
        user_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new guided assessment.

        Args:
            repository_id: ID of the repository to assess
            repository_info: Information about the repository (languages, size, etc.)
            assessment_parameters: Optional parameters to customize the assessment
            user_id: Optional user ID initiating the assessment

        Returns:
            Assessment details including ID and plan
        """
        # Generate unique assessment ID
        assessment_id = (
            f"assessment_{repository_id}_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        )

        logger.info(f"Creating assessment plan for repository {repository_id}")

        # Initialize assessment record
        assessment = {
            "assessment_id": assessment_id,
            "repository_id": repository_id,
            "repository_info": repository_info,
            "parameters": assessment_parameters or {},
            "user_id": user_id,
            "start_time": time.time(),
            "current_stage": AssessmentStage.INITIALIZATION,
            "plan": None,
            "findings": [],
            "status": "initializing",
        }

        # Store assessment
        self.assessments[assessment_id] = assessment

        # Initialize stage results
        self.stage_results[assessment_id] = {}

        try:
            # Generate assessment plan
            plan = await self._generate_assessment_plan(
                repository_info, assessment_parameters or {}
            )

            # Update assessment with plan
            assessment["plan"] = plan
            assessment["status"] = "planned"

            # Emit assessment plan event
            await self._emit_assessment_plan_event(
                assessment_id,
                repository_id,
                plan,
                assessment_context={
                    "repository_info": repository_info,
                    "parameters": assessment_parameters or {},
                },
            )

            logger.info(
                f"Assessment plan created for {repository_id} with {len(plan['stages'])} stages"
            )

            # Begin initial stage
            asyncio.create_task(
                self._execute_stage(assessment_id, AssessmentStage.INITIALIZATION)
            )

            return {
                "assessment_id": assessment_id,
                "repository_id": repository_id,
                "plan": plan,
                "status": "started",
            }

        except Exception as e:
            logger.error(f"Error creating assessment plan: {e}")
            assessment["status"] = "failed"
            assessment["error"] = str(e)
            raise

    async def get_assessment_status(self, assessment_id: str) -> Dict[str, Any]:
        """Get the current status of an assessment.

        Args:
            assessment_id: ID of the assessment

        Returns:
            Assessment status information

        Raises:
            ValueError: If assessment ID is not found
        """
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment ID {assessment_id} not found")

        assessment = self.assessments[assessment_id]
        current_stage = assessment.get("current_stage", AssessmentStage.INITIALIZATION)

        # Calculate overall progress based on completed stages
        stages = assessment.get("plan", {}).get("stages", [])
        stage_count = len(stages)

        if stage_count == 0:
            progress = 0.0
        else:
            # Find current stage index
            current_stage_index = 0
            for i, stage in enumerate(stages):
                if stage.get("name") == current_stage.value:
                    current_stage_index = i
                    break

            # Calculate progress
            progress = (current_stage_index / stage_count) * 100

            # Add partial completion of current stage if available
            if current_stage.value in assessment.get("stage_progress", {}):
                stage_progress = assessment["stage_progress"].get(
                    current_stage.value, 0
                )
                progress += stage_progress / stage_count

        return {
            "assessment_id": assessment_id,
            "repository_id": assessment["repository_id"],
            "status": assessment["status"],
            "current_stage": current_stage.value,
            "progress": progress,
            "start_time": assessment["start_time"],
            "completion_time": assessment.get("completion_time"),
            "findings_count": len(assessment.get("findings", [])),
            "error": assessment.get("error"),
        }

    async def _generate_assessment_plan(
        self, repository_info: Dict[str, Any], parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate an assessment plan based on repository information.

        Args:
            repository_info: Information about the repository
            parameters: Parameters for the assessment

        Returns:
            Assessment plan with stages and tasks
        """
        # Extract key information
        languages = repository_info.get("languages", [])
        code_size = repository_info.get("size", 0)
        repo_type = repository_info.get("type", "unknown")

        # Prepare prompt for plan generation
        repo_info_str = json.dumps(repository_info, indent=2)
        params_str = json.dumps(parameters, indent=2)

        plan_prompt = (
            f"I need you to create a comprehensive vulnerability assessment plan for a repository "
            f"with the following characteristics:\n\n"
            f"REPOSITORY INFO:\n{repo_info_str}\n\n"
            f"ASSESSMENT PARAMETERS:\n{params_str}\n\n"
            f"Please generate a detailed assessment plan with the following stages:\n"
            f"1. Initialization - Initial setup and configuration\n"
            f"2. Repository Scan - High-level scan of the codebase\n"
            f"3. Threat Modeling - Identify attack surfaces and potential threats\n"
            f"4. Dependency Analysis - Analyze dependencies for vulnerabilities\n"
            f"5. Code Review - Detailed code review for security issues\n"
            f"6. Finding Verification - Verify findings and eliminate false positives\n"
            f"7. Report Generation - Generate comprehensive vulnerability report\n\n"
            f"For each stage, include:\n"
            f"- Specific tasks tailored to this repository's characteristics\n"
            f"- Estimated completion time for each task\n"
            f"- Required tools or agents\n"
            f"- Expected outputs\n\n"
            f"Return your plan in JSON format with the following structure:\n"
            f'{{"name": "Assessment Plan", "stages": [{{'
            f'"name": "initialization", "tasks": [{{'
            f'"task_id": "init_1", "description": "Task description", '
            f'"estimated_time": "10m", "tools": ["tool1"], "outputs": ["output1"]'
            f"}}]}}]}}"
        )

        # Use the chat model to generate the plan
        response = await self.openai_client.create_completion(
            prompt=plan_prompt,
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

            # Validate plan structure
            if "stages" not in plan:
                plan["stages"] = []

            # Normalize stage names
            for stage in plan["stages"]:
                stage["name"] = stage["name"].lower().replace(" ", "_")

            return plan

        except json.JSONDecodeError:
            logger.error(f"Failed to parse assessment plan: {response_text}")
            # Return a minimal default plan
            return {
                "name": "Default Assessment Plan",
                "stages": [
                    {
                        "name": "initialization",
                        "tasks": [
                            {
                                "task_id": "init_1",
                                "description": "Initialize repository assessment",
                                "estimated_time": "5m",
                                "tools": [],
                                "outputs": ["initialization_report"],
                            }
                        ],
                    },
                    {
                        "name": "repository_scan",
                        "tasks": [
                            {
                                "task_id": "scan_1",
                                "description": "Scan repository for basic security issues",
                                "estimated_time": "15m",
                                "tools": ["code_analyzer"],
                                "outputs": ["scan_report"],
                            }
                        ],
                    },
                ],
            }

    async def _execute_stage(
        self, assessment_id: str, stage: AssessmentStage
    ) -> Dict[str, Any]:
        """Execute a specific stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage: The stage to execute

        Returns:
            Results of the stage execution
        """
        if assessment_id not in self.assessments:
            raise ValueError(f"Assessment ID {assessment_id} not found")

        assessment = self.assessments[assessment_id]
        repository_id = assessment["repository_id"]

        # Find the stage in the plan
        plan = assessment.get("plan", {})
        stages = plan.get("stages", [])
        stage_info = None

        for s in stages:
            if s.get("name") == stage.value:
                stage_info = s
                break

        if not stage_info:
            logger.warning(f"Stage {stage.value} not found in assessment plan")
            stage_info = {"name": stage.value, "tasks": []}

        # Update assessment with current stage
        assessment["current_stage"] = stage

        # Emit stage starting event
        await self._emit_assessment_stage_event(
            assessment_id, repository_id, stage, "starting", 0.0
        )

        logger.info(f"Starting assessment stage {stage.value} for {repository_id}")

        try:
            # Execute the stage-specific logic
            if stage == AssessmentStage.INITIALIZATION:
                results = await self._execute_initialization_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.REPOSITORY_SCAN:
                results = await self._execute_repository_scan_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.THREAT_MODELING:
                results = await self._execute_threat_modeling_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.DEPENDENCY_ANALYSIS:
                results = await self._execute_dependency_analysis_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.CODE_REVIEW:
                results = await self._execute_code_review_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.FINDING_VERIFICATION:
                results = await self._execute_finding_verification_stage(
                    assessment_id, stage_info
                )

            elif stage == AssessmentStage.REPORT_GENERATION:
                results = await self._execute_report_generation_stage(
                    assessment_id, stage_info
                )

            else:
                logger.warning(f"Unknown assessment stage: {stage.value}")
                results = {
                    "status": "skipped",
                    "reason": f"Unknown stage {stage.value}",
                }

            # Store stage results
            self.stage_results[assessment_id][stage] = results

            # Emit stage completed event
            await self._emit_assessment_stage_event(
                assessment_id, repository_id, stage, "completed", 1.0, results
            )

            # Move to next stage if this isn't the final stage
            if stage != AssessmentStage.REPORT_GENERATION:
                # Find next stage
                next_stage = self._get_next_stage(stage)
                if next_stage:
                    # Schedule next stage execution
                    asyncio.create_task(self._execute_stage(assessment_id, next_stage))

            else:
                # Mark assessment as completed
                assessment["status"] = "completed"
                assessment["completion_time"] = time.time()

            logger.info(f"Completed assessment stage {stage.value} for {repository_id}")
            return results

        except Exception as e:
            logger.error(f"Error executing assessment stage {stage.value}: {e}")

            # Emit stage failed event
            await self._emit_assessment_stage_event(
                assessment_id, repository_id, stage, "failed", 0.0, {"error": str(e)}
            )

            # Update assessment with error
            assessment["status"] = "failed"
            assessment["error"] = str(e)

            raise

    def _get_next_stage(
        self, current_stage: AssessmentStage
    ) -> Optional[AssessmentStage]:
        """Get the next stage in the assessment process.

        Args:
            current_stage: The current stage

        Returns:
            The next stage or None if current is final
        """
        stages = [
            AssessmentStage.INITIALIZATION,
            AssessmentStage.REPOSITORY_SCAN,
            AssessmentStage.THREAT_MODELING,
            AssessmentStage.DEPENDENCY_ANALYSIS,
            AssessmentStage.CODE_REVIEW,
            AssessmentStage.FINDING_VERIFICATION,
            AssessmentStage.REPORT_GENERATION,
        ]

        try:
            current_index = stages.index(current_stage)
            if current_index < len(stages) - 1:
                return stages[current_index + 1]
        except ValueError:
            pass

        return None

    async def _execute_initialization_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the initialization stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the initialization stage
        """
        assessment = self.assessments[assessment_id]
        repository_info = assessment.get("repository_info", {})

        # Simulate initialization tasks
        await asyncio.sleep(1)  # In a real implementation, this would do actual work

        # Prepare initialization results
        results = {
            "stage": "initialization",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "repository_details": {
                "languages": repository_info.get("languages", []),
                "size": repository_info.get("size", 0),
                "files_count": repository_info.get("files_count", 0),
            },
            "assessment_configuration": {
                "focus_areas": assessment.get("parameters", {}).get("focus_areas", []),
                "depth": assessment.get("parameters", {}).get("depth", "standard"),
            },
            "status": "completed",
        }

        # In a real implementation, this would perform actual initialization tasks
        # such as repository checking, environment preparation, etc.

        return results

    async def _execute_repository_scan_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the repository scan stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the repository scan stage
        """
        # This would involve scanning the repository for basic metrics and issues
        # For this example, we'll simulate finding a few issues

        await asyncio.sleep(2)  # Simulate work

        # Simulate finding some issues
        findings = [
            {
                "finding_id": f"finding_{assessment_id}_1",
                "type": "security_misconfiguration",
                "severity": "medium",
                "confidence": 0.85,
                "description": "Hardcoded credentials found in configuration file",
                "location": "config/database.yml",
            },
            {
                "finding_id": f"finding_{assessment_id}_2",
                "type": "information_disclosure",
                "severity": "low",
                "confidence": 0.7,
                "description": "Debug information exposure in error handler",
                "location": "src/handlers/errors.js",
            },
        ]

        # Add findings to assessment
        assessment = self.assessments[assessment_id]
        assessment["findings"].extend(findings)

        # Return stage results
        return {
            "stage": "repository_scan",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "files_scanned": 120,  # Example count
            "findings": findings,
            "scan_coverage": 0.85,
            "status": "completed",
        }

    async def _execute_threat_modeling_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the threat modeling stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the threat modeling stage
        """
        # This would involve analyzing attack surfaces and potential threats
        await asyncio.sleep(2)  # Simulate work

        # Simulate threat model
        threat_model = {
            "assets": [
                {"name": "User data", "sensitivity": "high"},
                {"name": "Authentication system", "sensitivity": "high"},
                {"name": "Public API", "sensitivity": "medium"},
            ],
            "threat_actors": [
                {"name": "Malicious users", "capability": "medium"},
                {"name": "Advanced attackers", "capability": "high"},
            ],
            "attack_vectors": [
                {"name": "SQL Injection", "likelihood": "medium", "impact": "high"},
                {"name": "XSS", "likelihood": "high", "impact": "medium"},
                {"name": "CSRF", "likelihood": "low", "impact": "medium"},
            ],
        }

        # Return stage results
        return {
            "stage": "threat_modeling",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "threat_model": threat_model,
            "status": "completed",
        }

    async def _execute_dependency_analysis_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the dependency analysis stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the dependency analysis stage
        """
        # This would involve analyzing dependencies for vulnerabilities
        await asyncio.sleep(1.5)  # Simulate work

        # Simulate dependency findings
        dependency_findings = [
            {
                "finding_id": f"finding_{assessment_id}_3",
                "type": "vulnerable_dependency",
                "severity": "high",
                "confidence": 0.95,
                "description": "Known SQL injection vulnerability in outdated library",
                "dependency": "example-library@1.2.3",
                "cve": "CVE-2023-12345",
            }
        ]

        # Add findings to assessment
        assessment = self.assessments[assessment_id]
        assessment["findings"].extend(dependency_findings)

        # Return stage results
        return {
            "stage": "dependency_analysis",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "dependencies_analyzed": 45,  # Example count
            "vulnerable_dependencies": 3,
            "findings": dependency_findings,
            "status": "completed",
        }

    async def _execute_code_review_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the code review stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the code review stage
        """
        # This would involve detailed code review for security issues
        await asyncio.sleep(3)  # Simulate longer work

        # Simulate code review findings
        code_review_findings = [
            {
                "finding_id": f"finding_{assessment_id}_4",
                "type": "insecure_cryptography",
                "severity": "high",
                "confidence": 0.9,
                "description": "Use of weak MD5 hashing for password storage",
                "location": "src/auth/password.js",
                "line_number": 42,
            },
            {
                "finding_id": f"finding_{assessment_id}_5",
                "type": "access_control",
                "severity": "high",
                "confidence": 0.85,
                "description": "Missing authorization check in admin API",
                "location": "src/api/admin.js",
                "line_number": 87,
            },
        ]

        # Add findings to assessment
        assessment = self.assessments[assessment_id]
        assessment["findings"].extend(code_review_findings)

        # Return stage results
        return {
            "stage": "code_review",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "files_reviewed": 25,
            "code_patterns_detected": 12,
            "findings": code_review_findings,
            "status": "completed",
        }

    async def _execute_finding_verification_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the finding verification stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the finding verification stage
        """
        # This would involve verifying findings and eliminating false positives
        await asyncio.sleep(2)  # Simulate work

        # Get findings from assessment
        assessment = self.assessments[assessment_id]
        findings = assessment.get("findings", [])

        # Simulate verification results
        verified_findings = []
        false_positives = []

        for i, finding in enumerate(findings):
            # Simulate that 10% of findings are false positives
            if i % 10 == 0:
                false_positives.append(finding)
            else:
                finding["verified"] = True
                verified_findings.append(finding)

        # Update assessment with verified findings
        assessment["findings"] = verified_findings

        # Return stage results
        return {
            "stage": "finding_verification",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "findings_analyzed": len(findings),
            "verified_findings": len(verified_findings),
            "false_positives": len(false_positives),
            "verification_confidence": 0.9,
            "status": "completed",
        }

    async def _execute_report_generation_stage(
        self, assessment_id: str, stage_info: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute the report generation stage of the assessment.

        Args:
            assessment_id: ID of the assessment
            stage_info: Information about the stage from the plan

        Returns:
            Results of the report generation stage
        """
        # This would involve generating a comprehensive vulnerability report
        await asyncio.sleep(1)  # Simulate work

        # Get assessment data
        assessment = self.assessments[assessment_id]
        findings = assessment.get("findings", [])

        # Categorize findings by severity
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in severity_counts:
                severity_counts[severity] += 1

        # Generate report (in a real implementation, this would create a structured report)
        report = {
            "assessment_id": assessment_id,
            "repository_id": assessment["repository_id"],
            "summary": {
                "total_findings": len(findings),
                "severity_distribution": severity_counts,
                "risk_level": self._calculate_risk_level(severity_counts),
            },
            "findings": findings,
            "stage_results": {
                stage.value: results
                for stage, results in self.stage_results.get(assessment_id, {}).items()
            },
            "generated_at": time.time(),
        }

        # Set the report on the assessment
        assessment["report"] = report

        # Return stage results
        return {
            "stage": "report_generation",
            "tasks_completed": len(stage_info.get("tasks", [])),
            "report_sections": ["summary", "findings", "recommendations"],
            "report_id": f"report_{assessment_id}",
            "status": "completed",
        }

    def _calculate_risk_level(self, severity_counts: Dict[str, int]) -> str:
        """Calculate overall risk level based on finding severity distribution.

        Args:
            severity_counts: Count of findings by severity

        Returns:
            Overall risk level (critical, high, medium, low)
        """
        if severity_counts.get("critical", 0) > 0:
            return "critical"
        elif severity_counts.get("high", 0) > 0:
            return "high"
        elif severity_counts.get("medium", 0) > 0:
            return "medium"
        elif severity_counts.get("low", 0) > 0:
            return "low"
        else:
            return "low"

    async def _emit_assessment_plan_event(
        self,
        assessment_id: str,
        repository_id: str,
        plan: Dict[str, Any],
        assessment_context: Dict[str, Any],
    ) -> None:
        """Emit an assessment plan event.

        Args:
            assessment_id: ID of the assessment
            repository_id: ID of the repository
            plan: The assessment plan
            assessment_context: Context information for the assessment
        """
        event = AssessmentPlanEvent(
            sender_id=self.agent_id,
            repository_id=repository_id,
            assessment_id=assessment_id,
            plan=plan,
            assessment_context=assessment_context,
        )
        self.emit_event(event)

    async def _emit_assessment_stage_event(
        self,
        assessment_id: str,
        repository_id: str,
        stage: AssessmentStage,
        status: str,
        progress: float,
        results: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Emit an assessment stage event.

        Args:
            assessment_id: ID of the assessment
            repository_id: ID of the repository
            stage: The assessment stage
            status: Status of the stage
            progress: Progress percentage
            results: Optional results from the stage
        """
        event = AssessmentStageEvent(
            sender_id=self.agent_id,
            repository_id=repository_id,
            assessment_id=assessment_id,
            stage=stage,
            status=status,
            progress=progress,
            results=results,
        )
        self.emit_event(event)

    async def _handle_assessment_plan_event(self, event: AssessmentPlanEvent) -> None:
        """Handle assessment plan events.

        Args:
            event: The assessment plan event
        """
        logger.info(f"Received assessment plan event for {event.repository_id}")

        # Store plan if from another agent
        if event.sender_id != self.agent_id:
            if event.assessment_id not in self.assessments:
                self.assessments[event.assessment_id] = {
                    "assessment_id": event.assessment_id,
                    "repository_id": event.repository_id,
                    "plan": event.plan,
                    "status": "received",
                    "findings": [],
                }

    async def _handle_assessment_stage_event(self, event: AssessmentStageEvent) -> None:
        """Handle assessment stage events.

        Args:
            event: The assessment stage event
        """
        # Log stage event
        logger.info(
            f"Received assessment stage event: {event.stage.value} {event.status} "
            f"for {event.repository_id}"
        )

        # If this is from another agent, update our records
        if event.sender_id != self.agent_id and event.assessment_id in self.assessments:
            assessment = self.assessments[event.assessment_id]

            # Update assessment with stage progress
            if "stage_progress" not in assessment:
                assessment["stage_progress"] = {}

            assessment["stage_progress"][event.stage.value] = event.progress

            # If stage completed, store results
            if event.status == "completed" and event.results:
                if event.assessment_id not in self.stage_results:
                    self.stage_results[event.assessment_id] = {}

                self.stage_results[event.assessment_id][event.stage] = event.results

    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment events.

        Args:
            event: The task assignment event
        """
        # Only handle tasks assigned to this agent
        if event.receiver_id != self.agent_id:
            return

        logger.info(f"Received task assignment: {event.task_id} - {event.task_type}")

        # Handle different task types
        if event.task_type == "create_assessment":
            # Extract parameters
            params = event.task_parameters
            repository_id = params.get("repository_id")
            repository_info = params.get("repository_info", {})

            # Create assessment
            try:
                assessment = await self.create_assessment(
                    repository_id=repository_id,
                    repository_info=repository_info,
                    assessment_parameters=params.get("parameters"),
                    user_id=params.get("user_id"),
                )

                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=assessment,
                )

            except Exception as e:
                logger.error(f"Error creating assessment: {e}")

                # Emit task failure
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)},
                )

        elif event.task_type == "get_assessment_status":
            # Extract parameters
            params = event.task_parameters
            assessment_id = params.get("assessment_id")

            # Get assessment status
            try:
                status = await self.get_assessment_status(assessment_id)

                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=status,
                )

            except Exception as e:
                logger.error(f"Error getting assessment status: {e}")

                # Emit task failure
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)},
                )

        else:
            logger.warning(f"Unknown task type: {event.task_type}")

            # Emit task failure
            await self._emit_task_result(
                task_id=event.task_id,
                sender_id=event.sender_id,
                status="failed",
                result={"error": f"Unknown task type: {event.task_type}"},
            )

    async def _emit_task_result(
        self, task_id: str, sender_id: str, status: str, result: Any
    ) -> None:
        """Emit a task result event.

        Args:
            task_id: ID of the task
            sender_id: ID of the sender (who assigned the task)
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
            event: The task result event
        """
        # Only process results intended for this agent
        if event.receiver_id != self.agent_id:
            return

        logger.info(f"Received task result: {event.task_id} - {event.status}")

        # Currently no specific handling needed for task results
        # In a real implementation, we might update assessment state based on task results
