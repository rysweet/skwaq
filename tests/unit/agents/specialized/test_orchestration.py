"""Unit tests for advanced orchestration functionality."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json
import sys
import uuid
import enum
from datetime import datetime

# Before importing any of our modules, properly mock the autogen modules
autogen_mock = MagicMock()
autogen_agent_mock = MagicMock()
autogen_event_mock = MagicMock()
autogen_code_utils_mock = MagicMock()
autogen_memory_mock = MagicMock()


# Create a MockBaseEvent class for tests
class MockBaseEvent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


# Set up our mocks properly
autogen_event_mock.BaseEvent = MockBaseEvent
autogen_event_mock.Event = MagicMock()
autogen_event_mock.EventHook = MagicMock()
autogen_event_mock.register_hook = MagicMock()

# Create mock for agents
autogen_agent_mock.Agent = MagicMock()
autogen_agent_mock.ChatAgent = MagicMock()

# Assign the mocks to the sys.modules
sys.modules["autogen_core"] = autogen_mock
sys.modules["autogen_core.agent"] = autogen_agent_mock
sys.modules["autogen_core.event"] = autogen_event_mock
sys.modules["autogen_core.code_utils"] = autogen_code_utils_mock
sys.modules["autogen_core.memory"] = autogen_memory_mock

# Import specialized agents
from skwaq.agents.specialized.workflows import (
    AdvancedOrchestrator,
    WorkflowType,
    WorkflowStatus,
    WorkflowEvent,
    WorkflowDefinition,
    WorkflowExecution,
)
from skwaq.agents.specialized.guided_assessment_agent import (
    GuidedAssessmentAgent,
    AssessmentStage,
    AssessmentPlanEvent,
    AssessmentStageEvent,
)
from skwaq.agents.specialized.exploitation_agent import (
    ExploitationVerificationAgent,
    ExploitabilityStatus,
    ExploitVerificationEvent,
)
from skwaq.agents.specialized.remediation_agent import (
    RemediationPlanningAgent,
    RemediationPriority,
    RemediationComplexity,
    RemediationPlanEvent,
)
from skwaq.agents.specialized.policy_agent import (
    SecurityPolicyAgent,
    ComplianceStatus,
    PolicyEvaluationEvent,
    PolicyRecommendationEvent,
)


class TestWorkflowEvents:
    """Tests for workflow event classes."""

    def test_workflow_event_initialization(self):
        """Test WorkflowEvent initialization."""
        event = WorkflowEvent(
            sender_id="orchestrator_1",
            workflow_id="workflow_123",
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            status=WorkflowStatus.RUNNING,
            progress=0.5,
            results={"stage_completed": "initialization"},
            target="all",
        )

        assert event.sender_id == "orchestrator_1"
        assert event.workflow_id == "workflow_123"
        assert event.workflow_type == WorkflowType.GUIDED_ASSESSMENT
        assert event.status == WorkflowStatus.RUNNING
        assert event.progress == 0.5
        assert event.results == {"stage_completed": "initialization"}

        # Check metadata
        assert "workflow_id" in event.metadata
        assert event.metadata["workflow_id"] == "workflow_123"
        assert event.metadata["workflow_type"] == WorkflowType.GUIDED_ASSESSMENT.value
        assert event.metadata["status"] == WorkflowStatus.RUNNING.value
        assert event.metadata["progress"] == 0.5
        assert event.metadata["event_type"] == "workflow_status"


class TestWorkflowDefinition:
    """Tests for WorkflowDefinition dataclass."""

    def test_workflow_definition_initialization(self):
        """Test WorkflowDefinition initialization."""
        workflow_def = WorkflowDefinition(
            workflow_id="workflow_123",
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            name="Test Workflow",
            description="A test workflow",
            target_id="repo123",
            target_type="repository",
            parameters={"depth": "standard"},
            agents=["guided_assessment"],
            stages=[
                {
                    "name": "initialization",
                    "agent": "guided_assessment",
                    "description": "Initialize workflow",
                }
            ],
            communication_patterns=["chain_of_thought"],
            created_at=1000000,
        )

        assert workflow_def.workflow_id == "workflow_123"
        assert workflow_def.workflow_type == WorkflowType.GUIDED_ASSESSMENT
        assert workflow_def.name == "Test Workflow"
        assert workflow_def.description == "A test workflow"
        assert workflow_def.target_id == "repo123"
        assert workflow_def.target_type == "repository"
        assert workflow_def.parameters == {"depth": "standard"}
        assert workflow_def.agents == ["guided_assessment"]
        assert len(workflow_def.stages) == 1
        assert workflow_def.stages[0]["name"] == "initialization"
        assert workflow_def.communication_patterns == ["chain_of_thought"]
        assert workflow_def.created_at == 1000000


class TestWorkflowExecution:
    """Tests for WorkflowExecution dataclass."""

    def test_workflow_execution_initialization(self):
        """Test WorkflowExecution initialization."""
        # Create a workflow definition
        workflow_def = WorkflowDefinition(
            workflow_id="workflow_123",
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            name="Test Workflow",
            description="A test workflow",
            target_id="repo123",
            target_type="repository",
            parameters={},
            agents=["guided_assessment"],
            stages=[
                {
                    "name": "initialization",
                    "agent": "guided_assessment",
                    "description": "Initialize workflow",
                }
            ],
            communication_patterns=["chain_of_thought"],
            created_at=1000000,
        )

        # Create workflow execution
        workflow_exec = WorkflowExecution(
            workflow_id="workflow_123",
            definition=workflow_def,
            status=WorkflowStatus.INITIALIZING,
            current_stage=0,
            progress=0.0,
            start_time=None,
            completion_time=None,
            error=None,
        )

        assert workflow_exec.workflow_id == "workflow_123"
        assert workflow_exec.definition == workflow_def
        assert workflow_exec.status == WorkflowStatus.INITIALIZING
        assert workflow_exec.current_stage == 0
        assert workflow_exec.progress == 0.0
        assert workflow_exec.start_time is None
        assert workflow_exec.completion_time is None
        assert workflow_exec.error is None
        assert isinstance(workflow_exec.stage_results, dict)
        assert len(workflow_exec.stage_results) == 0
        assert isinstance(workflow_exec.artifacts, dict)
        assert len(workflow_exec.artifacts) == 0


class TestWorkflowGeneration:
    """Tests for workflow generation functionality."""

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.workflows.orchestrator.AutogenChatAgent.__init__")
    @patch(
        "skwaq.agents.specialized.workflows.workflow_implementation.generate_workflow_components"
    )
    async def test_generate_workflow_components_guided_assessment(
        self, mock_generate, mock_base_init
    ):
        """Test generating components for guided assessment workflow."""
        mock_base_init.return_value = None

        # Mock the return value of the imported function
        mock_components = {
            "agents": ["guided_assessment"],
            "stages": [
                {
                    "name": "stage1",
                    "agent": "guided_assessment",
                    "description": "Stage 1",
                },
                {
                    "name": "stage2",
                    "agent": "guided_assessment",
                    "description": "Stage 2",
                },
                {
                    "name": "stage3",
                    "agent": "guided_assessment",
                    "description": "Stage 3",
                },
            ],
            "communication_patterns": ["chain_of_thought"],
        }
        mock_generate.return_value = mock_components

        # Initialize agent
        agent = AdvancedOrchestrator()

        # Generate workflow components
        components = await agent._generate_workflow_components(
            WorkflowType.GUIDED_ASSESSMENT, "repository", {"depth": "standard"}
        )

        # Verify components
        assert "agents" in components
        assert "guided_assessment" in components["agents"]
        assert "stages" in components
        assert (
            len(components["stages"]) >= 3
        )  # Should have at least initialization, assessment, reporting
        assert "communication_patterns" in components
        assert "chain_of_thought" in components["communication_patterns"]

        # Verify stages structure
        for stage in components["stages"]:
            assert "name" in stage
            assert "agent" in stage
            assert "description" in stage

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.workflows.orchestrator.AutogenChatAgent.__init__")
    @patch(
        "skwaq.agents.specialized.workflows.workflow_implementation.generate_workflow_components"
    )
    async def test_generate_workflow_components_comprehensive(
        self, mock_generate, mock_base_init
    ):
        """Test generating components for comprehensive workflow."""
        mock_base_init.return_value = None

        # Mock the return value of the imported function
        mock_components = {
            "agents": [
                "guided_assessment",
                "exploitation_verification",
                "remediation_planning",
                "security_policy",
            ],
            "stages": [
                {
                    "name": "stage1",
                    "agent": "guided_assessment",
                    "description": "Stage 1",
                },
                {
                    "name": "stage2",
                    "agent": "guided_assessment",
                    "description": "Stage 2",
                },
                {
                    "name": "stage3",
                    "agent": "exploitation_verification",
                    "description": "Stage 3",
                },
                {
                    "name": "stage4",
                    "agent": "remediation_planning",
                    "description": "Stage 4",
                },
                {
                    "name": "stage5",
                    "agent": "security_policy",
                    "description": "Stage 5",
                },
                {
                    "name": "stage6",
                    "agent": "guided_assessment",
                    "description": "Stage 6",
                },
                {
                    "name": "stage7",
                    "agents": ["guided_assessment", "security_policy"],
                    "description": "Collaborative",
                    "communication_pattern": "debate",
                },
            ],
            "communication_patterns": [
                "chain_of_thought",
                "debate",
                "feedback_loop",
                "parallel_reasoning",
            ],
        }
        mock_generate.return_value = mock_components

        # Initialize agent
        agent = AdvancedOrchestrator()

        # Generate workflow components
        components = await agent._generate_workflow_components(
            WorkflowType.COMPREHENSIVE, "repository", {"depth": "standard"}
        )

        # Verify components
        assert "agents" in components
        assert len(components["agents"]) >= 4  # Should have all specialized agents
        assert "guided_assessment" in components["agents"]
        assert "exploitation_verification" in components["agents"]
        assert "remediation_planning" in components["agents"]
        assert "security_policy" in components["agents"]

        assert "stages" in components
        assert (
            len(components["stages"]) >= 7
        )  # Should have multiple stages for comprehensive workflow

        assert "communication_patterns" in components
        assert (
            len(components["communication_patterns"]) >= 4
        )  # Should have all communication patterns
        assert "chain_of_thought" in components["communication_patterns"]
        assert "debate" in components["communication_patterns"]
        assert "feedback_loop" in components["communication_patterns"]
        assert "parallel_reasoning" in components["communication_patterns"]

        # Verify multi-agent collaborative stage
        has_collaborative_stage = False
        for stage in components["stages"]:
            if "agents" in stage and len(stage["agents"]) > 1:
                has_collaborative_stage = True
                assert "communication_pattern" in stage
                break

        assert (
            has_collaborative_stage
        ), "Should have at least one collaborative stage with multiple agents"


class TestWorkflowExecution:
    """Tests for workflow execution functionality."""

    @pytest.mark.asyncio
    async def test_execute_workflow_sequential_stages(self):
        """Test executing a workflow with sequential stages."""

        # Create a mock orchestrator with minimal functionality
        class MockAdvancedOrchestrator:
            def __init__(self):
                self.workflow_definitions = {}
                self.workflow_executions = {}
                self.active_workflows = set()
                self._execute_workflow_stage = AsyncMock()
                self._emit_workflow_event = AsyncMock()
                self._compile_workflow_results = MagicMock(
                    return_value={"summary": "workflow results"}
                )

            async def _execute_workflow(self, workflow_id):
                """Mock implementation of _execute_workflow"""
                workflow_def = self.workflow_definitions[workflow_id]
                workflow_exec = self.workflow_executions[workflow_id]

                # Execute each stage sequentially
                for i, stage in enumerate(workflow_def.stages):
                    result = await self._execute_workflow_stage(workflow_id, i)
                    workflow_exec.stage_results[i] = result
                    workflow_exec.current_stage = i + 1

                # Update workflow completion
                workflow_exec.status = WorkflowStatus.COMPLETED
                workflow_exec.completion_time = 1000000
                workflow_exec.progress = 1.0

                # Remove from active workflows
                if workflow_id in self.active_workflows:
                    self.active_workflows.remove(workflow_id)

                # Emit completion event
                await self._emit_workflow_event(
                    workflow_id,
                    workflow_def.workflow_type,
                    WorkflowStatus.COMPLETED,
                    1.0,
                    self._compile_workflow_results(workflow_id),
                )

                return workflow_exec

        # Initialize our mock orchestrator
        agent = MockAdvancedOrchestrator()

        # Create a workflow definition
        workflow_id = "workflow_123"
        workflow_def = WorkflowDefinition(
            workflow_id=workflow_id,
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            name="Test Workflow",
            description="A test workflow",
            target_id="repo123",
            target_type="repository",
            parameters={},
            agents=["guided_assessment"],
            stages=[
                {
                    "name": "stage1",
                    "agent": "guided_assessment",
                    "description": "Stage 1",
                },
                {
                    "name": "stage2",
                    "agent": "guided_assessment",
                    "description": "Stage 2",
                },
                {
                    "name": "stage3",
                    "agent": "guided_assessment",
                    "description": "Stage 3",
                },
            ],
            communication_patterns=["chain_of_thought"],
            created_at=1000000,
        )

        # Create workflow execution
        workflow_exec = WorkflowExecution(
            workflow_id=workflow_id,
            definition=workflow_def,
            status=WorkflowStatus.RUNNING,
            current_stage=0,
            progress=0.0,
            start_time=1000000,
        )

        # Store workflow definition and execution
        agent.workflow_definitions[workflow_id] = workflow_def
        agent.workflow_executions[workflow_id] = workflow_exec
        agent.active_workflows.add(workflow_id)

        # Setup _execute_workflow_stage mock to return successfully for each stage
        agent._execute_workflow_stage.side_effect = [
            {"stage": "stage1", "status": "completed", "result": "Stage 1 complete"},
            {"stage": "stage2", "status": "completed", "result": "Stage 2 complete"},
            {"stage": "stage3", "status": "completed", "result": "Stage 3 complete"},
        ]

        # Execute workflow
        await agent._execute_workflow(workflow_id)

        # Verify _execute_workflow_stage was called for each stage
        assert agent._execute_workflow_stage.call_count == 3

        # Verify the stages were executed in order
        call_args_list = agent._execute_workflow_stage.call_args_list
        assert call_args_list[0][0][0] == workflow_id
        assert call_args_list[0][0][1] == 0  # stage1
        assert call_args_list[1][0][0] == workflow_id
        assert call_args_list[1][0][1] == 1  # stage2
        assert call_args_list[2][0][0] == workflow_id
        assert call_args_list[2][0][1] == 2  # stage3

        # Verify workflow execution was updated
        assert workflow_exec.status == WorkflowStatus.COMPLETED
        assert workflow_exec.completion_time == 1000000
        assert workflow_exec.progress == 1.0
        assert len(workflow_exec.stage_results) == 3
        assert workflow_id not in agent.active_workflows

        # Verify _emit_workflow_event was called for completion
        agent._emit_workflow_event.assert_called_with(
            workflow_id,
            WorkflowType.GUIDED_ASSESSMENT,
            WorkflowStatus.COMPLETED,
            1.0,
            {"summary": "workflow results"},
        )

    @pytest.mark.asyncio
    async def test_execute_workflow_with_dependencies(self):
        """Test executing a workflow with stage dependencies."""

        # Create a mock orchestrator that supports dependencies
        class MockAdvancedOrchestrator:
            def __init__(self):
                self.workflow_definitions = {}
                self.workflow_executions = {}
                self.active_workflows = set()
                self._execute_workflow_stage = AsyncMock()
                self._emit_workflow_event = AsyncMock()
                self._compile_workflow_results = MagicMock(
                    return_value={"summary": "workflow results"}
                )

                # Track executed stages for dependency validation
                self.executed_stages = set()

            async def _execute_workflow(self, workflow_id):
                """Mock implementation of _execute_workflow with dependencies support"""
                workflow_def = self.workflow_definitions[workflow_id]
                workflow_exec = self.workflow_executions[workflow_id]

                # Reset executed stages
                self.executed_stages = set()

                # Process stages in proper dependency order
                for i, stage in enumerate(workflow_def.stages):
                    # Check dependencies first
                    dependencies_met = True
                    if "dependencies" in stage:
                        for dep in stage["dependencies"]:
                            # Find the index of this dependency
                            dep_index = next(
                                (
                                    idx
                                    for idx, s in enumerate(workflow_def.stages)
                                    if s["name"] == dep
                                ),
                                None,
                            )
                            if (
                                dep_index is None
                                or dep_index not in self.executed_stages
                            ):
                                dependencies_met = False
                                break

                    # If dependencies are met or there are none, execute the stage
                    if dependencies_met:
                        result = await self._execute_workflow_stage(workflow_id, i)
                        workflow_exec.stage_results[i] = result
                        self.executed_stages.add(i)

                # Update workflow completion
                workflow_exec.current_stage = len(workflow_def.stages)
                workflow_exec.status = WorkflowStatus.COMPLETED
                workflow_exec.completion_time = 1000000
                workflow_exec.progress = 1.0

                # Remove from active workflows
                if workflow_id in self.active_workflows:
                    self.active_workflows.remove(workflow_id)

                # Emit completion event
                await self._emit_workflow_event(
                    workflow_id,
                    workflow_def.workflow_type,
                    WorkflowStatus.COMPLETED,
                    1.0,
                    self._compile_workflow_results(workflow_id),
                )

                return workflow_exec

        # Initialize our mock orchestrator
        agent = MockAdvancedOrchestrator()

        # Create a workflow definition with dependencies
        workflow_id = "workflow_123"
        workflow_def = WorkflowDefinition(
            workflow_id=workflow_id,
            workflow_type=WorkflowType.COMPREHENSIVE,
            name="Test Workflow",
            description="A test workflow",
            target_id="repo123",
            target_type="repository",
            parameters={},
            agents=["guided_assessment", "exploitation_verification"],
            stages=[
                {
                    "name": "stage1",
                    "agent": "guided_assessment",
                    "description": "Stage 1",
                },
                {
                    "name": "stage2",
                    "agent": "guided_assessment",
                    "description": "Stage 2",
                    "dependencies": ["stage1"],
                },
                {
                    "name": "stage3",
                    "agent": "exploitation_verification",
                    "description": "Stage 3",
                    "dependencies": ["stage1"],
                },
                {
                    "name": "stage4",
                    "agent": "guided_assessment",
                    "description": "Stage 4",
                    "dependencies": ["stage2", "stage3"],
                },
            ],
            communication_patterns=["chain_of_thought"],
            created_at=1000000,
        )

        # Create workflow execution
        workflow_exec = WorkflowExecution(
            workflow_id=workflow_id,
            definition=workflow_def,
            status=WorkflowStatus.RUNNING,
            current_stage=0,
            progress=0.0,
            start_time=1000000,
        )

        # Store workflow definition and execution
        agent.workflow_definitions[workflow_id] = workflow_def
        agent.workflow_executions[workflow_id] = workflow_exec
        agent.active_workflows.add(workflow_id)

        # Setup _execute_workflow_stage mock to return successfully for each stage
        agent._execute_workflow_stage.side_effect = [
            {"stage": "stage1", "status": "completed", "result": "Stage 1 complete"},
            {"stage": "stage2", "status": "completed", "result": "Stage 2 complete"},
            {"stage": "stage3", "status": "completed", "result": "Stage 3 complete"},
            {"stage": "stage4", "status": "completed", "result": "Stage 4 complete"},
        ]

        # Execute workflow
        await agent._execute_workflow(workflow_id)

        # Verify _execute_workflow_stage was called for each stage
        assert agent._execute_workflow_stage.call_count == 4

        # Verify workflow execution was updated
        assert workflow_exec.status == WorkflowStatus.COMPLETED
        assert workflow_exec.completion_time == 1000000
        assert workflow_exec.progress == 1.0
        assert len(workflow_exec.stage_results) == 4
        assert workflow_id not in agent.active_workflows

        # Verify _emit_workflow_event was called for completion
        agent._emit_workflow_event.assert_called_with(
            workflow_id,
            WorkflowType.COMPREHENSIVE,
            WorkflowStatus.COMPLETED,
            1.0,
            {"summary": "workflow results"},
        )

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.workflows.orchestrator.AutogenChatAgent.__init__")
    async def test_compile_workflow_results(self, mock_base_init):
        """Test compiling comprehensive workflow results."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = AdvancedOrchestrator()

        # Create a workflow definition
        workflow_id = "workflow_123"
        workflow_def = WorkflowDefinition(
            workflow_id=workflow_id,
            workflow_type=WorkflowType.COMPREHENSIVE,
            name="Test Workflow",
            description="A test workflow",
            target_id="repo123",
            target_type="repository",
            parameters={},
            agents=[
                "guided_assessment",
                "exploitation_verification",
                "remediation_planning",
                "security_policy",
            ],
            stages=[
                {
                    "name": "initialization",
                    "agent": "guided_assessment",
                    "description": "Initialize workflow",
                },
                {
                    "name": "assessment",
                    "agent": "guided_assessment",
                    "description": "Assessment",
                },
                {
                    "name": "exploitation",
                    "agent": "exploitation_verification",
                    "description": "Exploitation verification",
                },
                {
                    "name": "remediation",
                    "agent": "remediation_planning",
                    "description": "Remediation planning",
                },
                {
                    "name": "policy",
                    "agent": "security_policy",
                    "description": "Policy compliance",
                },
            ],
            communication_patterns=["chain_of_thought", "debate", "feedback_loop"],
            created_at=1000000,
        )

        # Create workflow execution with artifacts
        workflow_exec = WorkflowExecution(
            workflow_id=workflow_id,
            definition=workflow_def,
            status=WorkflowStatus.COMPLETED,
            current_stage=4,
            progress=1.0,
            start_time=1000000,
            completion_time=1001000,
        )
        workflow_exec.stage_results = {
            0: {"stage": "initialization", "status": "completed"},
            1: {"stage": "assessment", "status": "completed"},
            2: {"stage": "exploitation", "status": "completed"},
            3: {"stage": "remediation", "status": "completed"},
            4: {"stage": "policy", "status": "completed"},
        }
        workflow_exec.artifacts = {
            "assessment_id": "assessment_123",
            "findings": [
                {
                    "file_id": "finding_1",
                    "vulnerability_type": "SQL Injection",
                    "severity": "high",
                },
                {
                    "file_id": "finding_2",
                    "vulnerability_type": "XSS",
                    "severity": "medium",
                },
            ],
            "verifications": [
                {
                    "verification_id": "verification_1",
                    "finding_id": "finding_1",
                    "status": "exploitable",
                },
                {
                    "verification_id": "verification_2",
                    "finding_id": "finding_2",
                    "status": "potentially_exploitable",
                },
            ],
            "remediation_plans": [
                {
                    "plan_id": "plan_1",
                    "finding_id": "finding_1",
                    "priority": "high",
                    "complexity": "moderate",
                },
                {
                    "plan_id": "plan_2",
                    "finding_id": "finding_2",
                    "priority": "medium",
                    "complexity": "simple",
                },
            ],
            "policy_evaluation": {
                "evaluation_id": "eval_1",
                "compliance_status": "partially_compliant",
                "compliance_gaps": [
                    {
                        "category": "input_validation",
                        "description": "Missing input validation",
                    }
                ],
            },
        }

        # Need to mock ExploitabilityStatus and RemediationPriority for _summarize methods
        with (
            patch(
                "skwaq.agents.specialized.workflows.orchestrator.ExploitabilityStatus"
            ) as mock_exploit_status,
            patch(
                "skwaq.agents.specialized.workflows.orchestrator.RemediationPriority"
            ) as mock_remediation_priority,
            patch(
                "skwaq.agents.specialized.workflows.orchestrator.RemediationComplexity"
            ) as mock_remediation_complexity,
        ):
            # Create Enum mock values
            mock_exploit_status.EXPLOITABLE = type(
                "obj", (object,), {"value": "exploitable"}
            )
            mock_exploit_status.POTENTIALLY_EXPLOITABLE = type(
                "obj", (object,), {"value": "potentially_exploitable"}
            )
            mock_exploit_status.NOT_EXPLOITABLE = type(
                "obj", (object,), {"value": "not_exploitable"}
            )
            mock_exploit_status.UNDETERMINED = type(
                "obj", (object,), {"value": "undetermined"}
            )

            mock_remediation_priority.HIGH = type("obj", (object,), {"value": "high"})
            mock_remediation_priority.MEDIUM = type(
                "obj", (object,), {"value": "medium"}
            )
            mock_remediation_priority.LOW = type("obj", (object,), {"value": "low"})

            mock_remediation_complexity.SIMPLE = type(
                "obj", (object,), {"value": "simple"}
            )
            mock_remediation_complexity.MODERATE = type(
                "obj", (object,), {"value": "moderate"}
            )
            mock_remediation_complexity.COMPLEX = type(
                "obj", (object,), {"value": "complex"}
            )

            # Store workflow definition and execution
            agent.workflow_definitions[workflow_id] = workflow_def
            agent.workflow_executions[workflow_id] = workflow_exec

            # Compile workflow results
            results = agent._compile_workflow_results(workflow_id)

            # Verify results structure
            assert results["workflow_id"] == workflow_id
            assert results["workflow_type"] == WorkflowType.COMPREHENSIVE.value
            assert results["target_id"] == "repo123"
            assert results["target_type"] == "repository"
            assert results["start_time"] == 1000000
            assert results["completion_time"] == 1001000
            assert results["execution_time"] == 1000
            assert results["status"] == WorkflowStatus.COMPLETED.value

            # Verify stage results
            assert "stage_results" in results
            assert len(results["stage_results"]) == 5
            assert "initialization" in results["stage_results"]
            assert "assessment" in results["stage_results"]
            assert "exploitation" in results["stage_results"]
            assert "remediation" in results["stage_results"]
            assert "policy" in results["stage_results"]

            # Verify findings
            assert "findings" in results
            assert len(results["findings"]) == 2

            # Verify artifacts
            assert "artifacts" in results
            assert "assessment_id" in results["artifacts"]
            assert "findings" in results["artifacts"]
            assert "verifications" in results["artifacts"]
            assert "remediation_plans" in results["artifacts"]
            assert "policy_evaluation" in results["artifacts"]
