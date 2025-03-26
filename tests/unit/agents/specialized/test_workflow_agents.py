"""Unit tests for specialized workflow agents."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch, call
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

# Create a mock Task and TaskAssignmentEvent
class Task:
    def __init__(self, task_id, task_type, task_description, task_parameters, priority, sender_id, receiver_id, status):
        self.task_id = task_id
        self.task_type = task_type
        self.task_description = task_description
        self.task_parameters = task_parameters
        self.priority = priority
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.status = status
        self.result = None
        self.error = None

class TaskAssignmentEvent(MockBaseEvent):
    pass

class TaskResultEvent(MockBaseEvent):
    pass

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
from skwaq.agents.specialized.guided_assessment_agent import (
    GuidedAssessmentAgent,
    AssessmentStage,
    AssessmentPlanEvent,
    AssessmentStageEvent
)
from skwaq.agents.specialized.exploitation_agent import (
    ExploitationVerificationAgent,
    ExploitabilityStatus,
    ExploitVerificationEvent
)
from skwaq.agents.specialized.remediation_agent import (
    RemediationPlanningAgent,
    RemediationPriority,
    RemediationComplexity,
    RemediationPlanEvent
)
from skwaq.agents.specialized.policy_agent import (
    SecurityPolicyAgent,
    ComplianceStatus,
    PolicyRecommendationType,
    PolicyEvaluationEvent,
    PolicyRecommendationEvent
)
from skwaq.agents.specialized.orchestration import (
    AdvancedOrchestrator,
    WorkflowType,
    WorkflowStatus,
    WorkflowEvent,
    WorkflowDefinition,
    WorkflowExecution
)


class TestGuidedAssessmentAgent:
    """Tests for the GuidedAssessmentAgent class."""

    @patch("skwaq.agents.specialized.guided_assessment_agent.AutogenChatAgent.__init__")
    def test_guided_assessment_agent_init(self, mock_base_init):
        """Test GuidedAssessmentAgent initialization."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = GuidedAssessmentAgent()

        # Verify initialization and system message
        mock_base_init.assert_called_once()
        args, kwargs = mock_base_init.call_args
        assert kwargs["name"] == "GuidedAssessmentAgent"
        assert kwargs["description"] == "Provides guided vulnerability assessment workflows"
        assert kwargs["config_key"] == "agents.guided_assessment"
        assert "step-by-step approach" in kwargs["system_message"]

        # Verify internal data structures initialized
        assert hasattr(agent, "assessments")
        assert isinstance(agent.assessments, dict)
        assert hasattr(agent, "active_stages")
        assert isinstance(agent.active_stages, dict)
        assert hasattr(agent, "stage_results")
        assert isinstance(agent.stage_results, dict)

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.guided_assessment_agent.super")
    @patch("skwaq.agents.specialized.guided_assessment_agent.AutogenChatAgent.__init__")
    async def test_start_registers_event_handlers(self, mock_base_init, mock_super):
        """Test that _start registers event handlers."""
        mock_base_init.return_value = None
        
        # Set up super() mock to return an object with _start method
        mock_super_obj = MagicMock()
        mock_super_obj._start = AsyncMock()
        mock_super.return_value = mock_super_obj

        # Initialize agent
        agent = GuidedAssessmentAgent()
        agent.register_event_handler = MagicMock()

        # Call _start
        await agent._start()

        # Verify super()._start was called
        mock_super_obj._start.assert_called_once()
        
        # Verify register_event_handler was called for all event types
        assert agent.register_event_handler.call_count >= 3
        event_types = [call.args[0] for call in agent.register_event_handler.call_args_list]
        assert AssessmentPlanEvent in event_types
        assert AssessmentStageEvent in event_types

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.guided_assessment_agent.time")
    @patch("skwaq.agents.specialized.guided_assessment_agent.uuid")
    @patch("skwaq.agents.specialized.guided_assessment_agent.logger")
    @patch("skwaq.agents.specialized.guided_assessment_agent.AutogenChatAgent.__init__")
    async def test_create_assessment(self, mock_base_init, mock_logger, mock_uuid, mock_time):
        """Test creating an assessment."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = GuidedAssessmentAgent()
        
        # Mock _generate_assessment_plan and _emit_assessment_plan_event
        agent._generate_assessment_plan = AsyncMock(return_value={
            "name": "Assessment Plan",
            "stages": [
                {"name": "initialization", "tasks": [{"task_id": "init_1"}]}
            ]
        })
        agent._emit_assessment_plan_event = AsyncMock()
        
        # Mock asyncio.create_task
        with patch("asyncio.create_task") as mock_create_task:
            # Create assessment
            result = await agent.create_assessment(
                repository_id="repo123",
                repository_info={"languages": ["python"], "size": 1000},
                assessment_parameters={"depth": "standard"}
            )
            
            # Verify the result
            assert result["assessment_id"] == "assessment_repo123_1000000_12345678"
            assert result["repository_id"] == "repo123"
            assert result["status"] == "started"
            
            # Verify assessment was stored
            assert "assessment_repo123_1000000_12345678" in agent.assessments
            stored_assessment = agent.assessments["assessment_repo123_1000000_12345678"]
            assert stored_assessment["repository_id"] == "repo123"
            assert stored_assessment["status"] == "planned"
            
            # Verify _generate_assessment_plan was called
            agent._generate_assessment_plan.assert_called_once_with(
                {"languages": ["python"], "size": 1000},
                {"depth": "standard"}
            )
            
            # Verify _emit_assessment_plan_event was called
            agent._emit_assessment_plan_event.assert_called_once()
            
            # Verify asyncio.create_task was called
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.guided_assessment_agent.AutogenChatAgent.__init__")
    async def test_generate_assessment_plan(self, mock_base_init):
        """Test generating an assessment plan."""
        mock_base_init.return_value = None

        # Initialize agent with mocked openai_client
        agent = GuidedAssessmentAgent()
        
        # Create a properly mocked openai_client
        mock_openai_client = MagicMock()
        
        # Mock create_completion method to return a valid response
        mock_completion = AsyncMock()
        mock_completion.return_value = {
            "choices": [
                {
                    "text": json.dumps({
                        "name": "Assessment Plan",
                        "stages": [
                            {
                                "name": "initialization",
                                "tasks": [
                                    {
                                        "task_id": "init_1",
                                        "description": "Initialize repository assessment",
                                        "estimated_time": "5m"
                                    }
                                ]
                            }
                        ]
                    })
                }
            ]
        }
        
        mock_openai_client.create_completion = mock_completion
        
        # Assign the mock to the agent
        agent.openai_client = mock_openai_client
        agent.model = "gpt-4"  # Set model attribute which is used in the implementation
        
        # Generate plan
        plan = await agent._generate_assessment_plan(
            {"languages": ["python"], "size": 1000},
            {"depth": "standard"}
        )
        
        # Verify the plan
        assert plan["name"] == "Assessment Plan"
        assert isinstance(plan["stages"], list)
        assert len(plan["stages"]) > 0
        assert plan["stages"][0]["name"] == "initialization"
        
        # Verify openai_client.create_completion was called
        mock_completion.assert_called_once()
        args, kwargs = mock_completion.call_args
        assert "vulnerability assessment plan" in kwargs["prompt"]
        assert kwargs["model"] == "gpt-4"
        assert kwargs["response_format"] == {"type": "json"}


class TestExploitationVerificationAgent:
    """Tests for the ExploitationVerificationAgent class."""

    @patch("skwaq.agents.specialized.exploitation_agent.AutogenChatAgent.__init__")
    def test_exploitation_verification_agent_init(self, mock_base_init):
        """Test ExploitationVerificationAgent initialization."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = ExploitationVerificationAgent()

        # Verify initialization and system message
        mock_base_init.assert_called_once()
        args, kwargs = mock_base_init.call_args
        assert kwargs["name"] == "ExploitationVerificationAgent"
        assert kwargs["description"] == "Verifies if vulnerabilities are exploitable in practice"
        assert kwargs["config_key"] == "agents.exploitation_verification"
        assert "analyze reported vulnerabilities" in kwargs["system_message"]

        # Verify internal data structures initialized
        assert hasattr(agent, "verifications")
        assert isinstance(agent.verifications, dict)
        assert hasattr(agent, "verification_tasks")
        assert isinstance(agent.verification_tasks, dict)

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.exploitation_agent.time")
    @patch("skwaq.agents.specialized.exploitation_agent.uuid")
    @patch("skwaq.agents.specialized.exploitation_agent.AutogenChatAgent.__init__")
    async def test_verify_exploitability(self, mock_base_init, mock_uuid, mock_time):
        """Test verifying exploitability of a finding."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = ExploitationVerificationAgent()
        
        # Set model attribute used in the implementation
        agent.model = "gpt-4"
        agent.agent_id = "test_exploitation_agent"
        
        # Create a properly mocked openai_client
        mock_openai_client = MagicMock()
        
        # Mock create_completion method to return a valid response
        mock_completion = AsyncMock()
        mock_completion.return_value = {
            "choices": [
                {
                    "text": json.dumps({
                        "status": ExploitabilityStatus.EXPLOITABLE.value,
                        "justification": "Easy to exploit",
                        "exploitation_path": {"step1": "Inject payload"},
                        "risk_factors": {"authentication": "none"},
                        "impact": {"data_breach": "high"},
                        "confidence": 0.9
                    })
                }
            ]
        }
        
        mock_openai_client.create_completion = mock_completion
        
        # Assign the mock to the agent
        agent.openai_client = mock_openai_client
        
        # Mock the emit_event method to avoid side effects
        agent.emit_event = AsyncMock()
        
        # Create a test finding
        finding = {
            "file_id": "finding123",
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "line_number": 42,
            "matched_text": "query = 'SELECT * FROM users WHERE id = ' + user_input"
        }
        
        # Verify exploitability
        result = await agent.verify_exploitability(
            finding=finding,
            context={"environment": "production"}
        )
        
        # Verify the result
        assert result["finding_id"] == "finding123"
        assert result["status"] == ExploitabilityStatus.EXPLOITABLE.value
        assert result["justification"] == "Easy to exploit"
        assert "exploitation_path" in result
        assert "step1" in result["exploitation_path"]
        assert "risk_factors" in result
        assert "confidence" in result
        
        # Verify verification was stored
        verification_id = result["verification_id"]
        assert verification_id in agent.verifications
        
        # Verify openai_client.create_completion was called
        mock_completion.assert_called_once()
        args, kwargs = mock_completion.call_args
        assert "vulnerability finding" in kwargs["prompt"]
        assert kwargs["model"] == "gpt-4"
        assert kwargs["response_format"] == {"type": "json"}
        
        # Verify emit_event was called (at least once)
        assert agent.emit_event.called


class TestRemediationPlanningAgent:
    """Tests for the RemediationPlanningAgent class."""

    @patch("skwaq.agents.specialized.remediation_agent.AutogenChatAgent.__init__")
    def test_remediation_planning_agent_init(self, mock_base_init):
        """Test RemediationPlanningAgent initialization."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = RemediationPlanningAgent()

        # Verify initialization and system message
        mock_base_init.assert_called_once()
        args, kwargs = mock_base_init.call_args
        assert kwargs["name"] == "RemediationPlanningAgent"
        assert kwargs["description"] == "Creates detailed remediation plans for vulnerabilities"
        assert kwargs["config_key"] == "agents.remediation_planning"
        assert "analyze reported vulnerabilities and create detailed" in kwargs["system_message"]

        # Verify internal data structures initialized
        assert hasattr(agent, "remediation_plans")
        assert isinstance(agent.remediation_plans, dict)
        assert hasattr(agent, "remediation_tasks")
        assert isinstance(agent.remediation_tasks, dict)

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.remediation_agent.time")
    @patch("skwaq.agents.specialized.remediation_agent.uuid")
    @patch("skwaq.agents.specialized.remediation_agent.AutogenChatAgent.__init__")
    async def test_create_remediation_plan(self, mock_base_init, mock_uuid, mock_time):
        """Test creating a remediation plan for a finding."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = RemediationPlanningAgent()
        
        # Set model attribute used in the implementation
        agent.model = "gpt-4"
        agent.agent_id = "test_remediation_agent"
        
        # Create a properly mocked openai_client
        mock_openai_client = MagicMock()
        
        # Mock create_completion method to return a valid response
        mock_completion = AsyncMock()
        mock_completion.return_value = {
            "choices": [
                {
                    "text": json.dumps({
                        "priority": RemediationPriority.HIGH.value,
                        "complexity": RemediationComplexity.MODERATE.value,
                        "steps": [
                            {"description": "Sanitize inputs", "explanation": "Use parameterized queries"}
                        ],
                        "code_changes": {
                            "before": "query = 'SELECT * FROM users WHERE id = ' + user_input",
                            "after": "query = 'SELECT * FROM users WHERE id = ?'\nparams = [user_input]"
                        },
                        "estimated_effort": "2 hours",
                        "challenges": ["Updating all query instances"],
                        "best_practices": ["Always use parameterized queries"]
                    })
                }
            ]
        }
        
        mock_openai_client.create_completion = mock_completion
        
        # Assign the mock to the agent
        agent.openai_client = mock_openai_client
        
        # Mock the emit_event method to avoid side effects
        agent.emit_event = AsyncMock()
        
        # Create a test finding
        finding = {
            "file_id": "finding123",
            "vulnerability_type": "SQL Injection",
            "severity": "high",
            "line_number": 42,
            "matched_text": "query = 'SELECT * FROM users WHERE id = ' + user_input"
        }
        
        # Create remediation plan
        result = await agent.create_remediation_plan(
            finding=finding,
            context={"environment": "production"},
            code_context={"language": "python", "file_content": "...code..."},
            plan_id="remediation_123"
        )
        
        # Verify the result
        assert result["plan_id"] == "remediation_123"
        assert result["finding_id"] == "finding123"
        assert result["priority"] == RemediationPriority.HIGH.value
        assert result["complexity"] == RemediationComplexity.MODERATE.value
        assert "steps" in result
        assert len(result["steps"]) > 0
        assert "code_changes" in result
        assert "estimated_effort" in result
        
        # Verify plan was stored
        assert "remediation_123" in agent.remediation_plans
        
        # Verify openai_client.create_completion was called
        mock_completion.assert_called_once()
        args, kwargs = mock_completion.call_args
        assert "remediation plan" in kwargs["prompt"]
        assert kwargs["model"] == "gpt-4"
        assert kwargs["response_format"] == {"type": "json"}
        
        # Verify emit_event was called (at least once)
        assert agent.emit_event.called


class TestSecurityPolicyAgent:
    """Tests for the SecurityPolicyAgent class."""

    @patch("skwaq.agents.specialized.policy_agent.AutogenChatAgent.__init__")
    def test_security_policy_agent_init(self, mock_base_init):
        """Test SecurityPolicyAgent initialization."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = SecurityPolicyAgent()

        # Verify initialization and system message
        mock_base_init.assert_called_once()
        args, kwargs = mock_base_init.call_args
        assert kwargs["name"] == "SecurityPolicyAgent"
        assert kwargs["description"] == "Evaluates security policies and generates recommendations"
        assert kwargs["config_key"] == "agents.security_policy"
        assert "evaluate findings and repositories against security policies" in kwargs["system_message"]

        # Verify internal data structures initialized
        assert hasattr(agent, "policy_evaluations")
        assert isinstance(agent.policy_evaluations, dict)
        assert hasattr(agent, "policy_recommendations")
        assert isinstance(agent.policy_recommendations, dict)
        assert hasattr(agent, "evaluation_tasks")
        assert isinstance(agent.evaluation_tasks, dict)
        assert hasattr(agent, "policy_knowledge")
        assert isinstance(agent.policy_knowledge, dict)

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.policy_agent.time")
    @patch("skwaq.agents.specialized.policy_agent.uuid")
    @patch("skwaq.agents.specialized.policy_agent.AutogenChatAgent.__init__")
    async def test_evaluate_policy_compliance(self, mock_base_init, mock_uuid, mock_time):
        """Test evaluating policy compliance of a target."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = SecurityPolicyAgent()
        
        # Set model attribute used in the implementation
        agent.model = "gpt-4"
        agent.agent_id = "test_policy_agent"
        
        # Create a properly mocked openai_client
        mock_openai_client = MagicMock()
        
        # Mock create_completion method to return a valid response
        mock_completion = AsyncMock()
        mock_completion.return_value = {
            "choices": [
                {
                    "text": json.dumps({
                        "policy_references": [
                            {"standard": "OWASP_ASVS", "control_id": "4.1.3", "description": "Input validation"}
                        ],
                        "compliance_status": ComplianceStatus.PARTIALLY_COMPLIANT.value,
                        "compliance_gaps": [
                            {"category": "input_validation", "description": "Missing input validation", "severity": "high"}
                        ],
                        "recommendations": [
                            {"type": "policy_update", "title": "Update input validation policy", "description": "..."}
                        ]
                    })
                }
            ]
        }
        
        mock_openai_client.create_completion = mock_completion
        
        # Assign the mock to the agent
        agent.openai_client = mock_openai_client
        
        # Mock the emit_event method to avoid side effects
        agent.emit_event = AsyncMock()
        
        # Create test target
        target = {
            "file_id": "finding123",
            "vulnerability_type": "SQL Injection",
            "severity": "high"
        }
        
        # Evaluate policy compliance
        result = await agent.evaluate_policy_compliance(
            target=target,
            target_type="finding",
            policy_context={"standards": ["OWASP_ASVS"]},
            evaluation_id="policy_eval_123"
        )
        
        # Verify the result
        assert result["evaluation_id"] == "policy_eval_123"
        assert result["target_id"] == "finding123"
        assert result["target_type"] == "finding"
        assert result["compliance_status"] == ComplianceStatus.PARTIALLY_COMPLIANT.value
        assert "policy_references" in result
        assert len(result["policy_references"]) > 0
        assert "compliance_gaps" in result
        assert "recommendations" in result
        
        # Verify evaluation was stored
        assert "policy_eval_123" in agent.policy_evaluations
        
        # Verify openai_client.create_completion was called
        mock_completion.assert_called_once()
        args, kwargs = mock_completion.call_args
        assert "security policy compliance" in kwargs["prompt"]
        assert kwargs["model"] == "gpt-4"
        assert kwargs["response_format"] == {"type": "json"}
        
        # Verify emit_event was called (at least once)
        assert agent.emit_event.called


class TestAdvancedOrchestrator:
    """Tests for the AdvancedOrchestrator class."""

    @patch("skwaq.agents.specialized.orchestration.AutogenChatAgent.__init__")
    def test_advanced_orchestrator_init(self, mock_base_init):
        """Test AdvancedOrchestrator initialization."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = AdvancedOrchestrator()

        # Verify initialization and system message
        mock_base_init.assert_called_once()
        args, kwargs = mock_base_init.call_args
        assert kwargs["name"] == "AdvancedOrchestrator"
        assert kwargs["description"] == "Coordinates advanced vulnerability assessment workflows"
        assert kwargs["config_key"] == "agents.advanced_orchestrator"
        assert "coordinate complex workflows" in kwargs["system_message"]

        # Verify internal data structures initialized
        assert hasattr(agent, "workflow_definitions")
        assert isinstance(agent.workflow_definitions, dict)
        assert hasattr(agent, "workflow_executions")
        assert isinstance(agent.workflow_executions, dict)
        assert hasattr(agent, "active_workflows")
        assert isinstance(agent.active_workflows, set)
        assert hasattr(agent, "specialized_agents")
        assert isinstance(agent.specialized_agents, dict)
        assert hasattr(agent, "communication_patterns")
        assert isinstance(agent.communication_patterns, dict)

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.orchestration.super")
    @patch("skwaq.agents.specialized.orchestration.AutogenChatAgent.__init__")
    @patch("skwaq.agents.specialized.orchestration.GuidedAssessmentAgent")
    @patch("skwaq.agents.specialized.orchestration.ExploitationVerificationAgent")
    @patch("skwaq.agents.specialized.orchestration.RemediationPlanningAgent")
    @patch("skwaq.agents.specialized.orchestration.SecurityPolicyAgent")
    async def test_start_initializes_specialized_agents(self, mock_policy_agent, mock_remediation_agent, 
                                                       mock_exploit_agent, mock_guided_agent, 
                                                       mock_base_init, mock_super):
        """Test that _start initializes specialized agents."""
        mock_base_init.return_value = None
        
        # Set up super() mock to return an object with _start method
        mock_super_obj = MagicMock()
        mock_super_obj._start = AsyncMock()
        mock_super.return_value = mock_super_obj

        # Set up mocks for each specialized agent class
        mock_guided_instance = MagicMock()
        mock_guided_instance.start = AsyncMock()
        mock_guided_agent.return_value = mock_guided_instance
        
        mock_exploit_instance = MagicMock()
        mock_exploit_instance.start = AsyncMock()
        mock_exploit_agent.return_value = mock_exploit_instance
        
        mock_remediation_instance = MagicMock()
        mock_remediation_instance.start = AsyncMock()
        mock_remediation_agent.return_value = mock_remediation_instance
        
        mock_policy_instance = MagicMock()
        mock_policy_instance.start = AsyncMock()
        mock_policy_agent.return_value = mock_policy_instance

        # Initialize agent
        agent = AdvancedOrchestrator()
        agent.register_event_handler = MagicMock()
        
        # Create mock register_event_handler that captures event registrations
        event_types = []
        def mock_register_handler(event_type, handler):
            event_types.append(event_type)
        agent.register_event_handler.side_effect = mock_register_handler

        # Call _start
        await agent._start()

        # Verify super()._start was called
        mock_super_obj._start.assert_called_once()
        
        # Verify specialized agents were created
        mock_guided_agent.assert_called_once()
        mock_exploit_agent.assert_called_once()
        mock_remediation_agent.assert_called_once()
        mock_policy_agent.assert_called_once()
        
        # Verify agents were started
        mock_guided_instance.start.assert_called_once()
        mock_exploit_instance.start.assert_called_once()
        mock_remediation_instance.start.assert_called_once()
        mock_policy_instance.start.assert_called_once()
        
        # Verify specialized agents were stored
        assert "guided_assessment" in agent.specialized_agents
        assert "exploitation_verification" in agent.specialized_agents
        assert "remediation_planning" in agent.specialized_agents
        assert "security_policy" in agent.specialized_agents
        
        # Verify register_event_handler was called the expected number of times
        assert agent.register_event_handler.call_count >= 8
        
        # Verify by class name instead of direct class equality since our mocks create different instances
        event_class_names = [event_type.__name__ for event_type in event_types]
        assert "WorkflowEvent" in event_class_names
        assert any("TaskAssignmentEvent" in name for name in event_class_names)
        assert any("TaskResultEvent" in name for name in event_class_names)
        assert "AssessmentPlanEvent" in event_class_names
        assert "AssessmentStageEvent" in event_class_names
        assert "ExploitVerificationEvent" in event_class_names
        assert "RemediationPlanEvent" in event_class_names
        assert "PolicyEvaluationEvent" in event_class_names

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.orchestration.time")
    @patch("skwaq.agents.specialized.orchestration.uuid")
    @patch("skwaq.agents.specialized.orchestration.AutogenChatAgent.__init__")
    async def test_create_workflow(self, mock_base_init, mock_uuid, mock_time):
        """Test creating a workflow definition."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = AdvancedOrchestrator()
        
        # Mock _generate_workflow_components
        agent._generate_workflow_components = AsyncMock(return_value={
            "agents": ["guided_assessment"],
            "stages": [
                {"name": "initialization", "agent": "guided_assessment", "description": "Initialize workflow"}
            ],
            "communication_patterns": ["chain_of_thought"]
        })
        
        # Create workflow
        result = await agent.create_workflow(
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            target_id="repo123",
            target_type="repository",
            parameters={"depth": "standard"},
            name="Test Workflow",
            description="Workflow for testing"
        )
        
        # Verify the result
        workflow_id = f"workflow_guided_assessment_1000000_12345678"
        assert result["workflow_id"] == workflow_id
        assert result["name"] == "Test Workflow"
        assert result["description"] == "Workflow for testing"
        assert result["workflow_type"] == WorkflowType.GUIDED_ASSESSMENT.value
        assert result["target_id"] == "repo123"
        assert result["target_type"] == "repository"
        assert result["status"] == "created"
        
        # Verify workflow was stored
        assert workflow_id in agent.workflow_definitions
        assert workflow_id in agent.workflow_executions
        workflow_def = agent.workflow_definitions[workflow_id]
        assert workflow_def.name == "Test Workflow"
        assert workflow_def.target_id == "repo123"
        assert workflow_def.target_type == "repository"
        assert workflow_def.workflow_type == WorkflowType.GUIDED_ASSESSMENT
        
        # Verify _generate_workflow_components was called
        agent._generate_workflow_components.assert_called_once_with(
            WorkflowType.GUIDED_ASSESSMENT,
            "repository",
            {"depth": "standard"}
        )

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.orchestration.time")
    @patch("skwaq.agents.specialized.orchestration.uuid")
    @patch("skwaq.agents.specialized.orchestration.AutogenChatAgent.__init__")
    async def test_start_workflow(self, mock_base_init, mock_uuid, mock_time):
        """Test starting a workflow execution."""
        mock_base_init.return_value = None
        mock_uuid.uuid4.return_value = uuid.UUID('12345678-1234-5678-1234-567812345678')
        mock_time.time.return_value = 1000000

        # Initialize agent
        agent = AdvancedOrchestrator()
        
        # Mock _emit_workflow_event
        agent._emit_workflow_event = AsyncMock()
        
        # Mock asyncio.create_task
        with patch("asyncio.create_task") as mock_create_task:
            # Create workflow definition
            workflow_id = "workflow_test_1000000_12345678"
            workflow_def = WorkflowDefinition(
                workflow_id=workflow_id,
                workflow_type=WorkflowType.GUIDED_ASSESSMENT,
                name="Test Workflow",
                description="Workflow for testing",
                target_id="repo123",
                target_type="repository",
                parameters={},
                agents=["guided_assessment"],
                stages=[
                    {"name": "initialization", "agent": "guided_assessment", "description": "Initialize workflow"}
                ],
                communication_patterns=["chain_of_thought"],
                created_at=1000000
            )
            workflow_exec = WorkflowExecution(
                workflow_id=workflow_id,
                definition=workflow_def,
                status=WorkflowStatus.INITIALIZING
            )
            
            # Store workflow definition and execution
            agent.workflow_definitions[workflow_id] = workflow_def
            agent.workflow_executions[workflow_id] = workflow_exec
            
            # Start workflow
            result = await agent.start_workflow(workflow_id)
            
            # Verify the result
            assert result["workflow_id"] == workflow_id
            assert result["name"] == "Test Workflow"
            assert result["status"] == "running"
            
            # Verify workflow execution was updated
            assert workflow_exec.status == WorkflowStatus.RUNNING
            assert workflow_exec.start_time == 1000000
            
            # Verify workflow was added to active workflows
            assert workflow_id in agent.active_workflows
            
            # Verify _emit_workflow_event was called
            agent._emit_workflow_event.assert_called_once_with(
                workflow_id,
                WorkflowType.GUIDED_ASSESSMENT,
                WorkflowStatus.RUNNING,
                0.0
            )
            
            # Verify asyncio.create_task was called
            mock_create_task.assert_called_once()

    @pytest.mark.asyncio
    @patch("skwaq.agents.specialized.orchestration.AutogenChatAgent.__init__")
    async def test_get_workflow_status(self, mock_base_init):
        """Test getting workflow status."""
        mock_base_init.return_value = None

        # Initialize agent
        agent = AdvancedOrchestrator()
        
        # Create workflow definition
        workflow_id = "workflow_test_1000000_12345678"
        workflow_def = WorkflowDefinition(
            workflow_id=workflow_id,
            workflow_type=WorkflowType.GUIDED_ASSESSMENT,
            name="Test Workflow",
            description="Workflow for testing",
            target_id="repo123",
            target_type="repository",
            parameters={},
            agents=["guided_assessment"],
            stages=[
                {"name": "initialization", "agent": "guided_assessment", "description": "Initialize workflow"}
            ],
            communication_patterns=["chain_of_thought"],
            created_at=1000000
        )
        workflow_exec = WorkflowExecution(
            workflow_id=workflow_id,
            definition=workflow_def,
            status=WorkflowStatus.RUNNING,
            current_stage=0,
            progress=0.5,
            start_time=1000000
        )
        
        # Store workflow definition and execution
        agent.workflow_definitions[workflow_id] = workflow_def
        agent.workflow_executions[workflow_id] = workflow_exec
        
        # Get workflow status
        status = await agent.get_workflow_status(workflow_id)
        
        # Verify the status
        assert status["workflow_id"] == workflow_id
        assert status["name"] == "Test Workflow"
        assert status["description"] == "Workflow for testing"
        assert status["workflow_type"] == WorkflowType.GUIDED_ASSESSMENT.value
        assert status["target_id"] == "repo123"
        assert status["target_type"] == "repository"
        assert status["status"] == WorkflowStatus.RUNNING.value
        assert status["progress"] == 0.5
        assert status["current_stage"] == 0
        assert status["current_stage_name"] == "initialization"
        assert status["total_stages"] == 1
        assert status["start_time"] == 1000000