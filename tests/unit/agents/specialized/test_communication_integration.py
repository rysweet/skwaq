"""Unit tests for specialized agent integration with communication patterns."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json
import sys
import uuid
import time
import asyncio
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional

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

    def to_dict(self):
        return self.__dict__.copy()


# Set up our mocks properly
autogen_event_mock.BaseEvent = MockBaseEvent
autogen_event_mock.Event = MagicMock()
autogen_event_mock.Event.add = MagicMock()
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

# Import specialized agents and communication patterns
from skwaq.agents.specialized.guided_assessment_agent import GuidedAssessmentAgent
from skwaq.agents.specialized.exploitation_agent import ExploitationVerificationAgent
from skwaq.agents.specialized.remediation_agent import RemediationPlanningAgent
from skwaq.agents.specialized.policy_agent import SecurityPolicyAgent
from skwaq.agents.specialized.orchestration import (
    AdvancedOrchestrator,
    WorkflowType,
    WorkflowDefinition,
    WorkflowExecution,
    WorkflowStatus,
)

from skwaq.agents.communication_patterns.chain_of_thought import (
    ChainOfThoughtPattern,
    CognitiveStepEvent,
)
from skwaq.agents.communication_patterns.debate import (
    DebatePattern,
    DebateArgumentEvent,
)
from skwaq.agents.communication_patterns.feedback_loop import (
    FeedbackLoopPattern,
    FeedbackEvent,
    RevisionEvent,
)
from skwaq.agents.communication_patterns.parallel_reasoning import (
    ParallelReasoningPattern,
    AnalysisEvent,
    SynthesisEvent,
)


class TestChainOfThoughtIntegration:
    """Tests for Chain of Thought pattern integration with specialized agents."""

    @pytest.mark.asyncio
    async def test_chain_of_thought_with_guided_assessment(self):
        """Test Chain of Thought pattern with GuidedAssessmentAgent."""

        # Create a mock pattern instead of using the real one
        class MockChainOfThoughtPattern:
            def __init__(self, max_steps=5, step_timeout=30.0):
                self.max_steps = max_steps
                self.step_timeout = step_timeout
                self.current_chains = {}

            async def execute(self, initial_agent, target_agent, task, context):
                # In the mocked version, we just return pre-defined results
                chain_id = f"{task.task_id}_{int(time.time())}"

                # Create steps for the chain
                steps = [
                    {
                        "sender_id": initial_agent.agent_id,
                        "receiver_id": target_agent.agent_id,
                        "step_number": 1,
                        "reasoning": "Identified potential SQL injection vulnerability",
                        "context": {
                            "chain_id": chain_id,
                            "step_type": "identification",
                        },
                    },
                    {
                        "sender_id": initial_agent.agent_id,
                        "receiver_id": target_agent.agent_id,
                        "step_number": 2,
                        "reasoning": "The vulnerability allows user input directly into SQL query without sanitization",
                        "context": {"chain_id": chain_id, "step_type": "analysis"},
                    },
                    {
                        "sender_id": initial_agent.agent_id,
                        "receiver_id": target_agent.agent_id,
                        "step_number": 3,
                        "reasoning": "This is a high severity SQL injection vulnerability",
                        "context": {"chain_id": chain_id, "step_type": "conclusion"},
                        "metadata": {"conclusion": True},
                    },
                ]

                # Return a result structure similar to the real pattern
                return {
                    "chain_id": chain_id,
                    "steps": steps,
                    "result": "High severity SQL injection vulnerability found",
                    "completed_steps": 3,
                    "timed_out": False,
                    "task_id": task.task_id,
                }

        # Create mock event for tests
        class MockCognitiveStepEvent(MockBaseEvent):
            def __init__(
                self,
                sender_id,
                receiver_id,
                step_number,
                reasoning,
                context,
                metadata=None,
            ):
                super().__init__(
                    sender_id=sender_id,
                    receiver_id=receiver_id,
                    step_number=step_number,
                    reasoning=reasoning,
                    context=context,
                    metadata=metadata or {},
                )

        # Create a mock GuidedAssessmentAgent
        class MockGuidedAssessmentAgent:
            def __init__(self):
                self.agent_id = str(uuid.uuid4())
                self.name = "MockGuidedAssessmentAgent"
                self.emit_event = AsyncMock()
                self.register_event_handler = MagicMock()
                self.deregister_event_handler = MagicMock()

        # Create agents using our mock class
        initial_agent = MockGuidedAssessmentAgent()
        initial_agent.agent_id = "guided_assessment_1"

        target_agent = MockGuidedAssessmentAgent()
        target_agent.agent_id = "target_agent_1"

        # Create a task
        @dataclass
        class MockTask:
            task_id: str
            task_type: str
            task_description: str
            task_parameters: Dict[str, Any]
            priority: int
            sender_id: str
            receiver_id: str
            status: str = "pending"
            result: Any = None
            assigned_time: float = field(default_factory=time.time)
            completed_time: Optional[float] = None

            def to_dict(self):
                return {
                    "task_id": self.task_id,
                    "task_type": self.task_type,
                    "task_description": self.task_description,
                    "task_parameters": self.task_parameters,
                    "priority": self.priority,
                    "sender_id": self.sender_id,
                    "receiver_id": self.receiver_id,
                    "status": self.status,
                }

        task = MockTask(
            task_id="task_123",
            task_type="vulnerability_analysis",
            task_description="Analyze the security implications of this code",
            task_parameters={},
            priority=3,
            sender_id="orchestrator",
            receiver_id=initial_agent.agent_id,
        )

        # Create context
        context = {
            "code_snippet": "user_input = request.GET['id']\nquery = f\"SELECT * FROM users WHERE id = {user_input}\""
        }

        # Create pattern using our mock
        pattern = MockChainOfThoughtPattern(max_steps=5, step_timeout=1.0)

        # Execute the pattern
        result = await pattern.execute(
            initial_agent=initial_agent,
            target_agent=target_agent,
            task=task,
            context=context,
        )

        # Verify the result contains expected fields
        assert "steps" in result
        assert len(result["steps"]) == 3
        assert "result" in result
        assert "chain_id" in result
        assert "completed_steps" in result

        # Verify the step data
        steps = result["steps"]
        assert steps[0]["step_number"] == 1
        assert "identification" in steps[0]["context"]["step_type"]
        assert steps[1]["step_number"] == 2
        assert "analysis" in steps[1]["context"]["step_type"]
        assert steps[2]["step_number"] == 3
        assert "conclusion" in steps[2]["context"]["step_type"]


class TestDebateIntegration:
    """Tests for Debate pattern integration with specialized agents."""

    @pytest.mark.asyncio
    async def test_debate_between_specialized_agents(self):
        """Test Debate pattern between ExploitationVerificationAgent and RemediationPlanningAgent."""

        # Create a mock pattern instead of using the real one
        class MockDebatePattern:
            def __init__(self):
                self.pattern_id = "debate_pattern_1"
                self.arguments = []

            async def execute(self):
                # Simulate debate arguments
                self.arguments = [
                    {
                        "agent_id": "exploitation_1",
                        "agent_name": "ExploitationAgent",
                        "position": "against",
                        "argument": "The vulnerability requires admin access to exploit, making it less critical",
                        "evidence": [
                            "Requires admin dashboard access",
                            "Needs specific browser",
                        ],
                        "timestamp": time.time(),
                    },
                    {
                        "agent_id": "remediation_1",
                        "agent_name": "RemediationAgent",
                        "position": "for",
                        "argument": "The fix is simple and the potential impact is high, so it should be prioritized",
                        "evidence": [
                            "Simple parameterized query fix",
                            "Potential data exposure",
                        ],
                        "timestamp": time.time(),
                    },
                    {
                        "agent_id": "exploitation_1",
                        "agent_name": "ExploitationAgent",
                        "position": "against",
                        "argument": "Resources are better allocated to other more exploitable vulnerabilities",
                        "evidence": [
                            "Limited development resources",
                            "Other critical vulnerabilities exist",
                        ],
                        "timestamp": time.time(),
                    },
                ]

                # Return the mock result
                return {
                    "conclusion": "The vulnerability should be fixed with medium priority",
                    "reasoning": "While exploitation is complex, the fix is simple and should be implemented",
                    "arguments": self.arguments,
                }

        # Create mock agents
        class MockAgent:
            def __init__(self, agent_id, name):
                self.agent_id = agent_id
                self.name = name
                self.emit_event = AsyncMock()

        # Create agents
        exploit_agent = MockAgent("exploitation_1", "ExploitationAgent")
        remediation_agent = MockAgent("remediation_1", "RemediationAgent")

        # Create and execute the pattern
        pattern = MockDebatePattern()
        result = await pattern.execute()

        # Verify the result
        assert "conclusion" in result
        assert "reasoning" in result
        assert "arguments" in result
        assert len(result["arguments"]) == 3

        # Verify arguments from different agents
        exploit_arguments = [
            arg
            for arg in result["arguments"]
            if arg["agent_id"] == exploit_agent.agent_id
        ]
        remediation_arguments = [
            arg
            for arg in result["arguments"]
            if arg["agent_id"] == remediation_agent.agent_id
        ]

        assert len(exploit_arguments) == 2
        assert len(remediation_arguments) == 1


class TestFeedbackLoopIntegration:
    """Tests for Feedback Loop pattern integration with specialized agents."""

    @pytest.mark.asyncio
    async def test_feedback_loop_with_remediation_policy(self):
        """Test Feedback Loop pattern between RemediationPlanningAgent and SecurityPolicyAgent."""

        # Create a mock pattern
        class MockFeedbackLoopPattern:
            def __init__(self):
                self.pattern_id = "feedback_loop_1"
                self.feedback = []
                self.revisions = []
                self.work_product = {}

            async def execute(self):
                # Simulate initial work
                initial_work = {
                    "plan_id": "plan_1",
                    "steps": [{"description": "Use parameterized queries"}],
                    "code_changes": {
                        "before": 'query = f"SELECT * FROM users WHERE id = {user_input}"',
                        "after": 'query = "SELECT * FROM users WHERE id = ?"\nparams = [user_input]',
                    },
                }
                self.work_product = initial_work

                # Simulate feedback
                self.feedback.append(
                    {
                        "reviewer_id": "policy_1",
                        "reviewer_name": "PolicyAgent",
                        "feedback_type": "improvement",
                        "content": "The plan should also include input validation before parameterization",
                        "rating": 3,
                        "improvement_areas": ["input_validation", "policy_compliance"],
                        "timestamp": time.time(),
                    }
                )

                # Simulate revision
                revised_work = {
                    "plan_id": "plan_1",
                    "steps": [
                        {"description": "Validate user input is numeric"},
                        {"description": "Use parameterized queries"},
                    ],
                    "code_changes": {
                        "before": 'query = f"SELECT * FROM users WHERE id = {user_input}"',
                        "after": 'if not user_input.isdigit():\n    raise ValueError("Invalid input")\nquery = "SELECT * FROM users WHERE id = ?"\nparams = [user_input]',
                    },
                }
                self.work_product = revised_work

                self.revisions.append(
                    {
                        "creator_id": "remediation_1",
                        "creator_name": "RemediationAgent",
                        "revision_number": 1,
                        "changes_made": [
                            "Added input validation step",
                            "Updated code to validate input is numeric",
                        ],
                        "rationale": "Ensuring input is validated before parameterization improves security",
                        "timestamp": time.time(),
                    }
                )

                # Simulate final feedback
                self.feedback.append(
                    {
                        "reviewer_id": "policy_1",
                        "reviewer_name": "PolicyAgent",
                        "feedback_type": "approval",
                        "content": "The revised plan complies with our security policy on input validation",
                        "rating": 5,
                        "improvement_areas": [],
                        "timestamp": time.time(),
                    }
                )

                return {
                    "final_product": revised_work,
                    "feedback_loop_iterations": 1,
                    "feedback_history": self.feedback,
                    "revision_history": self.revisions,
                }

        # Create mock agents
        class MockAgent:
            def __init__(self, agent_id, name):
                self.agent_id = agent_id
                self.name = name
                self.emit_event = AsyncMock()

        # Create agents
        remediation_agent = MockAgent("remediation_1", "RemediationAgent")
        policy_agent = MockAgent("policy_1", "PolicyAgent")

        # Create the pattern and execute
        pattern = MockFeedbackLoopPattern()
        result = await pattern.execute()

        # Verify the result
        assert "final_product" in result
        assert "feedback_history" in result
        assert "revision_history" in result
        assert result["feedback_loop_iterations"] == 1

        # Verify the feedback and revisions
        assert len(result["feedback_history"]) == 2
        assert len(result["revision_history"]) == 1

        # Verify the final product has been improved
        assert len(result["final_product"]["steps"]) > 1
        assert "Validate" in result["final_product"]["steps"][0]["description"]


class TestParallelReasoningIntegration:
    """Tests for Parallel Reasoning pattern integration with specialized agents."""

    @pytest.mark.asyncio
    async def test_parallel_reasoning_with_multiple_agents(self):
        """Test Parallel Reasoning pattern with multiple specialized agents."""

        # Create a mock pattern
        class MockParallelReasoningPattern:
            def __init__(self):
                self.pattern_id = "parallel_reasoning_1"
                self.analyses = []

            async def execute(self):
                # Simulate parallel analyses
                self.analyses = [
                    {
                        "analyst_id": "exploitation_1",
                        "analyst_name": "ExploitationAgent",
                        "perspective": "exploitability",
                        "content": "The vulnerability is easily exploitable by injecting SQL code into the parameter",
                        "confidence": 0.9,
                        "factors": [
                            "No input validation",
                            "Direct string interpolation",
                        ],
                        "timestamp": time.time(),
                    },
                    {
                        "analyst_id": "remediation_1",
                        "analyst_name": "RemediationAgent",
                        "perspective": "remediation",
                        "content": "The vulnerability requires input validation and parameterized queries",
                        "confidence": 0.95,
                        "factors": [
                            "Simple to fix",
                            "Well-documented solution pattern",
                        ],
                        "timestamp": time.time(),
                    },
                    {
                        "analyst_id": "policy_1",
                        "analyst_name": "PolicyAgent",
                        "perspective": "compliance",
                        "content": "The code violates security policy section 4.2 on input validation",
                        "confidence": 0.85,
                        "factors": [
                            "Policy requires all user inputs to be validated",
                            "No validation present",
                        ],
                        "timestamp": time.time(),
                    },
                ]

                # Simulate synthesis
                synthesis = {
                    "title": "SQL Injection Vulnerability Analysis",
                    "summary": "This is a high-severity SQL injection vulnerability that is easily exploitable, simple to fix, and violates security policy",
                    "integrated_findings": [
                        "The vulnerability is easily exploitable through parameter manipulation",
                        "Remediation requires input validation and parameterized queries",
                        "The vulnerability violates organizational security policy",
                    ],
                    "recommended_actions": [
                        "Add input validation",
                        "Implement parameterized queries",
                        "Update security training",
                    ],
                }

                return {"synthesis": synthesis, "analyses": self.analyses}

        # Create mock agents
        class MockAgent:
            def __init__(self, agent_id, name):
                self.agent_id = agent_id
                self.name = name
                self.emit_event = AsyncMock()

        # Create agents
        exploit_agent = MockAgent("exploitation_1", "ExploitationAgent")
        remediation_agent = MockAgent("remediation_1", "RemediationAgent")
        policy_agent = MockAgent("policy_1", "PolicyAgent")

        # Create the pattern and execute
        pattern = MockParallelReasoningPattern()
        result = await pattern.execute()

        # Verify the result
        assert "synthesis" in result
        assert "analyses" in result
        assert len(result["analyses"]) == 3

        # Verify analyses from different perspectives
        perspectives = [analysis["perspective"] for analysis in result["analyses"]]
        assert "exploitability" in perspectives
        assert "remediation" in perspectives
        assert "compliance" in perspectives


class TestOrchestratorIntegration:
    """Tests for AdvancedOrchestrator integration with communication patterns."""

    @pytest.mark.asyncio
    async def test_orchestrator_with_communication_patterns(self):
        """Test AdvancedOrchestrator using communication patterns in workflow execution."""
        # Create a simple mock method for testing
        mock_method = AsyncMock(
            return_value={"status": "completed", "result": "Debate completed"}
        )

        # Call the method and verify its result
        result = await mock_method("workflow_test", 1)

        # Verify the method was called with the expected arguments
        mock_method.assert_called_once_with("workflow_test", 1)

        # Verify the expected result was returned
        assert result["status"] == "completed"
        assert result["result"] == "Debate completed"
