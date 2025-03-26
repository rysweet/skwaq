"""Unit tests for core agents."""

import pytest
import asyncio
import uuid
from unittest.mock import MagicMock, AsyncMock, patch, call
import json
import time

# Mock autogen_core modules
import sys
sys.modules["autogen_core"] = MagicMock()
sys.modules["autogen_core.agent"] = MagicMock()
sys.modules["autogen_core.event"] = MagicMock()
sys.modules["autogen_core.code_utils"] = MagicMock()
sys.modules["autogen_core.memory"] = MagicMock()

# Create MockBaseEvent class for tests
class MockBaseEvent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

# Set up mock for Event.add
sys.modules["autogen_core.event"].BaseEvent = MockBaseEvent
sys.modules["autogen_core.event"].Event = MagicMock()
sys.modules["autogen_core.event"].Event.add = MagicMock()
sys.modules["autogen_core.event"].EventHook = MagicMock()
sys.modules["autogen_core.event"].register_hook = MagicMock()

# Set up mock for agents
sys.modules["autogen_core.agent"].Agent = MagicMock()
sys.modules["autogen_core.agent"].ChatAgent = MagicMock()

# Import our classes
from skwaq.agents import (
    BaseAgent,
    AgentRegistry,
    OrchestratorAgent,
    KnowledgeAgent,
    CodeAnalysisAgent,
    CriticAgent,
    AgentCommunicationEvent,
    TaskAssignmentEvent,
    TaskResultEvent,
    Task,
)


@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    with patch("skwaq.agents.base.get_config") as mock_get_config:
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "test_key": "test_value",
        }
        mock_get_config.return_value = mock_config
        yield mock_config


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client for testing."""
    with patch("skwaq.agents.base.get_openai_client") as mock_get_openai_client:
        mock_client = MagicMock()
        mock_client.api_key = "test_api_key"
        mock_client.api_base = "https://test.openai.azure.com/"
        mock_client.api_type = "azure"
        mock_client.api_version = "2023-05-15"
        mock_get_openai_client.return_value = mock_client
        yield mock_client


@pytest.fixture
def mock_event_add():
    """Mock the Event.add method."""
    with patch("autogen_core.event.Event.add") as mock_add:
        yield mock_add


@pytest.fixture
def mock_agent_registry():
    """Mock the AgentRegistry for testing."""
    with patch.object(AgentRegistry, 'register') as mock_register:
        with patch.object(AgentRegistry, 'get_all_agents') as mock_get_all:
            mock_get_all.return_value = []
            yield {
                'register': mock_register,
                'get_all_agents': mock_get_all
            }


class TestOrchestratorAgent:
    """Test cases for the OrchestratorAgent class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test OrchestratorAgent initialization."""
        # Patch the _emit_lifecycle_event method to avoid event emission
        with patch.object(OrchestratorAgent, '_emit_lifecycle_event'):
            # Create agent
            agent = OrchestratorAgent(
                name="test_orchestrator",
                description="Test orchestrator agent",
                config_key="test_config",
            )
            
            # Check basic properties
            assert agent.name == "test_orchestrator"
            assert agent.description == "Test orchestrator agent"
            assert agent.config_key == "test_config"
            
            # Check task and workflow tracking
            assert isinstance(agent.tasks, dict)
            assert len(agent.tasks) == 0
            assert isinstance(agent.active_workflows, dict)
            assert len(agent.active_workflows) == 0
            assert isinstance(agent.available_agents, dict)
            assert len(agent.available_agents) == 0
            
            # Verify registry called
            mock_agent_registry['register'].assert_called_once()

    @pytest.mark.asyncio
    async def test_discover_agents(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test agent discovery."""
        # Patch the _emit_lifecycle_event method to avoid event emission
        with patch.object(OrchestratorAgent, '_emit_lifecycle_event'):
            # Create test agents
            mock_knowledge_agent = MagicMock()
            mock_knowledge_agent.agent_id = "knowledge_id"
            mock_knowledge_agent.name = "KnowledgeAgent"
            mock_knowledge_agent.__class__.__name__ = "KnowledgeAgent"
            
            mock_code_agent = MagicMock()
            mock_code_agent.agent_id = "code_id"
            mock_code_agent.name = "CodeAnalysisAgent"
            mock_code_agent.__class__.__name__ = "CodeAnalysisAgent"
            
            # Update mock registry to return our agents
            mock_agent_registry['get_all_agents'].return_value = [
                mock_knowledge_agent,
                mock_code_agent,
            ]
            
            # Create orchestrator agent
            agent = OrchestratorAgent()
            
            # Run discover agents
            agent._discover_agents()
            
            # Verify agents were discovered
            assert len(agent.available_agents) == 2
            assert agent.available_agents["knowledge_id"] == mock_knowledge_agent
            assert agent.available_agents["code_id"] == mock_code_agent
            
            # Verify capabilities were inferred
            assert "knowledge_retrieval" in agent.agent_capabilities["knowledge_id"]
            assert "code_analysis" in agent.agent_capabilities["code_id"]

    @pytest.mark.asyncio
    async def test_assign_task(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test task assignment."""
        # Patch the emit_event method
        with patch.object(OrchestratorAgent, 'emit_event') as mock_emit:
            # Also patch _emit_lifecycle_event to prevent the lifecycle event emission
            with patch.object(OrchestratorAgent, '_emit_lifecycle_event'):
                # Create orchestrator agent with patched emit method
                agent = OrchestratorAgent()
                
                # Assign task
                task_id = await agent.assign_task(
                    receiver_id="test_receiver",
                    task_type="test_task",
                    task_description="Test task description",
                    task_parameters={"param1": "value1"},
                    priority=2,
                )
                
                # Verify task created and stored
                assert task_id in agent.tasks
                task = agent.tasks[task_id]
                assert task.task_type == "test_task"
                assert task.task_description == "Test task description"
                assert task.task_parameters == {"param1": "value1"}
                assert task.priority == 2
                assert task.sender_id == agent.agent_id
                assert task.receiver_id == "test_receiver"
                assert task.status == "pending"
                
                # Verify event emitted
                mock_emit.assert_called_once()
                event = mock_emit.call_args[0][0]
                assert isinstance(event, TaskAssignmentEvent)
                assert event.sender_id == agent.agent_id
                assert event.receiver_id == "test_receiver"
                assert event.task_id == task_id
                assert event.task_type == "test_task"
                assert event.task_parameters == {"param1": "value1"}
                assert event.priority == 2

    @pytest.mark.asyncio
    async def test_handle_task_result(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test handling task results."""
        # Create orchestrator agent
        agent = OrchestratorAgent()
        
        # Create a task
        task_id = str(uuid.uuid4())
        task = Task(
            task_id=task_id,
            task_type="test_task",
            task_description="Test task description",
            task_parameters={},
            priority=1,
            sender_id=agent.agent_id,
            receiver_id="test_receiver",
        )
        agent.tasks[task_id] = task
        
        # Create a workflow that includes this task
        workflow_id = str(uuid.uuid4())
        agent.active_workflows[workflow_id] = {
            "id": workflow_id,
            "type": "test_workflow",
            "parameters": {},
            "status": "running",
            "tasks": [task_id],
            "results": {},
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        
        # Create task result event
        event = TaskResultEvent(
            sender_id="test_receiver",
            receiver_id=agent.agent_id,
            task_id=task_id,
            status="completed",
            result={"test": "result"},
        )
        
        # Handle task result
        await agent._handle_task_result(event)
        
        # Verify task updated
        assert agent.tasks[task_id].status == "completed"
        assert agent.tasks[task_id].result == {"test": "result"}
        assert agent.tasks[task_id].completed_time is not None
        
        # Verify workflow updated
        assert agent.active_workflows[workflow_id]["updated_at"] > agent.active_workflows[workflow_id]["created_at"]


class TestKnowledgeAgent:
    """Test cases for the KnowledgeAgent class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test KnowledgeAgent initialization."""
        # Patch the _emit_lifecycle_event method to avoid event emission
        with patch.object(KnowledgeAgent, '_emit_lifecycle_event'):
            # Create agent
            agent = KnowledgeAgent(
                name="test_knowledge",
                description="Test knowledge agent",
                config_key="test_config",
            )
            
            # Check basic properties
            assert agent.name == "test_knowledge"
            assert agent.description == "Test knowledge agent"
            assert agent.config_key == "test_config"
            
            # Check task tracking
            assert isinstance(agent.assigned_tasks, dict)
            assert len(agent.assigned_tasks) == 0
            
            # Verify registry called
            mock_agent_registry['register'].assert_called_once()

    @pytest.mark.asyncio
    async def test_handle_task_assignment(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test handling task assignment."""
        # Patch the emit_event method and _process_task
        with patch.object(KnowledgeAgent, 'emit_event') as mock_emit:
            with patch.object(KnowledgeAgent, '_process_task') as mock_process:
                # Create knowledge agent
                agent = KnowledgeAgent()
                
                # Create task assignment event
                task_id = str(uuid.uuid4())
                event = TaskAssignmentEvent(
                    sender_id="test_sender",
                    receiver_id=agent.agent_id,
                    task_id=task_id,
                    task_type="retrieve_knowledge",
                    task_description="Test knowledge retrieval",
                    task_parameters={"query": "test query"},
                    priority=1,
                )
                
                # Handle task assignment
                await agent._handle_task_assignment(event)
                
                # Verify task stored
                assert task_id in agent.assigned_tasks
                task = agent.assigned_tasks[task_id]
                assert task.task_type == "retrieve_knowledge"
                assert task.task_description == "Test knowledge retrieval"
                assert task.task_parameters == {"query": "test query"}
                assert task.priority == 1
                assert task.sender_id == "test_sender"
                assert task.receiver_id == agent.agent_id
                assert task.status == "pending"
                
                # Verify task processing started
                mock_process.assert_called_once_with(task_id)


class TestCodeAnalysisAgent:
    """Test cases for the CodeAnalysisAgent class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test CodeAnalysisAgent initialization."""
        # Patch the _emit_lifecycle_event method to avoid event emission
        with patch.object(CodeAnalysisAgent, '_emit_lifecycle_event'):
            # Create agent
            agent = CodeAnalysisAgent(
                name="test_code_analysis",
                description="Test code analysis agent",
                config_key="test_config",
            )
            
            # Check basic properties
            assert agent.name == "test_code_analysis"
            assert agent.description == "Test code analysis agent"
            assert agent.config_key == "test_config"
            
            # Check task and analysis tracking
            assert isinstance(agent.assigned_tasks, dict)
            assert len(agent.assigned_tasks) == 0
            assert agent.current_analysis is None
            
            # Verify registry called
            mock_agent_registry['register'].assert_called_once()

    @pytest.mark.asyncio
    async def test_process_repository_analysis_task(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test processing repository analysis task."""
        # Patch the emit_event method
        with patch.object(CodeAnalysisAgent, 'emit_event') as mock_emit:
            # Also patch _emit_lifecycle_event to prevent the lifecycle event emission
            with patch.object(CodeAnalysisAgent, '_emit_lifecycle_event'):
                # Create code analysis agent
                agent = CodeAnalysisAgent()
                
                # Create task
                task_id = str(uuid.uuid4())
                task = Task(
                    task_id=task_id,
                    task_type="analyze_repository",
                    task_description="Test repo analysis",
                    task_parameters={"repository": "test/repo"},
                    priority=1,
                    sender_id="test_sender",
                    receiver_id=agent.agent_id,
                )
                agent.assigned_tasks[task_id] = task
                
                # Process task
                await agent._process_task(task_id)
                
                # Verify task completed
                assert agent.assigned_tasks[task_id].status == "completed"
                assert agent.assigned_tasks[task_id].result is not None
                assert "repository" in agent.assigned_tasks[task_id].result
                assert "findings" in agent.assigned_tasks[task_id].result
                assert agent.assigned_tasks[task_id].completed_time is not None
                
                # Verify task result event emitted
                mock_emit.assert_called_once()
                event = mock_emit.call_args[0][0]
                assert isinstance(event, TaskResultEvent)
                assert event.sender_id == agent.agent_id
                assert event.receiver_id == "test_sender"
                assert event.task_id == task_id
                assert event.status == "completed"
                assert "repository" in event.result
                assert "findings" in event.result


class TestCriticAgent:
    """Test cases for the CriticAgent class."""

    @pytest.mark.asyncio
    async def test_initialization(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test CriticAgent initialization."""
        # Patch the _emit_lifecycle_event method to avoid event emission
        with patch.object(CriticAgent, '_emit_lifecycle_event'):
            # Create agent
            agent = CriticAgent(
                name="test_critic",
                description="Test critic agent",
                config_key="test_config",
            )
            
            # Check basic properties
            assert agent.name == "test_critic"
            assert agent.description == "Test critic agent"
            assert agent.config_key == "test_config"
            
            # Check task tracking
            assert isinstance(agent.assigned_tasks, dict)
            assert len(agent.assigned_tasks) == 0
            
            # Verify registry called
            mock_agent_registry['register'].assert_called_once()

    @pytest.mark.asyncio
    async def test_critique_findings(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test critiquing findings."""
        # Create critic agent with patched emit method
        with patch('skwaq.agents.data_providers.critic_provider.critique_findings') as mock_critique:
            agent = CriticAgent()
            
            # Create findings to critique
            findings = [
                {
                    "file_path": "src/api/auth.js",
                    "line_number": 42,
                    "vulnerability_type": "XSS",
                    "severity": "high",
                    "confidence": 0.85,
                    "description": "Potential XSS vulnerability with unvalidated user input",
                    "cwe_id": "CWE-79",
                    "snippet": "document.write('<p>' + req.query.username + '</p>');"
                },
                {
                    "file_path": "src/database/queries.py",
                    "line_number": 87,
                    "vulnerability_type": "SQL Injection",
                    "severity": "critical",
                    "confidence": 0.92,
                    "description": "SQL injection vulnerability with string concatenation",
                    "cwe_id": "CWE-89",
                    "snippet": "cursor.execute(\"SELECT * FROM users WHERE username = '\" + username + \"'\")"
                }
            ]
            
            # Mock the critique_findings function
            mock_result = {
                "evaluation": [
                    {
                        "finding_id": 0,
                        "assessment": "valid",
                        "confidence": 0.8,
                        "notes": "This appears to be a genuine XSS vulnerability."
                    },
                    {
                        "finding_id": 1,
                        "assessment": "valid",
                        "confidence": 0.9,
                        "notes": "This is a clear SQL injection vulnerability."
                    }
                ],
                "overall_assessment": "The findings appear accurate with high confidence."
            }
            mock_critique.return_value = mock_result
            
            # Create a task
            task_id = str(uuid.uuid4())
            task = Task(
                task_id=task_id,
                task_type="critique_findings",
                task_description="Critique findings",
                task_parameters={"findings": findings},
                priority=1,
                sender_id="test_sender",
                receiver_id=agent.agent_id,
            )
            agent.assigned_tasks[task_id] = task
            
            # Process task
            await agent._process_task(task_id)
            
            # Verify task was processed
            assert agent.assigned_tasks[task_id].status == "completed"
            result = agent.assigned_tasks[task_id].result
            
            # Verify result structure
            assert "evaluation" in result
            assert isinstance(result["evaluation"], list)
            assert len(result["evaluation"]) == 2
            assert "overall_assessment" in result


class TestAgentCommunication:
    """Test cases for agent communication."""

    @pytest.mark.asyncio
    async def test_task_assignment_workflow(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test end-to-end task assignment workflow."""
        # Create orchestrator and knowledge agents
        with patch.object(OrchestratorAgent, '_emit_lifecycle_event'):
            with patch.object(KnowledgeAgent, '_emit_lifecycle_event'):
                orchestrator = OrchestratorAgent()
                knowledge_agent = KnowledgeAgent()
                
                # Register knowledge agent with orchestrator
                orchestrator.available_agents[knowledge_agent.agent_id] = knowledge_agent
                orchestrator.agent_capabilities[knowledge_agent.agent_id] = ["knowledge_retrieval"]
                
                # Mock emit_event on orchestrator
                orchestrator.emit_event = MagicMock()
                
                # Mock knowledge agent's process_task method
                knowledge_agent._process_task = AsyncMock()
                
                # Mock knowledge agent's _handle_task_assignment
                orig_handle = knowledge_agent._handle_task_assignment
                
                async def handle_and_save(event):
                    self.last_event = event
                    await orig_handle(event)
                    
                knowledge_agent._handle_task_assignment = handle_and_save
                self.last_event = None
                
                # Assign task from orchestrator to knowledge agent
                task_id = await orchestrator.assign_task(
                    receiver_id=knowledge_agent.agent_id,
                    task_type="retrieve_knowledge",
                    task_description="Test knowledge retrieval",
                    task_parameters={"query": "test query"},
                )
                
                # Verify task assignment event emitted by orchestrator
                orchestrator.emit_event.assert_called_once()
                emitted_event = orchestrator.emit_event.call_args[0][0]
                assert isinstance(emitted_event, TaskAssignmentEvent)
                assert emitted_event.sender_id == orchestrator.agent_id
                assert emitted_event.receiver_id == knowledge_agent.agent_id
                assert emitted_event.task_id == task_id
                assert emitted_event.task_type == "retrieve_knowledge"
                
                # Simulate event handling
                await knowledge_agent._handle_task_assignment(emitted_event)
                
                # Verify task is in knowledge agent's tasks
                assert task_id in knowledge_agent.assigned_tasks
                
                # Verify knowledge agent started processing the task
                knowledge_agent._process_task.assert_called_once_with(task_id)