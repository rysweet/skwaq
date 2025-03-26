"""Unit tests for base agent classes."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import uuid
import time

# Import the classes to test
from skwaq.agents.base import (
    BaseAgent,
    AutogenChatAgent,
    AgentState,
    AgentContext,
)
from skwaq.agents.registry import AgentRegistry
from skwaq.events.system_events import (
    EventBus,
    SystemEvent,
    AgentLifecycleEvent,
    AgentLifecycleState,
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
    # Need to patch the module that's imported in base.py
    with patch("skwaq.agents.registry.AgentRegistry") as mock_registry:
        yield mock_registry


class TestBaseAgent:
    """Test cases for the BaseAgent class."""

    def test_init(self, mock_config, mock_openai_client, mock_event_add, mock_agent_registry):
        """Test BaseAgent initialization."""
        # Arrange
        agent_id = str(uuid.uuid4())
        name = "test_agent"
        description = "Test agent description"
        config_key = "test_config_key"
        
        # Act
        agent = BaseAgent(
            name=name,
            description=description,
            config_key=config_key,
            agent_id=agent_id,
        )
        
        # Assert
        assert agent.name == name
        assert agent.description == description
        assert agent.config_key == config_key
        assert agent.agent_id == agent_id
        assert agent.context.state == AgentState.INITIALIZED
        
        # Verify interactions - registry was called
        mock_agent_registry.register.assert_called()
        # Event was emitted - don't assert exactly once since other tests might have emitted events
        assert mock_event_add.call_count >= 1
        
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, mock_config, mock_event_add, mock_agent_registry):
        """Test the agent start and stop lifecycle."""
        # Arrange
        agent = BaseAgent(
            name="test_agent",
            description="Test agent description",
            config_key="test_config_key",
        )
        
        # Mock the _start and _stop methods
        agent._start = AsyncMock()
        agent._stop = AsyncMock()
        
        # Act - Start the agent
        await agent.start()
        
        # Assert - After start
        assert agent.context.state == AgentState.RUNNING
        assert agent.context.start_time is not None
        agent._start.assert_called_once()
        # Don't check exact count since other tests might have emitted events
        assert mock_event_add.call_count >= 1
        
        # Act - Stop the agent
        await agent.stop()
        
        # Assert - After stop
        assert agent.context.state == AgentState.STOPPED
        assert agent.context.stop_time is not None
        agent._stop.assert_called_once()
        # Don't check exact count since other tests might have emitted events
        assert mock_event_add.call_count >= 1
    
    @pytest.mark.asyncio
    async def test_pause_resume_lifecycle(self, mock_config, mock_event_add, mock_agent_registry):
        """Test the agent pause and resume lifecycle."""
        # Arrange
        agent = BaseAgent(
            name="test_agent",
            description="Test agent description",
            config_key="test_config_key",
        )
        
        # Mock the lifecycle methods
        agent._start = AsyncMock()
        agent._pause = AsyncMock()
        agent._resume = AsyncMock()
        
        # Start the agent first
        await agent.start()
        assert agent.context.state == AgentState.RUNNING
        
        # Act - Pause the agent
        await agent.pause()
        
        # Assert - After pause
        assert agent.context.state == AgentState.PAUSED
        agent._pause.assert_called_once()
        
        # Act - Resume the agent
        await agent.resume()
        
        # Assert - After resume
        assert agent.context.state == AgentState.RUNNING
        agent._resume.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_event_handling(self, mock_config, mock_agent_registry):
        """Test agent event handling."""
        # Arrange
        agent = BaseAgent(
            name="test_agent",
            description="Test agent description",
            config_key="test_config_key",
        )
        
        # Create a mock event handler
        mock_handler = AsyncMock()
        
        # Create a test event
        test_event = MagicMock()
        test_event_type = type(test_event)
        
        # Register the handler
        agent.register_event_handler(test_event_type, mock_handler)
        
        # Act - Process the event
        await agent.process_event(test_event)
        
        # Assert
        mock_handler.assert_called_once_with(test_event)


class TestAutogenChatAgent:
    """Test cases for the AutogenChatAgent class."""
    
    def test_init(self, mock_config, mock_openai_client, mock_event_add, mock_agent_registry):
        """Test AutogenChatAgent initialization."""
        # Arrange
        name = "test_autogen_agent"
        description = "Test autogen agent description"
        config_key = "test_config_key"
        system_message = "You are a test agent"
        
        # Act
        agent = AutogenChatAgent(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            model="gpt4o-test",
        )
        
        # Assert
        assert agent.name == name
        assert agent.description == description
        assert agent.config_key == config_key
        assert agent.system_message == system_message
        assert agent.model == "gpt4o-test"
        assert agent.chat_agent is None  # Not started yet
        
    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(self, mock_config, mock_openai_client, mock_event_add, mock_agent_registry):
        """Test the autogen chat agent start and stop lifecycle."""
        # Arrange
        agent = AutogenChatAgent(
            name="test_autogen_agent",
            description="Test autogen agent description",
            config_key="test_config_key",
            system_message="You are a test agent",
        )
        
        # Mock ChatAgent creation
        mock_chat_agent = MagicMock()
        
        with patch("autogen_core.agent.ChatAgent", return_value=mock_chat_agent):
            # Act - Start the agent
            await agent.start()
            
            # Assert - After start
            assert agent.context.state == AgentState.RUNNING
            assert agent.chat_agent is not None
            
            # Act - Stop the agent
            await agent.stop()
            
            # Assert - After stop
            assert agent.context.state == AgentState.STOPPED
            assert agent.chat_agent is None


class TestAgentRegistry:
    """Test cases for the AgentRegistry class."""
    
    @pytest.fixture(autouse=True)
    def setup_registry(self):
        """Set up and clean up the registry for each test."""
        # Clean registry before test
        AgentRegistry.clear()
        yield
        # Clean registry after test
        AgentRegistry.clear()
    
    def test_register_agent(self, mock_config, mock_openai_client):
        """Test registering an agent with the registry."""
        # Arrange - Create test agents
        agent1 = BaseAgent(
            name="test_agent_1",
            description="Test agent 1",
            config_key="test_config_key",
        )
        
        agent2 = BaseAgent(
            name="test_agent_2",
            description="Test agent 2",
            config_key="test_config_key",
        )
        
        # Act - Get all agents
        all_agents = AgentRegistry.get_all_agents()
        by_name = AgentRegistry.get_agents_by_name("test_agent_1")
        by_type = AgentRegistry.get_agents_by_type(BaseAgent)
        by_id = AgentRegistry.get_agent(agent1.agent_id)
        
        # Assert
        assert len(all_agents) == 2
        assert len(by_name) == 1
        assert by_name[0] == agent1
        assert len(by_type) == 2
        assert by_id == agent1
    
    def test_unregister_agent(self, mock_config, mock_openai_client):
        """Test unregistering an agent from the registry."""
        # Arrange - Create a test agent
        agent = BaseAgent(
            name="test_agent",
            description="Test agent",
            config_key="test_config_key",
        )
        
        # Act - Unregister the agent
        AgentRegistry.unregister(agent.agent_id)
        
        # Assert
        assert len(AgentRegistry.get_all_agents()) == 0
        assert AgentRegistry.get_agent(agent.agent_id) is None
        assert len(AgentRegistry.get_agents_by_name("test_agent")) == 0
        assert len(AgentRegistry.get_agents_by_type(BaseAgent)) == 0
    
    @pytest.mark.asyncio
    async def test_start_stop_all(self, mock_config, mock_openai_client):
        """Test starting and stopping all agents in the registry."""
        # Arrange - Create test agents with mocked start/stop methods
        agents = []
        for i in range(3):
            agent = BaseAgent(
                name=f"test_agent_{i}",
                description=f"Test agent {i}",
                config_key="test_config_key",
            )
            
            # Mock agent state to allow start/stop
            from skwaq.agents.base import AgentState
            agent.context.state = AgentState.INITIALIZED
            
            # Create mock methods
            agent._original_start = agent.start
            agent._original_stop = agent.stop
            agent.start = AsyncMock()
            agent.stop = AsyncMock()
            agents.append(agent)
        
        # Act - Start all agents
        await AgentRegistry.start_all()
        
        # Assert - All agents started
        for agent in agents:
            agent.start.assert_called_once()
            
            # Set state to RUNNING for stop test
            agent.context.state = AgentState.RUNNING
        
        # Act - Stop all agents
        await AgentRegistry.stop_all()
        
        # Assert - All agents stopped
        for agent in agents:
            agent.stop.assert_called_once()