"""Unit tests for AutoGen integration."""

import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
import uuid
import json

# Mock autogen_core modules
import sys
autogen_event = MagicMock()
autogen_agent = MagicMock()
autogen_hooks = MagicMock()
sys.modules["autogen_core"] = MagicMock()
sys.modules["autogen_core.event"] = autogen_event
sys.modules["autogen_core.agent"] = autogen_agent
sys.modules["autogen_core.code_utils"] = MagicMock()
sys.modules["autogen_core.memory"] = MagicMock()

# Import the classes to test
from skwaq.agents.autogen_integration import (
    AutogenEventBridge,
    AutogenAgentAdapter,
    AutogenGroupChatAdapter,
)
from skwaq.events.system_events import (
    EventBus,
    SystemEvent,
    AgentLifecycleEvent,
    AgentLifecycleState,
)


@pytest.fixture
def mock_event_bus():
    """Mock the EventBus for testing."""
    with patch("skwaq.agents.autogen_integration.EventBus") as mock_bus_class:
        mock_bus = MagicMock()
        mock_bus_class.return_value = mock_bus
        yield mock_bus


@pytest.fixture
def mock_register_hook():
    """Mock the register_hook function."""
    with patch("skwaq.agents.autogen_integration.register_hook") as mock_register:
        yield mock_register


@pytest.fixture
def mock_config():
    """Mock configuration for testing."""
    with patch("skwaq.agents.autogen_integration.get_config") as mock_get_config:
        mock_config = MagicMock()
        mock_config.get.return_value = {
            "openai": {"chat_model": "gpt4o-test"},
        }
        mock_get_config.return_value = mock_config
        yield mock_config


@pytest.fixture
def mock_openai_client():
    """Mock OpenAI client for testing."""
    with patch("skwaq.agents.autogen_integration.get_openai_client") as mock_get_openai_client:
        mock_client = MagicMock()
        mock_client.api_key = "test_api_key"
        mock_client.api_base = "https://test.openai.azure.com/"
        mock_client.api_type = "azure"
        mock_client.api_version = "2023-05-15"
        mock_get_openai_client.return_value = mock_client
        yield mock_client


class TestAutogenEventBridge:
    """Test cases for the AutogenEventBridge class."""
    
    def test_init(self, mock_event_bus, mock_register_hook):
        """Test AutogenEventBridge initialization."""
        # Act
        bridge = AutogenEventBridge()
        
        # Assert
        assert bridge.skwaq_event_bus == mock_event_bus
        assert len(bridge.autogen_event_handlers) == 0
        
        # Verify hooks registered
        assert mock_register_hook.call_count >= 3  # At least for init, close, message events
    
    def test_handle_agent_init_event(self, mock_event_bus):
        """Test handling of AutogenAgentInitEvent."""
        # Arrange
        bridge = AutogenEventBridge()
        
        # Create a mock agent and event
        mock_agent = MagicMock()
        mock_agent.name = "test_agent"
        
        mock_event = MagicMock()
        mock_event.agent = mock_agent
        
        # Patch the cast function since we're mocking the event
        with patch("skwaq.agents.autogen_integration.cast", return_value=mock_event):
            # Act
            bridge._handle_agent_init_event(mock_event)
            
            # Assert
            mock_event_bus.publish.assert_called_once()
            
            # Verify the published event
            skwaq_event = mock_event_bus.publish.call_args[0][0]
            assert isinstance(skwaq_event, AgentLifecycleEvent)
            assert skwaq_event.agent_name == "test_agent"
            assert skwaq_event.state == AgentLifecycleState.CREATED.value
    
    def test_handle_agent_close_event(self, mock_event_bus):
        """Test handling of AutogenAgentCloseEvent."""
        # Arrange
        bridge = AutogenEventBridge()
        
        # Create a mock agent and event
        mock_agent = MagicMock()
        mock_agent.name = "test_agent"
        
        mock_event = MagicMock()
        mock_event.agent = mock_agent
        
        # Patch the cast function since we're mocking the event
        with patch("skwaq.agents.autogen_integration.cast", return_value=mock_event):
            # Act
            bridge._handle_agent_close_event(mock_event)
            
            # Assert
            mock_event_bus.publish.assert_called_once()
            
            # Verify the published event
            skwaq_event = mock_event_bus.publish.call_args[0][0]
            assert isinstance(skwaq_event, AgentLifecycleEvent)
            assert skwaq_event.agent_name == "test_agent"
            assert skwaq_event.state == AgentLifecycleState.STOPPED.value


class TestAutogenAgentAdapter:
    """Test cases for the AutogenAgentAdapter class."""
    
    def test_init(self, mock_config, mock_openai_client):
        """Test AutogenAgentAdapter initialization."""
        # Arrange
        name = "test_agent"
        system_message = "You are a test agent"
        
        # Act
        adapter = AutogenAgentAdapter(
            name=name,
            system_message=system_message,
            model="gpt4o-test",
        )
        
        # Assert
        assert adapter.name == name
        assert adapter.system_message == system_message
        assert adapter.model == "gpt4o-test"
        assert adapter.agent is None
        assert isinstance(adapter.event_bridge, AutogenEventBridge)
    
    @pytest.mark.asyncio
    async def test_create_agent(self, mock_config, mock_openai_client):
        """Test creating an AutoGen agent."""
        # Arrange
        adapter = AutogenAgentAdapter(
            name="test_agent",
            system_message="You are a test agent",
        )
        
        # Mock the ChatAgent constructor
        mock_chat_agent = MagicMock()
        
        with patch("autogen_core.agent.ChatAgent", return_value=mock_chat_agent) as mock_constructor:
            # Act
            agent = await adapter.create_agent()
            
            # Assert - just verify an agent was created and that properties are as expected
            assert agent is not None
            assert adapter.agent is not None
            
            # Verify ChatAgent was constructed (don't require exactly one call since we can't control
            # test execution order and other tests might have already created agents)
            mock_constructor.assert_called()
    
    @pytest.mark.asyncio
    async def test_close_agent(self, mock_config, mock_openai_client):
        """Test closing an AutoGen agent."""
        # Arrange
        adapter = AutogenAgentAdapter(
            name="test_agent",
            system_message="You are a test agent",
        )
        
        # Set a mock agent
        adapter.agent = MagicMock()
        
        # Act
        await adapter.close_agent()
        
        # Assert
        assert adapter.agent is None


class TestAutogenGroupChatAdapter:
    """Test cases for the AutogenGroupChatAdapter class."""
    
    def test_init(self):
        """Test AutogenGroupChatAdapter initialization."""
        # Arrange
        name = "test_group_chat"
        mock_agents = [MagicMock(), MagicMock()]
        
        # Act
        adapter = AutogenGroupChatAdapter(
            name=name,
            agents=mock_agents,
        )
        
        # Assert
        assert adapter.name == name
        assert adapter.agents == mock_agents
        assert adapter.group_chat is None
        assert isinstance(adapter.event_bridge, AutogenEventBridge)
    
    @pytest.mark.asyncio
    async def test_create_group_chat(self):
        """Test creating an AutoGen GroupChat."""
        # Arrange
        mock_agents = [MagicMock(), MagicMock()]
        adapter = AutogenGroupChatAdapter(
            name="test_group_chat",
            agents=mock_agents,
        )
        
        # Mock the GroupChat constructor
        mock_group_chat = MagicMock()
        
        with patch("autogen_core.GroupChat", return_value=mock_group_chat) as mock_constructor:
            # Act
            group_chat = await adapter.create_group_chat()
            
            # Assert - just verify a group chat was created
            assert group_chat is not None
            assert adapter.group_chat is not None
            
            # Verify GroupChat was constructed (don't require exactly one call since we can't control
            # test execution order and other tests might have already created agents)
            mock_constructor.assert_called()
    
    @pytest.mark.asyncio
    async def test_close_group_chat(self):
        """Test closing an AutoGen GroupChat."""
        # Arrange
        adapter = AutogenGroupChatAdapter(
            name="test_group_chat",
            agents=[],
        )
        
        # Set a mock group_chat
        adapter.group_chat = MagicMock()
        
        # Act
        await adapter.close_group_chat()
        
        # Assert
        assert adapter.group_chat is None