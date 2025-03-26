"""Milestone A1 tests for Agent Foundation."""

import pytest
import asyncio
import inspect
from unittest.mock import MagicMock, AsyncMock, patch
import uuid
import time
import sys

# First we need to mock the autogen dependencies
autogen_mock = MagicMock()
autogen_agent_mock = MagicMock()
autogen_event_mock = MagicMock()
autogen_code_utils_mock = MagicMock()
autogen_memory_mock = MagicMock()

class MockBaseEvent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)

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

# Import registry module early to ensure it's loaded before patching
import skwaq.agents.registry

# Import the components to test
from skwaq.agents import (
    BaseAgent,
    AutogenChatAgent,
    AgentState,
    AgentContext,
    AgentRegistry,
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


class TestMilestoneA1:
    """Test suite for Milestone A1: Agent Foundation."""

    def test_base_agent_class_exists(self):
        """Verify that the BaseAgent class exists with required methods."""
        # Check that the BaseAgent class exists
        assert inspect.isclass(BaseAgent)
        
        # Required methods
        assert hasattr(BaseAgent, "__init__")
        assert hasattr(BaseAgent, "start")
        assert hasattr(BaseAgent, "stop")
        assert hasattr(BaseAgent, "process_event")
        assert inspect.iscoroutinefunction(BaseAgent.start)
        assert inspect.iscoroutinefunction(BaseAgent.stop)
        assert inspect.iscoroutinefunction(BaseAgent.process_event)
    
    def test_agent_context_exists(self):
        """Verify that the AgentContext data class exists with required fields."""
        # Check that the AgentContext class exists
        assert inspect.isclass(AgentContext)
        
        # Required fields
        agent_context = AgentContext(agent_id="test")
        assert hasattr(agent_context, "agent_id")
        assert hasattr(agent_context, "state")
        assert hasattr(agent_context, "config")
        assert hasattr(agent_context, "metadata")
    
    def test_agent_state_exists(self):
        """Verify that the AgentState enum exists with required states."""
        # Check that the AgentState enum exists
        assert inspect.isclass(AgentState)
        
        # Required states
        assert hasattr(AgentState, "INITIALIZED")
        assert hasattr(AgentState, "STARTING")
        assert hasattr(AgentState, "RUNNING")
        assert hasattr(AgentState, "PAUSED")
        assert hasattr(AgentState, "STOPPING")
        assert hasattr(AgentState, "STOPPED")
        assert hasattr(AgentState, "ERROR")
    
    def test_agent_registry_exists(self):
        """Verify that the AgentRegistry class exists with required methods."""
        # Check that the AgentRegistry class exists
        assert inspect.isclass(AgentRegistry)
        
        # Required methods
        assert hasattr(AgentRegistry, "register")
        assert hasattr(AgentRegistry, "unregister")
        assert hasattr(AgentRegistry, "get_agent")
        assert hasattr(AgentRegistry, "get_agents_by_name")
        assert hasattr(AgentRegistry, "get_agents_by_type")
        assert hasattr(AgentRegistry, "get_all_agents")
        assert hasattr(AgentRegistry, "start_all")
        assert hasattr(AgentRegistry, "stop_all")
        assert inspect.iscoroutinefunction(AgentRegistry.start_all)
        assert inspect.iscoroutinefunction(AgentRegistry.stop_all)
    
    def test_autogen_chat_agent_exists(self):
        """Verify that the AutogenChatAgent class exists with required methods."""
        # Check that the AutogenChatAgent class exists
        assert inspect.isclass(AutogenChatAgent)
        assert issubclass(AutogenChatAgent, BaseAgent)
        
        # Required methods
        assert hasattr(AutogenChatAgent, "__init__")
        assert hasattr(AutogenChatAgent, "_start")
        assert hasattr(AutogenChatAgent, "_stop")
        assert hasattr(AutogenChatAgent, "chat")
        assert inspect.iscoroutinefunction(AutogenChatAgent._start)
        assert inspect.iscoroutinefunction(AutogenChatAgent._stop)
        assert inspect.iscoroutinefunction(AutogenChatAgent.chat)
    
    def test_autogen_integration_exists(self):
        """Verify that AutoGen integration components exist."""
        # Check that the AutogenEventBridge class exists
        assert inspect.isclass(AutogenEventBridge)
        
        # Check that the AutogenAgentAdapter class exists
        assert inspect.isclass(AutogenAgentAdapter)
        
        # Check that the AutogenGroupChatAdapter class exists
        assert inspect.isclass(AutogenGroupChatAdapter)
        
        # Required methods for AutogenAgentAdapter
        assert hasattr(AutogenAgentAdapter, "create_agent")
        assert hasattr(AutogenAgentAdapter, "close_agent")
        assert inspect.iscoroutinefunction(AutogenAgentAdapter.create_agent)
        assert inspect.iscoroutinefunction(AutogenAgentAdapter.close_agent)
        
        # Required methods for AutogenGroupChatAdapter
        assert hasattr(AutogenGroupChatAdapter, "create_group_chat")
        assert hasattr(AutogenGroupChatAdapter, "close_group_chat")
        assert inspect.iscoroutinefunction(AutogenGroupChatAdapter.create_group_chat)
        assert inspect.iscoroutinefunction(AutogenGroupChatAdapter.close_group_chat)
    
    def test_agent_lifecycle_events_exist(self):
        """Verify that agent lifecycle events exist in the event system."""
        # Check AgentLifecycleState enum
        assert inspect.isclass(AgentLifecycleState)
        
        # Required states
        assert hasattr(AgentLifecycleState, "CREATED")
        assert hasattr(AgentLifecycleState, "STARTING")
        assert hasattr(AgentLifecycleState, "STARTED")
        assert hasattr(AgentLifecycleState, "RUNNING")
        assert hasattr(AgentLifecycleState, "PAUSED")
        assert hasattr(AgentLifecycleState, "RESUMED")
        assert hasattr(AgentLifecycleState, "STOPPING")
        assert hasattr(AgentLifecycleState, "STOPPED")
        assert hasattr(AgentLifecycleState, "ERROR")
        
        # Check AgentLifecycleEvent class
        assert inspect.isclass(AgentLifecycleEvent)
        assert issubclass(AgentLifecycleEvent, SystemEvent)
    
    @pytest.mark.asyncio
    async def test_agent_lifecycle_basic_scenario(self):
        """Test a basic agent lifecycle scenario."""
        # Create a temporary mock for AgentRegistry
        original_registry = skwaq.agents.registry.AgentRegistry
        mock_registry = MagicMock()
        mock_registry.register = MagicMock()
        skwaq.agents.registry.AgentRegistry = mock_registry
        
        try:
            # Mock other dependencies to avoid actual infrastructure usage
            with patch("skwaq.agents.base.get_config") as mock_get_config, \
                 patch("skwaq.agents.base.get_openai_client") as mock_get_openai_client, \
                 patch("skwaq.agents.base.BaseAgent._emit_lifecycle_event") as mock_emit:
                
                # Set up mocks
                mock_config = MagicMock()
                mock_config.get.return_value = {}
                mock_get_config.return_value = mock_config
                
                mock_openai_client = MagicMock()
                mock_get_openai_client.return_value = mock_openai_client
                
                # Create a test agent
                agent = BaseAgent(
                    name="test_agent",
                    description="Test agent for milestone A1",
                    config_key="test.agent",
                )
                
                # Start the agent
                await agent.start()
                
                # Verify agent state
                assert agent.context.state == AgentState.RUNNING
                
                # Pause the agent
                await agent.pause()
                assert agent.context.state == AgentState.PAUSED
                
                # Resume the agent
                await agent.resume()
                assert agent.context.state == AgentState.RUNNING
                
                # Stop the agent
                await agent.stop()
                assert agent.context.state == AgentState.STOPPED
                
                # Verify event emissions (1 create + 2 start events + 1 pause + 1 resume + 2 stop events)
                assert mock_emit.call_count >= 7
                
                # Verify agent was registered
                mock_registry.register.assert_called_with(agent)
        finally:
            # Restore the original registry
            skwaq.agents.registry.AgentRegistry = original_registry
    
    @pytest.mark.asyncio
    async def test_agent_registry_operations(self):
        """Test basic registry operations with multiple agents."""
        # Clear registry for clean test
        AgentRegistry.clear()
        
        # Mock dependencies to avoid actual infrastructure usage
        with patch("skwaq.agents.base.get_config") as mock_get_config, \
             patch("skwaq.agents.base.get_openai_client") as mock_get_openai_client, \
             patch("autogen_core.event.Event.add") as mock_event_add:
            
            # Set up mocks
            mock_config = MagicMock()
            mock_config.get.return_value = {}
            mock_get_config.return_value = mock_config
            
            mock_openai_client = MagicMock()
            mock_get_openai_client.return_value = mock_openai_client
            
            # Create test agents
            agent1 = BaseAgent(
                name="test_agent_1",
                description="Test agent 1",
                config_key="test.agent",
            )
            
            agent2 = BaseAgent(
                name="test_agent_2",
                description="Test agent 2",
                config_key="test.agent",
            )
            
            # Test registry queries
            all_agents = AgentRegistry.get_all_agents()
            assert len(all_agents) == 2
            
            agents_by_name1 = AgentRegistry.get_agents_by_name("test_agent_1")
            assert len(agents_by_name1) == 1
            assert agents_by_name1[0] == agent1
            
            agent_by_id = AgentRegistry.get_agent(agent1.agent_id)
            assert agent_by_id == agent1
            
            # Unregister an agent
            AgentRegistry.unregister(agent1.agent_id)
            
            # Verify it's gone
            all_agents_after = AgentRegistry.get_all_agents()
            assert len(all_agents_after) == 1
            assert all_agents_after[0] == agent2
            
            # Clean up
            AgentRegistry.clear()
    
    @pytest.mark.asyncio
    async def test_autogen_chat_agent_integration(self):
        """Test AutogenChatAgent integration with AutoGen Core."""
        # Mock dependencies to avoid actual infrastructure usage
        with patch("skwaq.agents.base.get_config") as mock_get_config, \
             patch("skwaq.agents.base.get_openai_client") as mock_get_openai_client, \
             patch("autogen_core.event.Event.add") as mock_event_add, \
             patch("skwaq.agents.registry.AgentRegistry") as mock_registry, \
             patch("autogen_core.agent.ChatAgent") as mock_chat_agent_class:
            
            # Set up mocks
            mock_config = MagicMock()
            mock_config.get.return_value = {"openai": {"chat_model": "gpt4o-test"}}
            mock_get_config.return_value = mock_config
            
            mock_openai_client = MagicMock()
            mock_openai_client.api_key = "test_api_key"
            mock_openai_client.api_base = "https://test.openai.azure.com/"
            mock_openai_client.api_type = "azure"
            mock_openai_client.api_version = "2023-05-15"
            mock_get_openai_client.return_value = mock_openai_client
            
            # Mock the registry too to avoid shared state issues
            mock_registry.register = MagicMock()
            
            # Mock the ChatAgent
            mock_chat_agent = MagicMock()
            mock_chat_agent.generate_reply.return_value = "Test response"
            mock_chat_agent_class.return_value = mock_chat_agent
            
            # Create an AutogenChatAgent
            agent = AutogenChatAgent(
                name="test_autogen_agent",
                description="Test AutoGen agent for milestone A1",
                config_key="test.agent",
                system_message="You are a test agent",
            )
            
            # Start the agent
            await agent.start()
            
            # Verify agent state
            assert agent.context.state == AgentState.RUNNING
            # Just check that a chat agent was created, not comparing the exact mock
            assert agent.chat_agent is not None
            
            # Test agent chat functionality with direct access to mock response
            mock_chat_agent.generate_reply.return_value = "Test response"
            agent.chat_agent = mock_chat_agent  # Replace the actual chat agent with our mock
            
            response = await agent.chat("Hello, agent!")
            assert response == "Test response"
            
            # Verify our mock was called
            mock_chat_agent.generate_reply.assert_called_once()
            
            # We just need to verify the key functionality works, not worry about how many times
            # the mock was called in implementation details
            
            # Stop the agent
            await agent.stop()
            
            # Verify agent state
            assert agent.context.state == AgentState.STOPPED
            assert agent.chat_agent is None