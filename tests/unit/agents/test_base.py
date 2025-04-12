"""Unit tests for base agent classes."""

import sys
import uuid
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Create module mocks for autogen dependencies
modules_to_mock = [
    "autogen_core",
    "autogen_core.agent",
    "autogen_core.event",
    "autogen_core.code_utils",
    "autogen_core.memory",
]

# Create a clean module mock system
mocks = {}
for module_name in modules_to_mock:
    mocks[module_name] = MagicMock()
    sys.modules[module_name] = mocks[module_name]


# Set up specific behaviors
class MockBaseEvent:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


# Configure mocks with necessary attributes
mocks["autogen_core.event"].BaseEvent = MockBaseEvent
mocks["autogen_core.event"].Event = MagicMock()
mocks["autogen_core.event"].Event.add = MagicMock()
mocks["autogen_core.event"].EventHook = MagicMock()
mocks["autogen_core.event"].register_hook = MagicMock()

mocks["autogen_core.agent"].Agent = MagicMock()
mocks["autogen_core.agent"].ChatAgent = MagicMock()

# Now import our actual modules
import skwaq.agents.registry

# Now import the classes to test
from skwaq.agents.base import AgentState, AutogenChatAgent, BaseAgent
from skwaq.agents.registry import AgentRegistry
from skwaq.events.system_events import AgentLifecycleState


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
def mock_event_add(monkeypatch):
    """Mock the Event.add method."""
    # Create a mock for Event.add
    mock_add = MagicMock()

    # Patch the Event.add method
    monkeypatch.setattr("autogen_core.event.Event.add", mock_add)

    # Also patch BaseAgent.emit_event to make tests simpler
    # This ensures our mock is used when _emit_lifecycle_event calls emit_event
    def mock_emit_event(self, event):
        mock_add(event)

    # Apply the patch after BaseAgent is imported
    from skwaq.agents import base

    monkeypatch.setattr(base.BaseAgent, "emit_event", mock_emit_event)

    return mock_add


@pytest.fixture
def mock_agent_registry(monkeypatch):
    """Mock the AgentRegistry for testing."""
    # Import the modules directly
    from skwaq.agents import base

    # Create a fresh mock for the test
    mock_registry = MagicMock()
    mock_registry.register = MagicMock()

    # Monkeypatch both the class and the module
    monkeypatch.setattr(skwaq.agents.registry, "AgentRegistry", mock_registry)

    # Create a temporary function to override the import inside BaseAgent.__init__
    def mock_register(self_obj):
        mock_registry.register(self_obj)

    # Use monkeypatch to modify the internal import function temporarily
    monkeypatch.setattr(base.BaseAgent, "_register_with_registry", mock_register)

    return mock_registry


class TestBaseAgent:
    """Test cases for the BaseAgent class."""

    def test_init(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test BaseAgent initialization."""
        # Reset the registry mock
        mock_agent_registry.reset_mock()

        # Patch event emission to avoid actual events
        with patch.object(BaseAgent, "_emit_lifecycle_event"):
            # Arrange
            agent_id = str(uuid.uuid4())
            name = "test_agent"
            description = "Test agent description"
            config_key = "test_config_key"

            # Act - Create agent
            agent = BaseAgent(
                name=name,
                description=description,
                config_key=config_key,
                agent_id=agent_id,
            )

            # Assert basic properties
            assert agent.name == name
            assert agent.description == description
            assert agent.config_key == config_key
            assert agent.agent_id == agent_id
            assert agent.context.state == AgentState.INITIALIZED

            # Verify registry called
            mock_agent_registry.register.assert_called_once()

    @pytest.mark.asyncio
    async def test_start_stop_lifecycle(
        self, mock_config, mock_openai_client, mock_agent_registry
    ):
        """Test the agent start and stop lifecycle."""
        # Reset the registry mock
        mock_agent_registry.reset_mock()

        # Patch the _emit_lifecycle_event method to verify calls
        with patch.object(BaseAgent, "_emit_lifecycle_event") as mock_emit:
            # Arrange - Create agent with mocked methods
            agent = BaseAgent(
                name="test_agent",
                description="Test agent description",
                config_key="test_config_key",
            )

            # Reset the mock for creation event
            mock_emit.reset_mock()

            # Mock internal methods to isolate test
            agent._start = AsyncMock()
            agent._stop = AsyncMock()

            # Act - Start the agent
            await agent.start()

            # Assert - After start
            assert agent.context.state == AgentState.RUNNING
            assert agent.context.start_time is not None
            agent._start.assert_called_once()

            # Verify the events in order
            assert mock_emit.call_count == 2
            mock_emit.assert_any_call(AgentLifecycleState.STARTING)
            mock_emit.assert_any_call(AgentLifecycleState.STARTED)

            # Reset mocks for stop test
            mock_emit.reset_mock()

            # Act - Stop the agent
            await agent.stop()

            # Assert - After stop
            assert agent.context.state == AgentState.STOPPED
            assert agent.context.stop_time is not None
            agent._stop.assert_called_once()

            # Verify the events in order
            assert mock_emit.call_count == 2
            mock_emit.assert_any_call(AgentLifecycleState.STOPPING)
            mock_emit.assert_any_call(AgentLifecycleState.STOPPED)

    @pytest.mark.asyncio
    async def test_pause_resume_lifecycle(self, mock_config, mock_agent_registry):
        """Test the agent pause and resume lifecycle."""
        with patch.object(BaseAgent, "_emit_lifecycle_event") as mock_emit:
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

            # Clear the event emission from creation
            mock_emit.reset_mock()

            # Start the agent first
            await agent.start()
            assert agent.context.state == AgentState.RUNNING

            # Clear events from start
            mock_emit.reset_mock()

            # Act - Pause the agent
            await agent.pause()

            # Assert - After pause
            assert agent.context.state == AgentState.PAUSED
            agent._pause.assert_called_once()
            mock_emit.assert_called_once_with(AgentLifecycleState.PAUSED)

            # Clear events for resume
            mock_emit.reset_mock()

            # Act - Resume the agent
            await agent.resume()

            # Assert - After resume
            assert agent.context.state == AgentState.RUNNING
            agent._resume.assert_called_once()
            mock_emit.assert_called_once_with(AgentLifecycleState.RESUMED)

    @pytest.mark.asyncio
    async def test_event_handling(self, mock_config, mock_agent_registry):
        """Test agent event handling."""
        with patch.object(BaseAgent, "_emit_lifecycle_event"):
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

    def test_init(self, mock_config, mock_openai_client, mock_agent_registry):
        """Test AutogenChatAgent initialization."""
        with patch.object(BaseAgent, "_emit_lifecycle_event"):
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
    async def test_start_stop_lifecycle(
        self, mock_config, mock_openai_client, mock_agent_registry
    ):
        """Test the autogen chat agent start and stop lifecycle."""
        with patch.object(BaseAgent, "_emit_lifecycle_event"):
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
    def setup_registry(self, monkeypatch):
        """Set up clean registry state for each test."""
        # Create a clean registry for each test

        # Save original registry
        self.original_agents = skwaq.agents.registry.AgentRegistry._agents
        self.original_agents_by_name = (
            skwaq.agents.registry.AgentRegistry._agents_by_name
        )
        self.original_agents_by_type = (
            skwaq.agents.registry.AgentRegistry._agents_by_type
        )

        # Replace with empty collections for this test
        monkeypatch.setattr(skwaq.agents.registry.AgentRegistry, "_agents", {})
        monkeypatch.setattr(skwaq.agents.registry.AgentRegistry, "_agents_by_name", {})
        monkeypatch.setattr(skwaq.agents.registry.AgentRegistry, "_agents_by_type", {})

        yield

        # Restore original registry state
        skwaq.agents.registry.AgentRegistry._agents = self.original_agents
        skwaq.agents.registry.AgentRegistry._agents_by_name = (
            self.original_agents_by_name
        )
        skwaq.agents.registry.AgentRegistry._agents_by_type = (
            self.original_agents_by_type
        )

    def test_register_agent(self, mock_config, mock_openai_client):
        """Test registering an agent with the registry."""
        # Need to patch Event.add to avoid real event emission
        with patch("autogen_core.event.Event.add"):
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

    def test_unregister_agent(self, mock_config, mock_openai_client, mock_event_add):
        """Test unregistering an agent from the registry."""
        # Setup registry with a test agent
        test_agent = MagicMock()
        test_agent.agent_id = "test-id"
        test_agent.name = "test_agent"

        # Manually add agent to registry collections
        AgentRegistry._agents["test-id"] = test_agent
        AgentRegistry._agents_by_name["test_agent"] = [test_agent]
        AgentRegistry._agents_by_type[type(test_agent)] = [test_agent]

        # Act - Unregister the agent
        AgentRegistry.unregister("test-id")

        # Assert
        assert len(AgentRegistry.get_all_agents()) == 0
        assert AgentRegistry.get_agent("test-id") is None
        assert len(AgentRegistry.get_agents_by_name("test_agent")) == 0
        assert len(AgentRegistry.get_agents_by_type(type(test_agent))) == 0

    @pytest.mark.asyncio
    async def test_start_stop_all(self, mock_config, mock_openai_client):
        """Test starting and stopping all agents in the registry."""
        # Create mock agents
        mock_agents = []
        for i in range(3):
            agent = MagicMock()
            agent.agent_id = f"agent-{i}"
            agent.name = f"test_agent_{i}"
            agent.context = MagicMock()
            agent.context.state = AgentState.INITIALIZED
            agent.start = AsyncMock()
            agent.stop = AsyncMock()
            mock_agents.append(agent)

        # Manually add agents to registry
        for agent in mock_agents:
            AgentRegistry._agents[agent.agent_id] = agent

        # Act - Start all agents
        await AgentRegistry.start_all()

        # Assert - All agents started
        for agent in mock_agents:
            agent.start.assert_called_once()

            # Set state to RUNNING for stop test
            agent.context.state = AgentState.RUNNING

        # Act - Stop all agents
        await AgentRegistry.stop_all()

        # Assert - All agents stopped
        for agent in mock_agents:
            agent.stop.assert_called_once()
