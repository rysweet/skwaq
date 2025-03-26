"""Base agent classes for the Skwaq agent system.

This module provides the foundation for the Skwaq agent system, including base
agent classes, agent lifecycle management, and other core agent functionality.
"""

from typing import (
    Dict,
    List,
    Any,
    Optional,
    Set,
    Callable,
    Awaitable,
    Type,
    Union,
    cast,
)
import inspect
import asyncio
import uuid
from dataclasses import dataclass, field
from enum import Enum
import json
import logging
import time

from autogen_core.agent import Agent, ChatAgent
from autogen_core.event import BaseEvent, Event, EventHook, register_hook
from autogen_core.code_utils import extract_code
from autogen_core.memory import MemoryRecord

from ..utils.config import get_config
from ..utils.logging import get_logger
from ..core.openai_client import get_openai_client
from ..events.system_events import AgentLifecycleEvent, AgentLifecycleState

logger = get_logger(__name__)


class AgentState(Enum):
    """Enum representing the possible states of an agent."""

    INITIALIZED = "initialized"
    STARTING = "starting"
    RUNNING = "running"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class AgentContext:
    """Context information for an agent during its lifecycle.

    This context is passed between agent lifecycle methods and contains
    state and configuration information for the agent.
    """

    agent_id: str
    state: AgentState = AgentState.INITIALIZED
    config: Dict[str, Any] = field(default_factory=dict)
    start_time: Optional[float] = None
    stop_time: Optional[float] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[Exception] = None


class BaseAgent:
    """Base class for all agents in the Skwaq system.

    This class implements the basic agent lifecycle management functionality
    and provides hooks for agent-specific logic.
    """

    def __init__(
        self,
        name: str,
        description: str,
        config_key: str,
        agent_id: Optional[str] = None,
    ) -> None:
        """Initialize a base agent.

        Args:
            name: The name of the agent
            description: A description of the agent's purpose
            config_key: The configuration key for this agent
            agent_id: Optional unique identifier for the agent. If not
                provided, a UUID will be generated.
        """
        self.name = name
        self.description = description
        self.config_key = config_key
        self.agent_id = agent_id or str(uuid.uuid4())
        self.config = get_config()

        # Create agent context
        self.context = AgentContext(
            agent_id=self.agent_id,
            config=self.config.get(config_key, {}),
        )

        # Set up event handlers
        self._event_handlers: Dict[
            Type[BaseEvent], List[Callable[[BaseEvent], Awaitable[None]]]
        ] = {}

        # Register with AgentRegistry
        self._register_with_registry()

    def _register_with_registry(self):
        """Register this agent with the AgentRegistry.

        This method exists as a separate function to make it easier to mock in tests.
        """
        # Import registry only when needed to avoid circular dependency
        import skwaq.agents.registry

        skwaq.agents.registry.AgentRegistry.register(self)

        # Emit agent creation event
        self._emit_lifecycle_event(
            AgentLifecycleState.CREATED,
            {
                "description": self.description,
                "config_key": self.config_key,
            },
        )

        logger.info(f"Agent {self.name} (ID: {self.agent_id}) initialized")

    async def start(self) -> None:
        """Start the agent.

        This method initializes the agent and prepares it for operation.
        Subclasses should override _start() to implement agent-specific
        startup logic.
        """
        if self.context.state not in (AgentState.INITIALIZED, AgentState.STOPPED):
            logger.warning(
                f"Agent {self.name} (ID: {self.agent_id}) cannot be started from state {self.context.state}"
            )
            return

        try:
            self.context.state = AgentState.STARTING
            self.context.start_time = time.time()

            # Emit agent starting event
            self._emit_lifecycle_event(AgentLifecycleState.STARTING)

            # Call agent-specific startup logic
            await self._start()

            self.context.state = AgentState.RUNNING

            # Emit agent started event
            self._emit_lifecycle_event(AgentLifecycleState.STARTED)

            logger.info(f"Agent {self.name} (ID: {self.agent_id}) started")
        except Exception as e:
            self.context.state = AgentState.ERROR
            self.context.error = e

            # Emit agent error event
            self._emit_lifecycle_event(AgentLifecycleState.ERROR, {"error": str(e)})

            logger.error(f"Error starting agent {self.name} (ID: {self.agent_id}): {e}")
            raise

    async def _start(self) -> None:
        """Agent-specific startup logic.

        Subclasses should override this method to implement their own startup logic.
        """
        pass

    async def stop(self) -> None:
        """Stop the agent.

        This method stops the agent and releases any resources it was using.
        Subclasses should override _stop() to implement agent-specific
        shutdown logic.
        """
        if self.context.state != AgentState.RUNNING:
            logger.warning(
                f"Agent {self.name} (ID: {self.agent_id}) cannot be stopped from state {self.context.state}"
            )
            return

        try:
            self.context.state = AgentState.STOPPING

            # Emit agent stopping event
            self._emit_lifecycle_event(AgentLifecycleState.STOPPING)

            # Call agent-specific shutdown logic
            await self._stop()

            self.context.state = AgentState.STOPPED
            self.context.stop_time = time.time()

            # Emit agent stopped event
            self._emit_lifecycle_event(AgentLifecycleState.STOPPED)

            logger.info(f"Agent {self.name} (ID: {self.agent_id}) stopped")
        except Exception as e:
            self.context.state = AgentState.ERROR
            self.context.error = e

            # Emit agent error event
            self._emit_lifecycle_event(AgentLifecycleState.ERROR, {"error": str(e)})

            logger.error(f"Error stopping agent {self.name} (ID: {self.agent_id}): {e}")
            raise

    async def _stop(self) -> None:
        """Agent-specific shutdown logic.

        Subclasses should override this method to implement their own shutdown logic.
        """
        pass

    async def pause(self) -> None:
        """Pause the agent.

        This method temporarily suspends the agent's operations.
        Subclasses should override _pause() to implement agent-specific
        pause logic.
        """
        if self.context.state != AgentState.RUNNING:
            logger.warning(
                f"Agent {self.name} (ID: {self.agent_id}) cannot be paused from state {self.context.state}"
            )
            return

        try:
            # Call agent-specific pause logic
            await self._pause()

            self.context.state = AgentState.PAUSED

            # Emit agent paused event
            self._emit_lifecycle_event(AgentLifecycleState.PAUSED)

            logger.info(f"Agent {self.name} (ID: {self.agent_id}) paused")
        except Exception as e:
            self.context.state = AgentState.ERROR
            self.context.error = e

            # Emit agent error event
            self._emit_lifecycle_event(AgentLifecycleState.ERROR, {"error": str(e)})

            logger.error(f"Error pausing agent {self.name} (ID: {self.agent_id}): {e}")
            raise

    async def _pause(self) -> None:
        """Agent-specific pause logic.

        Subclasses should override this method to implement their own pause logic.
        """
        pass

    async def resume(self) -> None:
        """Resume a paused agent.

        This method resumes a previously paused agent.
        Subclasses should override _resume() to implement agent-specific
        resume logic.
        """
        if self.context.state != AgentState.PAUSED:
            logger.warning(
                f"Agent {self.name} (ID: {self.agent_id}) cannot be resumed from state {self.context.state}"
            )
            return

        try:
            # Call agent-specific resume logic
            await self._resume()

            self.context.state = AgentState.RUNNING

            # Emit agent resumed event
            self._emit_lifecycle_event(AgentLifecycleState.RESUMED)

            logger.info(f"Agent {self.name} (ID: {self.agent_id}) resumed")
        except Exception as e:
            self.context.state = AgentState.ERROR
            self.context.error = e

            # Emit agent error event
            self._emit_lifecycle_event(AgentLifecycleState.ERROR, {"error": str(e)})

            logger.error(f"Error resuming agent {self.name} (ID: {self.agent_id}): {e}")
            raise

    async def _resume(self) -> None:
        """Agent-specific resume logic.

        Subclasses should override this method to implement their own resume logic.
        """
        pass

    async def process_event(self, event: BaseEvent) -> None:
        """Process an incoming event.

        This method dispatches events to the appropriate event handlers.
        Subclasses may override this method to implement custom event
        processing logic.

        Args:
            event: The event to process
        """
        event_type = type(event)

        if event_type in self._event_handlers:
            for handler in self._event_handlers[event_type]:
                try:
                    await handler(event)
                except Exception as e:
                    logger.error(
                        f"Error in event handler for {event_type.__name__} in agent {self.name}: {e}"
                    )

    def register_event_handler(
        self,
        event_type: Type[BaseEvent],
        handler: Callable[[BaseEvent], Awaitable[None]],
    ) -> None:
        """Register a handler for a specific event type.

        Args:
            event_type: The type of event to handle
            handler: The handler function
        """
        if event_type not in self._event_handlers:
            self._event_handlers[event_type] = []

        self._event_handlers[event_type].append(handler)

        # Register with autogen_core's event system
        register_hook(
            event_type,
            EventHook(
                handler_function=handler,
                filters={"agent_id": self.agent_id},
            ),
        )

        logger.debug(
            f"Registered handler for {event_type.__name__} events in agent {self.name}"
        )

    def _emit_lifecycle_event(
        self, state: AgentLifecycleState, metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Emit a lifecycle event.

        This is a helper method to emit standardized lifecycle events.

        Args:
            state: The lifecycle state to emit
            metadata: Optional metadata to include in the event
        """
        event = AgentLifecycleEvent(
            agent_id=self.agent_id,
            agent_name=self.name,
            state=state,
            metadata=metadata or {},
        )
        self.emit_event(event)

    def emit_event(self, event: BaseEvent) -> None:
        """Emit an event.

        This method adds an event to the global event system.

        Args:
            event: The event to emit
        """
        Event.add(event)
        logger.debug(f"Agent {self.name} emitted event: {type(event).__name__}")

    def __str__(self) -> str:
        """Return a string representation of the agent.

        Returns:
            String representation of the agent
        """
        return f"{self.name} (ID: {self.agent_id}, State: {self.context.state.value})"


class AutogenChatAgent(BaseAgent):
    """Base class for agents based on AutoGen's ChatAgent.

    This class integrates with AutoGen's ChatAgent to provide LLM-based
    agent capabilities.
    """

    def __init__(
        self,
        name: str,
        description: str,
        config_key: str,
        system_message: str,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize an AutoGen-based chat agent.

        Args:
            name: The name of the agent
            description: A description of the agent's purpose
            config_key: The configuration key for this agent
            system_message: The system message for the agent
            agent_id: Optional unique identifier for the agent
            model: The model to use for this agent (overrides config)
            **kwargs: Additional arguments to pass to ChatAgent
        """
        super().__init__(name, description, config_key, agent_id)

        self.system_message = system_message
        self.model = model or self.config.get("openai", {}).get("chat_model", "gpt4o")
        self.kwargs = kwargs
        self.chat_agent: Optional[ChatAgent] = None

    async def _start(self) -> None:
        """Start the Autogen chat agent."""
        # Create an AutoGen ChatAgent
        openai_client = get_openai_client()

        # Get LLM configuration
        model_config = {
            "model": self.model,
            "api_key": openai_client.api_key,
            "azure_endpoint": openai_client.api_base,
            "api_type": openai_client.api_type,
            "api_version": openai_client.api_version,
        }

        self.chat_agent = ChatAgent(
            name=self.name,
            system_message=self.system_message,
            llm_config=model_config,
            **self.kwargs,
        )

        logger.info(f"AutoGen chat agent {self.name} created with model {self.model}")

    async def _stop(self) -> None:
        """Stop the Autogen chat agent."""
        # Currently, there's no specific shutdown needed for ChatAgent
        self.chat_agent = None

    async def chat(self, message: str, sender: Optional[str] = None) -> str:
        """Send a chat message to the agent and get its response.

        Args:
            message: The message to send
            sender: Optional sender name

        Returns:
            The agent's response

        Raises:
            ValueError: If the agent is not in the RUNNING state
        """
        if self.context.state != AgentState.RUNNING:
            raise ValueError(
                f"Agent is not running (current state: {self.context.state.value})"
            )

        if self.chat_agent is None:
            raise ValueError("Chat agent not initialized")

        # TODO: Implement proper async communication with AutoGen
        # For now, we'll just use a direct call
        response = self.chat_agent.generate_reply(
            message=message,
            sender=sender or "user",
        )

        return response
