"""Integration with AutoGen.

This module provides adapters and utilities for integrating AutoGen Core
with the Skwaq agent system, including event bridging, message handling,
and agent lifecycle management.
"""

from typing import Dict, List, Any, Optional, Set, Callable, Awaitable, Type, cast
import asyncio
import logging
import json
import time
from functools import wraps

import autogen_core
from autogen_core.agent import Agent, ChatAgent
from autogen_core.event import BaseEvent, Event, EventHook, register_hook
from autogen_core.code_utils import extract_code
from autogen_core.memory import MemoryRecord

from ..utils.config import get_config
from ..utils.logging import get_logger
from ..core.openai_client import get_openai_client
from ..events.system_events import (
    EventBus,
    SystemEvent,
    AgentLifecycleEvent,
    AgentLifecycleState,
)

logger = get_logger(__name__)


class AutogenEventBridge:
    """Bridge between AutoGen events and Skwaq events.

    This class converts AutoGen Core events to Skwaq events and vice versa,
    allowing seamless integration between the two event systems.
    """

    def __init__(self) -> None:
        """Initialize the event bridge."""
        self.autogen_event_handlers: Dict[
            Type[BaseEvent], List[Callable[[BaseEvent], None]]
        ] = {}
        self.skwaq_event_bus = EventBus()

        # Register with AutoGen Core's event system
        self._setup_autogen_hooks()

    def _setup_autogen_hooks(self) -> None:
        """Set up hooks for AutoGen Core events.

        This method registers handlers for key AutoGen Core events
        and converts them to Skwaq events.
        """
        # Register for AgentInitEvent
        register_hook(
            autogen_core.event.AgentInitEvent,
            EventHook(
                handler_function=self._handle_agent_init_event,
                filters={},
            ),
        )

        # Register for AgentCloseEvent
        register_hook(
            autogen_core.event.AgentCloseEvent,
            EventHook(
                handler_function=self._handle_agent_close_event,
                filters={},
            ),
        )

        # Register for GroupChatInitEvent
        register_hook(
            autogen_core.event.GroupChatInitEvent,
            EventHook(
                handler_function=self._handle_group_chat_init_event,
                filters={},
            ),
        )

        # Register for MessageEvent
        register_hook(
            autogen_core.event.MessageEvent,
            EventHook(
                handler_function=self._handle_message_event,
                filters={},
            ),
        )

        logger.info("AutoGen Core event hooks registered")

    def _handle_agent_init_event(self, event: BaseEvent) -> None:
        """Handle AutoGen AgentInitEvent.

        Args:
            event: The AutoGen event
        """
        # Cast to correct event type
        agent_init_event = cast(autogen_core.event.AgentInitEvent, event)

        # Convert to Skwaq event
        skwaq_event = AgentLifecycleEvent(
            agent_id=str(id(agent_init_event.agent)),
            agent_name=agent_init_event.agent.name,
            state=AgentLifecycleState.CREATED,
            metadata={
                "agent_type": type(agent_init_event.agent).__name__,
                "autogen_event": "AgentInitEvent",
            },
        )

        # Publish to Skwaq event bus
        self.skwaq_event_bus.publish(skwaq_event)

        logger.debug(
            f"Converted AutoGen AgentInitEvent to Skwaq AgentLifecycleEvent for {agent_init_event.agent.name}"
        )

    def _handle_agent_close_event(self, event: BaseEvent) -> None:
        """Handle AutoGen AgentCloseEvent.

        Args:
            event: The AutoGen event
        """
        # Cast to correct event type
        agent_close_event = cast(autogen_core.event.AgentCloseEvent, event)

        # Convert to Skwaq event
        skwaq_event = AgentLifecycleEvent(
            agent_id=str(id(agent_close_event.agent)),
            agent_name=agent_close_event.agent.name,
            state=AgentLifecycleState.STOPPED,
            metadata={
                "agent_type": type(agent_close_event.agent).__name__,
                "autogen_event": "AgentCloseEvent",
            },
        )

        # Publish to Skwaq event bus
        self.skwaq_event_bus.publish(skwaq_event)

        logger.debug(
            f"Converted AutoGen AgentCloseEvent to Skwaq AgentLifecycleEvent for {agent_close_event.agent.name}"
        )

    def _handle_group_chat_init_event(self, event: BaseEvent) -> None:
        """Handle AutoGen GroupChatInitEvent.

        Args:
            event: The AutoGen event
        """
        # Cast to correct event type
        group_chat_init_event = cast(autogen_core.event.GroupChatInitEvent, event)

        # For each agent in the group chat, emit a lifecycle event
        for agent in group_chat_init_event.agents:
            skwaq_event = AgentLifecycleEvent(
                agent_id=str(id(agent)),
                agent_name=agent.name,
                state=AgentLifecycleState.RUNNING,
                metadata={
                    "agent_type": type(agent).__name__,
                    "autogen_event": "GroupChatInitEvent",
                    "group_chat_id": str(id(group_chat_init_event.manager)),
                },
            )

            # Publish to Skwaq event bus
            self.skwaq_event_bus.publish(skwaq_event)

        logger.debug(
            f"Processed AutoGen GroupChatInitEvent with {len(group_chat_init_event.agents)} agents"
        )

    def _handle_message_event(self, event: BaseEvent) -> None:
        """Handle AutoGen MessageEvent.

        Args:
            event: The AutoGen event
        """
        # Cast to correct event type
        message_event = cast(autogen_core.event.MessageEvent, event)

        # For now, we just log this event
        logger.debug(
            f"AutoGen MessageEvent: {message_event.sender} -> {message_event.receiver}: "
            f"{message_event.message[:50]}{'...' if len(message_event.message) > 50 else ''}"
        )


class AutogenAgentAdapter:
    """Adapter for AutoGen agents.

    This class adapts AutoGen agents to work with the Skwaq agent system,
    handling lifecycle management and event bridging.
    """

    def __init__(
        self,
        name: str,
        system_message: str,
        model: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize an AutoGen agent adapter.

        Args:
            name: The name of the agent
            system_message: The system message for the agent
            model: The model to use (defaults to config)
            **kwargs: Additional parameters for the AutoGen agent
        """
        self.name = name
        self.system_message = system_message
        self.config = get_config()
        self.openai_client = get_openai_client()

        self.model = model or self.config.get("openai", {}).get("chat_model", "gpt4o")
        self.kwargs = kwargs

        # The actual AutoGen agent
        self.agent: Optional[Agent] = None

        # Create event bridge for this agent
        self.event_bridge = AutogenEventBridge()

        logger.info(f"Created AutoGen agent adapter for {name}")

    async def create_agent(self) -> Agent:
        """Create and initialize the AutoGen agent.

        Returns:
            The created AutoGen agent
        """
        if self.agent is not None:
            return self.agent

        # Get LLM configuration
        model_config = {
            "model": self.model,
            "api_key": self.openai_client.api_key,
            "azure_endpoint": self.openai_client.api_base,
            "api_type": self.openai_client.api_type,
            "api_version": self.openai_client.api_version,
        }

        # Create the ChatAgent
        self.agent = ChatAgent(
            name=self.name,
            system_message=self.system_message,
            llm_config=model_config,
            **self.kwargs,
        )

        logger.info(f"Created AutoGen ChatAgent {self.name} with model {self.model}")
        return self.agent

    async def close_agent(self) -> None:
        """Close the AutoGen agent."""
        if self.agent is not None:
            # Currently, there's no specific shutdown needed for ChatAgent
            self.agent = None
            logger.info(f"Closed AutoGen agent {self.name}")


class AutogenGroupChatAdapter:
    """Adapter for AutoGen GroupChat.

    This class adapts AutoGen GroupChat to work with the Skwaq agent system,
    handling lifecycle management and event bridging.
    """

    def __init__(
        self,
        name: str,
        agents: List[Agent],
        **kwargs: Any,
    ) -> None:
        """Initialize a GroupChat adapter.

        Args:
            name: Name of the group chat
            agents: List of AutoGen agents to include
            **kwargs: Additional parameters for GroupChat
        """
        self.name = name
        self.agents = agents
        self.kwargs = kwargs

        # The actual AutoGen GroupChat
        self.group_chat: Optional[autogen_core.GroupChat] = None

        # Create event bridge for this group chat
        self.event_bridge = AutogenEventBridge()

        logger.info(
            f"Created AutoGen GroupChat adapter for {name} with {len(agents)} agents"
        )

    async def create_group_chat(self) -> autogen_core.GroupChat:
        """Create and initialize the AutoGen GroupChat.

        Returns:
            The created AutoGen GroupChat
        """
        if self.group_chat is not None:
            return self.group_chat

        # Create the GroupChat
        self.group_chat = autogen_core.GroupChat(
            agents=self.agents,
            **self.kwargs,
        )

        logger.info(
            f"Created AutoGen GroupChat {self.name} with {len(self.agents)} agents"
        )
        return self.group_chat

    async def close_group_chat(self) -> None:
        """Close the AutoGen GroupChat."""
        if self.group_chat is not None:
            # Currently, there's no specific shutdown needed for GroupChat
            self.group_chat = None
            logger.info(f"Closed AutoGen GroupChat {self.name}")
