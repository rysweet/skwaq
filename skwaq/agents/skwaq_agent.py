"""Base agent implementation for Skwaq workflows.

This module provides a simplified agent implementation for workflow agents,
focusing on integration with the LLM-based tasks rather than complex multi-agent
orchestration.
"""

from typing import (
    Dict,
    List,
    Any,
    Optional,
    Union,
    Callable,
    TypeVar,
    Generic,
    AsyncGenerator,
    Type,
)
import asyncio
import json
import uuid
from abc import ABC, abstractmethod

import autogen_core
from autogen_core import Agent

from ..core.openai_client import get_openai_client
from ..utils.logging import get_logger

logger = get_logger(__name__)

T = TypeVar("T")


class SkwaqAgent:
    """Base agent implementation for Skwaq workflows.

    This is a simplified version of the BaseAgent class designed specifically
    for workflow integration, focusing on LLM interactions rather than complex
    agent communication patterns.
    """

    def __init__(
        self,
        name: str,
        system_message: str,
        description: Optional[str] = None,
        **kwargs,
    ):
        """Initialize the Skwaq agent.

        Args:
            name: The name of the agent
            system_message: The system message for the agent
            description: Optional description of the agent's purpose
            **kwargs: Additional keyword arguments
        """
        self.name = name
        self.system_message = system_message
        self.description = description or "Skwaq workflow agent"
        self.id = f"{name.lower().replace(' ', '_')}_{uuid.uuid4().hex[:8]}"
        self.agents = {}  # For accessing other agents
        self.event_hooks: Dict[type, List[Callable]] = {}

        # Store any additional kwargs as attributes
        for key, value in kwargs.items():
            setattr(self, key, value)

        logger.info(f"Created agent: {self.name} ({self.id})")

    def register_event_hook(self, event_type: type, callback: Callable) -> None:
        """Register a callback for a specific event type.

        Args:
            event_type: The type of event to listen for
            callback: The callback function to call when the event occurs
        """
        if event_type not in self.event_hooks:
            self.event_hooks[event_type] = []

        self.event_hooks[event_type].append(callback)
        logger.debug(f"Agent {self.name} registered hook for {event_type.__name__}")

    async def handle_event(self, event: Any) -> None:
        """Handle an event.

        Args:
            event: The event to handle
        """
        # Check if we have a hook for this event type
        for event_type, hooks in self.event_hooks.items():
            if isinstance(event, event_type):
                for hook in hooks:
                    try:
                        await hook(event)
                    except Exception as e:
                        logger.error(f"Error in event hook: {e}")

    async def generate_response(self, prompt: str, temperature: float = 0.7) -> str:
        """Generate a response from the LLM.

        Args:
            prompt: The prompt to send to the LLM
            temperature: The temperature to use for generation

        Returns:
            The generated response
        """
        full_prompt = f"{self.system_message}\n\n{prompt}"

        # Get the OpenAI client
        openai_client = get_openai_client(async_mode=True)

        # Generate a response
        response = await openai_client.get_completion(
            full_prompt, temperature=temperature
        )

        return response

    def add_agent(self, agent_id: str, agent: "SkwaqAgent") -> None:
        """Add a reference to another agent.

        Args:
            agent_id: The ID of the agent
            agent: The agent instance
        """
        self.agents[agent_id] = agent
        logger.debug(f"Agent {self.name} added reference to agent {agent_id}")

    def emit_event(self, event: Any) -> None:
        """Emit an event.

        Args:
            event: The event to emit
        """
        # In autogen_core 0.4.x, the event API is different
        logger.debug(f"Agent {self.name} emitted event: {event.__class__.__name__}")
