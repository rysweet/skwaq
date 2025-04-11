"""Agent registry for centralized agent management.

This module provides the AgentRegistry class for centralized tracking and
management of all agents in the system.
"""

from typing import Dict, List, Optional, Type, Any, cast
import asyncio
import threading
from functools import wraps

from ..utils.logging import get_logger
from ..events.system_events import AgentLifecycleEvent, AgentLifecycleState

logger = get_logger(__name__)


class AgentRegistry:
    """Centralized registry for tracking and managing all agents in the system.

    This class implements the Singleton pattern to ensure there is only one
    registry instance in the system.
    """

    # Class-level storage for agents
    _agents: Dict[str, "BaseAgent"] = {}
    _agents_by_name: Dict[str, List["BaseAgent"]] = {}
    _agents_by_type: Dict[Type["BaseAgent"], List["BaseAgent"]] = {}

    # Lock for thread safety
    _lock = threading.RLock()

    @classmethod
    def register(cls, agent: "BaseAgent") -> None:
        """Register an agent with the registry.

        Args:
            agent: The agent to register
        """
        # Avoiding circular imports
        from .base import BaseAgent

        if not isinstance(agent, BaseAgent):
            raise TypeError(
                f"Agent must be an instance of BaseAgent, got {type(agent)}"
            )

        with cls._lock:
            # Register agent by ID
            cls._agents[agent.agent_id] = agent

            # Register agent by name
            if agent.name not in cls._agents_by_name:
                cls._agents_by_name[agent.name] = []
            cls._agents_by_name[agent.name].append(agent)

            # Register agent by type
            agent_type = type(agent)
            if agent_type not in cls._agents_by_type:
                cls._agents_by_type[agent_type] = []
            cls._agents_by_type[agent_type].append(agent)

            logger.debug(f"Agent {agent.name} (ID: {agent.agent_id}) registered")

    @classmethod
    def unregister(cls, agent_id: str) -> None:
        """Unregister an agent from the registry.

        Args:
            agent_id: The ID of the agent to unregister
        """
        with cls._lock:
            if agent_id not in cls._agents:
                logger.warning(f"Agent with ID {agent_id} not found in registry")
                return

            agent = cls._agents[agent_id]

            # Remove from agents by ID
            del cls._agents[agent_id]

            # Remove from agents by name
            if agent.name in cls._agents_by_name:
                cls._agents_by_name[agent.name] = [
                    a for a in cls._agents_by_name[agent.name] if a.agent_id != agent_id
                ]
                if not cls._agents_by_name[agent.name]:
                    del cls._agents_by_name[agent.name]

            # Remove from agents by type
            agent_type = type(agent)
            if agent_type in cls._agents_by_type:
                cls._agents_by_type[agent_type] = [
                    a for a in cls._agents_by_type[agent_type] if a.agent_id != agent_id
                ]
                if not cls._agents_by_type[agent_type]:
                    del cls._agents_by_type[agent_type]

            logger.debug(f"Agent {agent.name} (ID: {agent_id}) unregistered")

    @classmethod
    def get_agent(cls, agent_id: str) -> Optional["BaseAgent"]:
        """Get an agent by its ID.

        Args:
            agent_id: The ID of the agent to get

        Returns:
            The agent with the specified ID, or None if not found
        """
        with cls._lock:
            return cls._agents.get(agent_id)

    @classmethod
    def get_agents_by_name(cls, name: str) -> List["BaseAgent"]:
        """Get all agents with a specific name.

        Args:
            name: The name to search for

        Returns:
            A list of agents with the specified name
        """
        with cls._lock:
            return cls._agents_by_name.get(name, [])

    @classmethod
    def get_agents_by_type(cls, agent_type: Type["BaseAgent"]) -> List["BaseAgent"]:
        """Get all agents of a specific type.

        Args:
            agent_type: The type of agents to get

        Returns:
            A list of agents of the specified type
        """
        with cls._lock:
            return cls._agents_by_type.get(agent_type, [])

    @classmethod
    def get_all_agents(cls) -> List["BaseAgent"]:
        """Get all registered agents.

        Returns:
            A list of all registered agents
        """
        with cls._lock:
            return list(cls._agents.values())

    @classmethod
    async def start_all(cls) -> None:
        """Start all registered agents.

        This method starts all registered agents that are not already running.
        """
        # Import here to avoid circular imports
        from .base import AgentState

        with cls._lock:
            agents_to_start = [
                agent
                for agent in cls._agents.values()
                if agent.context.state in (AgentState.INITIALIZED, AgentState.STOPPED)
            ]

        # Start agents outside of the lock to avoid deadlocks
        start_tasks = [agent.start() for agent in agents_to_start]
        await asyncio.gather(*start_tasks)

        logger.info(f"Started {len(agents_to_start)} agents")

    @classmethod
    async def stop_all(cls) -> None:
        """Stop all registered agents.

        This method stops all registered agents that are currently running.
        """
        # Import here to avoid circular imports
        from .base import AgentState

        with cls._lock:
            agents_to_stop = [
                agent
                for agent in cls._agents.values()
                if agent.context.state == AgentState.RUNNING
            ]

        # Stop agents outside of the lock to avoid deadlocks
        stop_tasks = [agent.stop() for agent in agents_to_stop]
        await asyncio.gather(*stop_tasks)

        logger.info(f"Stopped {len(agents_to_stop)} agents")

    @classmethod
    def clear(cls) -> None:
        """Clear the registry.

        This method removes all agents from the registry.
        Warning: This should only be used in tests or during system shutdown.
        """
        with cls._lock:
            cls._agents.clear()
            cls._agents_by_name.clear()
            cls._agents_by_type.clear()

            logger.warning("Agent registry cleared")
