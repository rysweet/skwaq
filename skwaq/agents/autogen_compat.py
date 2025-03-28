"""Compatibility layer for autogen_core.

This module creates compatibility shims for the autogen_core module
to match the expected API structure in our codebase.
"""

import autogen_core
import logging
import sys
from typing import Any, Dict, List, Optional, Callable, Type

logger = logging.getLogger(__name__)


# Create compatibility classes
class Agent:
    """Compatibility shim for autogen_core.agent.Agent."""

    def __init__(self, name: str, **kwargs: Any) -> None:
        """Initialize the agent."""
        self.name = name
        self.kwargs = kwargs
        self._agent = None
        logger.warning(
            f"Using compatibility layer for autogen_core.agent.Agent: {name}"
        )

    def __repr__(self) -> str:
        """Return a string representation of the agent."""
        return f"Agent(name={self.name})"


class ChatAgent(Agent):
    """Compatibility shim for autogen_core.agent.ChatAgent."""

    def __init__(
        self, name: str, system_message: str, llm_config: Dict[str, Any], **kwargs: Any
    ) -> None:
        """Initialize the chat agent."""
        super().__init__(name=name, **kwargs)
        self.system_message = system_message
        self.llm_config = llm_config
        logger.warning(
            f"Using compatibility layer for autogen_core.agent.ChatAgent: {name}"
        )


class GroupChat:
    """Compatibility shim for autogen_core.GroupChat."""

    def __init__(self, agents: List[Agent], **kwargs: Any) -> None:
        """Initialize the group chat."""
        self.agents = agents
        self.kwargs = kwargs
        logger.warning(f"Using compatibility layer for autogen_core.GroupChat")


# Event system compatibility
class BaseEvent:
    """Compatibility shim for autogen_core.event.BaseEvent."""

    def __init__(self) -> None:
        """Initialize the event."""
        pass


class Event(BaseEvent):
    """Compatibility shim for autogen_core.event.Event."""

    def __init__(self, type_name: str, data: Dict[str, Any]) -> None:
        """Initialize the event."""
        super().__init__()
        self.type_name = type_name
        self.data = data


class EventHook:
    """Compatibility shim for autogen_core.event.EventHook."""

    def __init__(
        self, handler_function: Callable[[BaseEvent], None], filters: Dict[str, Any]
    ) -> None:
        """Initialize the event hook."""
        self.handler_function = handler_function
        self.filters = filters


def register_hook(event_type: Type[BaseEvent], hook: EventHook) -> None:
    """Register an event hook for the specified event type."""
    logger.warning(f"Using compatibility layer for autogen_core.event.register_hook")
    # In actual usage, we would register with autogen_core's event system


# Define specific event types
class AgentInitEvent(BaseEvent):
    """Event fired when an agent is initialized."""

    def __init__(self, agent: Agent) -> None:
        """Initialize the event."""
        super().__init__()
        self.agent = agent


class AgentCloseEvent(BaseEvent):
    """Event fired when an agent is closed."""

    def __init__(self, agent: Agent) -> None:
        """Initialize the event."""
        super().__init__()
        self.agent = agent


class GroupChatInitEvent(BaseEvent):
    """Event fired when a group chat is initialized."""

    def __init__(self, manager: Any, agents: List[Agent]) -> None:
        """Initialize the event."""
        super().__init__()
        self.manager = manager
        self.agents = agents


class MessageEvent(BaseEvent):
    """Event fired when a message is sent."""

    def __init__(self, sender: str, receiver: str, message: str) -> None:
        """Initialize the event."""
        super().__init__()
        self.sender = sender
        self.receiver = receiver
        self.message = message


# Code utilities compatibility
def extract_code(text: str, patterns: Optional[List[str]] = None) -> List[str]:
    """Extract code blocks from text."""
    logger.warning(
        f"Using compatibility layer for autogen_core.code_utils.extract_code"
    )
    # Return an empty list as a fallback
    return []


# Memory compatibility
class MemoryRecord:
    """Compatibility shim for autogen_core.memory.MemoryRecord."""

    def __init__(self, content: str, metadata: Dict[str, Any]) -> None:
        """Initialize the memory record."""
        self.content = content
        self.metadata = metadata
        logger.warning(
            f"Using compatibility layer for autogen_core.memory.MemoryRecord"
        )


# Group these classes into modules for easier import
class AgentModule:
    Agent = Agent
    ChatAgent = ChatAgent


class EventModule:
    BaseEvent = BaseEvent
    Event = Event
    EventHook = EventHook
    register_hook = register_hook
    AgentInitEvent = AgentInitEvent
    AgentCloseEvent = AgentCloseEvent
    GroupChatInitEvent = GroupChatInitEvent
    MessageEvent = MessageEvent


class CodeUtilsModule:
    extract_code = extract_code


class MemoryModule:
    MemoryRecord = MemoryRecord


# Create module instances
agent = AgentModule()
event = EventModule()
code_utils = CodeUtilsModule()
memory = MemoryModule()
GroupChat = GroupChat

# Export version info from the real autogen_core
__version__ = autogen_core.__version__
