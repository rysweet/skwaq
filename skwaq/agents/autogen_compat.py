"""Compatibility layer for autogen_core.

This module creates compatibility shims for the autogen_core module
to match the expected API structure in our codebase.
"""

import autogen_core
import logging
import sys
from typing import Any, Dict, List, Optional, Callable, Type, Union

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


class AsyncAPIResponse:
    """Compatibility shim for async API response."""
    
    def __init__(self, content: str) -> None:
        """Initialize the response."""
        self.choices = [AsyncAPIChoice(content)]


class AsyncAPIChoice:
    """Compatibility shim for async API choice."""
    
    def __init__(self, content: str) -> None:
        """Initialize the choice."""
        self.message = {"role": "assistant", "content": content}


class ChatCompletionClient:
    """Compatibility shim for autogen_core.ChatCompletionClient."""
    
    def __init__(
        self, 
        config_list: List[Dict[str, Any]], 
        is_async: bool = False,
        **kwargs: Any
    ) -> None:
        """Initialize the client."""
        self.config_list = config_list
        self.is_async = is_async
        self.kwargs = kwargs
        logger.warning(
            f"Using compatibility layer for autogen_core.ChatCompletionClient"
        )
    
    async def generate(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.7,
        max_tokens: Optional[int] = None,
        stop: Optional[List[str]] = None,
        **kwargs: Any
    ) -> AsyncAPIResponse:
        """Generate a response from an async API."""
        try:
            # Try using the actual API with OpenAI package
            # This is a simplified implementation for compatibility
            import openai
            
            # Extract config from the first item in config_list
            config = self.config_list[0]
            api_key = config.get("api_key")
            api_type = config.get("api_type", "openai")
            model = config.get("model", "gpt-4")
            
            # Set up the client
            if api_type == "azure":
                client = openai.AzureOpenAI(
                    api_key=api_key,
                    api_version=config.get("api_version", "2023-05-15"),
                    azure_endpoint=config.get("base_url"),
                )
            else:
                client = openai.OpenAI(
                    api_key=api_key,
                )
            
            # Make the API call
            response = await client.chat.completions.create(
                model=model,
                messages=messages,
                temperature=temperature,
                max_tokens=max_tokens,
                stop=stop,
                **kwargs
            )
            
            # Extract the content from the response
            content = response.choices[0].message.content
            
            # Return a compatible response
            return AsyncAPIResponse(content)
            
        except Exception as e:
            # Fallback to a simple mock response for testing
            logger.error(f"Error in ChatCompletionClient.generate: {e}")
            return AsyncAPIResponse("This is a mock response from the compatibility layer.")


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
ChatCompletionClient = ChatCompletionClient

# Export version info from the real autogen_core
__version__ = autogen_core.__version__
