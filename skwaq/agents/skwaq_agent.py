"""Legacy Skwaq agent implementation for backward compatibility.

This module provides the legacy SkwaqAgent implementation to maintain
backward compatibility with existing code.
"""

from typing import Optional, Any, Type, Callable

from ..utils.config import get_config, Config
from ..utils.logging import get_logger

logger = get_logger(__name__)


class SkwaqAgent:
    """Legacy class for backward compatibility."""

    def __init__(
        self,
        name: str,
        system_message: str,
        description: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Initialize a Skwaq agent.

        Args:
            name: The name of the agent
            system_message: System message for the agent
            description: Optional description of the agent
            **kwargs: Additional configuration
        """
        self.name = name
        self.system_message = system_message
        self.description = description or f"{name} Agent"
        self.config: Config = get_config()

    def register_event_hook(self, event_type: Type[Any], hook: Callable[..., Any]) -> None:
        """Register an event hook (dummy implementation).

        Args:
            event_type: Event type
            hook: Hook function
        """
        pass

    def emit_event(self, event: Any) -> None:
        """Emit an event (dummy implementation).

        Args:
            event: Event to emit
        """
        logger.debug(f"Agent {self.name} emitted event: {type(event).__name__}")


# Legacy agent implementations if autogen is available
try:
    from autogen_core.agent import Agent, ChatAgent  # type: ignore
    from autogen_core.event import Event, EventHook, register_hook  # type: ignore
    from autogen_core.code_utils import extract_code  # type: ignore
    from autogen_core.memory import MemoryRecord  # type: ignore

    HAS_AUTOGEN = True

    class OrchestratorAgent(SkwaqAgent):
        """The main orchestrator agent for vulnerability assessment."""

        def __init__(
            self,
            name: str = "Orchestrator",
            system_message: Optional[str] = None,
            **kwargs: Any,
        ) -> None:
            """Initialize orchestrator agent.

            Args:
                name: Agent name
                system_message: System message
                **kwargs: Additional configuration
            """
            if system_message is None:
                system_message = """You are the orchestrator agent for a vulnerability assessment system.
Your role is to coordinate the activities of all specialized agents, manage workflows,
and ensure the overall process runs smoothly."""

            super().__init__(
                name=name,
                system_message=system_message,
                description="Coordinates the overall vulnerability assessment process",
                **kwargs,
            )

        async def _on_vulnerability_discovered(self, event: Any) -> None:
            """Handle vulnerability discovery event.

            Args:
                event: Vulnerability discovery event
            """
            logger.info(f"Vulnerability discovered: {event.vulnerability_type}")

    class KnowledgeAgent(SkwaqAgent):
        """Agent for knowledge retrieval."""

        def __init__(
            self,
            name: str = "KnowledgeAgent",
            system_message: Optional[str] = None,
            **kwargs: Any,
        ) -> None:
            """Initialize knowledge agent.

            Args:
                name: Agent name
                system_message: System message
                **kwargs: Additional configuration
            """
            if system_message is None:
                system_message = """You are the knowledge agent for a vulnerability assessment system.
Your role is to retrieve and provide relevant background knowledge about vulnerabilities."""

            super().__init__(
                name=name,
                system_message=system_message,
                description="Manages and retrieves background knowledge about vulnerabilities",
                **kwargs,
            )

    class CodeAnalysisAgent(SkwaqAgent):
        """Agent for code analysis."""

        def __init__(
            self,
            name: str = "CodeAnalysisAgent",
            system_message: Optional[str] = None,
            **kwargs: Any,
        ) -> None:
            """Initialize code analysis agent.

            Args:
                name: Agent name
                system_message: System message
                **kwargs: Additional configuration
            """
            if system_message is None:
                system_message = """You are the code analysis agent for a vulnerability assessment system.
Your role is to analyze source code for potential security vulnerabilities."""

            super().__init__(
                name=name,
                system_message=system_message,
                description="Analyzes code for potential security vulnerabilities",
                **kwargs,
            )

except ImportError:
    HAS_AUTOGEN = False
