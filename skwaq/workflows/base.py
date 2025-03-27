"""Base workflow class for Skwaq."""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod
import asyncio

from ..db.neo4j_connector import get_connector


class Workflow(ABC):
    """Base workflow class that all specific workflows should inherit from."""

    def __init__(
        self, 
        name: str = "Workflow",
        description: str = "Generic workflow",
        repository_id: Optional[int] = None
    ):
        """Initialize the workflow.
        
        Args:
            name: Name of the workflow
            description: Description of the workflow
            repository_id: Optional ID of the repository to work with
        """
        self.name = name
        self.description = description
        self.repository_id = repository_id
        self.investigation_id: Optional[int] = None
        self.agents: Dict[str, Any] = {}
        self.connector = get_connector()
        
        # State management
        self._should_continue = True
        self._pause_event = asyncio.Event()
        self._pause_event.set()  # Not paused by default

    async def setup(self) -> None:
        """Set up the workflow. Override in subclasses."""
        pass

    @abstractmethod
    async def run(self, *args, **kwargs):
        """Run the workflow. Must be implemented by subclasses."""
        pass

    def should_continue(self) -> bool:
        """Check if the workflow should continue iterating.

        Returns:
            bool: True if the workflow should continue, False if it should stop
        """
        return self._should_continue

    def pause(self) -> None:
        """Pause the workflow iteration."""
        self._pause_event.clear()

    def resume(self) -> None:
        """Resume the workflow iteration."""
        self._pause_event.set()
    
    def _get_timestamp(self) -> str:
        """Get the current timestamp.
        
        Returns:
            Timestamp string in ISO format
        """
        import datetime
        return datetime.datetime.utcnow().isoformat()
