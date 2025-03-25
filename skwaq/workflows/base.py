"""Base workflow class for Skwaq."""

from typing import Dict, Any, Optional
from abc import ABC, abstractmethod


class Workflow(ABC):
    """Base workflow class that all specific workflows should inherit from."""

    def __init__(self):
        """Initialize the workflow."""
        self.investigation_id: Optional[str] = None
        self.agents: Dict[str, Any] = {}
        self.connector = None

    @abstractmethod
    async def run(self):
        """Run the workflow. Must be implemented by subclasses."""
        pass

    def should_continue(self) -> bool:
        """Check if the workflow should continue iterating.

        Returns:
            bool: True if the workflow should continue, False if it should stop
        """
        return True

    def pause(self) -> None:
        """Pause the workflow iteration."""
        pass

    def resume(self) -> None:
        """Resume the workflow iteration."""
        pass
