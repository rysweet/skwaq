"""Agents module for the Skwaq vulnerability assessment copilot.

This module contains the implementation of the various specialized agents
that work together to perform vulnerability assessment tasks.
"""

from typing import Dict, Any, Optional

# Using autogen-core instead of pyautogen
from autogen_core.agent import Agent, ChatAgent

class BaseSkwaqAgent(ChatAgent):
    """Base class for all Skwaq agents providing common functionality."""

    def __init__(self, name: str, system_message: str, **kwargs):
        super().__init__(**kwargs)
        self.name = name
        self.system_message = system_message
        self.register_reply(
            Agent,
            self._default_auto_reply,
            position=0
        )
    
    async def _default_auto_reply(
        self,
        message: Optional[str],
        sender: Optional[Agent],
        config: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Default reply handler for messages from other agents."""
        if message is None:
            return None
            
        # Process the message and generate appropriate response
        # This will be overridden by specific agent implementations
        return f"Received message from {sender.name}: {message}"