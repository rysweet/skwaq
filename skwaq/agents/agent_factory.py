"""Agent factory functions for creating agent instances.

This module provides factory functions for creating various types of agents
for the vulnerability assessment system.
"""

from typing import Any, Union

from .skwaq_agent import HAS_AUTOGEN, SkwaqAgent
from .orchestration_agent import OrchestrationAgent


def create_orchestrator_agent(**kwargs: Any) -> Union[SkwaqAgent, OrchestrationAgent]:
    """Create an orchestrator agent instance.

    Args:
        **kwargs: Agent configuration

    Returns:
        Orchestrator agent
    """
    if HAS_AUTOGEN:
        # Use SkwaqAgent version if autogen is available
        return SkwaqAgent(
            name="Orchestrator",
            system_message="""You are the orchestrator agent for a vulnerability assessment system.
Your role is to coordinate the activities of all specialized agents and ensure the
assessment process runs smoothly.""",
            **kwargs,
        )
    else:
        # Use simplified version
        return OrchestrationAgent()
