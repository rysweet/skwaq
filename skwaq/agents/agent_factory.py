"""Agent factory functions for creating agent instances.

This module provides factory functions for creating various types of agents
for the vulnerability assessment system.
"""

from typing import Any

from .orchestrator_agent import OrchestratorAgent


def create_orchestrator_agent(**kwargs: Any) -> OrchestratorAgent:
    """Create an orchestrator agent instance.

    Args:
        **kwargs: Agent configuration

    Returns:
        Orchestrator agent
    """
    return OrchestratorAgent(
        name="Orchestrator",
        system_message="""You are the orchestrator agent for a vulnerability assessment system.
Your role is to coordinate the activities of all specialized agents and ensure the
assessment process runs smoothly.""",
        **kwargs,
    )
