"""Legacy critic agent implementation.

This module provides the implementation of the critic agent
for vulnerability assessment.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class CriticAgent(BaseVulnerabilityAgent):
    """Agent for critiquing vulnerability findings."""

    def __init__(self) -> None:
        """Initialize a critic agent."""
        super().__init__(
            name="critic_agent",
            description="Agent for critiquing vulnerability findings",
            config_key="agents.critic_agent",
        )
