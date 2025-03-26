"""Orchestration agent implementation.

This module provides the implementation of the orchestration agent
for vulnerability assessment workflow.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class OrchestrationAgent(BaseVulnerabilityAgent):
    """Agent for orchestrating vulnerability research workflow."""

    def __init__(self) -> None:
        """Initialize an orchestration agent."""
        super().__init__(
            name="orchestration_agent",
            description="Agent for orchestrating vulnerability research workflow",
            config_key="agents.orchestration_agent",
        )
