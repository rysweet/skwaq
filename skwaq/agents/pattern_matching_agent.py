"""Pattern matching agent implementation.

This module provides the implementation of the pattern matching agent
for vulnerability assessment.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class PatternMatchingAgent(BaseVulnerabilityAgent):
    """Agent for matching vulnerability patterns in code."""

    def __init__(self) -> None:
        """Initialize a pattern matching agent."""
        super().__init__(
            name="pattern_matching_agent",
            description="Agent for matching vulnerability patterns in code",
            config_key="agents.pattern_matching_agent",
        )
