"""Legacy code analysis agent implementation.

This module provides the implementation of the code analysis agent
for vulnerability assessment.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class CodeAnalysisAgent(BaseVulnerabilityAgent):
    """Agent for analyzing code to identify potential vulnerabilities."""

    def __init__(self) -> None:
        """Initialize a code analysis agent."""
        super().__init__(
            name="code_analysis_agent",
            description="Agent for analyzing code to identify potential vulnerabilities",
            config_key="agents.code_analysis_agent",
        )
