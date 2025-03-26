"""Semantic analysis agent implementation.

This module provides the implementation of the semantic analysis agent
for vulnerability assessment.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class SemanticAnalysisAgent(BaseVulnerabilityAgent):
    """Agent for semantic analysis of code for vulnerabilities."""

    def __init__(self) -> None:
        """Initialize a semantic analysis agent."""
        super().__init__(
            name="semantic_analysis_agent",
            description="Agent for semantic analysis of code for vulnerabilities",
            config_key="agents.semantic_analysis_agent",
        )
