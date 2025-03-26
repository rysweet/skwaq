"""Legacy knowledge retrieval agent implementation.

This module provides the implementation of the knowledge retrieval agent
for vulnerability assessment.
"""

from .base_vulnerability_agent import BaseVulnerabilityAgent


class KnowledgeRetrievalAgent(BaseVulnerabilityAgent):
    """Agent for retrieving vulnerability knowledge."""

    def __init__(self) -> None:
        """Initialize a knowledge retrieval agent."""
        super().__init__(
            name="knowledge_retrieval_agent",
            description="Agent for retrieving vulnerability knowledge",
            config_key="agents.knowledge_retrieval_agent",
        )
