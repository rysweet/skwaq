"""Base analysis strategy for vulnerability detection.

This module defines the base AnalysisStrategy class, which serves as the foundation
for different analysis approaches like pattern matching, semantic analysis, etc.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional
import asyncio

from ...db.neo4j_connector import get_connector
from ...core.openai_client import get_openai_client
from ...utils.logging import get_logger
from ...shared.finding import Finding, AnalysisResult


logger = get_logger(__name__)


class AnalysisStrategy(ABC):
    """Base class for code analysis strategies.

    This abstract class defines the interface for different code analysis strategies
    used to detect vulnerabilities in source code.
    """

    def __init__(self) -> None:
        """Initialize the analysis strategy."""
        self.connector = get_connector()
        self.openai_client = get_openai_client(async_mode=True)

    @abstractmethod
    async def analyze(
        self,
        file_id: int,
        content: str,
        language: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> List[Finding]:
        """Analyze a file for potential vulnerabilities.

        Args:
            file_id: ID of the file in the database
            content: Content of the file
            language: Programming language of the file
            options: Additional options for the analysis

        Returns:
            List of findings
        """
        pass

    def _create_finding_node(self, file_id: int, finding: Finding) -> Optional[int]:
        """Create a finding node in the graph database.

        Args:
            file_id: ID of the file node in the graph
            finding: Dictionary with finding information

        Returns:
            ID of the created finding node, or None if creation failed
        """
        try:
            # Create properties for the finding node
            properties = {
                "type": finding.type,
                "vulnerability_type": finding.vulnerability_type,
                "description": finding.description,
                "line_number": finding.line_number,
                "matched_text": finding.matched_text or "",
                "severity": finding.severity,
                "confidence": finding.confidence,
                "suggestion": finding.suggestion or "",
                "timestamp": self._get_timestamp(),
            }

            # Create the finding node
            finding_id = self.connector.create_node(
                labels=["Finding"],
                properties=properties,
            )

            if finding_id is None:
                logger.error("Failed to create finding node")
                return None

            # Link the finding to the file
            self.connector.create_relationship(file_id, finding_id, "HAS_FINDING")

            # If there is a pattern_id, link to the pattern
            if finding.pattern_id:
                self.connector.create_relationship(
                    finding_id, finding.pattern_id, "MATCHES_PATTERN"
                )

            return finding_id

        except Exception as e:
            logger.error(f"Error creating finding node: {e}")
            return None

    def _get_timestamp(self) -> str:
        """Get the current timestamp as an ISO 8601 string.

        Returns:
            Timestamp string
        """
        from datetime import datetime

        return datetime.utcnow().isoformat()
