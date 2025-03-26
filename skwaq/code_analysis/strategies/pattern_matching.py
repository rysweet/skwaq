"""Pattern matching strategy for vulnerability detection.

This module implements the pattern matching strategy for detecting vulnerabilities
in source code using regular expressions.
"""

from typing import Dict, List, Any, Optional

from ...shared.finding import Finding
from ...utils.logging import get_logger
from ..patterns.matcher import PatternMatcher
from .base import AnalysisStrategy

logger = get_logger(__name__)


class PatternMatchingStrategy(AnalysisStrategy):
    """Pattern matching strategy for vulnerability detection.
    
    This class implements a vulnerability detection strategy that uses
    regular expressions to match known vulnerability patterns in source code.
    """
    
    def __init__(self) -> None:
        """Initialize the pattern matching strategy."""
        super().__init__()
        self.matcher = PatternMatcher()
    
    async def analyze(
        self, 
        file_id: int, 
        content: str, 
        language: str,
        options: Optional[Dict[str, Any]] = None
    ) -> List[Finding]:
        """Analyze a file for potential vulnerabilities using pattern matching.
        
        Args:
            file_id: ID of the file node in the graph
            content: Content of the file
            language: Programming language of the file
            options: Optional dictionary with analysis configuration
            
        Returns:
            List of findings
        """
        logger.debug(f"Performing pattern matching for file ID {file_id}")
        
        findings = []
        
        # Get vulnerability patterns from the knowledge graph
        patterns = self.connector.run_query(
            f"""
            MATCH (p:VulnerabilityPattern)
            WHERE p.language IS NULL OR p.language = $language
            RETURN id(p) as pattern_id, p.name as name, p.description as description, 
                   p.regex_pattern as regex_pattern, p.severity as severity
            """,
            {"language": language}
        )
        
        # Use the matcher to find patterns
        match_findings = self.matcher.match_patterns(file_id, content, patterns)
        findings.extend(match_findings)
        
        # Create finding nodes in the database
        for finding in findings:
            self._create_finding_node(file_id, finding)
        
        logger.debug(f"Pattern matching complete: {len(findings)} matches found")
        return findings