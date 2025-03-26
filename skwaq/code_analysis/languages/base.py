"""Base language analyzer for the Skwaq vulnerability assessment copilot.

This module defines the base LanguageAnalyzer class, which serves as the foundation
for language-specific analyzers used to detect vulnerabilities in different languages.
"""

from abc import ABC, abstractmethod
import re
from typing import Dict, List, Any, Optional, Pattern, Set

from ...shared.finding import Finding
from ...utils.logging import get_logger

logger = get_logger(__name__)


class LanguageAnalyzer(ABC):
    """Base class for language-specific code analyzers.

    This abstract class defines the interface for language-specific analyzers
    that detect vulnerabilities in different programming languages.
    """

    def __init__(self) -> None:
        """Initialize the language analyzer."""
        self.language: str = self.get_language_name()
        self.patterns: Dict[str, Dict[str, Any]] = {}

    @abstractmethod
    def get_language_name(self) -> str:
        """Get the name of the programming language.

        Returns:
            Language name
        """
        pass

    @abstractmethod
    def get_file_extensions(self) -> Set[str]:
        """Get the set of file extensions supported by this analyzer.

        Returns:
            Set of supported file extensions
        """
        pass

    @abstractmethod
    def analyze_ast(self, file_id: int, content: str) -> List[Finding]:
        """Analyze a file using AST-based techniques.

        Args:
            file_id: ID of the file in the database
            content: Content of the file

        Returns:
            List of findings
        """
        pass

    def register_patterns(self, patterns: Dict[str, Dict[str, Any]]) -> None:
        """Register vulnerability patterns for this language.

        Args:
            patterns: Dictionary of pattern definitions, where keys are pattern names
                and values are dictionaries with pattern definitions
        """
        self.patterns.update(patterns)

    def get_pattern(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a vulnerability pattern by name.

        Args:
            name: Name of the pattern

        Returns:
            Pattern definition or None if not found
        """
        return self.patterns.get(name)

    def match_pattern(
        self,
        file_id: int,
        content: str,
        pattern_name: str,
        line_offset: int = 0,
    ) -> List[Finding]:
        """Match a specific pattern against file content.

        Args:
            file_id: ID of the file in the database
            content: Content to match against
            pattern_name: Name of the pattern to use
            line_offset: Line number offset to add to findings

        Returns:
            List of findings
        """
        pattern = self.get_pattern(pattern_name)
        if not pattern:
            logger.warning(
                f"Pattern '{pattern_name}' not found for language {self.language}"
            )
            return []

        return self._apply_regex_pattern(
            file_id,
            content,
            pattern.get("regex_pattern", ""),
            pattern.get("name", pattern_name),
            pattern.get("description", ""),
            pattern.get("severity", "Medium"),
            pattern.get("confidence", 0.7),
            pattern.get("pattern_id"),
            line_offset,
        )

    def _apply_regex_pattern(
        self,
        file_id: int,
        content: str,
        regex_str: str,
        name: str,
        description: str,
        severity: str = "Medium",
        confidence: float = 0.7,
        pattern_id: Optional[int] = None,
        line_offset: int = 0,
    ) -> List[Finding]:
        """Apply a regex pattern to content to find vulnerabilities.

        Args:
            file_id: ID of the file in the database
            content: Content to search
            regex_str: Regular expression pattern
            name: Name of the vulnerability
            description: Description of the vulnerability
            severity: Severity level (Low, Medium, High)
            confidence: Confidence level (0.0-1.0)
            pattern_id: ID of the pattern in the database
            line_offset: Line number offset to add to findings

        Returns:
            List of findings
        """
        findings = []

        try:
            if not regex_str:
                return []

            # Compile and apply regex
            regex = re.compile(regex_str, re.MULTILINE | re.DOTALL)
            matches = list(regex.finditer(content))

            # Process matches
            for match in matches:
                # Extract matching code and surrounding context
                match_text = match.group(0)

                # Get line number (approximate)
                line_number = content[: match.start()].count("\n") + 1 + line_offset

                # Create finding
                finding = Finding(
                    type="pattern_match",
                    pattern_id=pattern_id,
                    pattern_name=name,
                    vulnerability_type=name,
                    description=description,
                    line_number=line_number,
                    matched_text=match_text,
                    confidence=confidence,
                    severity=severity,
                    file_id=file_id,
                )

                findings.append(finding)

        except re.error as e:
            logger.error(f"Invalid regex pattern '{regex_str}': {e}")

        return findings
