"""Pattern matching module for vulnerability detection.

This module handles pattern matching operations for detecting vulnerabilities
in source code files.
"""

import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field

from ...shared.finding import Finding
from ...utils.logging import get_logger

logger = get_logger(__name__)


@dataclass
class VulnerabilityPattern:
    """Represents a pattern used to identify vulnerabilities in code.

    This class encapsulates information about a vulnerability pattern,
    including the regex pattern, associated metadata, and severity.
    """

    id: str
    name: str
    regex: str
    language: str
    severity: str = "Medium"
    confidence: float = 0.5
    description: str = ""
    cwe_id: Optional[str] = None
    remediation: Optional[str] = None
    compiled_regex: Optional[re.Pattern] = None

    def __post_init__(self):
        """Compile the regex pattern after initialization."""
        try:
            self.compiled_regex = re.compile(self.regex, re.MULTILINE | re.DOTALL)
        except re.error as e:
            logger.error(f"Failed to compile regex pattern for '{self.name}': {e}")
            # Don't raise, just leave compiled_regex as None

    def match(self, content: str) -> Optional[re.Match]:
        """Match the pattern against content.

        Args:
            content: The string content to search in

        Returns:
            Match object if found, otherwise None
        """
        if self.compiled_regex:
            return self.compiled_regex.search(content)
        return None

    def to_dict(self) -> Dict[str, Any]:
        """Convert the pattern to a dictionary.

        Returns:
            Dictionary representation of the pattern
        """
        return {
            "id": self.id,
            "name": self.name,
            "regex": self.regex,
            "language": self.language,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "cwe_id": self.cwe_id,
            "remediation": self.remediation,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "VulnerabilityPattern":
        """Create a pattern from a dictionary.

        Args:
            data: Dictionary containing the pattern data

        Returns:
            VulnerabilityPattern instance
        """
        return cls(
            id=data["id"],
            name=data["name"],
            regex=data["regex"],
            language=data["language"],
            severity=data.get("severity", "Medium"),
            confidence=data.get("confidence", 0.5),
            description=data.get("description", ""),
            cwe_id=data.get("cwe_id"),
            remediation=data.get("remediation"),
        )


class PatternMatcher:
    """Pattern matcher for vulnerability detection.

    This class handles the application of regular expression patterns
    to detect potential vulnerabilities in source code.
    """

    def __init__(self) -> None:
        """Initialize the pattern matcher."""
        self.patterns: Dict[str, Dict[str, VulnerabilityPattern]] = {}

    def add_pattern(self, pattern: VulnerabilityPattern) -> None:
        """Add a vulnerability pattern to the matcher.

        Args:
            pattern: The vulnerability pattern to add
        """
        language = pattern.language
        if language not in self.patterns:
            self.patterns[language] = {}

        self.patterns[language][pattern.id] = pattern

    def get_patterns_for_language(
        self, language: str
    ) -> Dict[str, VulnerabilityPattern]:
        """Get all patterns for a specific language.

        Args:
            language: The programming language to get patterns for

        Returns:
            Dictionary of pattern ID to pattern object
        """
        return self.patterns.get(language, {})

    def match_code(self, code: str, language: str) -> List[Dict[str, Any]]:
        """Match patterns against code content.

        Args:
            code: The code content to match against
            language: The programming language of the code

        Returns:
            List of match results
        """
        results = []

        # Get patterns for this language
        language_patterns = self.get_patterns_for_language(language)

        # Apply each pattern
        for pattern_id, pattern in language_patterns.items():
            match = pattern.match(code)
            if match:
                results.append(
                    {
                        "pattern_id": pattern_id,
                        "start": match.start(),
                        "end": match.end(),
                        "matched_text": match.group(0),
                        "pattern": pattern.to_dict(),
                    }
                )

        # Sort results by position in code
        results.sort(key=lambda x: x["start"])

        return results

    # Legacy methods for backward compatibility

    def compile_pattern(self, name: str, regex_pattern: str) -> bool:
        """Compile a regular expression pattern.

        Args:
            name: Name of the pattern
            regex_pattern: Regular expression pattern string

        Returns:
            True if compilation succeeded, False otherwise
        """
        try:
            if not regex_pattern:
                logger.warning(f"Empty regex pattern for '{name}'")
                return False

            # Create a vulnerability pattern
            pattern = VulnerabilityPattern(
                id=name,
                name=name,
                regex=regex_pattern,
                language="unknown",  # Legacy patterns don't have language
            )

            # Add the pattern
            self.add_pattern(pattern)
            return True

        except Exception as e:
            logger.error(f"Failed to compile regex pattern '{name}': {e}")
            return False

    def match_pattern(
        self, file_id: int, content: str, pattern_def: Dict[str, Any]
    ) -> List[Finding]:
        """Match a pattern against file content.

        Args:
            file_id: ID of the file in the database
            content: Content to match against
            pattern_def: Pattern definition dictionary

        Returns:
            List of findings
        """
        pattern_name = pattern_def.get("name", "Unknown Pattern")
        regex_pattern = pattern_def.get("regex_pattern", "")
        description = pattern_def.get("description", "")
        pattern_id = pattern_def.get("pattern_id")
        severity = pattern_def.get("severity", "Medium")

        # Create pattern if not exists
        if pattern_name not in self.patterns.get("unknown", {}):
            self.compile_pattern(pattern_name, regex_pattern)

        findings = []

        try:
            # Get pattern
            pattern = self.patterns.get("unknown", {}).get(pattern_name)
            if not pattern:
                return []

            # Apply the pattern
            match = pattern.match(content)
            if match:
                # Extract matching code
                match_text = match.group(0)

                # Get line number (approximate)
                line_number = content[: match.start()].count("\n") + 1

                # Create finding
                finding = Finding(
                    type="pattern_match",
                    vulnerability_type=pattern_name,
                    description=description,
                    line_number=line_number,
                    matched_text=match_text,
                    file_id=file_id,
                    severity=severity,
                    confidence=0.7,  # Pattern matches have moderate confidence
                    pattern_id=pattern_id,
                    pattern_name=pattern_name,
                )

                findings.append(finding)

        except Exception as e:
            logger.error(f"Error matching pattern '{pattern_name}': {e}")

        return findings

    def match_patterns(
        self, file_id: int, content: str, patterns: List[Dict[str, Any]]
    ) -> List[Finding]:
        """Match multiple patterns against file content.

        Args:
            file_id: ID of the file in the database
            content: Content to match against
            patterns: List of pattern definitions

        Returns:
            List of findings
        """
        findings = []

        for pattern in patterns:
            pattern_findings = self.match_pattern(file_id, content, pattern)
            findings.extend(pattern_findings)

        return findings
