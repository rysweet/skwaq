"""Unit tests for the pattern matcher module."""

import pytest
from unittest.mock import MagicMock, patch
import re

from skwaq.code_analysis.patterns.matcher import PatternMatcher, VulnerabilityPattern


class TestVulnerabilityPattern:
    """Tests for the VulnerabilityPattern class."""

    def test_initialization(self):
        """Test pattern initialization."""
        pattern = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        assert pattern.id == "TEST-1"
        assert pattern.name == "Test Pattern"
        assert pattern.regex == r"test\s+pattern"
        assert pattern.language == "python"
        assert pattern.severity == "medium"
        assert pattern.confidence == 0.7
        assert pattern.description == "Test vulnerability pattern"
        assert pattern.cwe_id == "CWE-1"
        assert pattern.remediation == "Fix test pattern"
        assert isinstance(pattern.compiled_regex, re.Pattern)

    def test_match(self):
        """Test pattern matching."""
        pattern = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        # Test matching code
        code = "This is a test pattern in the code"
        match = pattern.match(code)

        assert match is not None
        assert match.start() == 10
        assert match.end() == 22

        # Test non-matching code
        code = "This does not match"
        match = pattern.match(code)

        assert match is None

    def test_to_dict(self):
        """Test pattern serialization to dictionary."""
        pattern = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        pattern_dict = pattern.to_dict()

        assert pattern_dict["id"] == "TEST-1"
        assert pattern_dict["name"] == "Test Pattern"
        assert pattern_dict["regex"] == r"test\s+pattern"
        assert pattern_dict["language"] == "python"
        assert pattern_dict["severity"] == "medium"
        assert pattern_dict["confidence"] == 0.7
        assert pattern_dict["description"] == "Test vulnerability pattern"
        assert pattern_dict["cwe_id"] == "CWE-1"
        assert pattern_dict["remediation"] == "Fix test pattern"

        # compiled_regex should not be included
        assert "compiled_regex" not in pattern_dict

    def test_from_dict(self):
        """Test pattern creation from dictionary."""
        pattern_dict = {
            "id": "TEST-1",
            "name": "Test Pattern",
            "regex": r"test\s+pattern",
            "language": "python",
            "severity": "medium",
            "confidence": 0.7,
            "description": "Test vulnerability pattern",
            "cwe_id": "CWE-1",
            "remediation": "Fix test pattern",
        }

        pattern = VulnerabilityPattern.from_dict(pattern_dict)

        assert pattern.id == "TEST-1"
        assert pattern.name == "Test Pattern"
        assert pattern.regex == r"test\s+pattern"
        assert pattern.language == "python"
        assert pattern.severity == "medium"
        assert pattern.confidence == 0.7
        assert pattern.description == "Test vulnerability pattern"
        assert pattern.cwe_id == "CWE-1"
        assert pattern.remediation == "Fix test pattern"
        assert isinstance(pattern.compiled_regex, re.Pattern)


class TestPatternMatcher:
    """Tests for the PatternMatcher class."""

    def test_initialization(self):
        """Test pattern matcher initialization."""
        matcher = PatternMatcher()

        assert matcher.patterns == {}

    def test_add_pattern(self):
        """Test adding a pattern."""
        matcher = PatternMatcher()

        # Create a pattern
        pattern = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        # Add pattern
        matcher.add_pattern(pattern)

        # Verify pattern was added
        assert "python" in matcher.patterns
        assert pattern.id in matcher.patterns["python"]
        assert matcher.patterns["python"][pattern.id] == pattern

    def test_get_patterns_for_language(self):
        """Test getting patterns for a specific language."""
        matcher = PatternMatcher()

        # Create patterns for different languages
        pattern1 = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern 1",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        pattern2 = VulnerabilityPattern(
            id="TEST-2",
            name="Test Pattern 2",
            regex=r"another\s+pattern",
            language="python",
            severity="high",
            confidence=0.8,
            description="Another test pattern",
            cwe_id="CWE-2",
            remediation="Fix another pattern",
        )

        pattern3 = VulnerabilityPattern(
            id="TEST-3",
            name="Test Pattern 3",
            regex=r"javascript\s+pattern",
            language="javascript",
            severity="low",
            confidence=0.6,
            description="JavaScript pattern",
            cwe_id="CWE-3",
            remediation="Fix JavaScript pattern",
        )

        # Add patterns
        matcher.add_pattern(pattern1)
        matcher.add_pattern(pattern2)
        matcher.add_pattern(pattern3)

        # Get patterns for python
        python_patterns = matcher.get_patterns_for_language("python")

        assert len(python_patterns) == 2
        assert pattern1.id in python_patterns
        assert pattern2.id in python_patterns
        assert pattern3.id not in python_patterns

        # Get patterns for javascript
        javascript_patterns = matcher.get_patterns_for_language("javascript")

        assert len(javascript_patterns) == 1
        assert pattern3.id in javascript_patterns

        # Get patterns for non-existent language
        java_patterns = matcher.get_patterns_for_language("java")

        assert java_patterns == {}

    def test_match_code(self):
        """Test matching code against patterns."""
        matcher = PatternMatcher()

        # Create patterns
        pattern1 = VulnerabilityPattern(
            id="TEST-1",
            name="Test Pattern 1",
            regex=r"test\s+pattern",
            language="python",
            severity="medium",
            confidence=0.7,
            description="Test vulnerability pattern",
            cwe_id="CWE-1",
            remediation="Fix test pattern",
        )

        pattern2 = VulnerabilityPattern(
            id="TEST-2",
            name="Test Pattern 2",
            regex=r"another\s+pattern",
            language="python",
            severity="high",
            confidence=0.8,
            description="Another test pattern",
            cwe_id="CWE-2",
            remediation="Fix another pattern",
        )

        # Add patterns
        matcher.add_pattern(pattern1)
        matcher.add_pattern(pattern2)

        # Test code with both patterns
        code = "This is a test pattern and another pattern in the code"
        matches = matcher.match_code(code, "python")

        assert len(matches) == 2

        # Check first match
        assert matches[0]["pattern_id"] == "TEST-1"
        assert matches[0]["start"] == 10
        assert matches[0]["end"] == 22
        assert matches[0]["matched_text"] == "test pattern"

        # Check second match
        assert matches[1]["pattern_id"] == "TEST-2"
        assert matches[1]["start"] == 27
        assert matches[1]["end"] == 42
        assert matches[1]["matched_text"] == "another pattern"

        # Test code with no matches
        code = "This code has no patterns"
        matches = matcher.match_code(code, "python")

        assert len(matches) == 0

        # Test code with non-existent language
        matches = matcher.match_code(code, "java")

        assert len(matches) == 0
