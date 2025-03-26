"""Unit tests for the finding module."""

import pytest
import json
import time
from datetime import datetime
from unittest.mock import patch

from skwaq.shared.finding import Finding, AnalysisResult


class TestFinding:
    """Tests for the Finding class."""

    def test_initialization(self):
        """Test finding initialization."""
        finding = Finding(
            type="pattern_match",
            vulnerability_type="SQL Injection",
            description="Possible SQL injection vulnerability",
            file_id=123,
            line_number=42,
            severity="high",
            confidence=0.9,
            matched_text="query = 'SELECT * FROM users WHERE id = ' + user_input",
            pattern_id=89,
            pattern_name="SQL Injection",
            suggestion="Use parameterized queries",
        )

        assert finding.type == "pattern_match"
        assert finding.vulnerability_type == "SQL Injection"
        assert finding.description == "Possible SQL injection vulnerability"
        assert finding.file_id == 123
        assert finding.line_number == 42
        assert finding.severity == "high"
        assert finding.confidence == 0.9
        assert (
            finding.matched_text
            == "query = 'SELECT * FROM users WHERE id = ' + user_input"
        )
        assert finding.pattern_id == 89
        assert finding.pattern_name == "SQL Injection"
        assert finding.suggestion == "Use parameterized queries"
        assert isinstance(finding.metadata, dict)

    def test_default_values(self):
        """Test default values when not provided."""
        finding = Finding(
            type="semantic_analysis",
            vulnerability_type="XSS",
            description="Possible XSS vulnerability",
            file_id=456,
            line_number=53,
        )

        assert finding.severity == "Medium"
        assert finding.confidence == 0.5
        assert finding.matched_text is None
        assert finding.pattern_id is None
        assert finding.pattern_name is None
        assert finding.suggestion is None
        assert finding.metadata == {}

    def test_to_dict(self):
        """Test conversion to dictionary."""
        finding = Finding(
            type="pattern_match",
            vulnerability_type="SQL Injection",
            description="Possible SQL injection vulnerability",
            file_id=123,
            line_number=42,
            severity="high",
            confidence=0.9,
            matched_text="query = 'SELECT * FROM users WHERE id = ' + user_input",
            pattern_id=89,
            pattern_name="SQL Injection",
            suggestion="Use parameterized queries",
        )

        finding_dict = finding.to_dict()

        assert finding_dict["type"] == "pattern_match"
        assert finding_dict["vulnerability_type"] == "SQL Injection"
        assert finding_dict["description"] == "Possible SQL injection vulnerability"
        assert finding_dict["line_number"] == 42
        assert finding_dict["severity"] == "high"
        assert finding_dict["confidence"] == 0.9
        assert (
            finding_dict["matched_text"]
            == "query = 'SELECT * FROM users WHERE id = ' + user_input"
        )
        assert finding_dict["pattern_id"] == 89
        assert finding_dict["pattern_name"] == "SQL Injection"
        assert finding_dict["suggestion"] == "Use parameterized queries"


class TestAnalysisResult:
    """Tests for the AnalysisResult class."""

    def test_initialization(self):
        """Test analysis result initialization."""
        findings = [
            Finding(
                type="pattern_match",
                vulnerability_type="SQL Injection",
                description="Possible SQL injection vulnerability",
                file_id=123,
                line_number=42,
                severity="high",
                confidence=0.9,
            ),
            Finding(
                type="semantic_analysis",
                vulnerability_type="XSS",
                description="Possible XSS vulnerability",
                file_id=123,
                line_number=53,
                severity="medium",
                confidence=0.8,
            ),
        ]

        result = AnalysisResult(
            file_id=123,
            findings=findings,
        )

        assert result.file_id == 123
        assert len(result.findings) == 2
        assert result.findings[0].vulnerability_type == "SQL Injection"
        assert result.findings[1].vulnerability_type == "XSS"
        assert isinstance(result.metadata, dict)

    def test_empty_findings(self):
        """Test initialization with empty findings list."""
        result = AnalysisResult(
            file_id=123,
        )

        assert result.file_id == 123
        assert len(result.findings) == 0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        findings = [
            Finding(
                type="pattern_match",
                vulnerability_type="SQL Injection",
                description="Possible SQL injection vulnerability",
                file_id=123,
                line_number=42,
                severity="high",
                confidence=0.9,
            ),
        ]

        result = AnalysisResult(
            file_id=123,
            findings=findings,
        )

        result_dict = result.to_dict()

        assert result_dict["file_id"] == 123
        assert len(result_dict["findings"]) == 1
        assert result_dict["findings"][0]["vulnerability_type"] == "SQL Injection"
        assert "vulnerabilities_found" in result_dict
        assert "patterns_matched" in result_dict
        assert "metadata" in result_dict

    def test_add_finding(self):
        """Test adding a finding to the results."""
        result = AnalysisResult(file_id=123)
        finding = Finding(
            type="pattern_match",
            vulnerability_type="SQL Injection",
            description="Possible SQL injection vulnerability",
            file_id=123,
            line_number=42,
        )

        # Initially empty
        assert len(result.findings) == 0

        # Add finding
        result.add_finding(finding)

        # Check finding was added
        assert len(result.findings) == 1
        assert result.findings[0].vulnerability_type == "SQL Injection"

    def test_add_findings(self):
        """Test adding multiple findings to the results."""
        result = AnalysisResult(file_id=123)
        findings = [
            Finding(
                type="pattern_match",
                vulnerability_type="SQL Injection",
                description="Possible SQL injection vulnerability",
                file_id=123,
                line_number=42,
            ),
            Finding(
                type="semantic_analysis",
                vulnerability_type="XSS",
                description="Possible XSS vulnerability",
                file_id=123,
                line_number=53,
            ),
        ]

        # Initially empty
        assert len(result.findings) == 0

        # Add findings
        result.add_findings(findings)

        # Check findings were added
        assert len(result.findings) == 2
        assert result.findings[0].vulnerability_type == "SQL Injection"
        assert result.findings[1].vulnerability_type == "XSS"

    def test_vulnerabilities_found(self):
        """Test vulnerabilities_found property."""
        result = AnalysisResult(file_id=123)
        findings = [
            Finding(
                type="pattern_match",  # Not counted as vulnerability
                vulnerability_type="SQL Injection",
                description="Possible SQL injection vulnerability",
                file_id=123,
                line_number=42,
            ),
            Finding(
                type="semantic_analysis",  # Counted as vulnerability
                vulnerability_type="XSS",
                description="Possible XSS vulnerability",
                file_id=123,
                line_number=53,
            ),
            Finding(
                type="ast_analysis",  # Counted as vulnerability
                vulnerability_type="Command Injection",
                description="Possible command injection vulnerability",
                file_id=123,
                line_number=65,
            ),
        ]

        result.add_findings(findings)
        assert result.vulnerabilities_found == 2

    def test_patterns_matched(self):
        """Test patterns_matched property."""
        result = AnalysisResult(file_id=123)
        findings = [
            Finding(
                type="pattern_match",  # Counted as pattern match
                vulnerability_type="SQL Injection",
                description="Possible SQL injection vulnerability",
                file_id=123,
                line_number=42,
            ),
            Finding(
                type="semantic_analysis",  # Not counted as pattern match
                vulnerability_type="XSS",
                description="Possible XSS vulnerability",
                file_id=123,
                line_number=53,
            ),
            Finding(
                type="pattern_match",  # Counted as pattern match
                vulnerability_type="Command Injection",
                description="Possible command injection vulnerability",
                file_id=123,
                line_number=65,
            ),
        ]

        result.add_findings(findings)
        assert result.patterns_matched == 2
