"""Unit tests for the base analysis strategy module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from skwaq.code_analysis.strategies.base import AnalysisStrategy
from skwaq.shared.finding import Finding


class ConcreteStrategy(AnalysisStrategy):
    """Concrete implementation of abstract AnalysisStrategy for testing."""
    
    def __init__(self):
        """Initialize the concrete strategy."""
        super().__init__(name="test_strategy")
        
    async def analyze(self, code, parsed_code, file_path, repository_id, language):
        """Implement abstract analyze method."""
        finding = Finding(
            id="test_finding",
            vulnerability_type="Test vulnerability",
            severity="medium",
            confidence=0.8,
            file_path=file_path,
            line_number=10,
            code_snippet="test code",
            description="Test description",
            cwe_id="CWE-1",
            remediation="Test remediation",
        )
        return [finding]


class TestAnalysisStrategy:
    """Tests for the AnalysisStrategy base class."""

    def test_initialization(self):
        """Test analysis strategy initialization."""
        strategy = ConcreteStrategy()
        
        assert strategy.name == "test_strategy"

    def test_get_name(self):
        """Test get_name method."""
        strategy = ConcreteStrategy()
        
        assert strategy.get_name() == "test_strategy"

    @pytest.mark.asyncio
    async def test_analyze(self):
        """Test analyze method in concrete implementation."""
        strategy = ConcreteStrategy()
        
        findings = await strategy.analyze(
            code="def test(): pass",
            parsed_code={"ast": "test"},
            file_path="test.py",
            repository_id="repo123",
            language="python",
        )
        
        assert len(findings) == 1
        assert findings[0].id == "test_finding"
        assert findings[0].vulnerability_type == "Test vulnerability"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == 0.8
        assert findings[0].file_path == "test.py"
        assert findings[0].line_number == 10
        assert findings[0].code_snippet == "test code"
        assert findings[0].description == "Test description"
        assert findings[0].cwe_id == "CWE-1"
        assert findings[0].remediation == "Test remediation"