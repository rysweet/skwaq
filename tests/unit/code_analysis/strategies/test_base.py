"""Unit tests for the base analysis strategy module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from skwaq.code_analysis.strategies.base import AnalysisStrategy
from skwaq.shared.finding import Finding


class ConcreteStrategy(AnalysisStrategy):
    """Concrete implementation of abstract AnalysisStrategy for testing."""

    def __init__(self):
        """Initialize the concrete strategy."""
        super().__init__()
        self.name = "test_strategy"

    def get_name(self):
        """Get the name of the strategy."""
        return self.name

    async def analyze(self, file_id, content, language, options=None):
        """Implement abstract analyze method."""
        finding = Finding(
            type="test",
            vulnerability_type="Test vulnerability",
            severity="medium",
            confidence=0.8,
            file_id=file_id,
            line_number=10,
            description="Test description",
            matched_text=content[:20] if content else "",
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
            file_id=123,
            content="def test(): pass",
            language="python",
        )

        assert len(findings) == 1
        assert findings[0].vulnerability_type == "Test vulnerability"
        assert findings[0].severity == "medium"
        assert findings[0].confidence == 0.8
        assert findings[0].line_number == 10
        assert findings[0].description == "Test description"
        assert findings[0].type == "test"
