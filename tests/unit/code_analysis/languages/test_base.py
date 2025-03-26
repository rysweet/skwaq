"""Unit tests for the base language analyzer module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch

from skwaq.code_analysis.languages.base import LanguageAnalyzer


class ConcreteLanguageAnalyzer(LanguageAnalyzer):
    """Concrete implementation of abstract LanguageAnalyzer for testing."""
    
    def __init__(self):
        """Initialize the concrete analyzer."""
        super().__init__(language="test_language")
        
    async def parse_code(self, code: str):
        """Implement abstract parse_code method."""
        return {"type": "parsed_code", "language": self.language, "ast": {"root": "node"}}


class TestLanguageAnalyzer:
    """Tests for the LanguageAnalyzer base class."""

    def test_initialization(self):
        """Test language analyzer initialization."""
        analyzer = ConcreteLanguageAnalyzer()
        
        assert analyzer.language == "test_language"

    def test_get_language(self):
        """Test get_language method."""
        analyzer = ConcreteLanguageAnalyzer()
        
        assert analyzer.get_language() == "test_language"

    @pytest.mark.asyncio
    async def test_parse_code(self):
        """Test parse_code method in concrete implementation."""
        analyzer = ConcreteLanguageAnalyzer()
        
        result = await analyzer.parse_code("def test(): pass")
        
        assert result["type"] == "parsed_code"
        assert result["language"] == "test_language"
        assert "ast" in result
        assert result["ast"]["root"] == "node"