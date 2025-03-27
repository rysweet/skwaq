"""Unit tests for the AST analysis strategy."""

import pytest
from unittest.mock import patch, MagicMock, AsyncMock

from skwaq.code_analysis.strategies.ast_analysis import ASTAnalysisStrategy
from skwaq.shared.finding import Finding


class TestASTAnalysisStrategy:
    """Tests for the ASTAnalysisStrategy class."""
    
    def test_initialization(self):
        """Test strategy initialization."""
        # Create strategy
        strategy = ASTAnalysisStrategy()
        
        # Verify initial state
        assert strategy.language_analyzers == {}
        assert hasattr(strategy, "blarify_integration")
    
    def test_register_language_analyzer(self):
        """Test registering a language analyzer."""
        # Create strategy
        strategy = ASTAnalysisStrategy()
        
        # Create mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer.get_language_name.return_value = "Python"
        
        # Register analyzer
        strategy.register_language_analyzer(mock_analyzer)
        
        # Verify registration
        assert "Python" in strategy.language_analyzers
        assert strategy.language_analyzers["Python"] is mock_analyzer
    
    def test_normalize_language(self):
        """Test language normalization."""
        # Create strategy
        strategy = ASTAnalysisStrategy()
        
        # Test various language normalizations
        assert strategy._normalize_language("Python") == "Python"
        assert strategy._normalize_language("python") == "Python"
        assert strategy._normalize_language("JavaScript") == "JavaScript"
        assert strategy._normalize_language("javascript") == "JavaScript"
        assert strategy._normalize_language("TypeScript") == "JavaScript"
        assert strategy._normalize_language("C#") == "C#"
        assert strategy._normalize_language("Java") == "Java"