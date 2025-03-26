"""Pytest fixtures specific to code analysis tests."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
from dataclasses import dataclass
from typing import Dict, List, Optional, Any


@pytest.fixture
def mock_strategy():
    """Mock analysis strategy."""
    strategy = MagicMock()
    strategy.analyze = AsyncMock(return_value=[])
    strategy.get_name.return_value = "mock_strategy"
    return strategy


@pytest.fixture
def mock_language_analyzer():
    """Mock language analyzer."""
    analyzer = MagicMock()
    analyzer.get_language_name.return_value = "MockLanguage"
    analyzer.parse_code.return_value = {"ast": {}, "tokens": []}
    return analyzer


@pytest.fixture
def isolated_code_analyzer(mock_connector, mock_openai_client, mock_config, monkeypatch):
    """Create an isolated CodeAnalyzer instance for testing.
    
    This fixture creates a completely isolated CodeAnalyzer instance with proper mocks
    to ensure that it doesn't affect other tests.
    """
    from skwaq.code_analysis.analyzer import CodeAnalyzer
    from skwaq.code_analysis.strategies.pattern_matching import PatternMatchingStrategy
    from skwaq.code_analysis.strategies.semantic_analysis import SemanticAnalysisStrategy
    from skwaq.code_analysis.strategies.ast_analysis import ASTAnalysisStrategy
    
    # Create mock strategies
    mock_pattern_strategy = MagicMock()
    mock_pattern_strategy.analyze = AsyncMock(return_value=[])
    
    mock_semantic_strategy = MagicMock()
    mock_semantic_strategy.analyze = AsyncMock(return_value=[])
    
    mock_ast_strategy = MagicMock()
    mock_ast_strategy.analyze = AsyncMock(return_value=[])
    
    # Patch strategy classes to return our mocks
    with (
        patch("skwaq.code_analysis.analyzer.get_connector", return_value=mock_connector),
        patch("skwaq.code_analysis.analyzer.get_openai_client", return_value=mock_openai_client),
        patch("skwaq.code_analysis.analyzer.get_config", return_value=mock_config),
        patch("skwaq.code_analysis.analyzer.PatternMatchingStrategy", return_value=mock_pattern_strategy),
        patch("skwaq.code_analysis.analyzer.SemanticAnalysisStrategy", return_value=mock_semantic_strategy),
        patch("skwaq.code_analysis.analyzer.ASTAnalysisStrategy", return_value=mock_ast_strategy),
        patch.object(CodeAnalyzer, "_register_default_language_analyzers"),
    ):
        # Create analyzer instance
        analyzer = CodeAnalyzer()
        
        # Set up strategies
        analyzer.strategies = {
            "pattern_matching": mock_pattern_strategy,
            "semantic_analysis": mock_semantic_strategy,
            "ast_analysis": mock_ast_strategy,
        }
        
        # Initialize language analyzers dictionary
        analyzer.language_analyzers = {}
        
        yield analyzer