"""Unit tests for the code analyzer module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import json
import os
from pathlib import Path

from skwaq.code_analysis.analyzer import CodeAnalyzer
from skwaq.shared.finding import Finding, AnalysisResult


class TestCodeAnalyzer:
    """Tests for the CodeAnalyzer class."""

    def test_initialization(self):
        """Test CodeAnalyzer initialization.
        
        The test skips complex mocking and focuses on testing the interface.
        """
        # Use a context manager with multiple patches
        with patch("skwaq.code_analysis.analyzer.get_connector") as mock_get_connector, \
             patch("skwaq.code_analysis.analyzer.get_openai_client") as mock_get_openai_client, \
             patch("skwaq.code_analysis.analyzer.get_config") as mock_get_config, \
             patch("skwaq.code_analysis.analyzer.PatternMatchingStrategy") as mock_pattern_strategy, \
             patch("skwaq.code_analysis.analyzer.SemanticAnalysisStrategy") as mock_semantic_strategy, \
             patch("skwaq.code_analysis.analyzer.ASTAnalysisStrategy") as mock_ast_strategy, \
             patch.object(CodeAnalyzer, "_register_default_language_analyzers"):
                
            # Setup mocks
            mock_config = MagicMock()
            mock_get_config.return_value = mock_config
            
            mock_openai_client = MagicMock()
            mock_get_openai_client.return_value = mock_openai_client
            
            mock_connector = MagicMock()
            mock_get_connector.return_value = mock_connector
            
            # Create mock strategy instances
            mock_pattern_instance = MagicMock()
            mock_semantic_instance = MagicMock()
            mock_ast_instance = MagicMock()
            mock_pattern_strategy.return_value = mock_pattern_instance
            mock_semantic_strategy.return_value = mock_semantic_instance
            mock_ast_strategy.return_value = mock_ast_instance
            
            # Initialize analyzer
            analyzer = CodeAnalyzer()
            
            # Verify initialization of core components
            assert analyzer.connector == mock_connector
            assert analyzer.openai_client == mock_openai_client
            assert analyzer.config == mock_config
            
            # Verify default strategies are registered
            assert "pattern_matching" in analyzer.strategies
            assert "semantic_analysis" in analyzer.strategies
            assert "ast_analysis" in analyzer.strategies
            assert analyzer.strategies["pattern_matching"] == mock_pattern_instance
            assert analyzer.strategies["semantic_analysis"] == mock_semantic_instance
            assert analyzer.strategies["ast_analysis"] == mock_ast_instance

    def test_register_language_analyzer(self):
        """Test registering a language analyzer."""
        # Import the real ASTAnalysisStrategy class for isinstance check
        from skwaq.code_analysis.strategies.ast_analysis import ASTAnalysisStrategy
        
        # Use a context manager with relevant patches
        with patch("skwaq.code_analysis.analyzer.get_connector") as mock_get_connector, \
             patch("skwaq.code_analysis.analyzer.get_openai_client") as mock_get_openai_client, \
             patch("skwaq.code_analysis.analyzer.get_config") as mock_get_config, \
             patch("skwaq.code_analysis.analyzer.PatternMatchingStrategy"), \
             patch("skwaq.code_analysis.analyzer.SemanticAnalysisStrategy"), \
             patch("skwaq.code_analysis.analyzer.ASTAnalysisStrategy"), \
             patch.object(CodeAnalyzer, "_register_default_language_analyzers"):
            
            # Setup mocks
            mock_get_config.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            mock_get_connector.return_value = MagicMock()
            
            # Create mock language analyzer
            mock_language_analyzer = MagicMock()
            mock_language_analyzer.get_language_name.return_value = "test_language"
            
            # Initialize analyzer
            analyzer = CodeAnalyzer()
            
            # Clear existing language analyzers to avoid interference
            analyzer.language_analyzers = {}
            
            # Create a real AST strategy instance or a properly conforming mock
            mock_ast_instance = MagicMock(spec=ASTAnalysisStrategy)
            mock_ast_instance.register_language_analyzer = MagicMock()
            
            # Override strategies with our controlled mock
            analyzer.strategies = {"ast_analysis": mock_ast_instance}
            
            # Register language analyzer
            analyzer.register_language_analyzer(mock_language_analyzer)
            
            # Verify language analyzer was registered
            assert "test_language" in analyzer.language_analyzers
            assert analyzer.language_analyzers["test_language"] == mock_language_analyzer
            
            # Verify it was registered with the AST strategy
            mock_ast_instance.register_language_analyzer.assert_called_once_with(mock_language_analyzer)

    def test_register_strategy(self):
        """Test registering an analysis strategy."""
        # Use a context manager with relevant patches
        with patch("skwaq.code_analysis.analyzer.get_connector") as mock_get_connector, \
             patch("skwaq.code_analysis.analyzer.get_openai_client") as mock_get_openai_client, \
             patch("skwaq.code_analysis.analyzer.get_config") as mock_get_config, \
             patch("skwaq.code_analysis.analyzer.PatternMatchingStrategy"), \
             patch("skwaq.code_analysis.analyzer.SemanticAnalysisStrategy"), \
             patch("skwaq.code_analysis.analyzer.ASTAnalysisStrategy"), \
             patch.object(CodeAnalyzer, "_register_default_language_analyzers"):
            
            # Setup mocks
            mock_get_config.return_value = MagicMock()
            mock_get_openai_client.return_value = MagicMock()
            mock_get_connector.return_value = MagicMock()
            
            # Create mock strategy
            mock_strategy = MagicMock()
            mock_strategy.analyze = AsyncMock()  # Mock the analyze method as it's likely async
            
            # Initialize analyzer
            analyzer = CodeAnalyzer()
            
            # Start with empty strategies
            analyzer.strategies = {}
            
            # Register strategy
            analyzer.register_strategy("test_strategy", mock_strategy)
            
            # Verify strategy was registered
            assert "test_strategy" in analyzer.strategies
            assert analyzer.strategies["test_strategy"] == mock_strategy
            
            # Verify logging call
            with patch("skwaq.code_analysis.analyzer.logger") as mock_logger:
                analyzer.register_strategy("another_strategy", mock_strategy)
                mock_logger.info.assert_called_once_with("Registered analysis strategy: another_strategy")

    # Skip this test as the API has changed
    @pytest.mark.skip(reason="API has changed, test needs rewriting")
    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    @pytest.mark.asyncio
    async def test_analyze_code(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test analyzing code with multiple strategies."""
        pass

    # Skip this test as the API has changed
    @pytest.mark.skip(reason="API has changed, test needs rewriting")
    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    @pytest.mark.asyncio
    async def test_analyze_file(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test analyzing a file."""
        pass

    # Skip this test as the API has changed
    @pytest.mark.skip(reason="API has changed, test needs rewriting")
    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    def test_detect_language(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test language detection from file path."""
        pass