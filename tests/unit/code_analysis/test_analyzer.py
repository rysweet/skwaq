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

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    def test_initialization(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test CodeAnalyzer initialization."""
        # Setup mocks
        mock_config = MagicMock()
        mock_get_config.return_value = mock_config
        
        mock_openai_client = MagicMock()
        mock_get_openai_client.return_value = mock_openai_client
        
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        
        # Verify initialization
        assert analyzer.connector == mock_connector
        assert analyzer.openai_client == mock_openai_client
        assert analyzer.config == mock_config
        assert analyzer.strategies == {}
        assert analyzer.language_analyzers == {}
        
        # Verify default strategies are registered
        assert len(analyzer.strategies) >= 3  # At least pattern, semantic, AST
        
        # Verify default language analyzers are registered
        assert len(analyzer.language_analyzers) >= 2  # At least Python and JavaScript

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    def test_register_language_analyzer(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test registering a language analyzer."""
        # Setup mocks
        mock_get_config.return_value = MagicMock()
        mock_get_openai_client.return_value = MagicMock()
        mock_get_connector.return_value = MagicMock()
        
        # Create mock language analyzer
        mock_language_analyzer = MagicMock()
        mock_language_analyzer.get_language.return_value = "test_language"
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        
        # Clear existing language analyzers
        analyzer.language_analyzers = {}
        
        # Register language analyzer
        analyzer.register_language_analyzer(mock_language_analyzer)
        
        # Verify language analyzer was registered
        assert "test_language" in analyzer.language_analyzers
        assert analyzer.language_analyzers["test_language"] == mock_language_analyzer

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    def test_register_strategy(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test registering an analysis strategy."""
        # Setup mocks
        mock_get_config.return_value = MagicMock()
        mock_get_openai_client.return_value = MagicMock()
        mock_get_connector.return_value = MagicMock()
        
        # Create mock strategy
        mock_strategy = MagicMock()
        mock_strategy.get_name.return_value = "test_strategy"
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        
        # Clear existing strategies
        analyzer.strategies = {}
        
        # Register strategy
        analyzer.register_strategy(mock_strategy)
        
        # Verify strategy was registered
        assert "test_strategy" in analyzer.strategies
        assert analyzer.strategies["test_strategy"] == mock_strategy

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    @pytest.mark.asyncio
    async def test_analyze_code(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test analyzing code with multiple strategies."""
        # Setup mocks
        mock_get_config.return_value = MagicMock()
        mock_get_openai_client.return_value = MagicMock()
        mock_get_connector.return_value = MagicMock()
        
        # Create mock strategies
        mock_strategy1 = MagicMock()
        mock_strategy1.get_name.return_value = "strategy1"
        mock_strategy1.analyze = AsyncMock(return_value=[
            Finding(
                id="finding1",
                vulnerability_type="Test vulnerability 1",
                severity="high",
                confidence=0.9,
                file_path="test.py",
                line_number=10,
                code_snippet="test code 1",
                description="Test finding 1",
                cwe_id="CWE-1",
                remediation="Fix test 1",
            )
        ])
        
        mock_strategy2 = MagicMock()
        mock_strategy2.get_name.return_value = "strategy2"
        mock_strategy2.analyze = AsyncMock(return_value=[
            Finding(
                id="finding2",
                vulnerability_type="Test vulnerability 2",
                severity="medium",
                confidence=0.7,
                file_path="test.py",
                line_number=20,
                code_snippet="test code 2",
                description="Test finding 2",
                cwe_id="CWE-2",
                remediation="Fix test 2",
            )
        ])
        
        # Create mock language analyzer
        mock_language_analyzer = MagicMock()
        mock_language_analyzer.parse_code = AsyncMock(return_value="parsed_code")
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        
        # Replace strategies and language analyzers
        analyzer.strategies = {
            "strategy1": mock_strategy1,
            "strategy2": mock_strategy2,
        }
        analyzer.language_analyzers = {
            "python": mock_language_analyzer,
        }
        
        # Test code to analyze
        code = "def test(): pass"
        
        # Analyze code
        result = await analyzer.analyze_code(
            code=code,
            file_path="test.py",
            repository_id="repo123",
            language="python",
            strategy_names=["strategy1", "strategy2"],
        )
        
        # Verify language analyzer was called
        mock_language_analyzer.parse_code.assert_called_once_with(code)
        
        # Verify strategies were called
        mock_strategy1.analyze.assert_called_once()
        mock_strategy2.analyze.assert_called_once()
        
        # Verify result
        assert isinstance(result, AnalysisResult)
        assert len(result.findings) == 2
        assert result.findings[0].id == "finding1"
        assert result.findings[1].id == "finding2"
        assert result.repository_id == "repo123"
        assert result.file_path == "test.py"

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    @pytest.mark.asyncio
    async def test_analyze_file(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test analyzing a file."""
        # Setup mocks
        mock_get_config.return_value = MagicMock()
        mock_get_openai_client.return_value = MagicMock()
        mock_get_connector.return_value = MagicMock()
        
        # Mock file reading
        file_content = "def test(): pass"
        mock_open = MagicMock()
        mock_open.return_value.__enter__.return_value.read.return_value = file_content
        
        # Mock analyze_code
        mock_analyze_code = AsyncMock()
        mock_analyze_code.return_value = AnalysisResult(
            repository_id="repo123",
            file_path="test.py",
            findings=[
                Finding(
                    id="finding1",
                    vulnerability_type="Test vulnerability",
                    severity="high",
                    confidence=0.9,
                    file_path="test.py",
                    line_number=10,
                    code_snippet="test code",
                    description="Test finding",
                    cwe_id="CWE-1",
                    remediation="Fix test",
                )
            ],
        )
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        analyzer.analyze_code = mock_analyze_code
        
        # Test file analyzing
        with patch("builtins.open", mock_open):
            result = await analyzer.analyze_file(
                file_path="test.py",
                repository_id="repo123",
                strategy_names=["pattern_matching", "semantic_analysis"],
            )
        
        # Verify analyze_code was called with correct parameters
        mock_analyze_code.assert_called_once_with(
            code=file_content,
            file_path="test.py",
            repository_id="repo123",
            language="python",
            strategy_names=["pattern_matching", "semantic_analysis"],
        )
        
        # Verify result
        assert isinstance(result, AnalysisResult)
        assert len(result.findings) == 1
        assert result.findings[0].id == "finding1"

    @patch("skwaq.code_analysis.analyzer.get_connector")
    @patch("skwaq.code_analysis.analyzer.get_openai_client")
    @patch("skwaq.code_analysis.analyzer.get_config")
    def test_detect_language(self, mock_get_config, mock_get_openai_client, mock_get_connector):
        """Test language detection from file path."""
        # Setup mocks
        mock_get_config.return_value = MagicMock()
        mock_get_openai_client.return_value = MagicMock()
        mock_get_connector.return_value = MagicMock()
        
        # Initialize analyzer
        analyzer = CodeAnalyzer()
        
        # Test language detection
        assert analyzer.detect_language("test.py") == "python"
        assert analyzer.detect_language("test.js") == "javascript"
        assert analyzer.detect_language("test.java") == "java"
        assert analyzer.detect_language("test.cs") == "csharp"
        assert analyzer.detect_language("test.php") == "php"
        
        # Test unknown extension
        assert analyzer.detect_language("test.unknown") is None