"""Unit tests for the CLI main module."""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import argparse
import sys
from io import StringIO

from skwaq.cli.main import (
    create_parser,
    handle_analyze_command,
    handle_repository_command,
)


class TestCLIParser:
    """Tests for the CLI argument parser."""

    def test_create_parser(self):
        """Test parser creation."""
        parser = create_parser()
        
        assert isinstance(parser, argparse.ArgumentParser)
        
        # Get all subparsers
        subparsers = next(action for action in parser._actions if isinstance(action, argparse._SubParsersAction))
        
        # Check that we have the expected commands
        assert "analyze" in subparsers.choices
        assert "repo" in subparsers.choices
        assert "knowledge" in subparsers.choices

    def test_analyze_command(self):
        """Test analyze command parser."""
        parser = create_parser()
        
        # Parse analyze command arguments
        args = parser.parse_args(["analyze", "--file", "test.py"])
        
        assert args.command == "analyze"
        assert args.file == "test.py"
        
        # Test with additional options
        args = parser.parse_args([
            "analyze", 
            "--file", "test.py",
            "--strategy", "pattern_matching",
            "--output", "json",
        ])
        
        assert args.command == "analyze"
        assert args.file == "test.py"
        assert args.strategy == ["pattern_matching"]
        assert args.output == "json"

    def test_repository_command(self):
        """Test repository command parser."""
        parser = create_parser()
        
        # Parse repo list command arguments
        args = parser.parse_args(["repo", "list"])
        
        assert args.command == "repo"
        assert args.repo_command == "list"
        
        # Parse repo add command arguments
        args = parser.parse_args([
            "repo", 
            "add",
            "--path", "/path/to/repo",
            "--name", "test-repo",
        ])
        
        assert args.command == "repo"
        assert args.repo_command == "add"
        assert args.path == "/path/to/repo"
        assert args.name == "test-repo"
        
        # Parse repo github command arguments
        args = parser.parse_args([
            "repo", 
            "github",
            "--url", "https://github.com/user/test-repo",
        ])
        
        assert args.command == "repo"
        assert args.repo_command == "github"
        assert args.url == "https://github.com/user/test-repo"


class TestCommandHandlers:
    """Tests for command handlers."""

    @pytest.mark.asyncio
    @patch("skwaq.cli.main.get_connector")
    @patch("skwaq.cli.main.CodeAnalyzer")
    async def test_handle_analyze_command(self, mock_analyzer_cls, mock_get_connector):
        """Test analyze command handler."""
        # Setup mocks
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        mock_analyzer = MagicMock()
        mock_analyzer.analyze_file = AsyncMock()
        mock_analyzer.analyze_file.return_value = MagicMock(
            findings=[
                MagicMock(
                    id="finding-1",
                    vulnerability_type="SQL Injection",
                    severity="high",
                    confidence=0.9,
                    file_path="test.py",
                    line_number=42,
                    description="Test vulnerability",
                )
            ]
        )
        mock_analyzer_cls.return_value = mock_analyzer
        
        # Create args
        args = MagicMock()
        args.file = "test.py"
        args.strategy = ["pattern_matching"]
        args.output = "text"
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Run the handler
        await handle_analyze_command(args)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Verify analyzer was called
        mock_analyzer.analyze_file.assert_called_once_with(
            file_path="test.py",
            repository_id=None,
            strategy_names=["pattern_matching"],
        )
        
        # Verify output contains expected content
        output = captured_output.getvalue()
        assert "Analyzing file: test.py" in output
        assert "SQL Injection" in output
        assert "high" in output
        assert "test.py:42" in output

    @pytest.mark.asyncio
    @patch("skwaq.cli.main.get_connector")
    @patch("skwaq.cli.main.ingest_repository")
    @patch("skwaq.cli.main.list_repositories")
    async def test_handle_repository_command_list(self, mock_list_repos, mock_ingest_repo, mock_get_connector):
        """Test repository list command handler."""
        # Setup mocks
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        mock_list_repos.return_value = [
            {
                "id": 1,
                "name": "repo1",
                "path": "/path/to/repo1",
                "url": "https://github.com/user/repo1",
                "ingested_at": "2023-01-01T00:00:00",
                "files": 10,
                "code_files": 7,
            },
            {
                "id": 2,
                "name": "repo2",
                "path": "/path/to/repo2",
                "url": None,
                "ingested_at": "2023-01-02T00:00:00",
                "files": 20,
                "code_files": 15,
            },
        ]
        
        # Create args
        args = MagicMock()
        args.repo_command = "list"
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Run the handler
        await handle_repository_command(args)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Verify list_repositories was called
        mock_list_repos.assert_called_once()
        
        # Verify output contains expected content
        output = captured_output.getvalue()
        assert "repo1" in output
        assert "repo2" in output
        assert "/path/to/repo1" in output
        assert "/path/to/repo2" in output
        assert "https://github.com/user/repo1" in output

    @pytest.mark.asyncio
    @patch("skwaq.cli.main.get_connector")
    @patch("skwaq.cli.main.ingest_repository")
    async def test_handle_repository_command_add(self, mock_ingest_repo, mock_get_connector):
        """Test repository add command handler."""
        # Setup mocks
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        mock_ingest_repo.return_value = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "file_count": 10,
            "directory_count": 5,
            "code_files_processed": 7,
            "summary": "Test repository summary",
        }
        
        # Create args
        args = MagicMock()
        args.repo_command = "add"
        args.path = "/path/to/repo"
        args.name = "test-repo"
        args.include = ["*.py"]
        args.exclude = ["*test*"]
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Run the handler
        await handle_repository_command(args)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Verify ingest_repository was called with correct arguments
        mock_ingest_repo.assert_called_once_with(
            repo_path_or_url="/path/to/repo",
            is_github_url=False,
            include_patterns=["*.py"],
            exclude_patterns=["*test*"],
            github_token=None,
            branch=None,
            show_progress=True,
        )
        
        # Verify output contains expected content
        output = captured_output.getvalue()
        assert "Successfully ingested repository" in output
        assert "test-repo" in output
        assert "7 code files" in output

    @pytest.mark.asyncio
    @patch("skwaq.cli.main.get_connector")
    @patch("skwaq.cli.main.ingest_repository")
    async def test_handle_repository_command_github(self, mock_ingest_repo, mock_get_connector):
        """Test repository github command handler."""
        # Setup mocks
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        mock_ingest_repo.return_value = {
            "repository_id": 1,
            "repository_name": "test-repo",
            "file_count": 10,
            "directory_count": 5,
            "code_files_processed": 7,
            "summary": "Test repository summary",
            "github_url": "https://github.com/user/test-repo",
            "branch": "main",
        }
        
        # Create args
        args = MagicMock()
        args.repo_command = "github"
        args.url = "https://github.com/user/test-repo"
        args.token = "github_token"
        args.branch = "main"
        args.include = ["*.py"]
        args.exclude = ["*test*"]
        
        # Capture stdout
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Run the handler
        await handle_repository_command(args)
        
        # Reset stdout
        sys.stdout = sys.__stdout__
        
        # Verify ingest_repository was called with correct arguments
        mock_ingest_repo.assert_called_once_with(
            repo_path_or_url="https://github.com/user/test-repo",
            is_github_url=True,
            include_patterns=["*.py"],
            exclude_patterns=["*test*"],
            github_token="github_token",
            branch="main",
            show_progress=True,
        )
        
        # Verify output contains expected content
        output = captured_output.getvalue()
        assert "Successfully ingested GitHub repository" in output
        assert "test-repo" in output
        assert "7 code files" in output
        assert "branch: main" in output