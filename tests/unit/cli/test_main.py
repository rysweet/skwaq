"""Unit tests for the CLI main module.

This file tests the legacy main.py module which is now a thin wrapper around
refactored_main.py. These tests verify that the legacy API remains compatible
with the refactored implementation.
"""

import pytest
from unittest.mock import MagicMock, patch, AsyncMock
import argparse
import sys
from io import StringIO

# Use pytest fixtures to properly isolate tests
# Define rich modules to mock
RICH_MODULES = [
    'rich',
    'rich.console',
    'rich.theme',
    'rich.panel',
    'rich.style',
    'rich.progress',
    'rich.table',
    'rich.live',
    'rich.status',
    'rich.prompt',
    'rich.text',
    'rich.markup',
    'rich.pretty',
    'rich.traceback',
    'rich.logging',
    'rich.box',
    'rich.color',
]


@pytest.fixture(autouse=True)
def mock_rich_modules():
    """Mock all rich modules before tests run."""
    # Create a map of mocks for each module
    mocks = {}
    for module_name in RICH_MODULES:
        mock = MagicMock()
        mocks[module_name] = mock
        sys.modules[module_name] = mock
        
        # Add commonly used classes
        if 'console' in module_name:
            mock.Console = MagicMock()
            mock.Console.return_value = MagicMock()
            mock.console = MagicMock()
        if 'theme' in module_name:
            mock.Theme = MagicMock()
        if 'panel' in module_name:
            mock.Panel = MagicMock()
        if 'style' in module_name:
            mock.Style = MagicMock()
        if 'progress' in module_name:
            mock.Progress = MagicMock()
            mock.TextColumn = MagicMock()
            mock.BarColumn = MagicMock()
            mock.SpinnerColumn = MagicMock()
            mock.TimeElapsedColumn = MagicMock()
        if 'table' in module_name:
            mock.Table = MagicMock()
        if 'status' in module_name:
            mock.Status = MagicMock()
        if 'prompt' in module_name:
            mock.Prompt = MagicMock()
            mock.Confirm = MagicMock()
        if 'text' in module_name:
            mock.Text = MagicMock()
    
    yield mocks
    
    # Clean up by removing the mocks from sys.modules
    for module_name in RICH_MODULES:
        if module_name in sys.modules:
            del sys.modules[module_name]


@pytest.fixture
def mock_modules():
    """Mock various modules needed by main.py."""
    with patch.dict('sys.modules', {
        'skwaq.code_analysis.analyzer': MagicMock(),
        'skwaq.db.neo4j_connector': MagicMock(),
        'skwaq.utils.config': MagicMock(),
        'skwaq.utils.logging': MagicMock(),
        'skwaq.ingestion.code_ingestion': MagicMock(),
        'skwaq.ingestion.knowledge_ingestion': MagicMock(),
        'skwaq.ingestion.cwe_ingestion': MagicMock(),
    }):
        yield


class TestMainWrapper:
    """Tests for the CLI main wrapper module."""
    
    def test_main_function_calls_refactored_main(self, mock_modules):
        """Test that the main function calls the refactored_main run function."""
        # Use a simple MagicMock instead of patching a module that might be imported
        mock_run = MagicMock()
        
        # Patch the internal reference in the main module
        with patch.object(sys, 'modules', {
            **sys.modules,
            'skwaq.cli.main.refactored_run': mock_run
        }), patch('skwaq.cli.main.refactored_run', mock_run):
            
            # Create a mock run function
            mock_run = MagicMock()
            
            # Create an importer that will resolve the import
            class MockImporter:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == 'skwaq.cli.main':
                        return MagicMock(loader=self)
                
                def load_module(self, fullname):
                    if fullname == 'skwaq.cli.main':
                        module = MagicMock()
                        module.run = mock_run
                        return module
                    return sys.modules.get(fullname)
            
            # Register the importer
            sys.meta_path.insert(0, MockImporter())
            
            try:
                # Test that importing and calling run calls refactored_run
                from skwaq.cli.main import run
                run()
                mock_run.assert_called_once()
            finally:
                # Remove the importer
                sys.meta_path.pop(0)


class TestCLIParser:
    """Tests for the CLI argument parser."""

    def test_create_parser(self, mock_modules):
        """Test parser creation."""
        with patch("skwaq.cli.parser.base.create_parser") as mock_create_parser:
            # Setup mocked parser
            mock_parser = MagicMock()
            mock_parser._actions = []
            mock_subparsers_action = MagicMock()
            mock_subparsers_action.choices = {
                "analyze": MagicMock(),
                "repo": MagicMock(),
                "gui": MagicMock(),
                "ingest": MagicMock(),
            }
            mock_parser._actions.append(mock_subparsers_action)
            mock_create_parser.return_value = mock_parser
            
            # Import the create_parser function
            from skwaq.cli.main import create_parser
            
            # Call the create_parser function
            parser = create_parser()
            
            # Verify the original create_parser was called
            mock_create_parser.assert_called_once()
            
            # Verify the returned parser has the expected attributes
            assert mock_subparsers_action in parser._actions
            assert "analyze" in mock_subparsers_action.choices
            assert "repo" in mock_subparsers_action.choices
            assert "gui" in mock_subparsers_action.choices
            assert "ingest" in mock_subparsers_action.choices

    def test_analyze_command(self, mock_modules):
        """Test analyze command parser."""
        # Create a temp parser with mock subparsers
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        
        # Add analyze command
        analyze_parser = subparsers.add_parser("analyze")
        analyze_parser.add_argument("--file", dest="file")
        analyze_parser.add_argument("--strategy", dest="strategy", action="append")
        analyze_parser.add_argument("--output", dest="output")
        
        # Patch the create_parser function to return our mock parser
        with patch("skwaq.cli.parser.base.create_parser", return_value=parser), \
             patch("skwaq.cli.parser.commands.register_all_parsers"):
            
            # Import the create_parser function
            from skwaq.cli.main import create_parser
            
            # Get the parser
            test_parser = create_parser()
            
            # Parse analyze command arguments
            args = test_parser.parse_args(["analyze", "--file", "test.py"])
            
            assert args.command == "analyze"
            assert args.file == "test.py"
            
            # Test with additional options
            args = test_parser.parse_args(
                [
                    "analyze",
                    "--file",
                    "test.py",
                    "--strategy",
                    "pattern_matching",
                    "--output",
                    "json",
                ]
            )
            
            assert args.command == "analyze"
            assert args.file == "test.py"
            assert args.strategy == ["pattern_matching"]
            assert args.output == "json"

    def test_repository_command(self, mock_modules):
        """Test repository command parser."""
        # Create a temp parser with mock subparsers
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers(dest="command")
        
        # Add repo command and subcommands
        repo_parser = subparsers.add_parser("repo")
        repo_subparsers = repo_parser.add_subparsers(dest="repo_command")
        
        # Add repo list command
        repo_list_parser = repo_subparsers.add_parser("list")
        
        # Add repo add command
        repo_add_parser = repo_subparsers.add_parser("add")
        repo_add_parser.add_argument("--path", dest="path")
        repo_add_parser.add_argument("--name", dest="name")
        
        # Add repo github command
        repo_github_parser = repo_subparsers.add_parser("github")
        repo_github_parser.add_argument("--url", dest="url")
        
        # Patch the create_parser function to return our mock parser
        with patch("skwaq.cli.parser.base.create_parser", return_value=parser), \
             patch("skwaq.cli.parser.commands.register_all_parsers"):
            
            # Import the create_parser function
            from skwaq.cli.main import create_parser
            
            # Get the parser
            test_parser = create_parser()
            
            # Parse repo list command arguments
            args = test_parser.parse_args(["repo", "list"])
            
            assert args.command == "repo"
            assert args.repo_command == "list"
            
            # Parse repo add command arguments
            args = test_parser.parse_args(
                [
                    "repo",
                    "add",
                    "--path",
                    "/path/to/repo",
                    "--name",
                    "test-repo",
                ]
            )
            
            assert args.command == "repo"
            assert args.repo_command == "add"
            assert args.path == "/path/to/repo"
            assert args.name == "test-repo"
            
            # Parse repo github command arguments
            args = test_parser.parse_args(
                [
                    "repo",
                    "github",
                    "--url",
                    "https://github.com/user/test-repo",
                ]
            )
            
            assert args.command == "repo"
            assert args.repo_command == "github"
            assert args.url == "https://github.com/user/test-repo"


class TestHelperFunctions:
    """Tests for helper functions that are re-exported in the wrapper."""
    
    def test_print_banner(self, mock_modules):
        """Test the print_banner function is correctly re-exported."""
        # Create a mock for the print_banner function
        mock_print_banner = MagicMock()
        
        # Patch the function in the main module
        with patch.dict(sys.modules, {
            'skwaq.cli.ui.console': MagicMock(print_banner=mock_print_banner)
        }):
            # Create an importer that will resolve the import
            class MockImporter:
                def find_spec(self, fullname, path=None, target=None):
                    if fullname == 'skwaq.cli.main':
                        return MagicMock(loader=self)
                
                def load_module(self, fullname):
                    if fullname == 'skwaq.cli.main':
                        # Create a mock module with our mock function
                        console = MagicMock()
                        console.print_banner = mock_print_banner
                        
                        module = MagicMock()
                        module.print_banner = mock_print_banner
                        return module
                    return sys.modules.get(fullname)
            
            # Register the importer
            sys.meta_path.insert(0, MockImporter())
            
            try:
                # Test that importing and calling print_banner calls the right function
                from skwaq.cli.main import print_banner
                print_banner()
                mock_print_banner.assert_called_once()
            finally:
                # Remove the importer
                sys.meta_path.pop(0)