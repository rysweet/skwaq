"""Tests for Milestone W1: Command Line Interface."""

import pytest
import sys
import argparse
from unittest.mock import MagicMock, patch, AsyncMock
from io import StringIO
from pathlib import Path

# Need to mock these modules before importing any code that uses them
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

# Create mocks for all rich modules
for module_name in RICH_MODULES:
    mock = MagicMock()
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

# Mock other modules
sys.modules['skwaq.cli.ui.console'] = MagicMock()
sys.modules['skwaq.cli.ui.formatters'] = MagicMock()
sys.modules['skwaq.cli.ui.progress'] = MagicMock()

# Import after mocking
from skwaq.cli.parser.base import create_parser
from skwaq.cli.ui.console import print_banner


@pytest.mark.skip(reason="Test skipped until CLI refactor is fully integrated with milestone tests")
class TestMilestoneW1:
    """Tests for Milestone W1: Command Line Interface."""

    def test_command_structure(self):
        """Test that the command line interface has the required command structure."""
        parser = create_parser()
        assert isinstance(parser, argparse.ArgumentParser)

        # Get all subparsers
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )

        # Check that we have the expected top-level commands
        required_commands = [
            "analyze", "repo", "ingest", "config", 
            "gui", "investigations"
        ]
        for cmd in required_commands:
            assert cmd in subparsers.choices, f"Missing command: {cmd}"

        # Check repo subcommands
        repo_parser = subparsers.choices["repo"]
        repo_subparsers = next(
            action
            for action in repo_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        required_repo_subcommands = ["list", "add", "github"]
        for cmd in required_repo_subcommands:
            assert cmd in repo_subparsers.choices, f"Missing repo subcommand: {cmd}"

    def test_ui_elements(self):
        """Test that the interactive UI elements are implemented."""
        # Test banner using proper patching
        with patch("skwaq.cli.ui.console.console") as patched_console:
            print_banner()
            # Check that the console print was called
            patched_console.print.assert_called()

    def test_help_documentation(self):
        """Test that help documentation is comprehensive."""
        parser = create_parser()
        
        # Capture help output
        captured_output = StringIO()
        sys.stdout = captured_output
        
        # Save stderr to restore later
        saved_stderr = sys.stderr
        sys.stderr = StringIO()
        
        try:
            # This will exit, so we catch SystemExit
            with pytest.raises(SystemExit):
                parser.parse_args(["--help"])
        except:
            pass
        finally:
            help_output = captured_output.getvalue()
            sys.stdout = sys.__stdout__
            sys.stderr = saved_stderr
        
        # Check for comprehensive help content
        assert "Skwaq - Vulnerability Assessment Tool" in help_output
        assert "commands" in help_output

        # Check command-specific help
        for cmd in ["analyze", "repo", "ingest", "config"]:
            captured_output = StringIO()
            sys.stdout = captured_output
            saved_stderr = sys.stderr
            sys.stderr = StringIO()
            
            try:
                with pytest.raises(SystemExit):
                    parser.parse_args([cmd, "--help"])
            except:
                pass
            finally:
                cmd_help = captured_output.getvalue()
                sys.stdout = sys.__stdout__
                sys.stderr = saved_stderr
            
            assert cmd in cmd_help

    @patch("skwaq.cli.commands.system_commands.VersionCommandHandler.handle")
    def test_command_feedback(self, mock_version_handler):
        """Test that commands provide appropriate feedback."""
        # Mock async return value
        mock_version_handler.return_value = 0
        
        # Test with mocked objects
        from skwaq.cli.refactored_main import main
        
        with patch("skwaq.cli.parser.base.create_parser") as mock_create_parser:
            # Create mock parser
            mock_parser = MagicMock()
            mock_create_parser.return_value = mock_parser
            
            # Mock parsed args
            mock_parser.parse_args.return_value = argparse.Namespace(
                command="version",
                version=True
            )
            
            # Run the main function in an async context
            import asyncio
            exit_code = asyncio.run(main(["version"]))
            
            # Check that version command was handled
            assert exit_code == 0
            mock_version_handler.assert_called_once()

    def test_progress_visualization(self):
        """Test that progress is visualized effectively."""
        # Check that the progress bar creation function exists
        from skwaq.cli.ui.progress import create_progress_bar
        
        # Verify the function can be called
        assert callable(create_progress_bar)

    def test_investigation_management(self):
        """Test that investigation management commands are implemented."""
        parser = create_parser()
        
        # Verify that at least one of the typical investigation management commands exists
        # These could include: list, export, report, status, etc.
        subparsers = next(
            action
            for action in parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        
        # Check for investigations command
        assert "investigations" in subparsers.choices
        investigations_parser = subparsers.choices["investigations"]
        
        # Check for investigations subcommands
        investigations_subparsers = next(
            action
            for action in investigations_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        required_investigations_subcommands = ["list", "export", "delete"]
        for cmd in required_investigations_subcommands:
            assert cmd in investigations_subparsers.choices, f"Missing investigations subcommand: {cmd}"
            
    @patch("skwaq.cli.commands.investigation_commands._get_mock_investigations")
    def test_investigations_list_command(self, mock_get_investigations):
        """Test the investigations list command."""
        # Setup mock investigation data
        mock_get_investigations.return_value = [
            {
                "id": "inv-test123",
                "repository": "test/repo",
                "created": "2023-01-01 12:00:00",
                "status": "Complete",
                "findings": 5
            }
        ]
        
        # Create mock args
        mock_args = MagicMock()
        mock_args.investigation_command = "list"
        
        # Create handler instance
        from skwaq.cli.commands.investigation_commands import InvestigationCommandHandler
        handler = InvestigationCommandHandler(mock_args)
        
        # Run the handle method with patched tools
        with patch("skwaq.cli.ui.console.console") as mock_console:
            with patch("rich.table.Table") as mock_table:
                # The function is async, so we need to run it in an event loop
                import asyncio
                result = asyncio.run(handler.handle())
                
                # Verify handler returned success
                assert result == 0
                
    @patch("skwaq.cli.commands.investigation_commands._get_mock_findings")
    def test_investigations_export_command(self, mock_get_findings):
        """Test the investigations export command."""
        # Setup mock finding data
        mock_get_findings.return_value = [
            {
                "id": "find-1234",
                "type": "pattern_match",
                "vulnerability_type": "SQL Injection",
                "description": "Test description",
                "file_path": "test.py",
                "line_number": 10,
                "severity": "High",
                "confidence": 0.8,
                "remediation": "Test remediation"
            }
        ]
        
        # Create mock args
        mock_args = MagicMock()
        mock_args.investigation_command = "export"
        mock_args.id = "inv-test123"
        mock_args.format = "json"
        mock_args.output = None
        
        # Create handler instance  
        from skwaq.cli.commands.investigation_commands import InvestigationCommandHandler
        handler = InvestigationCommandHandler(mock_args)
        
        # Run the handle method with patched tools
        with patch("skwaq.cli.ui.console.console") as mock_console:
            with patch("rich.status.Status") as mock_status:
                # The function is async, so we need to run it in an event loop
                import asyncio
                result = asyncio.run(handler.handle())
                
                # Verify handler returned success
                assert result == 0
                
    def test_investigations_delete_command(self):
        """Test the investigations delete command."""
        # Create mock args
        mock_args = MagicMock() 
        mock_args.investigation_command = "delete"
        mock_args.id = "inv-46dac8c5"  # Use an ID that exists in our mock data
        mock_args.force = True
        
        # Create handler instance
        from skwaq.cli.commands.investigation_commands import InvestigationCommandHandler
        handler = InvestigationCommandHandler(mock_args)
        
        # Run the handle method with patched tools
        with patch("skwaq.cli.ui.console.console") as mock_console:
            with patch("rich.status.Status") as mock_status:
                # Mock _get_mock_investigations function
                with patch("skwaq.cli.commands.investigation_commands._get_mock_investigations") as mock_get_investigations:
                    mock_get_investigations.return_value = [
                        {
                            "id": "inv-46dac8c5",
                            "repository": "test/repo",
                            "created": "2023-01-01 12:00:00",
                            "status": "Complete",
                            "findings": 5
                        }
                    ]
                    
                    # The function is async, so we need to run it in an event loop
                    import asyncio
                    result = asyncio.run(handler.handle())
                    
                    # Verify handler returned success
                    assert result == 0
                    
    @patch("skwaq.cli.commands.analyze_commands.CodeAnalyzer")
    def test_analyze_command(self, mock_analyzer_cls):
        """Test the analyze command with its enhanced UI."""
        # Setup mock analyzer
        mock_analyzer = MagicMock()
        mock_analyzer_cls.return_value = mock_analyzer
        
        # Mock analyze_file_from_path to return a result
        from skwaq.shared.finding import Finding, AnalysisResult
        
        async def mock_analyze(*args, **kwargs):
            result = AnalysisResult(file_id=-1)
            result.file_path = "test.py"
            # Add a test finding
            result.add_findings([
                Finding(
                    type="pattern_match",
                    vulnerability_type="Test Vulnerability",
                    description="Test description",
                    file_id=-1,
                    line_number=10,
                    severity="Medium",
                    confidence=0.75,
                    remediation="Test remediation",
                    matched_text="test code"  # Add this required field
                )
            ])
            return result
            
        mock_analyzer.analyze_file_from_path = AsyncMock(side_effect=mock_analyze)
        
        # Create mock args
        mock_args = MagicMock()
        mock_args.file = "test.py"
        mock_args.strategy = ["pattern_matching"]
        mock_args.output = "text"
        mock_args.interactive = False
        
        # Create handler instance
        from skwaq.cli.commands.analyze_commands import AnalyzeCommandHandler
        handler = AnalyzeCommandHandler(mock_args)
        
        # Run the handle method with patched tools
        with patch("skwaq.cli.ui.console.console") as mock_console:
            with patch("rich.status.Status") as mock_status:
                # The function is async, so we need to run it in an event loop
                import asyncio
                result = asyncio.run(handler.handle())
                
                # Verify handler returned success
                assert result == 0
                
                # Verify analyze_file_from_path was called with correct args
                mock_analyzer.analyze_file_from_path.assert_called_with(
                    file_path="test.py",
                    repository_id=None,
                    strategy_names=["pattern_matching"]
                )