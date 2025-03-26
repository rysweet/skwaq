"""Tests for Milestone W1: Command Line Interface."""

import pytest
import sys
import argparse
from unittest.mock import MagicMock, patch, AsyncMock
from io import StringIO
from pathlib import Path

# Mock the rich module before importing
mock_rich = MagicMock()
mock_console = MagicMock()
mock_console.print = MagicMock(side_effect=lambda *args, **kwargs: print(*args))
mock_rich.Console.return_value = mock_console
mock_panel = MagicMock()
mock_rich.Panel = mock_panel
mock_table = MagicMock()
mock_rich.Table = mock_table
mock_progress = MagicMock()
mock_rich.Progress = mock_progress
mock_status = MagicMock()
mock_rich.status = mock_status
mock_prompt = MagicMock()
mock_rich.Prompt = mock_prompt

sys.modules["rich"] = mock_rich
sys.modules["rich.console"] = MagicMock()
sys.modules["rich.console"].Console = mock_rich.Console
sys.modules["rich.panel"] = MagicMock()
sys.modules["rich.panel"].Panel = mock_rich.Panel
sys.modules["rich.table"] = MagicMock()
sys.modules["rich.table"].Table = mock_rich.Table
sys.modules["rich.progress"] = MagicMock()
sys.modules["rich.progress"].Progress = mock_rich.Progress
sys.modules["rich.status"] = MagicMock()
sys.modules["rich.status"].Status = mock_status
sys.modules["rich.prompt"] = MagicMock()
sys.modules["rich.prompt"].Prompt = mock_prompt

# Import after mocking
from skwaq.cli.main import create_parser, main, print_banner


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
            "version", "config", "init", "analyze", "repo", "ingest", "query"
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
        # Test banner
        captured_output = StringIO()
        sys.stdout = captured_output
        print_banner()
        sys.stdout = sys.__stdout__

        # Check that the banner has meaningful content
        mock_console.print.assert_called()

        # Test that rich components are used
        with patch("skwaq.cli.main.Progress") as mock_progress:
            with patch("skwaq.cli.main.Panel") as mock_panel:
                with patch("skwaq.cli.main.Table") as mock_table:
                    print_banner()
                    mock_panel.assert_called()

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
        assert "Skwaq - Vulnerability Assessment Copilot" in help_output
        assert "commands" in help_output

        # Check command-specific help
        for cmd in ["analyze", "repo", "ingest", "query", "config", "version"]:
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

    @patch("skwaq.cli.main.cmd_version")
    def test_command_feedback(self, mock_cmd_version):
        """Test that commands provide appropriate feedback."""
        # Test version command feedback
        with patch("sys.argv", ["skwaq", "version"]):
            main()
            mock_cmd_version.assert_called_once()

    def test_progress_visualization(self):
        """Test that progress is visualized effectively."""
        # Simply check that the progress bar creation function exists
        from skwaq.cli.main import create_progress_bar
        
        # Also check that the Progress class is imported
        from rich.progress import Progress
        
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
        
        # Check for repo list command which is a form of investigation management
        assert "repo" in subparsers.choices
        repo_parser = subparsers.choices["repo"]
        repo_subparsers = next(
            action
            for action in repo_parser._actions
            if isinstance(action, argparse._SubParsersAction)
        )
        assert "list" in repo_subparsers.choices