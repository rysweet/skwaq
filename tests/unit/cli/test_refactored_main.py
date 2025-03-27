"""Tests for the refactored CLI main module."""

import pytest
from unittest.mock import patch, MagicMock

from skwaq.cli.refactored_main import main

@pytest.mark.asyncio
async def test_main_version_flag():
    """Test the main function with --version flag."""
    with patch('skwaq.cli.commands.system_commands.VersionCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['--version'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_no_command():
    """Test the main function with no command."""
    with patch('skwaq.cli.ui.console.error') as mock_error:
        exit_code = await main([])
        assert exit_code == 1
        mock_error.assert_called_once()

@pytest.mark.asyncio
async def test_main_unknown_command():
    """Test the main function with an unknown command."""
    with patch('skwaq.cli.ui.console.error') as mock_error:
        exit_code = await main(['unknown_command'])
        assert exit_code == 1
        mock_error.assert_called_once()

@pytest.mark.asyncio
async def test_main_analyze_command():
    """Test the main function with the analyze command."""
    with patch('skwaq.cli.commands.analyze_commands.AnalyzeCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        
        with patch('builtins.open', MagicMock()):
            with patch('os.path.exists', return_value=True):
                exit_code = await main(['analyze', 'dummy_file.py'])
                assert exit_code == 0
                mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_repo_list_command():
    """Test the main function with the repo list command."""
    with patch('skwaq.cli.commands.repository_commands.RepositoryCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['repo', 'list'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_investigations_command():
    """Test the main function with the investigations command."""
    with patch('skwaq.cli.commands.investigation_commands.InvestigationCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['investigations', 'list'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_gui_command():
    """Test the main function with the gui command."""
    with patch('skwaq.cli.commands.system_commands.GuiCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['gui'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_qa_command():
    """Test the main function with the qa command."""
    with patch('skwaq.cli.commands.workflow_commands.QACommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['qa'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_inquiry_command():
    """Test the main function with the inquiry command."""
    with patch('skwaq.cli.commands.workflow_commands.GuidedInquiryCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['inquiry'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_tool_command():
    """Test the main function with the tool command."""
    with patch('skwaq.cli.commands.workflow_commands.ToolCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['tool', 'test_tool'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_research_command():
    """Test the main function with the research command."""
    with patch('skwaq.cli.commands.workflow_commands.VulnerabilityResearchCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['research', '--repo', '123'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_ingest_command():
    """Test the main function with the ingest command."""
    with patch('skwaq.cli.commands.ingest_commands.IngestCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        with patch('pathlib.Path.exists', return_value=True):
            exit_code = await main(['ingest', 'repo', '/path/to/repo'])
            assert exit_code == 0
            mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_main_config_command():
    """Test the main function with the config command."""
    with patch('skwaq.cli.commands.config_commands.ConfigCommandHandler.handle') as mock_handle:
        mock_handle.return_value = 0
        exit_code = await main(['config', 'show'])
        assert exit_code == 0
        mock_handle.assert_called_once()

@pytest.mark.asyncio
async def test_command_error_handling():
    """Test error handling in commands."""
    with patch('skwaq.cli.commands.analyze_commands.AnalyzeCommandHandler.handle') as mock_handle:
        # Simulate an error in the command handler
        mock_handle.side_effect = Exception("Test error")
        
        with patch('skwaq.cli.ui.console.error') as mock_error:
            with patch('builtins.open', MagicMock()):
                with patch('os.path.exists', return_value=True):
                    exit_code = await main(['analyze', 'dummy_file.py'])
                    assert exit_code == 1
                    mock_error.assert_called_once()