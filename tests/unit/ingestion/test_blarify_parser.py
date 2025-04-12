"""Tests for the Blarify parser implementation."""

import json
import os
import platform
from unittest import mock

import pytest

from skwaq.ingestion.parsers.blarify_parser import BlarifyParser


@pytest.mark.asyncio
async def test_blarify_parser_initialization():
    """Test the BlarifyParser initialization."""
    parser = BlarifyParser()

    # Check Docker detection on macOS
    if platform.system() == "Darwin":
        assert parser.use_docker is True, "Should use Docker on macOS"
    else:
        assert (
            parser.use_docker is False
        ), "Should not use Docker on non-macOS platforms"


@pytest.mark.asyncio
@mock.patch("subprocess.run")
@mock.patch(
    "skwaq.ingestion.parsers.blarify_parser.BlarifyParser._process_docker_result"
)
async def test_docker_fallback(mock_process_result, mock_subprocess_run, tmpdir):
    """Test the Docker fallback mechanism when native parsing fails."""
    # Create a test codebase
    codebase_path = str(tmpdir)
    with open(os.path.join(codebase_path, "test.py"), "w") as f:
        f.write("def test_function():\n    pass\n")

    # Mock Docker check to indicate it's available
    docker_check_result = mock.Mock()
    docker_check_result.returncode = 0

    # Mock Docker build and run to succeed
    docker_build_result = mock.Mock()
    docker_build_result.returncode = 0

    docker_run_result = mock.Mock()
    docker_run_result.returncode = 0
    docker_run_result.stdout = json.dumps(
        {
            "success": True,
            "stats": {
                "files_processed": 1,
                "nodes_created": 2,
                "relationships_created": 1,
                "errors": 0,
            },
            "nodes": [
                {
                    "id": 1,
                    "type": "File",
                    "labels": ["File"],
                    "file_path": "test.py",
                    "name": "test.py",
                },
                {
                    "id": 2,
                    "type": "Function",
                    "labels": ["Function"],
                    "file_path": "test.py",
                    "name": "test_function",
                },
            ],
            "relationships": [
                {"source_id": 1, "target_id": 2, "type": "DEFINES", "properties": {}}
            ],
        }
    )

    # Configure the mocks
    mock_subprocess_run.side_effect = [
        docker_check_result,
        docker_build_result,
        docker_run_result,
    ]

    # Force Docker mode
    parser = BlarifyParser()
    parser.use_docker = True
    parser.docker_available = True

    # Run the parser with mocked json.loads
    with mock.patch("json.loads", return_value=json.loads(docker_run_result.stdout)):
        result = await parser._parse_with_docker(codebase_path, {"errors": 0})

    # Check that Docker was used correctly
    assert (
        mock_subprocess_run.call_count == 3
    ), "Should have called subprocess.run 3 times"
    assert (
        mock_process_result.call_count == 1
    ), "Should have processed the Docker result"

    # Verify the result
    assert result["success"] is True, "Parsing should have succeeded"
    assert result["docker_mode"] is True, "Should indicate Docker mode was used"
    assert result["stats"]["files_processed"] == 1, "Should have processed 1 file"


@pytest.mark.asyncio
@mock.patch("subprocess.run")
async def test_docker_build_failure(mock_subprocess_run, tmpdir):
    """Test handling of Docker build failures."""
    # Create a test codebase
    codebase_path = str(tmpdir)
    with open(os.path.join(codebase_path, "test.py"), "w") as f:
        f.write("def test_function():\n    pass\n")

    # Mock Docker check to indicate it's available
    docker_check_result = mock.Mock()
    docker_check_result.returncode = 0

    # Mock Docker build to fail
    mock_subprocess_run.side_effect = [
        docker_check_result,
        Exception("Docker build failed"),
    ]

    # Force Docker mode
    parser = BlarifyParser()
    parser.use_docker = True
    parser.docker_available = True

    # Run the parser and expect an error
    stats = {"errors": 0}
    with pytest.raises(ValueError, match="Docker.*failed"):
        await parser._parse_with_docker(codebase_path, stats)

    # Verify error was recorded
    assert stats["errors"] > 0, "Error count should have increased"
