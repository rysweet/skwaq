"""Unit tests for the base workflow module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio

from skwaq.workflows.base import Workflow


class ConcreteWorkflow(Workflow):
    """A concrete implementation of the abstract Workflow class for testing."""

    def __init__(self):
        """Initialize the concrete workflow."""
        super().__init__(
            name="TestWorkflow",
            description="Test workflow for unit tests",
            repository_id=None,
        )
        self.run_called = False

    async def run(self, *args, **kwargs):
        """Implement the abstract run method."""
        self.run_called = True
        return "workflow result"

    def set_should_continue(self, value: bool):
        """Set the should_continue value for testing."""
        self._should_continue = value


class TestWorkflow:
    """Tests for the Workflow base class."""

    def test_initialization(self):
        """Test workflow initialization."""
        with patch("skwaq.workflows.base.get_connector") as mock_get_connector:
            # Setup connector mock
            mock_connector = MagicMock()
            mock_get_connector.return_value = mock_connector

            # Create workflow
            workflow = ConcreteWorkflow()

            # Validate initialization
            assert workflow.name == "TestWorkflow"
            assert workflow.description == "Test workflow for unit tests"
            assert workflow.repository_id is None
            assert workflow.investigation_id is None
            assert workflow.agents == {}
            assert workflow.connector is mock_connector
            assert hasattr(workflow, "_pause_event")

    @pytest.mark.asyncio
    async def test_run(self):
        """Test the run method of a concrete workflow."""
        with patch("skwaq.workflows.base.get_connector"):
            workflow = ConcreteWorkflow()
            result = await workflow.run()

            assert workflow.run_called is True
            assert result == "workflow result"

    def test_should_continue(self):
        """Test the should_continue method."""
        with patch("skwaq.workflows.base.get_connector"):
            workflow = ConcreteWorkflow()

            # Default value from initialization
            assert workflow.should_continue() is True

            # Set to False
            workflow.set_should_continue(False)
            assert workflow.should_continue() is False

            # Set back to True
            workflow.set_should_continue(True)
            assert workflow.should_continue() is True

    def test_pause_resume(self):
        """Test the pause and resume methods with event."""
        with patch("skwaq.workflows.base.get_connector"):
            workflow = ConcreteWorkflow()

            # Initially event should be set
            assert workflow._pause_event.is_set() is True

            # Pause workflow
            workflow.pause()

            # Event should be cleared (paused)
            assert workflow._pause_event.is_set() is False

            # Resume workflow
            workflow.resume()

            # Event should be set again (resumed)
            assert workflow._pause_event.is_set() is True

    @pytest.mark.asyncio
    async def test_timestamp_generation(self):
        """Test the timestamp generation utility method."""
        with patch("skwaq.workflows.base.get_connector"):
            workflow = ConcreteWorkflow()
            timestamp = workflow._get_timestamp()

            # Verify it's a properly formatted ISO timestamp
            assert isinstance(timestamp, str)

            # Should be in ISO format (basic check)
            assert "T" in timestamp
            assert "-" in timestamp
            assert ":" in timestamp

            # Try parsing it as a datetime
            import datetime

            datetime.datetime.fromisoformat(timestamp)
