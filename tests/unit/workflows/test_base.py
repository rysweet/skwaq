"""Unit tests for the base workflow module."""

import pytest
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio

from skwaq.workflows.base import Workflow


class ConcreteWorkflow(Workflow):
    """A concrete implementation of the abstract Workflow class for testing."""

    def __init__(self):
        """Initialize the concrete workflow."""
        super().__init__()
        self.run_called = False
        self._should_continue = True

    async def run(self):
        """Implement the abstract run method."""
        self.run_called = True
        return "workflow result"

    def should_continue(self) -> bool:
        """Override should_continue method for testing."""
        return self._should_continue

    def set_should_continue(self, value: bool):
        """Set the should_continue value for testing."""
        self._should_continue = value


class TestWorkflow:
    """Tests for the Workflow base class."""

    def test_initialization(self):
        """Test workflow initialization."""
        workflow = ConcreteWorkflow()

        assert workflow.investigation_id is None
        assert workflow.agents == {}
        assert workflow.connector is None

    @pytest.mark.asyncio
    async def test_run(self):
        """Test the run method of a concrete workflow."""
        workflow = ConcreteWorkflow()

        result = await workflow.run()

        assert workflow.run_called is True
        assert result == "workflow result"

    def test_should_continue(self):
        """Test the should_continue method."""
        workflow = ConcreteWorkflow()

        # Default value from concrete implementation
        assert workflow.should_continue() is True

        # Set to False
        workflow.set_should_continue(False)
        assert workflow.should_continue() is False

        # Set back to True
        workflow.set_should_continue(True)
        assert workflow.should_continue() is True

    def test_pause(self):
        """Test the pause method."""
        # Create a subclass that implements pause correctly
        class PausableWorkflow(ConcreteWorkflow):
            """A concrete workflow with pause implementation."""
            
            def pause(self):
                """Implement pause by setting should_continue to False."""
                self.set_should_continue(False)
        
        # Create workflow instance
        workflow = PausableWorkflow()
        
        # Initially should continue
        assert workflow.should_continue() is True
        
        # Pause workflow
        workflow.pause()
        
        # After pause, should_continue should return False
        assert workflow.should_continue() is False

    def test_resume(self):
        """Test the resume method."""
        # Create a subclass that implements both pause and resume correctly
        class PausableResumableWorkflow(ConcreteWorkflow):
            """A concrete workflow with pause and resume implementation."""
            
            def pause(self):
                """Implement pause by setting should_continue to False."""
                self.set_should_continue(False)
                
            def resume(self):
                """Implement resume by setting should_continue to True."""
                self.set_should_continue(True)
        
        # Create workflow instance
        workflow = PausableResumableWorkflow()
        
        # Pause workflow
        workflow.pause()
        assert workflow.should_continue() is False
        
        # Resume workflow
        workflow.resume()
        
        # After resume, should_continue should return True
        assert workflow.should_continue() is True
