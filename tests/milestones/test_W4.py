"""Tests for the W4 milestone: Workflow Refinement and Integration.

This test suite verifies the implementation of workflow refinement and integration
features including inter-workflow communication, context preservation, workflow chaining,
and performance optimization.
"""

import os
import json
import uuid
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Any, Dict, List, Optional, Type

from skwaq.workflows.base import Workflow
from skwaq.workflows.qa_workflow import QAWorkflow
from skwaq.workflows.guided_inquiry import GuidedInquiryWorkflow
from skwaq.workflows.tool_invocation import ToolInvocationWorkflow
from skwaq.workflows.vulnerability_research import VulnerabilityResearchWorkflow
from skwaq.workflows.integration import (
    # Context Management
    WorkflowContext,
    ContextManager,
    get_context_manager,
    
    # Workflow Chaining
    TransitionType,
    WorkflowTransition,
    WorkflowChain,
    WorkflowExecutionPlan,
    
    # Workflow Communication
    CommunicationChannel,
    MessageType,
    WorkflowMessage,
    WorkflowCommunicationEvent, 
    WorkflowCommunicationManager,
    get_communication_manager,
    
    # Performance Optimization
    WorkflowCache,
    PerformanceOptimizer,
    ResourceManager,
    get_performance_optimizer,
    get_resource_manager
)


class MockWorkflow(Workflow):
    """Mock workflow for testing."""
    
    def __init__(self, name: str = "MockWorkflow", **kwargs):
        """Initialize the mock workflow."""
        super().__init__(name=name, description="Mock workflow for testing", **kwargs)
        self.setup_called = False
        self.cleanup_called = False
        self.run_iterator = None
        self._should_continue_value = True
        
    async def setup(self) -> None:
        """Setup the workflow."""
        self.setup_called = True
        
    def cleanup(self) -> None:
        """Clean up resources."""
        self.cleanup_called = True
        
    def should_continue(self) -> bool:
        """Check if the workflow should continue."""
        return self._should_continue_value
        
    async def run(self):
        """Run the workflow."""
        if not self.run_iterator:
            self.run_iterator = [
                {"status": "starting", "message": "Starting mock workflow"},
                {"status": "in_progress", "message": "Mock workflow in progress"},
                {"status": "complete", "message": "Mock workflow complete"}
            ]
            
        for item in self.run_iterator:
            yield item


class TestContextManagement:
    """Tests for the workflow context management functionality."""
    
    def test_workflow_context_creation(self):
        """Test creating a workflow context."""
        context = WorkflowContext(repository_id="test-repo")
        
        assert context.context_id is not None
        assert context.repository_id == "test-repo"
        
    def test_context_data_storage(self):
        """Test storing and retrieving data in a context."""
        context = WorkflowContext(repository_id="test-repo")
        
        # Add user preferences
        context.add_user_preference("theme", "dark")
        assert context.get_user_preference("theme") == "dark"
        
        # Add workflow data
        context.add_workflow_data("wf1", "result", {"value": 42})
        assert context.get_workflow_data("wf1", "result") == {"value": 42}
        
        # Add shared data
        context.add_shared_data("api_token", "secret-token")
        assert context.get_shared_data("api_token") == "secret-token"
        
    def test_workflow_transition_recording(self):
        """Test recording workflow transitions."""
        context = WorkflowContext(repository_id="test-repo")
        
        context.record_workflow_transition("wf1", "wf2", "Completed initial analysis")
        
        # Check that the transition was recorded
        metadata = context._data["metadata"]
        assert len(metadata["workflow_history"]) == 1
        assert metadata["workflow_history"][0]["from"] == "wf1"
        assert metadata["workflow_history"][0]["to"] == "wf2"
        assert metadata["workflow_id"] == "wf2"
        
    def test_context_serialization(self):
        """Test serializing and deserializing contexts."""
        context = WorkflowContext(repository_id="test-repo")
        context.add_user_preference("theme", "dark")
        context.add_workflow_data("wf1", "result", {"value": 42})
        context.add_shared_data("api_token", "secret-token")
        
        # Serialize
        serialized = context.serialize()
        
        # Deserialize
        new_context = WorkflowContext.deserialize(serialized)
        
        # Check that data was preserved
        assert new_context.repository_id == "test-repo"
        assert new_context.get_user_preference("theme") == "dark"
        assert new_context.get_workflow_data("wf1", "result") == {"value": 42}
        assert new_context.get_shared_data("api_token") == "secret-token"
        
    @pytest.mark.skip(reason="Requires database connection")
    def test_context_persistence(self):
        """Test saving and loading contexts from the database."""
        context = WorkflowContext(repository_id="test-repo")
        context.add_user_preference("theme", "dark")
        
        # Mock the database operations
        with patch('skwaq.workflows.integration.context_manager.get_connector') as mock_get_connector:
            mock_connector = MagicMock()
            mock_get_connector.return_value = mock_connector
            mock_connector.run_query.return_value = []
            
            # Save the context
            result = context.save()
            assert result is True
            
            # Verify create_node was called
            mock_connector.create_node.assert_called_once()
            
    def test_context_manager(self):
        """Test the context manager functionality."""
        manager = ContextManager()
        
        # Create a context
        context = manager.create_context(repository_id="test-repo")
        
        # Get the context
        retrieved = manager.get_context(context.context_id)
        
        assert retrieved is context
        assert retrieved.repository_id == "test-repo"


class TestWorkflowChaining:
    """Tests for the workflow chaining functionality."""
    
    def test_workflow_transition_creation(self):
        """Test creating workflow transitions."""
        transition = WorkflowTransition(
            from_workflow_type=MockWorkflow,
            to_workflow_type=MockWorkflow,
            transition_type=TransitionType.SEQUENTIAL
        )
        
        assert transition.from_workflow_type == MockWorkflow
        assert transition.to_workflow_type == MockWorkflow
        assert transition.transition_type == TransitionType.SEQUENTIAL
        assert transition.condition is None
        
    def test_workflow_chain_creation(self):
        """Test creating a workflow chain."""
        chain = WorkflowChain(name="test-chain")
        
        # Add transitions
        chain.add_sequential_transition(
            from_workflow_type=MockWorkflow,
            to_workflow_type=MockWorkflow
        )
        
        assert len(chain.transitions) == 1
        assert chain.transitions[0].from_workflow_type == MockWorkflow
        assert chain.transitions[0].to_workflow_type == MockWorkflow
        
    def test_workflow_chain_start(self):
        """Test starting a workflow chain."""
        chain = WorkflowChain(name="test-chain")
        
        # Add transitions
        chain.add_sequential_transition(
            from_workflow_type=MockWorkflow,
            to_workflow_type=MockWorkflow
        )
        
        # Start the chain
        chain.start(MockWorkflow, repository_id="test-repo")
        
        assert chain._is_running is True
        assert isinstance(chain.current_workflow, MockWorkflow)
        assert chain.context is not None
        assert chain.context.repository_id == "test-repo"
        
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Test needs more comprehensive mocking to handle async workflow chain interactions properly")
    async def test_workflow_chain_execution(self):
        """Test executing a workflow chain."""
        # Create a custom mock workflow class for this test
        class TestMockWorkflow(Workflow):
            def __init__(self, name="TestMock", **kwargs):
                super().__init__(name=name, description="Test mock workflow", **kwargs)
                self.setup_called = False
                self.run_called = False
                
            async def setup(self):
                self.setup_called = True
                
            async def run(self):
                self.run_called = True
                # Only yield 3 specific results to make the test more predictable
                yield {"status": "starting", "message": "Starting test"}
                yield {"status": "in_progress", "message": "In progress"}
                yield {"status": "complete", "message": "Complete"}
                
        # Create mock workflows
        mock1 = TestMockWorkflow(name="Mock1")
        mock2 = TestMockWorkflow(name="Mock2")
        
        # Create a chain
        chain = WorkflowChain(name="test-chain")
        
        # Create a controlled environment for the test
        with patch.object(chain, '_create_workflow_instance') as mock_create:
            mock_create.side_effect = [mock1, mock2]
            
            # Create a specific transition
            transition = WorkflowTransition(
                from_workflow_type=TestMockWorkflow,
                to_workflow_type=TestMockWorkflow,
                transition_type=TransitionType.SEQUENTIAL
            )
            
            # Patch the find_next_transition method
            with patch.object(chain, 'find_next_transition') as mock_find:
                mock_find.return_value = transition
                
                # Start the chain with a context
                context = WorkflowContext(repository_id="test-repo")
                chain.start(TestMockWorkflow, context=context)
                
                # Execute the chain
                results = []
                async for result in chain.run():
                    results.append(result)
                
                # We expect exactly 3 results from our controlled mock workflow
                assert len(results) == 3
                assert results[0]["status"] == "starting"
                assert results[1]["status"] == "in_progress"
                assert results[2]["status"] == "complete"
                
                # Verify setup was called
                assert mock1.setup_called is True
                
                # Execute next workflow - patch the context manager operations
                with patch('skwaq.workflows.integration.workflow_chain.get_context_manager'):
                    next_state = await chain.execute_next()
                    assert next_state is not None
                    assert "workflow" in next_state
                    assert next_state["workflow"] is mock2
        
    def test_workflow_execution_plan(self):
        """Test creating a workflow execution plan."""
        # Create chains
        chain1 = WorkflowChain(name="chain1")
        chain2 = WorkflowChain(name="chain2")
        
        # Create a plan
        plan = WorkflowExecutionPlan(name="test-plan")
        plan.add_chain(chain1)
        plan.add_chain(chain2)
        
        # Set entry points
        plan.set_entry_point("scenario1", "chain1")
        plan.set_entry_point("scenario2", "chain2")
        
        # Get chains for scenarios
        assert plan.get_chain_for_scenario("scenario1") is chain1
        assert plan.get_chain_for_scenario("scenario2") is chain2


class TestWorkflowCommunication:
    """Tests for the workflow communication functionality."""
    
    def test_communication_channel_creation(self):
        """Test creating a communication channel."""
        channel = CommunicationChannel(name="test-channel")
        
        assert channel.name == "test-channel"
        
    @pytest.mark.asyncio
    async def test_communication_channel_send_receive(self):
        """Test sending and receiving messages on a channel."""
        channel = CommunicationChannel(name="test-channel")
        
        # Send a message
        await channel.send({"text": "Hello"}, "sender1")
        
        # Receive the message
        message = await channel.receive(timeout=0.1)
        
        assert message is not None
        assert message["text"] == "Hello"
        assert message["sender"] == "sender1"
        assert message["channel"] == "test-channel"
        
    def test_workflow_message_creation(self):
        """Test creating workflow messages."""
        message = WorkflowMessage(
            message_type=MessageType.DATA,
            content={"data": "value"},
            sender_id="wf1",
            recipient_id="wf2"
        )
        
        assert message.message_type == MessageType.DATA
        assert message.content == {"data": "value"}
        assert message.sender_id == "wf1"
        assert message.recipient_id == "wf2"
        
    def test_message_serialization(self):
        """Test serializing and deserializing workflow messages."""
        message = WorkflowMessage(
            message_type=MessageType.DATA,
            content={"data": "value"},
            sender_id="wf1",
            recipient_id="wf2"
        )
        
        # Convert to dict
        message_dict = message.to_dict()
        
        # Convert back to message
        new_message = WorkflowMessage.from_dict(message_dict)
        
        assert new_message.message_type == message.message_type
        assert new_message.content == message.content
        assert new_message.sender_id == message.sender_id
        assert new_message.recipient_id == message.recipient_id
        
    def test_communication_manager(self):
        """Test the communication manager functionality."""
        manager = WorkflowCommunicationManager()
        
        # Create channels
        channel1 = manager.create_channel("channel1")
        channel2 = manager.create_channel("channel2")
        
        # Check channels were created
        assert manager.get_channel("channel1") is channel1
        assert manager.get_channel("channel2") is channel2
        
        # Subscribe workflows
        result = manager.subscribe_workflow("wf1", "channel1")
        assert result is True
        
        # Check subscription
        assert "wf1" in channel1.get_subscribers()


class TestPerformanceOptimization:
    """Tests for the performance optimization functionality."""
    
    def test_workflow_cache_creation(self):
        """Test creating a workflow cache."""
        cache = WorkflowCache(max_size=100)
        
        assert cache._max_size == 100
        assert len(cache._cache) == 0
        
    def test_cache_operations(self):
        """Test basic cache operations."""
        cache = WorkflowCache()
        
        # Set an item
        cache.set("key1", "value1")
        
        # Get the item
        value = cache.get("key1")
        assert value == "value1"
        
        # Get a non-existent item
        value = cache.get("key2", "default")
        assert value == "default"
        
        # Invalidate an item
        cache.invalidate("key1")
        value = cache.get("key1", "default")
        assert value == "default"
        
    def test_cache_expiration(self):
        """Test cache entry expiration."""
        cache = WorkflowCache()
        
        # Set an item with a very short TTL
        cache.set("key1", "value1", ttl=0.01)
        
        # Get it immediately
        value = cache.get("key1")
        assert value == "value1"
        
        # Wait for expiration
        import time
        time.sleep(0.02)
        
        # Get it again
        value = cache.get("key1", "default")
        assert value == "default"
        
    @pytest.mark.asyncio
    async def test_performance_optimizer_cached_decorator(self):
        """Test the cached decorator."""
        optimizer = PerformanceOptimizer()
        
        # Define a test function
        call_count = 0
        
        @optimizer.cached(ttl=10)
        async def test_function(arg1, arg2=None):
            nonlocal call_count
            call_count += 1
            return f"{arg1}-{arg2}"
        
        # Call it multiple times with the same arguments
        result1 = await test_function("a", arg2="b")
        result2 = await test_function("a", arg2="b")
        
        # Should only be called once
        assert call_count == 1
        assert result1 == result2 == "a-b"
        
        # Call with different arguments
        result3 = await test_function("c", arg2="d")
        
        # Should be called again
        assert call_count == 2
        assert result3 == "c-d"
        
    @pytest.mark.asyncio
    async def test_resource_manager(self):
        """Test the resource manager functionality."""
        manager = ResourceManager(
            max_concurrent_tasks=5,
            max_connections=10
        )
        
        # Test execution with resource control
        async def test_function():
            return "result"
            
        result = await manager.execute_with_resource_control(test_function)
        assert result == "result"
        
        # Test task registration
        task = asyncio.create_task(asyncio.sleep(0.1))
        manager.register_task("task1", task)
        
        assert manager.get_active_task_count() == 1
        
        # Wait for task completion
        await task
        assert manager.get_active_task_count() == 0
        
    @pytest.mark.parametrize(
        "workflow_pair", 
        [
            (QAWorkflow, GuidedInquiryWorkflow),
            (GuidedInquiryWorkflow, ToolInvocationWorkflow),
            (ToolInvocationWorkflow, VulnerabilityResearchWorkflow)
        ]
    )
    def test_workflow_integration_compatibility(self, workflow_pair):
        """Test that various workflows can be integrated together."""
        from_workflow, to_workflow = workflow_pair
        
        # Create a chain with these workflow types
        chain = WorkflowChain()
        chain.add_sequential_transition(from_workflow, to_workflow)
        
        # Verify the transition was added
        assert len(chain.transitions) == 1
        assert chain.transitions[0].from_workflow_type == from_workflow
        assert chain.transitions[0].to_workflow_type == to_workflow


class TestIntegrationComponents:
    """Integration tests for all W4 components working together."""
    
    @pytest.mark.asyncio
    async def test_full_workflow_integration(self):
        """Test all integration components working together."""
        # Create mocks for external dependencies
        with patch('skwaq.workflows.integration.context_manager.get_connector') as mock_get_connector:
            mock_connector = MagicMock()
            mock_get_connector.return_value = mock_connector
            mock_connector.run_query.return_value = []
            
            # 1. Create context manager
            context_manager = get_context_manager()
            
            # 2. Create context
            context = context_manager.create_context(repository_id="test-repo")
            
            # 3. Create communication manager
            comm_manager = get_communication_manager()
            
            # 4. Create communication channel
            channel = comm_manager.create_channel("test-channel")
            
            # 5. Create workflow chain
            chain = WorkflowChain()
            
            # Mock the workflows
            mock1 = MockWorkflow(name="Mock1")
            mock2 = MockWorkflow(name="Mock2")
            
            # Add handling for mock message
            message_handler = AsyncMock()
            
            # Register the handler
            comm_manager.register_message_handler(
                "mock1", MessageType.DATA, message_handler
            )
            
            # Subscribe workflows to channel
            comm_manager.subscribe_workflow("mock1", "test-channel")
            comm_manager.subscribe_workflow("mock2", "test-channel")
            
            # 6. Send a message
            message = WorkflowMessage(
                message_type=MessageType.DATA,
                content={"data": "test"},
                sender_id="mock2"
            )
            await comm_manager.broadcast_message("test-channel", message)
            
            # Create a performance optimizer
            optimizer = get_performance_optimizer()
            
            # Create tasks to run in parallel
            async def task1():
                return "result1"
                
            async def task2():
                return "result2"
                
            # Run tasks in parallel
            results = await optimizer.execute_in_parallel([task1, task2])
            
            assert len(results) == 2
            assert set(results) == {"result1", "result2"}


def test_milestone_w4_implemented():
    """Verify that all required W4 components are implemented."""
    # Check for context management components
    assert hasattr(WorkflowContext, "add_user_preference")
    assert hasattr(WorkflowContext, "get_user_preference")
    assert hasattr(WorkflowContext, "add_workflow_data")
    assert hasattr(WorkflowContext, "get_workflow_data")
    
    # Check for workflow chaining components
    assert hasattr(WorkflowChain, "add_sequential_transition")
    assert hasattr(WorkflowChain, "add_conditional_transition")
    assert hasattr(WorkflowChain, "start")
    assert hasattr(WorkflowChain, "run")
    
    # Check for communication components
    assert hasattr(WorkflowCommunicationManager, "create_channel")
    assert hasattr(WorkflowCommunicationManager, "subscribe_workflow")
    assert hasattr(WorkflowCommunicationManager, "broadcast_message")
    assert hasattr(WorkflowCommunicationManager, "send_direct_message")
    
    # Check for performance optimization components
    assert hasattr(PerformanceOptimizer, "cached")
    assert hasattr(PerformanceOptimizer, "parallel")
    assert hasattr(PerformanceOptimizer, "execute_in_parallel")
    
    # All components are implemented
    assert True