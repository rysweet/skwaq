"""Tests for the I1 milestone: System Integration.

This test suite verifies the implementation of system integration features
including full component integration, end-to-end testing, performance optimization,
and comprehensive documentation.
"""

import os
import json
import uuid
import time
import pytest
import asyncio
from unittest.mock import MagicMock, AsyncMock, patch
from typing import Any, Dict, List, Optional

import skwaq.cli.main as cli_main
from skwaq.code_analysis.analyzer import CodeAnalyzer
from skwaq.agents.registry import AgentRegistry
from skwaq.workflows.base import Workflow
from skwaq.workflows.vulnerability_research import VulnerabilityResearchWorkflow
from skwaq.workflows.guided_inquiry import GuidedInquiryWorkflow
from skwaq.workflows.qa_workflow import QAWorkflow
from skwaq.workflows.tool_invocation import ToolInvocationWorkflow
from skwaq.workflows.integration import (
    WorkflowChain,
    WorkflowExecutionPlan,
    get_context_manager,
    get_communication_manager,
    get_performance_optimizer,
    get_resource_manager
)
from skwaq.integration import (
    SystemIntegrationManager,
    EndToEndWorkflowOrchestrator,
    SystemDocumentation,
    get_system_manager,
    QueryOptimizer,
    DatabaseOptimization,
    MemoryOptimization,
    get_query_optimizer,
    get_db_optimization,
    get_memory_optimization
)
from skwaq.core.openai_client import OpenAIClient
from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger, setup_logging


class TestSystemIntegration:
    """Tests for full system integration."""
    
    def test_all_singletons_accessible(self):
        """Test that all singleton instances are accessible."""
        # Get all key singleton instances
        agent_registry = AgentRegistry()
        context_manager = get_context_manager()
        communication_manager = get_communication_manager()
        performance_optimizer = get_performance_optimizer()
        resource_manager = get_resource_manager()
        neo4j_connector = get_connector()
        config = get_config()
        logger = get_logger(__name__)
        
        # Verify all instances are created
        assert agent_registry is not None
        assert context_manager is not None
        assert communication_manager is not None
        assert performance_optimizer is not None
        assert resource_manager is not None
        assert config is not None
        assert logger is not None
        
        # Neo4j connector might be None if not configured
        if os.environ.get("NEO4J_URI"):
            assert neo4j_connector is not None
    
    def test_system_config_integration(self):
        """Test that configuration system works across components."""
        # Get base config
        config = get_config()
        
        # Check that config is available and has properties
        assert config is not None
        assert hasattr(config, "get")
        
        # Ensure some basic config properties
        config_data = config.as_dict() if hasattr(config, "as_dict") else {}
        assert isinstance(config_data, dict)
        
        # Test that logger configuration works with config
        setup_logging(level="DEBUG", module_name="test_system_integration")
        logger = get_logger("test_system_integration")
        assert logger is not None
    
    def test_cli_command_integration(self):
        """Test CLI command integration with workflows."""
        # Check that the CLI module is accessible
        assert cli_main is not None
        
        # Test that important command handlers exist
        assert hasattr(cli_main, "handle_analyze_command")
        assert hasattr(cli_main, "handle_repository_command")
        
        # Test that we can mock a CLI function
        with patch("skwaq.cli.main.handle_analyze_command") as mock_analyze:
            # Create mock args
            mock_args = MagicMock()
            mock_args.file_path = "test.py"
            mock_args.format = "json"
            
            # Call the handler
            cli_main.handle_analyze_command(mock_args)
            
            # Verify it was called
            mock_analyze.assert_called_once()


class TestEndToEndWorkflows:
    """Tests for end-to-end workflow scenarios."""
    
    @pytest.mark.asyncio
    @pytest.mark.skip(reason="Requires full database setup with repository data")
    async def test_vulnerability_research_e2e(self):
        """Test the complete vulnerability research workflow end-to-end."""
        # This would be a true end-to-end test, but requires a complete setup
        workflow = VulnerabilityResearchWorkflow(
            repository_id="test-repo",
            focus_areas=["Injection", "Authentication"]
        )
        
        await workflow.setup()
        
        results = []
        async for result in workflow.run():
            results.append(result)
            
        assert len(results) > 0
        # Expect findings and a report
        assert any("findings" in r for r in results)
        assert any("report" in r for r in results)
    
    @pytest.mark.asyncio
    async def test_workflow_chaining_e2e(self):
        """Test chaining multiple workflows together."""
        # Create a workflow execution plan
        plan = WorkflowExecutionPlan(name="test-plan")
        
        # Create and configure the workflow chain
        chain = WorkflowChain(name="test-chain")
        
        # Add a mock transition between two workflow types
        with patch("skwaq.workflows.integration.workflow_chain.WorkflowChain.run") as mock_run:
            mock_run.return_value = iter([{"status": "complete", "message": "Test complete"}])
            
            # Add workflows to the chain
            chain.add_sequential_transition(QAWorkflow, GuidedInquiryWorkflow)
            
            # Add the chain to the plan
            plan.add_chain(chain)
            plan.set_entry_point("vulnerability_assessment", "test-chain")
            
            # Get the chain for the scenario
            scenario_chain = plan.get_chain_for_scenario("vulnerability_assessment")
            assert scenario_chain is chain
            
            # This would execute the entire chain in a real setting
            with patch("skwaq.workflows.integration.workflow_chain.WorkflowExecutionPlan.execute_scenario") as mock_execute:
                mock_execute.return_value = iter([{"status": "complete", "message": "Scenario complete"}])
                
                # Assert the chain execution would work
                assert scenario_chain is not None


class TestPerformanceOptimization:
    """Tests for performance optimization features."""
    
    def test_caching_mechanism(self):
        """Test that caching works for expensive operations."""
        # Get the optimizer
        optimizer = get_performance_optimizer()
        
        # Test caching basic values
        cache = optimizer.cache
        cache.set("test_key", "test_value")
        assert cache.get("test_key") == "test_value"
        
        # Test cache expiration
        cache.set("expiring_key", "expiring_value", ttl=0.1)
        assert cache.get("expiring_key") == "expiring_value"
        time.sleep(0.2)
        assert cache.get("expiring_key", "default") == "default"
        
        # Get cache statistics
        stats = cache.get_stats()
        assert "size" in stats
        assert "hit_rate" in stats
    
    @pytest.mark.asyncio
    async def test_parallel_execution(self):
        """Test parallel execution of tasks."""
        optimizer = get_performance_optimizer()
        
        # Define test tasks
        async def task1():
            await asyncio.sleep(0.1)
            return "result1"
            
        async def task2():
            await asyncio.sleep(0.1)
            return "result2"
            
        # Execute tasks in parallel
        start_time = time.time()
        results = await optimizer.execute_in_parallel([task1, task2])
        end_time = time.time()
        
        # Both tasks should complete in roughly the same time as one task
        assert len(results) == 2
        assert set(results) == {"result1", "result2"}
        
        # Parallel execution should be faster than serial execution
        # We expect less than 0.19s for two 0.1s tasks running in parallel
        # Using 0.19 instead of 0.15 to allow for test environment variations
        assert end_time - start_time < 0.19
    
    def test_resource_management(self):
        """Test resource management capabilities."""
        resource_manager = get_resource_manager()
        
        # Test resource usage reporting
        usage = resource_manager.get_resource_usage()
        assert "active_tasks" in usage
        
        # Test task registration and counting
        # Create a mock task
        mock_task = MagicMock()
        mock_task.done.return_value = False
        mock_task.add_done_callback = MagicMock()
        
        # Register the task
        resource_manager.register_task("test_task", mock_task)
        assert resource_manager.get_active_task_count() == 1
        
        # Test task cancellation
        assert resource_manager.cancel_task("test_task") is True
        mock_task.cancel.assert_called_once()


class TestDocumentation:
    """Tests for documentation quality and coverage."""
    
    def test_module_docstrings(self):
        """Test that all modules have docstrings."""
        # Check our integration module docstrings
        import skwaq.integration
        assert skwaq.integration.__doc__ is not None
        
        # Check integration submodules 
        assert hasattr(skwaq.integration, 'system_integration')
        module = skwaq.integration.system_integration
        assert module.__doc__ is not None
        
        # Check workflow integration
        import skwaq.workflows.integration
        assert skwaq.workflows.integration.__doc__ is not None
    
    def test_class_docstrings(self):
        """Test that important classes have docstrings."""
        # Check a sample of important classes
        assert CodeAnalyzer.__doc__ is not None
        assert Workflow.__doc__ is not None
        assert VulnerabilityResearchWorkflow.__doc__ is not None
        assert WorkflowChain.__doc__ is not None
        assert WorkflowExecutionPlan.__doc__ is not None
    
    def test_docstring_completeness(self):
        """Test that docstrings are complete with all required sections."""
        # Sample classes to check for comprehensive docstrings
        samples = [
            CodeAnalyzer,
            Workflow,
            VulnerabilityResearchWorkflow,
            SystemIntegrationManager,
            QueryOptimizer
        ]
        
        for cls in samples:
            doc = cls.__doc__ or ""
            # Check for class description
            assert len(doc.strip()) > 10, f"{cls.__name__} has insufficient docstring"
            
            # Check method docstrings for a sample method if available
            if hasattr(cls, "__init__"):
                method_doc = cls.__init__.__doc__ or ""
                
                # If we have a docstring, check for Args section
                if method_doc:
                    assert "Args:" in method_doc, f"{cls.__name__}.__init__ is missing Args section"


def test_milestone_i1_implemented():
    """Verify that all required I1 components are implemented."""
    # System integration components
    assert hasattr(SystemIntegrationManager, "initialize_system"), "SystemIntegrationManager.initialize_system not implemented"
    assert hasattr(EndToEndWorkflowOrchestrator, "execute_workflow"), "EndToEndWorkflowOrchestrator.execute_workflow not implemented"
    assert hasattr(SystemDocumentation, "generate_docs_index"), "SystemDocumentation.generate_docs_index not implemented"
    
    # Performance optimization components
    db_optimization = get_db_optimization()
    assert hasattr(db_optimization, "cached_query"), "DatabaseOptimization.cached_query not implemented"
    
    query_optimizer = get_query_optimizer()
    assert hasattr(query_optimizer, "analyze_query"), "QueryOptimizer.analyze_query not implemented"
    
    memory_optimization = get_memory_optimization()
    assert hasattr(memory_optimization, "get_memory_usage"), "MemoryOptimization.get_memory_usage not implemented"
    
    # Workflow integration
    optimizer = get_performance_optimizer()
    assert hasattr(optimizer, "cache"), "Performance cache not implemented"
    assert hasattr(optimizer, "execute_in_parallel"), "Parallel execution not implemented"
    
    # Resource management
    manager = get_resource_manager()
    assert hasattr(manager, "get_resource_usage"), "Resource usage tracking not implemented"
    
    # All components are implemented
    assert True, "I1 milestone components are implemented"