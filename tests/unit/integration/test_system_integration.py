"""Unit tests for skwaq.integration.system_integration module."""

import pytest
from unittest.mock import MagicMock, patch
import time

from skwaq.integration.system_integration import (
    SystemIntegrationManager,
    EndToEndWorkflowOrchestrator,
    SystemDocumentation,
    get_system_manager
)


class TestSystemIntegrationManager:
    """Tests for the SystemIntegrationManager class."""
    
    def test_init(self):
        """Test that initialization works properly."""
        manager = SystemIntegrationManager()
        assert manager is not None
        assert hasattr(manager, '_initialized')
        assert manager._initialized is False
        assert hasattr(manager, '_components')
        assert isinstance(manager._components, dict)
        
    @patch('skwaq.integration.system_integration.get_config')
    @patch('skwaq.integration.system_integration.setup_logging')
    @patch('skwaq.integration.system_integration.get_connector')
    @patch('skwaq.integration.system_integration.OpenAIClient')
    @patch('skwaq.integration.system_integration.AgentRegistry')
    @patch('skwaq.integration.system_integration.CodeAnalyzer')
    @patch('skwaq.integration.system_integration.get_context_manager')
    @patch('skwaq.integration.system_integration.get_communication_manager')
    @patch('skwaq.integration.system_integration.get_performance_optimizer')
    @patch('skwaq.integration.system_integration.get_resource_manager')
    def test_initialize_system(self, mock_get_resource_manager, mock_get_performance_optimizer, 
                              mock_get_communication_manager, mock_get_context_manager, 
                              mock_code_analyzer, mock_agent_registry, mock_openai_client, 
                              mock_get_connector, mock_setup_logging, mock_get_config):
        """Test that system initialization works properly."""
        # Setup mocks
        mock_config = MagicMock()
        mock_config.get.return_value = "INFO"
        mock_get_config.return_value = mock_config
        
        mock_connector = MagicMock()
        mock_get_connector.return_value = mock_connector
        
        mock_openai = MagicMock()
        mock_openai_client.return_value = mock_openai
        
        mock_registry = MagicMock()
        mock_agent_registry.return_value = mock_registry
        
        mock_analyzer = MagicMock()
        mock_code_analyzer.return_value = mock_analyzer
        
        mock_context = MagicMock()
        mock_get_context_manager.return_value = mock_context
        
        mock_communication = MagicMock()
        mock_get_communication_manager.return_value = mock_communication
        
        mock_optimizer = MagicMock()
        mock_get_performance_optimizer.return_value = mock_optimizer
        
        mock_resource = MagicMock()
        mock_get_resource_manager.return_value = mock_resource
        
        # Create manager and initialize
        manager = SystemIntegrationManager()
        result = manager.initialize_system()
        
        # Verify results
        assert result is True
        assert manager._initialized is True
        assert "config" in manager._components
        assert "openai_client" in manager._components
        assert "agent_registry" in manager._components
        assert "code_analyzer" in manager._components
        assert "context_manager" in manager._components
        assert "communication_manager" in manager._components
        assert "performance_optimizer" in manager._components
        assert "resource_manager" in manager._components
        
        # Verify component initializations were called
        mock_setup_logging.assert_called_once()
        mock_get_connector.assert_called_once()
        mock_agent_registry.assert_called_once()
        mock_code_analyzer.assert_called_once()
    
    def test_get_health_status(self):
        """Test getting health status."""
        manager = SystemIntegrationManager()
        
        # Manually set components and startup time for testing
        manager._startup_time = time.time() - 60  # started 60 seconds ago
        manager._components = {
            "config": MagicMock(),
            "db_connector": MagicMock(),
            "openai_client": MagicMock(),
            "agent_registry": MagicMock(),
            "code_analyzer": MagicMock(),
            "context_manager": MagicMock(),
            "communication_manager": MagicMock(),
            "performance_optimizer": MagicMock(),
            "resource_manager": MagicMock()
        }
        
        # Set mock behavior
        manager._components["agent_registry"].get_all_agents.return_value = ["agent1", "agent2"]
        
        mock_cache = MagicMock()
        mock_cache.get_stats.return_value = {"size": 10, "hit_rate": 0.75}
        manager._components["performance_optimizer"].cache = mock_cache
        
        manager._components["resource_manager"].get_resource_usage.return_value = {"active_tasks": 5}
        
        # Mock the verify_health method to set health status
        manager._verify_health = MagicMock()
        manager._health_status = {
            "database": "healthy",
            "openai": "healthy",
            "agent_registry": "healthy",
            "registered_agents": 2,
            "overall": "healthy"
        }
        
        # Get health status
        status = manager.get_health_status()
        
        # Verify results
        assert status["overall"] == "healthy"
        assert "uptime_seconds" in status
        assert status["uptime_seconds"] >= 60
        assert "cache_stats" in status
        assert status["cache_stats"]["hit_rate"] == 0.75
        assert "resource_usage" in status
        assert status["resource_usage"]["active_tasks"] == 5
        assert manager._verify_health.called
    
    def test_get_component(self):
        """Test getting component by name."""
        manager = SystemIntegrationManager()
        
        # Set a test component
        test_component = MagicMock()
        manager._components = {"test_component": test_component}
        
        # Get components
        result = manager.get_component("test_component")
        missing = manager.get_component("missing_component")
        
        # Verify results
        assert result is test_component
        assert missing is None
    
    @patch('skwaq.integration.system_integration.logger')
    def test_shutdown(self, mock_logger):
        """Test system shutdown."""
        manager = SystemIntegrationManager()
        
        # Setup mock components
        mock_agent_registry = MagicMock()
        mock_agent_registry.cleanup = MagicMock()
        
        mock_db_connector = MagicMock()
        mock_db_connector.disconnect = MagicMock()
        
        mock_context_manager = MagicMock()
        
        manager._initialized = True
        manager._components = {
            "agent_registry": mock_agent_registry,
            "db_connector": mock_db_connector,
            "context_manager": mock_context_manager,
            "code_analyzer": MagicMock(),
            "openai_client": MagicMock()
        }
        
        # Call shutdown
        manager.shutdown()
        
        # Verify components were shut down
        mock_agent_registry.cleanup.assert_called_once()
        mock_db_connector.disconnect.assert_called_once()
        assert manager._initialized is False
        assert mock_logger.info.called


class TestEndToEndWorkflowOrchestrator:
    """Tests for the EndToEndWorkflowOrchestrator class."""
    
    def test_init(self):
        """Test initialization."""
        # Test with default parameters
        orchestrator = EndToEndWorkflowOrchestrator()
        assert orchestrator is not None
        assert orchestrator.system_manager is None
        assert orchestrator.workflows == {}
        
        # Test with system manager
        mock_manager = MagicMock()
        orchestrator = EndToEndWorkflowOrchestrator(system_manager=mock_manager)
        assert orchestrator.system_manager is mock_manager
    
    def test_register_workflow(self):
        """Test workflow registration."""
        orchestrator = EndToEndWorkflowOrchestrator()
        
        # Register a workflow
        workflow_def = {"steps": ["step1", "step2"], "type": "test"}
        orchestrator.register_workflow("test_workflow", workflow_def)
        
        # Verify it was registered
        assert "test_workflow" in orchestrator.workflows
        assert orchestrator.workflows["test_workflow"] == workflow_def
    
    def test_get_workflow(self):
        """Test getting a workflow by name."""
        orchestrator = EndToEndWorkflowOrchestrator()
        
        # Add test workflows
        workflow1 = {"type": "test1"}
        workflow2 = {"type": "test2"}
        orchestrator.workflows = {
            "workflow1": workflow1,
            "workflow2": workflow2
        }
        
        # Get workflows
        result1 = orchestrator.get_workflow("workflow1")
        result2 = orchestrator.get_workflow("workflow2")
        missing = orchestrator.get_workflow("missing")
        
        # Verify results
        assert result1 == workflow1
        assert result2 == workflow2
        assert missing is None
    
    def test_list_workflows(self):
        """Test listing all registered workflows."""
        orchestrator = EndToEndWorkflowOrchestrator()
        
        # Add test workflows
        orchestrator.workflows = {
            "workflow1": {"type": "test1"},
            "workflow2": {"type": "test2"},
            "workflow3": {"type": "test3"}
        }
        
        # List workflows
        result = orchestrator.list_workflows()
        
        # Verify results
        assert len(result) == 3
        assert set(result) == {"workflow1", "workflow2", "workflow3"}
    
    @pytest.mark.asyncio
    async def test_execute_workflow_not_found(self):
        """Test executing a non-existent workflow."""
        orchestrator = EndToEndWorkflowOrchestrator()
        
        # Try to execute a missing workflow
        with pytest.raises(ValueError):
            await orchestrator.execute_workflow("missing_workflow", {})
    
    @pytest.mark.asyncio
    @patch('skwaq.integration.system_integration.logger')
    async def test_execute_workflow(self, mock_logger):
        """Test workflow execution."""
        orchestrator = EndToEndWorkflowOrchestrator()
        
        # Register a test workflow
        orchestrator.workflows = {
            "test_workflow": {
                "scenario": "test_scenario",
                "steps": ["step1", "step2"]
            }
        }
        
        # Execute the workflow
        result = await orchestrator.execute_workflow("test_workflow", {"param": "value"})
        
        # Verify results
        assert result["workflow"] == "test_workflow"
        assert result["scenario"] == "test_scenario"
        assert result["status"] == "executed"
        assert result["parameters"] == {"param": "value"}
        assert mock_logger.info.called


class TestSystemDocumentation:
    """Tests for the SystemDocumentation class."""
    
    def test_init(self):
        """Test initialization."""
        # Test with default parameters
        with patch('os.path.dirname', return_value="/fake/path"):
            docs = SystemDocumentation()
            assert docs is not None
            assert "docs" in docs.docs_dir
        
        # Test with custom docs directory
        docs = SystemDocumentation(docs_dir="/custom/docs")
        assert docs.docs_dir == "/custom/docs"
    
    @patch('os.path.exists')
    @patch('builtins.open', new_callable=MagicMock)
    def test_get_module_documentation(self, mock_open, mock_exists):
        """Test getting module documentation."""
        docs = SystemDocumentation(docs_dir="/docs")
        
        # Setup mock for existing file
        mock_exists.return_value = True
        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = "# Module Documentation"
        mock_open.return_value = mock_file
        
        # Get documentation for existing module
        result = docs.get_module_documentation("test_module")
        
        # Verify results
        assert result == "# Module Documentation"
        mock_exists.assert_called_with("/docs/test_module.md")
        
        # Setup mock for non-existent file
        mock_exists.return_value = False
        
        # Get documentation for non-existent module
        result = docs.get_module_documentation("missing_module")
        
        # Verify results
        assert result is None
    
    @patch('os.path.exists')
    @patch('os.listdir')
    @patch('builtins.open', new_callable=MagicMock)
    def test_get_api_documentation(self, mock_open, mock_listdir, mock_exists):
        """Test getting API documentation."""
        docs = SystemDocumentation(docs_dir="/docs")
        
        # Setup mocks for API directory and file
        mock_exists.side_effect = lambda path: "api" in path
        mock_file = MagicMock()
        mock_file.__enter__.return_value.read.return_value = "# API Documentation"
        mock_open.return_value = mock_file
        mock_listdir.return_value = ["class1.md", "class2.md"]
        
        # Get documentation for specific class
        result = docs.get_api_documentation(class_name="TestClass")
        
        # Verify results
        assert result == "# API Documentation"
        
        # Get index of all API documentation
        result = docs.get_api_documentation()
        
        # Verify results
        assert "class1.md" in result
        assert "class2.md" in result
        
        # Setup mock for non-existent API directory
        mock_exists.side_effect = lambda path: False
        
        # Get documentation when API directory doesn't exist
        result = docs.get_api_documentation()
        
        # Verify results
        assert result is None
    
    @patch('os.path.exists')
    @patch('os.walk')
    def test_list_available_documentation(self, mock_walk, mock_exists):
        """Test listing available documentation."""
        docs = SystemDocumentation(docs_dir="/docs")
        
        # Setup mocks
        mock_exists.return_value = True
        mock_walk.return_value = [
            ("/docs", ["api", "workflows"], ["index.md", "readme.md"]),
            ("/docs/api", [], ["class1.md", "class2.md"]),
            ("/docs/workflows", [], ["workflow1.md"])
        ]
        
        # List available documentation
        result = docs.list_available_documentation()
        
        # Verify results
        assert "guides" in result
        assert "api" in result
        assert "workflows" in result
        assert len(result["guides"]) > 0
        assert len(result["api"]) > 0
        assert len(result["workflows"]) > 0
        
        # Setup mock for non-existent docs directory
        mock_exists.return_value = False
        
        # List documentation when directory doesn't exist
        result = docs.list_available_documentation()
        
        # Verify empty result structure
        assert "guides" in result
        assert "api" in result
        assert "architecture" in result
        assert "workflows" in result
        assert len(result["guides"]) == 0
        assert len(result["api"]) == 0
    
    @patch('builtins.open', new_callable=MagicMock)
    def test_generate_docs_index(self, mock_open):
        """Test generating documentation index."""
        docs = SystemDocumentation(docs_dir="/docs")
        
        # Override the list_available_documentation method
        docs.list_available_documentation = MagicMock(return_value={
            "guides": ["guide1.md", "guide2.md"],
            "api": ["api/class1.md"],
            "workflows": ["workflows/workflow1.md"],
            "architecture": []
        })
        
        mock_file = MagicMock()
        mock_open.return_value = mock_file
        
        # Generate index with default output path
        result = docs.generate_docs_index()
        
        # Verify results
        assert result == "/docs/index.md"
        assert mock_open.called
        
        # Generate index with custom output path
        result = docs.generate_docs_index(output_path="/custom/index.md")
        
        # Verify results
        assert result == "/custom/index.md"
        
        # Check index content
        write_calls = mock_file.__enter__.return_value.write.call_args_list
        assert len(write_calls) > 0
        index_content = write_calls[0][0][0]
        
        assert "# Skwaq Documentation Index" in index_content
        assert "## Guides" in index_content
        assert "## Api" in index_content
        assert "## Workflows" in index_content


def test_get_system_manager():
    """Test the get_system_manager function."""
    with patch('skwaq.integration.system_integration.SystemIntegrationManager') as mock_cls:
        # First call should create the instance
        manager1 = get_system_manager()
        
        # Verify instance was created
        mock_cls.assert_called_once()
        assert manager1 == mock_cls.return_value
        
        # Reset mock for next call
        mock_cls.reset_mock()
        
        # Second call should return the same instance
        manager2 = get_system_manager()
        
        # Verify no new instance was created
        mock_cls.assert_not_called()
        assert manager2 == manager1