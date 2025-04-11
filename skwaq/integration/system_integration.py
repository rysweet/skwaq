"""System integration for cohesive functionality across all components.

This module provides tools and utilities for integrating all parts of the system
together, ensuring seamless interaction between different components and efficient
resource usage.
"""

from typing import Any, Dict, List, Optional, Set, Type, Union, Callable, Awaitable
import asyncio
import time
import logging
import json
import os
from pathlib import Path

from ..agents.registry import AgentRegistry
from ..db.neo4j_connector import get_connector
from ..core.openai_client import OpenAIClient
from ..utils.config import get_config
from ..utils.logging import get_logger, setup_logging
from ..workflows.integration import (
    get_context_manager,
    get_communication_manager,
    get_performance_optimizer,
    get_resource_manager,
)

logger = get_logger(__name__)


class SystemIntegrationManager:
    """Central manager for system-wide integration and coordination.

    This class provides a centralized system for coordinating all components,
    managing shared resources, and ensuring consistent configuration across
    the entire application.
    """

    def __init__(self):
        """Initialize the system integration manager.

        Args:
            None
        """
        self._initialized = False
        self._components = {}
        self._health_status = {}
        self._startup_time = None

    def initialize_system(self, config_path: Optional[str] = None) -> bool:
        """Initialize all system components in the correct order.

        Args:
            config_path: Optional path to configuration file

        Returns:
            True if initialization was successful, False otherwise
        """
        if self._initialized:
            logger.warning("System already initialized")
            return True

        try:
            self._startup_time = time.time()

            # 1. Initialize configuration
            config = get_config(config_path)
            self._components["config"] = config

            # 2. Configure logging based on config
            log_level = config.get("log_level", "INFO")
            setup_logging(level=log_level)
            logger.info(f"Logging configured with level {log_level}")

            # 3. Initialize database connection if configured
            try:
                neo4j_connector = get_connector()
                if neo4j_connector:
                    self._components["db_connector"] = neo4j_connector
                    logger.info("Database connection established")
                else:
                    logger.warning("Database connection not configured")
            except Exception as e:
                logger.warning(f"Error initializing database connection: {e}")

            # 4. Initialize OpenAI client
            try:
                openai_client = OpenAIClient()
                self._components["openai_client"] = openai_client
                logger.info("OpenAI client initialized")
            except Exception as e:
                logger.error(f"Error initializing OpenAI client: {e}")
                return False

            # 5. Initialize agent registry
            agent_registry = AgentRegistry()
            self._components["agent_registry"] = agent_registry
            logger.info("Agent registry initialized")

            # 6. Code analyzer initialization removed
            logger.info("Code analyzer initialization skipped - module removed")

            # 7. Initialize integration managers
            context_manager = get_context_manager()
            self._components["context_manager"] = context_manager

            communication_manager = get_communication_manager()
            self._components["communication_manager"] = communication_manager

            performance_optimizer = get_performance_optimizer()
            self._components["performance_optimizer"] = performance_optimizer

            resource_manager = get_resource_manager()
            self._components["resource_manager"] = resource_manager

            logger.info("Integration managers initialized")

            # 8. Verify basic health
            self._verify_health()

            # Mark system as initialized
            self._initialized = True

            startup_duration = time.time() - self._startup_time
            logger.info(f"System initialized successfully in {startup_duration:.2f}s")
            return True

        except Exception as e:
            logger.error(f"Error during system initialization: {e}", exc_info=True)
            return False

    def _verify_health(self) -> None:
        """Verify the health of all system components."""
        # Check database connection
        if "db_connector" in self._components:
            db_connector = self._components["db_connector"]
            try:
                is_connected = db_connector.connect()
                self._health_status["database"] = (
                    "healthy" if is_connected else "unavailable"
                )
            except Exception:
                self._health_status["database"] = "error"
        else:
            self._health_status["database"] = "not_configured"

        # Check OpenAI client
        if "openai_client" in self._components:
            self._health_status["openai"] = "healthy"
        else:
            self._health_status["openai"] = "error"

        # Check agent registry
        if "agent_registry" in self._components:
            agent_registry = self._components["agent_registry"]
            self._health_status["agent_registry"] = "healthy"
            self._health_status["registered_agents"] = len(
                agent_registry.get_all_agents()
            )
        else:
            self._health_status["agent_registry"] = "error"

        # Overall system health
        if all(
            status == "healthy"
            for status in self._health_status.values()
            if isinstance(status, str)
        ):
            self._health_status["overall"] = "healthy"
        elif "error" in self._health_status.values():
            self._health_status["overall"] = "error"
        else:
            self._health_status["overall"] = "degraded"

    def get_health_status(self) -> Dict[str, Any]:
        """Get the health status of all system components.

        Returns:
            Dictionary with health status information
        """
        # Update health status
        self._verify_health()

        # Add additional metrics
        if self._startup_time:
            uptime = time.time() - self._startup_time
            self._health_status["uptime_seconds"] = uptime

        if "performance_optimizer" in self._components:
            optimizer = self._components["performance_optimizer"]
            self._health_status["cache_stats"] = optimizer.cache.get_stats()

        if "resource_manager" in self._components:
            resource_manager = self._components["resource_manager"]
            self._health_status[
                "resource_usage"
            ] = resource_manager.get_resource_usage()

        return self._health_status

    def get_component(self, component_name: str) -> Optional[Any]:
        """Get a system component by name.

        Args:
            component_name: The name of the component to retrieve

        Returns:
            The component if found, None otherwise
        """
        return self._components.get(component_name)

    def shutdown(self) -> None:
        """Perform a graceful shutdown of all system components."""
        if not self._initialized:
            logger.warning("System not initialized, nothing to shut down")
            return

        logger.info("Starting system shutdown")

        # Shutdown in reverse order of initialization

        # 1. Shutdown context and communication managers
        logger.info("Shutting down integration managers")

        # Save all active contexts
        if "context_manager" in self._components:
            context_manager = self._components["context_manager"]
            # Save any active contexts

        # 2. Code analyzer shutdown removed
        logger.info("Code analyzer shutdown skipped - module removed")

        # 3. Shutdown agent registry
        if "agent_registry" in self._components:
            logger.info("Shutting down agent registry")
            agent_registry = self._components["agent_registry"]
            agent_registry.cleanup()

        # 4. Shutdown OpenAI client
        if "openai_client" in self._components:
            logger.info("Shutting down OpenAI client")
            # No explicit cleanup needed

        # 5. Shutdown database connection
        if "db_connector" in self._components:
            logger.info("Shutting down database connection")
            db_connector = self._components["db_connector"]
            db_connector.disconnect()

        logger.info("System shutdown complete")
        self._initialized = False


class EndToEndWorkflowOrchestrator:
    """Orchestrates end-to-end workflows across system components.

    This class provides functionality for creating and executing complex
    workflows that integrate multiple components of the system to perform
    end-to-end tasks.
    """

    def __init__(self, system_manager: Optional[SystemIntegrationManager] = None):
        """Initialize the end-to-end workflow orchestrator.

        Args:
            system_manager: Optional system integration manager
        """
        self.system_manager = system_manager
        self.workflows = {}

    def register_workflow(self, name: str, workflow_definition: Dict[str, Any]) -> None:
        """Register a new end-to-end workflow.

        Args:
            name: The name of the workflow
            workflow_definition: The definition of the workflow
        """
        self.workflows[name] = workflow_definition
        logger.info(f"Registered end-to-end workflow: {name}")

    def get_workflow(self, name: str) -> Optional[Dict[str, Any]]:
        """Get a workflow definition by name.

        Args:
            name: The name of the workflow

        Returns:
            The workflow definition, or None if not found
        """
        return self.workflows.get(name)

    def list_workflows(self) -> List[str]:
        """List all registered workflows.

        Returns:
            List of workflow names
        """
        return list(self.workflows.keys())

    async def execute_workflow(
        self, workflow_name: str, parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute an end-to-end workflow with the given parameters.

        Args:
            workflow_name: The name of the workflow to execute
            parameters: Parameters for the workflow execution

        Returns:
            Results of the workflow execution

        Raises:
            ValueError: If the workflow is not found
        """
        if workflow_name not in self.workflows:
            raise ValueError(f"Workflow '{workflow_name}' not found")

        workflow_definition = self.workflows[workflow_name]

        try:
            # Create workflow execution plan based on definition
            from ..workflows.integration import WorkflowExecutionPlan

            plan = WorkflowExecutionPlan(name=workflow_name)

            # Configure the plan based on the workflow definition
            # This is a simplified version - in a real implementation,
            # you would create chains and transitions based on the definition

            # Execute the plan
            results = {}
            if "scenario" in workflow_definition:
                scenario = workflow_definition["scenario"]

                # In a real implementation, you would await the results from the plan execution

                results = {
                    "workflow": workflow_name,
                    "scenario": scenario,
                    "status": "executed",
                    "parameters": parameters,
                }

            logger.info(f"Executed end-to-end workflow: {workflow_name}")
            return results

        except Exception as e:
            logger.error(f"Error executing workflow '{workflow_name}': {e}")
            return {"workflow": workflow_name, "status": "error", "error": str(e)}


class SystemDocumentation:
    """System-wide documentation management.

    This class provides utilities for accessing and managing documentation
    across all system components, including API documentation, usage guides,
    and architecture documentation.
    """

    def __init__(self, docs_dir: Optional[str] = None):
        """Initialize the system documentation.

        Args:
            docs_dir: Optional directory containing documentation files
        """
        self.docs_dir = docs_dir or os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "docs"
        )

    def get_module_documentation(self, module_name: str) -> Optional[str]:
        """Get documentation for a specific module.

        Args:
            module_name: The name of the module

        Returns:
            The documentation content, or None if not found
        """
        module_path = os.path.join(self.docs_dir, f"{module_name}.md")
        if os.path.exists(module_path):
            with open(module_path, "r") as f:
                return f.read()
        return None

    def get_api_documentation(self, class_name: Optional[str] = None) -> Optional[str]:
        """Get API documentation for a specific class or all classes.

        Args:
            class_name: Optional name of the class to get documentation for

        Returns:
            The documentation content, or None if not found
        """
        api_path = os.path.join(self.docs_dir, "api")
        if not os.path.exists(api_path):
            return None

        if class_name:
            class_path = os.path.join(api_path, f"{class_name}.md")
            if os.path.exists(class_path):
                with open(class_path, "r") as f:
                    return f.read()
            return None

        # Return index of all API documentation
        api_files = [f for f in os.listdir(api_path) if f.endswith(".md")]
        return f"Available API documentation: {', '.join(api_files)}"

    def list_available_documentation(self) -> Dict[str, List[str]]:
        """List all available documentation.

        Returns:
            Dictionary with documentation categories as keys and lists of
            available documentation files as values
        """
        result = {"guides": [], "api": [], "architecture": [], "workflows": []}

        if not os.path.exists(self.docs_dir):
            return result

        # Get all markdown files in the docs directory
        for root, _, files in os.walk(self.docs_dir):
            rel_path = os.path.relpath(root, self.docs_dir)
            for file in files:
                if file.endswith(".md"):
                    if rel_path == ".":
                        category = "guides"
                    else:
                        category = rel_path.split(os.path.sep)[0]

                    if category in result:
                        result[category].append(os.path.join(rel_path, file))
                    else:
                        result["guides"].append(os.path.join(rel_path, file))

        return result

    def generate_docs_index(self, output_path: Optional[str] = None) -> str:
        """Generate an index of all available documentation.

        Args:
            output_path: Optional path to output the index

        Returns:
            The path to the generated index file
        """
        available_docs = self.list_available_documentation()

        # Generate index content
        lines = ["# Skwaq Documentation Index", ""]

        for category, docs in available_docs.items():
            if docs:
                lines.append(f"## {category.title()}")
                lines.append("")
                for doc in sorted(docs):
                    doc_name = os.path.basename(doc).replace(".md", "")
                    doc_path = doc
                    lines.append(f"- [{doc_name}]({doc_path})")
                lines.append("")

        content = "\n".join(lines)

        # Write index to file if output path is provided
        if output_path:
            with open(output_path, "w") as f:
                f.write(content)
            return output_path

        # Otherwise, just return the content
        index_path = os.path.join(self.docs_dir, "index.md")
        with open(index_path, "w") as f:
            f.write(content)

        return index_path


# Singleton instance
_system_manager = None


def get_system_manager() -> SystemIntegrationManager:
    """Get the singleton system integration manager instance.

    Returns:
        The SystemIntegrationManager instance
    """
    global _system_manager
    if _system_manager is None:
        _system_manager = SystemIntegrationManager()
    return _system_manager
