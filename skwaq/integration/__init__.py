"""System integration module for Skwaq vulnerability assessment copilot.

This module provides components for integrating all parts of the system together,
ensuring seamless interaction between agents, workflows, databases, and external tools.
"""

from .e2e_testing import (
    AsyncE2ETestScenario,
    E2ETestRunner,
    E2ETestScenario,
    PredefinedScenarios,
    get_test_runner,
)
from .performance_optimization import (
    DatabaseOptimization,
    MemoryOptimization,
    QueryOptimizer,
    get_db_optimization,
    get_memory_optimization,
    get_query_optimizer,
)
from .system_integration import (
    EndToEndWorkflowOrchestrator,
    SystemDocumentation,
    SystemIntegrationManager,
    get_system_manager,
)

__all__ = [
    # System Integration
    "SystemIntegrationManager",
    "EndToEndWorkflowOrchestrator",
    "SystemDocumentation",
    "get_system_manager",
    # Performance Optimization
    "QueryOptimizer",
    "DatabaseOptimization",
    "MemoryOptimization",
    "get_query_optimizer",
    "get_db_optimization",
    "get_memory_optimization",
    # End-to-End Testing
    "E2ETestScenario",
    "AsyncE2ETestScenario",
    "E2ETestRunner",
    "PredefinedScenarios",
    "get_test_runner",
]
