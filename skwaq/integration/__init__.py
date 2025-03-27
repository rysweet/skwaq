"""System integration module for Skwaq vulnerability assessment copilot.

This module provides components for integrating all parts of the system together,
ensuring seamless interaction between agents, workflows, databases, and external tools.
"""

from .system_integration import (
    SystemIntegrationManager,
    EndToEndWorkflowOrchestrator,
    SystemDocumentation,
    get_system_manager
)

from .performance_optimization import (
    QueryOptimizer,
    DatabaseOptimization,
    MemoryOptimization,
    get_query_optimizer,
    get_db_optimization,
    get_memory_optimization
)

from .e2e_testing import (
    E2ETestScenario,
    AsyncE2ETestScenario,
    E2ETestRunner,
    PredefinedScenarios,
    get_test_runner
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
    "get_test_runner"
]