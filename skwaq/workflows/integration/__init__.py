"""Integration components for workflow chaining and transition handling.

This module provides components for integrating multiple workflows together,
enabling seamless transitions, context preservation, and data sharing between
different workflows.
"""

from .context_manager import (
    WorkflowContext,
    ContextManager,
    get_context_manager
)

from .workflow_chain import (
    TransitionType,
    WorkflowTransition,
    WorkflowChain,
    WorkflowExecutionPlan
)

from .workflow_communication import (
    CommunicationChannel,
    MessageType,
    WorkflowMessage,
    WorkflowCommunicationEvent,
    WorkflowCommunicationManager,
    get_communication_manager
)

from .performance_optimizer import (
    WorkflowCache,
    PerformanceOptimizer,
    ResourceManager,
    get_performance_optimizer,
    get_resource_manager
)

__all__ = [
    # Context Management
    "WorkflowContext",
    "ContextManager",
    "get_context_manager",
    
    # Workflow Chaining
    "TransitionType",
    "WorkflowTransition",
    "WorkflowChain",
    "WorkflowExecutionPlan",
    
    # Workflow Communication
    "CommunicationChannel",
    "MessageType",
    "WorkflowMessage",
    "WorkflowCommunicationEvent", 
    "WorkflowCommunicationManager",
    "get_communication_manager",
    
    # Performance Optimization
    "WorkflowCache",
    "PerformanceOptimizer",
    "ResourceManager",
    "get_performance_optimizer",
    "get_resource_manager"
]