"""Agents module for the Skwaq vulnerability assessment copilot.

This module contains the implementation of the various specialized agents
that work together to perform vulnerability assessment tasks.
"""

from typing import Dict, Any, Optional, List, Type

from .base import (
    BaseAgent,
    AutogenChatAgent,
    AgentState,
    AgentContext,
)

from .registry import AgentRegistry

from .autogen_integration import (
    AutogenEventBridge,
    AutogenAgentAdapter,
    AutogenGroupChatAdapter,
)

# Legacy import to maintain compatibility
from .vulnerability_agents import (
    BaseVulnerabilityAgent,
    CodeAnalysisAgent,
    KnowledgeRetrievalAgent,
    PatternMatchingAgent,
    SemanticAnalysisAgent,
    CriticAgent,
    OrchestrationAgent,
    SkwaqAgent,
)

__all__ = [
    # Base agent framework
    "BaseAgent",
    "AutogenChatAgent",
    "AgentState",
    "AgentContext",
    "AgentRegistry",
    
    # AutoGen integration
    "AutogenEventBridge",
    "AutogenAgentAdapter",
    "AutogenGroupChatAdapter",
    
    # Legacy agents
    "BaseVulnerabilityAgent",
    "CodeAnalysisAgent",
    "KnowledgeRetrievalAgent",
    "PatternMatchingAgent",
    "SemanticAnalysisAgent",
    "CriticAgent",
    "OrchestrationAgent",
    "SkwaqAgent",
]
