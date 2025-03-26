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

# Agent communication events
from .events import (
    AgentCommunicationEvent,
    TaskAssignmentEvent,
    TaskResultEvent,
    Task,
)

# Core agent implementations
from .orchestrator_agent import OrchestratorAgent
from .knowledge_agent import KnowledgeAgent
from .code_analysis_agent import CodeAnalysisAgent
from .critic_agent import CriticAgent

# Legacy import to maintain compatibility
from .vulnerability_agents import (
    BaseVulnerabilityAgent,
    PatternMatchingAgent,
    SemanticAnalysisAgent,
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
    
    # Agent communication
    "AgentCommunicationEvent",
    "TaskAssignmentEvent",
    "TaskResultEvent",
    "Task",
    
    # Core agents
    "OrchestratorAgent",
    "KnowledgeAgent",
    "CodeAnalysisAgent",
    "CriticAgent",
    
    # Legacy agents
    "BaseVulnerabilityAgent",
    "PatternMatchingAgent",
    "SemanticAnalysisAgent",
    "SkwaqAgent",
]
