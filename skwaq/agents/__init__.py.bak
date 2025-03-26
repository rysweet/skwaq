"""Agents module for the Skwaq vulnerability assessment copilot.

This module contains the implementation of the various specialized agents
that work together to perform vulnerability assessment tasks.
"""

from typing import Dict, Any, Optional, List, Type

# Base agent framework
from .base import (
    BaseAgent,
    AutogenChatAgent,
    AgentState,
    AgentContext,
)

# Agent registry
from .registry import AgentRegistry

# AutoGen integration
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

# Legacy agent events
from .vulnerability_events import (
    VulnResearchEvent,
    CodeAnalysisEvent,
    KnowledgeRetrievalEvent,
    VulnerabilityFindingEvent,
)

# Core agent implementations
from .orchestrator_agent import OrchestratorAgent
from .knowledge_agent import KnowledgeAgent
from .code_analysis_agent import CodeAnalysisAgent
from .critic_agent import CriticAgent

# Legacy agents and framework
from .base_vulnerability_agent import BaseVulnerabilityAgent
from .pattern_matching_agent import PatternMatchingAgent
from .semantic_analysis_agent import SemanticAnalysisAgent
from .legacy_code_analysis_agent import CodeAnalysisAgent as LegacyCodeAnalysisAgent
from .legacy_critic_agent import CriticAgent as LegacyCriticAgent
from .legacy_knowledge_agent import KnowledgeRetrievalAgent
from .orchestration_agent import OrchestrationAgent
from .skwaq_agent import SkwaqAgent
from .agent_factory import create_orchestrator_agent
from .vulnerability_research_agent import VulnerabilityResearchAgent

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
    
    # Legacy events
    "VulnResearchEvent",
    "CodeAnalysisEvent",
    "KnowledgeRetrievalEvent",
    "VulnerabilityFindingEvent",
    
    # Core agents
    "OrchestratorAgent",
    "KnowledgeAgent",
    "CodeAnalysisAgent",
    "CriticAgent",
    
    # Legacy agents
    "BaseVulnerabilityAgent",
    "PatternMatchingAgent",
    "SemanticAnalysisAgent",
    "LegacyCodeAnalysisAgent",
    "LegacyCriticAgent",
    "KnowledgeRetrievalAgent",
    "OrchestrationAgent",
    "SkwaqAgent",
    "create_orchestrator_agent",
    "VulnerabilityResearchAgent",
]