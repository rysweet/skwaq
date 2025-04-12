"""Agents module for the Skwaq vulnerability assessment copilot.

This module contains the implementation of the various specialized agents
that work together to perform vulnerability assessment tasks.
"""

from typing import TYPE_CHECKING

from .agent_factory import create_orchestrator_agent

# AutoGen integration
from .autogen_integration import (
    AutogenAgentAdapter,
    AutogenEventBridge,
    AutogenGroupChatAdapter,
)

# Base agent framework
from .base import AgentContext, AgentState, AutogenChatAgent, BaseAgent
from .code_analysis_agent import CodeAnalysisAgent
from .critic_agent import CriticAgent

# Agent communication events
from .events import AgentCommunicationEvent, Task, TaskAssignmentEvent, TaskResultEvent
from .knowledge_agent import KnowledgeAgent

# Core agent implementations
from .orchestrator_agent import OrchestratorAgent

# Agent registry
from .registry import AgentRegistry
from .vulnerability_research_agent import VulnerabilityResearchAgent

# No typing imports needed at the module level







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
    "create_orchestrator_agent",
    "VulnerabilityResearchAgent",
]
