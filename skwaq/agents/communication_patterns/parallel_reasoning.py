"""Parallel Reasoning communication pattern for agents.

This module implements the Parallel Reasoning pattern, which enables multiple
agents to analyze the same problem independently and then synthesize their findings.
"""

import asyncio
from typing import Dict, List, Any, Optional, Callable, Awaitable, Type, Set, Union
import json
import enum
import logging
import time
import uuid

from autogen_core.agent import Agent, ChatAgent
from autogen_core.event import BaseEvent, Event, EventHook, register_hook

from ..events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task
from ..base import BaseAgent
from ...utils.logging import get_logger, LogEvent

logger = get_logger(__name__)


class ReasoningPriority(enum.Enum):
    """Priority levels for parallel reasoning tasks."""
    
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisEvent(AgentCommunicationEvent):
    """Event for sharing analysis results in parallel reasoning."""

    def __init__(
        self,
        sender_id: str,
        coordinator_id: str,
        reasoning: str,
        conclusion: str,
        reasoning_id: str,
        evidence: Optional[List[str]] = None,
        confidence: float = 0.5,
        priority: ReasoningPriority = ReasoningPriority.MEDIUM,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an analysis event.

        Args:
            sender_id: ID of the sending agent
            coordinator_id: ID of the coordinating agent
            reasoning: The reasoning process text
            conclusion: The conclusion reached
            reasoning_id: Unique ID for this reasoning task
            evidence: Supporting evidence for the conclusion
            confidence: Confidence level (0.0-1.0)
            priority: Priority of this analysis
            metadata: Additional metadata
        """
        analysis_metadata = metadata or {}
        analysis_metadata.update({
            "conclusion": conclusion,
            "evidence": evidence or [],
            "confidence": confidence,
            "priority": priority.value,
            "reasoning_id": reasoning_id,
            "pattern": "parallel_reasoning"
        })

        super().__init__(
            sender_id=sender_id,
            receiver_id=coordinator_id,
            message=reasoning,
            message_type="reasoning_analysis",
            metadata=analysis_metadata,
        )
        self.reasoning = reasoning
        self.conclusion = conclusion
        self.evidence = evidence or []
        self.confidence = confidence
        self.priority = priority
        self.reasoning_id = reasoning_id


class SynthesisEvent(AgentCommunicationEvent):
    """Event for communicating a synthesis of parallel analyses."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        synthesis: str,
        final_conclusion: str,
        supporting_analyses: List[Dict[str, Any]],
        reasoning_id: str,
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a synthesis event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            synthesis: The synthesized analysis text
            final_conclusion: The final conclusion
            supporting_analyses: List of supporting analyses
            reasoning_id: Unique ID for this reasoning task
            confidence: Confidence level (0.0-1.0)
            metadata: Additional metadata
        """
        synthesis_metadata = metadata or {}
        synthesis_metadata.update({
            "final_conclusion": final_conclusion,
            "supporting_analyses": supporting_analyses,
            "confidence": confidence,
            "reasoning_id": reasoning_id,
            "pattern": "parallel_reasoning"
        })

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=synthesis,
            message_type="reasoning_synthesis",
            metadata=synthesis_metadata,
        )
        self.synthesis = synthesis
        self.final_conclusion = final_conclusion
        self.supporting_analyses = supporting_analyses
        self.confidence = confidence
        self.reasoning_id = reasoning_id


class ParallelReasoningPattern:
    """Implements the Parallel Reasoning communication pattern.

    This pattern allows multiple agents to analyze the same problem
    independently and then synthesizes their findings.
    """

    def __init__(
        self, 
        analysis_timeout: float = 180.0,
        synthesis_timeout: float = 120.0,
        min_analyses: int = 2
    ):
        """Initialize the Parallel Reasoning pattern.

        Args:
            analysis_timeout: Timeout in seconds for analysis phase
            synthesis_timeout: Timeout in seconds for synthesis phase
            min_analyses: Minimum number of analyses required
        """
        self.analysis_timeout = analysis_timeout
        self.synthesis_timeout = synthesis_timeout
        self.min_analyses = min_analyses
        self.current_reasoning: Dict[str, Dict[str, Any]] = {}
        
    @LogEvent("parallel_reasoning_started")
    async def execute(
        self,
        analyst_agents: List[BaseAgent],
        coordinator_agent: BaseAgent,
        problem: str,
        context: Optional[Dict[str, Any]] = None,
        task: Optional[Task] = None,
        priority: ReasoningPriority = ReasoningPriority.MEDIUM,
    ) -> Dict[str, Any]:
        """Execute parallel reasoning across multiple agents.

        Args:
            analyst_agents: List of agents to perform analysis
            coordinator_agent: Agent to coordinate and synthesize results
            problem: The problem to analyze
            context: Additional context for the problem
            task: Optional task associated with this reasoning
            priority: Priority level for this reasoning

        Returns:
            Dictionary with reasoning results
        """
        if len(analyst_agents) < self.min_analyses:
            raise ValueError(f"At least {self.min_analyses} analyst agents are required")
            
        # Generate unique reasoning ID
        reasoning_id = f"reasoning_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        # Initialize reasoning structure
        reasoning_structure = {
            "reasoning_id": reasoning_id,
            "problem": problem,
            "task_id": task.task_id if task else None,
            "context": context or {},
            "priority": priority.value,
            "participants": {
                "analysts": [agent.agent_id for agent in analyst_agents],
                "coordinator": coordinator_agent.agent_id
            },
            "analyses": [],
            "synthesis": None,
            "completion_time": None,
            "completed": False
        }
        
        self.current_reasoning[reasoning_id] = reasoning_structure
        
        # Set up coordination primitives
        analysis_complete = asyncio.Event()
        synthesis_complete = asyncio.Event()
        
        # Track analyses
        analyses: Dict[str, AnalysisEvent] = {}
        
        # Define event handler for analysis events
        async def _handle_analysis(event: AnalysisEvent) -> None:
            if not isinstance(event, AnalysisEvent):
                return
                
            if event.reasoning_id != reasoning_id:
                return
                
            # Record this analysis
            analyses[event.sender_id] = event
            
            # Check if we have enough analyses
            if len(analyses) >= len(analyst_agents):
                analysis_complete.set()
            elif len(analyses) >= self.min_analyses:
                # We have the minimum number of analyses
                # Check if high priority analyses are complete
                high_priority_complete = all(
                    agent.agent_id in analyses
                    for agent in analyst_agents
                    if getattr(agent, "priority", ReasoningPriority.MEDIUM) 
                       in [ReasoningPriority.HIGH, ReasoningPriority.CRITICAL]
                )
                
                if high_priority_complete:
                    analysis_complete.set()
        
        # Define event handler for synthesis events
        async def _handle_synthesis(event: SynthesisEvent) -> None:
            if not isinstance(event, SynthesisEvent):
                return
                
            if event.reasoning_id != reasoning_id:
                return
                
            # Record the synthesis
            reasoning_structure["synthesis"] = {
                "text": event.synthesis,
                "conclusion": event.final_conclusion,
                "confidence": event.confidence,
                "supporting_analyses": event.supporting_analyses
            }
            
            # Mark as complete
            synthesis_complete.set()
            
        # Register event handlers
        for agent in analyst_agents:
            agent.register_event_handler(AnalysisEvent, _handle_analysis)
            
        coordinator_agent.register_event_handler(SynthesisEvent, _handle_synthesis)
        
        try:
            # Start analysis phase
            await self._start_analysis_phase(
                analyst_agents,
                coordinator_agent,
                problem,
                context or {},
                reasoning_id,
                priority
            )
            
            # Wait for analysis phase to complete or timeout
            try:
                await asyncio.wait_for(analysis_complete.wait(), self.analysis_timeout)
                logger.info(f"Analysis phase completed with {len(analyses)} analyses")
            except asyncio.TimeoutError:
                logger.warning(f"Analysis phase timed out with {len(analyses)}/{len(analyst_agents)} analyses")
                if len(analyses) < self.min_analyses:
                    reasoning_structure["timeout"] = "analysis_insufficient"
                    reasoning_structure["completed"] = False
                    return reasoning_structure
            
            # Record completed analyses
            for analysis in analyses.values():
                analysis_data = {
                    "agent_id": analysis.sender_id,
                    "reasoning": analysis.reasoning,
                    "conclusion": analysis.conclusion,
                    "evidence": analysis.evidence,
                    "confidence": analysis.confidence,
                    "priority": analysis.priority.value
                }
                reasoning_structure["analyses"].append(analysis_data)
            
            # Start synthesis phase
            await self._start_synthesis_phase(
                coordinator_agent,
                reasoning_structure["analyses"],
                problem,
                context or {},
                reasoning_id
            )
            
            # Wait for synthesis phase to complete or timeout
            try:
                await asyncio.wait_for(synthesis_complete.wait(), self.synthesis_timeout)
                logger.info(f"Synthesis phase completed successfully")
            except asyncio.TimeoutError:
                logger.warning(f"Synthesis phase timed out")
                reasoning_structure["timeout"] = "synthesis"
                
            # Mark as completed
            reasoning_structure["completed"] = True
            reasoning_structure["completion_time"] = time.time()
            
            return reasoning_structure
        finally:
            # Clean up event handlers
            for agent in analyst_agents:
                agent.deregister_event_handler(AnalysisEvent, _handle_analysis)
                
            coordinator_agent.deregister_event_handler(SynthesisEvent, _handle_synthesis)
    
    async def _start_analysis_phase(
        self,
        analyst_agents: List[BaseAgent],
        coordinator_agent: BaseAgent,
        problem: str,
        context: Dict[str, Any],
        reasoning_id: str,
        priority: ReasoningPriority
    ) -> None:
        """Start the analysis phase with all analyst agents.

        Args:
            analyst_agents: Agents to perform analysis
            coordinator_agent: Coordinating agent
            problem: Problem description
            context: Additional context
            reasoning_id: Unique reasoning ID
            priority: Task priority
        """
        # Assign analysis tasks to all analyst agents
        for agent in analyst_agents:
            # Create a task assignment event
            task_event = TaskAssignmentEvent(
                sender_id=coordinator_agent.agent_id,
                receiver_id=agent.agent_id,
                task_id=f"{reasoning_id}_{agent.agent_id}",
                task_type="parallel_analysis",
                task_description=f"Analyze the following problem: {problem}",
                task_parameters={
                    "problem": problem,
                    "context": context,
                    "reasoning_id": reasoning_id,
                    "priority": priority.value
                },
                priority=self._priority_to_int(priority),
                metadata={
                    "pattern": "parallel_reasoning",
                    "phase": "analysis"
                }
            )
            
            # Emit the event
            await coordinator_agent.emit_event(task_event)
    
    async def _start_synthesis_phase(
        self,
        coordinator_agent: BaseAgent,
        analyses: List[Dict[str, Any]],
        problem: str,
        context: Dict[str, Any],
        reasoning_id: str
    ) -> None:
        """Start the synthesis phase with the coordinator agent.

        Args:
            coordinator_agent: Agent to synthesize results
            analyses: List of completed analyses
            problem: Original problem
            context: Additional context
            reasoning_id: Unique reasoning ID
        """
        # Create a task assignment event for synthesis
        task_event = TaskAssignmentEvent(
            sender_id=coordinator_agent.agent_id,  # Self-assignment
            receiver_id=coordinator_agent.agent_id,
            task_id=f"{reasoning_id}_synthesis",
            task_type="reasoning_synthesis",
            task_description=f"Synthesize analyses for problem: {problem}",
            task_parameters={
                "problem": problem,
                "context": context,
                "reasoning_id": reasoning_id,
                "analyses": analyses
            },
            priority=5,  # High priority for synthesis
            metadata={
                "pattern": "parallel_reasoning",
                "phase": "synthesis"
            }
        )
        
        # Emit the event
        await coordinator_agent.emit_event(task_event)
    
    def _priority_to_int(self, priority: ReasoningPriority) -> int:
        """Convert a ReasoningPriority to an integer value.

        Args:
            priority: Priority enumeration value

        Returns:
            Integer priority (1-5)
        """
        priority_map = {
            ReasoningPriority.LOW: 1,
            ReasoningPriority.MEDIUM: 3,
            ReasoningPriority.HIGH: 4,
            ReasoningPriority.CRITICAL: 5
        }
        return priority_map.get(priority, 3)
        
    def get_reasoning(self, reasoning_id: str) -> Dict[str, Any]:
        """Get a specific reasoning by ID.

        Args:
            reasoning_id: The ID of the reasoning to retrieve

        Returns:
            Dictionary with reasoning information
        """
        return self.current_reasoning.get(reasoning_id, {})