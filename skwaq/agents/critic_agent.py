"""Critic agent for the Skwaq vulnerability assessment system.

This module defines the CriticAgent responsible for evaluating vulnerability
findings, detecting false positives, and prioritizing issues.
"""

from typing import Dict, List, Any, Optional
import uuid
import json
import asyncio
import time

from .base import BaseAgent, AutogenChatAgent, AgentState, AgentContext
from .registry import AgentRegistry
from .events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task

from ..events.system_events import EventBus
from ..utils.config import get_config
from ..utils.logging import get_logger

# Define logging
logger = get_logger(__name__)


class CriticAgent(AutogenChatAgent):
    """Critic agent for evaluating vulnerability findings.
    
    The critic agent evaluates findings from other agents, looking for
    false positives, missed vulnerabilities, and providing feedback.
    """

    def __init__(
        self,
        name: str = "CriticAgent",
        description: str = "Evaluates and critiques vulnerability findings",
        config_key: str = "agents.critic",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the critic agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are the critic agent for a vulnerability assessment system.
Your role is to evaluate and critique findings from other agents to ensure accuracy,
relevance, and value.

Your responsibilities include:
1. Evaluating vulnerability findings for accuracy and relevance
2. Identifying potential false positives in the results
3. Suggesting vulnerabilities that might have been missed
4. Prioritizing findings based on severity and impact
5. Providing constructive feedback to improve assessments

Approach each evaluation with a critical mindset, looking for evidence that supports
or refutes each finding. Consider context, application type, and technology stack
when evaluating the relevance of each vulnerability. Flag issues that need further
investigation or clarification.

Provide thorough, constructive critique that helps improve the quality of the
vulnerability assessment.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )
        
        # Task handling
        self.assigned_tasks: Dict[str, Task] = {}
        
    async def _start(self):
        """Initialize critic agent on startup."""
        await super()._start()
        
        # Register for task assignments
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        
        # Register capabilities with orchestrator
        await self._register_capabilities()
        
        logger.info(f"Critic agent started: {self.name}")
        
    async def _register_capabilities(self):
        """Register capabilities with the orchestrator."""
        # Find orchestrator
        orchestrator = None
        for agent in AgentRegistry.get_all_agents():
            if "orchestrator" in agent.name.lower():
                orchestrator = agent
                break
                
        if not orchestrator:
            logger.warning("No orchestrator found to register capabilities with")
            return
            
        # Register capabilities
        capabilities = {
            "capabilities": [
                "criticism",
                "false_positive_detection",
                "finding_evaluation",
                "vulnerability_prioritization"
            ]
        }
        
        registration_event = AgentCommunicationEvent(
            sender_id=self.agent_id,
            receiver_id=orchestrator.agent_id,
            message=json.dumps(capabilities),
            message_type="register_capability",
        )
        
        self.emit_event(registration_event)
        logger.debug(f"Registered capabilities with orchestrator: {capabilities}")
    
    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment event.
        
        Args:
            event: Task assignment event
        """
        # Only handle tasks assigned to this agent
        if event.receiver_id != self.agent_id:
            return
            
        logger.debug(f"Received task assignment: {event.task_id} - {event.task_type}")
        
        # Create task object
        task = Task(
            task_id=event.task_id,
            task_type=event.task_type,
            task_description=event.task_description,
            task_parameters=event.task_parameters,
            priority=event.priority,
            sender_id=event.sender_id,
            receiver_id=event.receiver_id,
        )
        
        # Store task
        self.assigned_tasks[event.task_id] = task
        
        # Process task asynchronously
        asyncio.create_task(self._process_task(event.task_id))
    
    async def _process_task(self, task_id: str) -> None:
        """Process an assigned task.
        
        Args:
            task_id: ID of the task to process
        """
        task = self.assigned_tasks.get(task_id)
        if not task:
            logger.error(f"Task {task_id} not found")
            return
            
        try:
            # Update task status
            task.status = "processing"
            
            # Import the critic provider here to avoid circular imports
            from .data_providers import critic_provider
            
            # Process task based on type
            if task.task_type == "critique_findings":
                result = await critic_provider.critique_findings(task.task_parameters)
            elif task.task_type == "prioritize_vulnerabilities":
                result = await critic_provider.prioritize_vulnerabilities(task.task_parameters)
            elif task.task_type == "analyze_false_positives":
                result = await critic_provider.analyze_false_positives(task.task_parameters)
            else:
                logger.warning(f"Unknown task type: {task.task_type}")
                task.status = "failed"
                task.result = {"error": f"Unknown task type: {task.task_type}"}
                return
                
            # Update task with result
            task.status = "completed"
            task.result = result
            task.completed_time = time.time()
            
            # Send task result event
            result_event = TaskResultEvent(
                sender_id=self.agent_id,
                receiver_id=task.sender_id,
                task_id=task_id,
                status="completed",
                result=result,
            )
            
            self.emit_event(result_event)
            logger.debug(f"Completed task {task_id}")
            
        except Exception as e:
            logger.exception(f"Error processing task {task_id}: {e}")
            
            # Update task with error
            task.status = "failed"
            task.result = {"error": str(e)}
            task.completed_time = time.time()
            
            # Send task failure event
            failure_event = TaskResultEvent(
                sender_id=self.agent_id,
                receiver_id=task.sender_id,
                task_id=task_id,
                status="failed",
                result={"error": str(e)},
            )
            
            self.emit_event(failure_event)