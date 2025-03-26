"""Code analysis agent for the Skwaq vulnerability assessment system.

This module defines the CodeAnalysisAgent responsible for analyzing code
to identify potential security vulnerabilities.
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


class CodeAnalysisAgent(AutogenChatAgent):
    """Code analysis agent for identifying vulnerabilities in code.
    
    The code analysis agent analyzes source code using various techniques to
    identify potential security vulnerabilities.
    """

    def __init__(
        self,
        name: str = "CodeAnalysisAgent",
        description: str = "Analyzes code for potential security vulnerabilities",
        config_key: str = "agents.code_analysis",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the code analysis agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are the code analysis agent for a vulnerability assessment system.
Your role is to analyze source code for potential security vulnerabilities.

Your responsibilities include:
1. Analyzing code repositories for security issues
2. Applying vulnerability patterns to detect potential problems
3. Examining code structure for security concerns
4. Prioritizing and categorizing identified vulnerabilities
5. Suggesting remediation approaches for discovered issues

You can analyze code using multiple techniques including:
- Pattern matching against known vulnerability signatures
- Static analysis of code structure and control flow
- Semantic analysis of code intent and implementation
- Language-specific vulnerability detection
- Dependency scanning

Provide detailed, actionable information about identified vulnerabilities,
including their location, severity, and potential impact.
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
        
        # Analysis state
        self.current_analysis: Optional[Dict[str, Any]] = None
        
    async def _start(self):
        """Initialize code analysis agent on startup."""
        await super()._start()
        
        # Register for task assignments
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        
        # Register capabilities with orchestrator
        await self._register_capabilities()
        
        logger.info(f"Code analysis agent started: {self.name}")
        
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
                "code_analysis",
                "pattern_matching",
                "semantic_analysis",
                "vulnerability_detection"
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
            
            # Import the code analysis provider here to avoid circular imports
            from .data_providers import code_analysis_provider
            
            # Process task based on type
            if task.task_type == "analyze_repository":
                result = await code_analysis_provider.analyze_repository(task.task_parameters)
            elif task.task_type == "analyze_file":
                result = await code_analysis_provider.analyze_file(task.task_parameters)
            elif task.task_type == "match_patterns":
                result = await code_analysis_provider.match_patterns(task.task_parameters)
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