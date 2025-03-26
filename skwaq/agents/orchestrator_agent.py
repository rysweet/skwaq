"""Orchestrator agent for the Skwaq vulnerability assessment system.

This module defines the OrchestratorAgent responsible for coordinating
other agents, managing workflows, and assigning tasks.
"""

from typing import Dict, List, Any, Optional, Set, Type, cast
import uuid
import json
import asyncio
import time
import logging

from .base import BaseAgent, AutogenChatAgent, AgentState, AgentContext
from .registry import AgentRegistry
from .events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task

from ..events.system_events import EventBus
from ..utils.config import get_config
from ..utils.logging import get_logger

# Define logging
logger = get_logger(__name__)


class OrchestratorAgent(AutogenChatAgent):
    """Orchestrator agent for coordinating the vulnerability assessment process.
    
    The orchestrator manages the workflow, assigns tasks to specialized agents,
    tracks progress, and aggregates results into a coherent assessment.
    """

    def __init__(
        self,
        name: str = "OrchestratorAgent",
        description: str = "Coordinates the overall vulnerability assessment process",
        config_key: str = "agents.orchestrator",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the orchestrator agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are the orchestrator agent for a vulnerability assessment system.
Your role is to coordinate the activities of all specialized agents, manage workflows,
and ensure the overall assessment process runs smoothly.

Your responsibilities include:
1. Delegating specific tasks to specialized agents
2. Tracking progress of all active tasks
3. Managing dependencies between tasks
4. Handling errors and timeouts
5. Aggregating and synthesizing results from multiple agents
6. Making decisions about assessment priorities
7. Ensuring comprehensive coverage of the target system

Use the agent messaging system to communicate with other agents and assign tasks.
Monitor task results and provide guidance when needed. Maintain a high-level view
of the entire assessment process and optimize for both thoroughness and efficiency.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )
        
        # Setup task tracking
        self.tasks: Dict[str, Task] = {}
        self.active_workflows: Dict[str, Dict[str, Any]] = {}
        
        # Agent relationship tracking
        self.available_agents: Dict[str, BaseAgent] = {}
        self.agent_capabilities: Dict[str, List[str]] = {}
        
    async def _start(self):
        """Initialize orchestrator agent on startup."""
        await super()._start()
        
        # Register event handlers
        self.register_event_handler(TaskResultEvent, self._handle_task_result)
        self.register_event_handler(AgentCommunicationEvent, self._handle_communication)
        
        # Discover available agents
        self._discover_agents()
        
        logger.info(f"Orchestrator agent started with {len(self.available_agents)} available agents")
        
    def _discover_agents(self):
        """Discover available agents and their capabilities."""
        all_agents = AgentRegistry.get_all_agents()
        
        # Filter out self
        other_agents = [agent for agent in all_agents if agent.agent_id != self.agent_id]
        
        for agent in other_agents:
            self.available_agents[agent.agent_id] = agent
            
            # Infer capabilities based on agent class and name
            capabilities = []
            agent_class = agent.__class__.__name__
            
            if "Knowledge" in agent_class:
                capabilities.append("knowledge_retrieval")
            if "Code" in agent_class or "Analysis" in agent_class:
                capabilities.append("code_analysis")
            if "Critic" in agent_class:
                capabilities.append("criticism")
            if "Pattern" in agent_class:
                capabilities.append("pattern_matching")
            if "Semantic" in agent_class:
                capabilities.append("semantic_analysis")
                
            self.agent_capabilities[agent.agent_id] = capabilities
            logger.debug(f"Discovered agent: {agent.name} with capabilities: {capabilities}")
            
    async def create_workflow(self, workflow_type: str, parameters: Dict[str, Any]) -> str:
        """Create a new workflow and begin executing it.
        
        Args:
            workflow_type: Type of workflow to create
            parameters: Parameters for the workflow
            
        Returns:
            Workflow ID
        """
        workflow_id = str(uuid.uuid4())
        
        # Create workflow tracking structure
        workflow = {
            "id": workflow_id,
            "type": workflow_type,
            "parameters": parameters,
            "status": "created",
            "tasks": [],
            "results": {},
            "created_at": time.time(),
            "updated_at": time.time(),
        }
        
        self.active_workflows[workflow_id] = workflow
        
        # Begin workflow execution
        logger.info(f"Creating workflow: {workflow_type} with ID {workflow_id}")
        
        # Start the workflow asynchronously
        asyncio.create_task(self._execute_workflow(workflow_id))
        
        return workflow_id
        
    async def _execute_workflow(self, workflow_id: str):
        """Execute a workflow by orchestrating multiple agents.
        
        Args:
            workflow_id: ID of the workflow to execute
        """
        workflow = self.active_workflows[workflow_id]
        workflow_type = workflow["type"]
        
        try:
            workflow["status"] = "running"
            workflow["updated_at"] = time.time()
            
            if workflow_type == "vulnerability_assessment":
                await self._execute_vuln_assessment_workflow(workflow_id)
            elif workflow_type == "knowledge_query":
                await self._execute_knowledge_query_workflow(workflow_id)
            else:
                logger.error(f"Unknown workflow type: {workflow_type}")
                workflow["status"] = "failed"
                workflow["error"] = f"Unknown workflow type: {workflow_type}"
                
        except Exception as e:
            logger.exception(f"Error executing workflow {workflow_id}: {e}")
            workflow["status"] = "failed"
            workflow["error"] = str(e)
            
        finally:
            workflow["updated_at"] = time.time()
            if workflow["status"] == "running":
                workflow["status"] = "completed"
    
    async def _execute_vuln_assessment_workflow(self, workflow_id: str):
        """Execute a vulnerability assessment workflow.
        
        Args:
            workflow_id: ID of the workflow to execute
        """
        workflow = self.active_workflows[workflow_id]
        parameters = workflow["parameters"]
        
        # 1. Retrieve repository information
        repository = parameters.get("repository")
        if not repository:
            raise ValueError("Repository parameter is required for vulnerability assessment")
            
        # 2. Assign knowledge retrieval task to gather vulnerability patterns
        knowledge_agent_id = self._find_agent_by_capability("knowledge_retrieval")
        if not knowledge_agent_id:
            raise ValueError("No knowledge retrieval agent available")
            
        patterns_task_id = await self.assign_task(
            receiver_id=knowledge_agent_id,
            task_type="retrieve_vulnerability_patterns",
            task_description="Retrieve vulnerability patterns for assessment",
            task_parameters={"context": "security vulnerabilities", "limit": 100},
        )
        
        # 3. Assign code analysis tasks in parallel
        code_agent_id = self._find_agent_by_capability("code_analysis")
        if not code_agent_id:
            raise ValueError("No code analysis agent available")
            
        analysis_task_id = await self.assign_task(
            receiver_id=code_agent_id,
            task_type="analyze_repository",
            task_description=f"Analyze repository for vulnerabilities: {repository}",
            task_parameters={"repository": repository},
        )
        
        # 4. Wait for results from both tasks
        pattern_result = await self._wait_for_task(patterns_task_id)
        analysis_result = await self._wait_for_task(analysis_task_id)
        
        # 5. Combine results and store in workflow
        workflow["results"]["patterns"] = pattern_result
        workflow["results"]["analysis"] = analysis_result
        
        # 6. Assign tasks to critique the findings
        critic_agent_id = self._find_agent_by_capability("criticism")
        if critic_agent_id:
            critique_task_id = await self.assign_task(
                receiver_id=critic_agent_id,
                task_type="critique_findings",
                task_description="Evaluate and critique vulnerability findings",
                task_parameters={
                    "findings": analysis_result.get("findings", []),
                    "patterns": pattern_result.get("patterns", []),
                },
            )
            
            critique_result = await self._wait_for_task(critique_task_id)
            workflow["results"]["critique"] = critique_result
    
    async def _execute_knowledge_query_workflow(self, workflow_id: str):
        """Execute a knowledge query workflow.
        
        Args:
            workflow_id: ID of the workflow to execute
        """
        workflow = self.active_workflows[workflow_id]
        parameters = workflow["parameters"]
        
        # Get query from parameters
        query = parameters.get("query")
        if not query:
            raise ValueError("Query parameter is required for knowledge query")
        
        # Assign knowledge retrieval task
        knowledge_agent_id = self._find_agent_by_capability("knowledge_retrieval")
        if not knowledge_agent_id:
            raise ValueError("No knowledge retrieval agent available")
        
        knowledge_task_id = await self.assign_task(
            receiver_id=knowledge_agent_id,
            task_type="retrieve_knowledge",
            task_description=f"Retrieve knowledge for query: {query}",
            task_parameters={"query": query, "context": parameters.get("context", {})},
        )
        
        # Wait for knowledge retrieval task to complete
        knowledge_result = await self._wait_for_task(knowledge_task_id)
        workflow["results"]["knowledge"] = knowledge_result
    
    def _find_agent_by_capability(self, capability: str) -> Optional[str]:
        """Find an agent with the specified capability.
        
        Args:
            capability: Capability to look for
            
        Returns:
            Agent ID or None if no agent found
        """
        for agent_id, capabilities in self.agent_capabilities.items():
            if capability in capabilities:
                return agent_id
        return None
    
    async def assign_task(
        self,
        receiver_id: str,
        task_type: str,
        task_description: str,
        task_parameters: Optional[Dict[str, Any]] = None,
        priority: int = 1,
    ) -> str:
        """Assign a task to another agent.
        
        Args:
            receiver_id: ID of the agent to assign the task to
            task_type: Type of task to assign
            task_description: Description of the task
            task_parameters: Parameters for the task
            priority: Priority level (1-5)
            
        Returns:
            Task ID
        """
        task_id = str(uuid.uuid4())
        
        # Create task
        task = Task(
            task_id=task_id,
            task_type=task_type,
            task_description=task_description,
            task_parameters=task_parameters or {},
            priority=priority,
            sender_id=self.agent_id,
            receiver_id=receiver_id,
        )
        
        # Store task
        self.tasks[task_id] = task
        
        # Create and emit task assignment event
        event = TaskAssignmentEvent(
            sender_id=self.agent_id,
            receiver_id=receiver_id,
            task_id=task_id,
            task_type=task_type,
            task_description=task_description,
            task_parameters=task_parameters,
            priority=priority,
        )
        
        self.emit_event(event)
        logger.debug(f"Assigned task {task_id} to agent {receiver_id}: {task_type}")
        
        return task_id
    
    async def _wait_for_task(self, task_id: str, timeout: float = 300.0) -> Any:
        """Wait for a task to complete.
        
        Args:
            task_id: ID of the task to wait for
            timeout: Maximum time to wait in seconds
            
        Returns:
            Task result
            
        Raises:
            TimeoutError: If task doesn't complete within timeout
            ValueError: If task fails
        """
        start_time = time.time()
        
        while True:
            if time.time() - start_time > timeout:
                raise TimeoutError(f"Task {task_id} did not complete within {timeout} seconds")
                
            task = self.tasks.get(task_id)
            if not task:
                raise ValueError(f"Task {task_id} not found")
                
            if task.status == "completed":
                return task.result
                
            if task.status == "failed":
                raise ValueError(f"Task {task.task_id} failed: {task.result}")
                
            # Wait a bit before checking again
            await asyncio.sleep(0.5)
    
    async def _handle_task_result(self, event: TaskResultEvent) -> None:
        """Handle a task result event.
        
        Args:
            event: Task result event
        """
        task_id = event.task_id
        
        # Verify this result is for a task we're tracking
        if task_id not in self.tasks:
            logger.warning(f"Received result for unknown task: {task_id}")
            return
            
        # Update task with result
        task = self.tasks[task_id]
        task.status = event.status
        task.result = event.result
        task.completed_time = time.time()
        
        logger.debug(f"Received result for task {task_id}: {event.status}")
        
        # Update workflows that might be waiting on this task
        for workflow in self.active_workflows.values():
            if task_id in workflow.get("tasks", []):
                workflow["updated_at"] = time.time()
    
    async def _handle_communication(self, event: AgentCommunicationEvent) -> None:
        """Handle communication from another agent.
        
        Args:
            event: Communication event
        """
        # Only process messages intended for this agent
        if event.receiver_id != self.agent_id:
            return
            
        logger.debug(f"Received message from {event.sender_id}: {event.message}")
        
        # Process message based on message type
        if event.message_type == "status_update":
            # Handle agent status update
            agent_id = event.sender_id
            if agent_id in self.available_agents:
                self.available_agents[agent_id].context.metadata["status"] = event.message
                
        elif event.message_type == "request_task":
            # Handle agent requesting task
            await self._handle_task_request(event.sender_id)
            
        elif event.message_type == "register_capability":
            # Handle agent registering new capability
            try:
                capability_data = json.loads(event.message)
                agent_id = event.sender_id
                
                if "capabilities" in capability_data:
                    self.agent_capabilities[agent_id] = capability_data["capabilities"]
                    logger.debug(f"Updated capabilities for agent {agent_id}: {capability_data['capabilities']}")
            except Exception as e:
                logger.error(f"Error parsing capability registration: {e}")
    
    async def _handle_task_request(self, agent_id: str) -> None:
        """Handle an agent requesting tasks.
        
        Args:
            agent_id: ID of the agent requesting tasks
        """
        # Check if agent has any capabilities
        if agent_id not in self.agent_capabilities:
            logger.warning(f"Agent {agent_id} requested tasks but has no registered capabilities")
            return
            
        # Check active workflows for tasks that match agent capabilities
        # For now, just send a response saying no tasks are available
        response = AgentCommunicationEvent(
            sender_id=self.agent_id,
            receiver_id=agent_id,
            message="No tasks available at this time",
            message_type="task_response",
        )
        
        self.emit_event(response)