"""Core agents for the Skwaq vulnerability assessment system.

This module implements the core agents required for vulnerability assessment,
including the orchestrator, knowledge, and code analysis agents. These agents
use the foundation from base.py and extend it with specialized capabilities.
"""

from typing import Dict, List, Any, Optional, Set, Callable, Awaitable, Type, cast
import uuid
import json
import asyncio
import logging
import time
from dataclasses import dataclass, field

from .base import BaseAgent, AutogenChatAgent, AgentState, AgentContext
from .registry import AgentRegistry
from .autogen_integration import AutogenEventBridge, AutogenAgentAdapter

from ..events.system_events import EventBus, SystemEvent
from ..utils.config import get_config
from ..utils.logging import get_logger
from ..core.openai_client import get_openai_client

# Define logging
logger = get_logger(__name__)


class AgentCommunicationEvent(SystemEvent):
    """Event for agent-to-agent communication."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        message: str,
        message_type: str = "text",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize an agent communication event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            message: The content of the message
            message_type: Type of message (text, json, etc.)
            metadata: Optional metadata for the message
        """
        super().__init__(
            sender=sender_id,
            message=message,
            target=receiver_id,
            metadata=metadata or {},
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.message_type = message_type


class TaskAssignmentEvent(SystemEvent):
    """Event for task assignment between agents."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        task_id: str,
        task_type: str,
        task_description: str,
        task_parameters: Optional[Dict[str, Any]] = None,
        priority: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a task assignment event.

        Args:
            sender_id: ID of the agent assigning the task
            receiver_id: ID of the agent receiving the task
            task_id: Unique identifier for the task
            task_type: Type of task
            task_description: Description of the task
            task_parameters: Parameters for the task
            priority: Task priority (1-5, with 5 being highest)
            metadata: Optional metadata for the task
        """
        task_metadata = metadata or {}
        task_metadata.update({
            "task_id": task_id,
            "task_type": task_type,
            "task_parameters": task_parameters or {},
            "priority": priority
        })
        
        super().__init__(
            sender=sender_id,
            message=task_description,
            target=receiver_id,
            metadata=task_metadata,
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.task_id = task_id
        self.task_type = task_type
        self.task_description = task_description
        self.task_parameters = task_parameters or {}
        self.priority = priority


class TaskResultEvent(SystemEvent):
    """Event for sending task results between agents."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        task_id: str,
        status: str,
        result: Any,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a task result event.

        Args:
            sender_id: ID of the agent sending the result
            receiver_id: ID of the agent that assigned the task
            task_id: ID of the task this is a result for
            status: Status of the task (completed, failed, etc.)
            result: The result data
            metadata: Optional metadata for the result
        """
        result_metadata = metadata or {}
        result_metadata.update({
            "task_id": task_id,
            "status": status,
            "result_summary": str(result)[:100],  # Include a summary in the metadata
        })
        
        message = f"Task {task_id} {status}"
        
        super().__init__(
            sender=sender_id,
            message=message,
            target=receiver_id,
            metadata=result_metadata,
        )
        self.sender_id = sender_id
        self.receiver_id = receiver_id
        self.task_id = task_id
        self.status = status
        self.result = result


@dataclass
class Task:
    """Task model for agent task tracking."""

    task_id: str
    task_type: str
    task_description: str
    task_parameters: Dict[str, Any]
    priority: int
    sender_id: str
    receiver_id: str
    status: str = "pending"
    result: Any = None
    assigned_time: float = field(default_factory=time.time)
    completed_time: Optional[float] = None


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
        

class KnowledgeAgent(AutogenChatAgent):
    """Knowledge agent for retrieving vulnerability information.
    
    The knowledge agent retrieves information from the knowledge graph,
    including CWEs, vulnerability patterns, and relevant documentation.
    """

    def __init__(
        self,
        name: str = "KnowledgeAgent",
        description: str = "Retrieves vulnerability knowledge from various sources",
        config_key: str = "agents.knowledge",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the knowledge agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are the knowledge agent for a vulnerability assessment system.
Your role is to retrieve and provide relevant knowledge about security vulnerabilities.

Your responsibilities include:
1. Retrieving information about specific vulnerabilities from the knowledge base
2. Providing context and background about vulnerability classes and categories
3. Retrieving vulnerability patterns for detection
4. Answering questions about security concepts
5. Providing remediation advice for identified vulnerabilities

You have access to a comprehensive knowledge base that includes:
- Common Weakness Enumeration (CWE) database
- Security documentation and best practices
- Vulnerability patterns and signatures
- Historical vulnerability data

Respond to knowledge requests with comprehensive, accurate information that helps
the assessment process and provides context for security findings.
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
        """Initialize knowledge agent on startup."""
        await super()._start()
        
        # Register for task assignments
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        
        # Register capabilities with orchestrator
        await self._register_capabilities()
        
        logger.info(f"Knowledge agent started: {self.name}")
        
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
                "knowledge_retrieval",
                "cwe_lookup",
                "vulnerability_patterns",
                "remediation_advice"
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
            
            # Process task based on type
            if task.task_type == "retrieve_knowledge":
                result = await self._retrieve_knowledge(task.task_parameters)
            elif task.task_type == "retrieve_vulnerability_patterns":
                result = await self._retrieve_vulnerability_patterns(task.task_parameters)
            elif task.task_type == "lookup_cwe":
                result = await self._lookup_cwe(task.task_parameters)
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
    
    async def _retrieve_knowledge(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve knowledge based on query.
        
        Args:
            parameters: Query parameters
            
        Returns:
            Retrieved knowledge
        """
        query = parameters.get("query", "")
        context = parameters.get("context", {})
        
        logger.debug(f"Retrieving knowledge for query: {query}")
        
        # For now, return mock data - this would connect to Neo4j in production
        return {
            "query": query,
            "results": [
                {
                    "type": "cwe",
                    "id": "CWE-79",
                    "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
                    "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
                    "likelihood": "High",
                    "impact": "High",
                    "remediation": "Properly validate and sanitize all user input before including it in web pages."
                },
                {
                    "type": "best_practice",
                    "title": "Input Validation",
                    "description": "Always validate and sanitize user input before processing or displaying it.",
                    "references": ["OWASP Input Validation Cheat Sheet"]
                }
            ],
            "context": context
        }
    
    async def _retrieve_vulnerability_patterns(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve vulnerability patterns for detection.
        
        Args:
            parameters: Parameters for pattern retrieval
            
        Returns:
            Vulnerability patterns
        """
        context = parameters.get("context", "")
        limit = parameters.get("limit", 10)
        
        logger.debug(f"Retrieving vulnerability patterns for context: {context}, limit: {limit}")
        
        # For now, return mock data - this would connect to Neo4j in production
        return {
            "patterns": [
                {
                    "id": "XSS-001",
                    "name": "Reflected XSS Pattern",
                    "language": "javascript",
                    "regex": r"document\.write\s*\(\s*.*(?:location|URL|documentURI|referrer|location.href).*\)",
                    "description": "Potential reflected XSS vulnerability using document.write with unvalidated input from URL",
                    "severity": "high",
                    "cwe": "CWE-79"
                },
                {
                    "id": "SQLI-001",
                    "name": "SQL Injection Pattern",
                    "language": "python",
                    "regex": r"execute\s*\(\s*[\"']SELECT.*\s*\+\s*.*\)",
                    "description": "Potential SQL injection using string concatenation in queries",
                    "severity": "high",
                    "cwe": "CWE-89"
                }
            ],
            "total": 2,
            "limit": limit,
            "context": context
        }
    
    async def _lookup_cwe(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Look up a specific CWE.
        
        Args:
            parameters: CWE lookup parameters
            
        Returns:
            CWE information
        """
        cwe_id = parameters.get("cwe_id", "")
        
        logger.debug(f"Looking up CWE: {cwe_id}")
        
        # For now, return mock data - this would connect to Neo4j in production
        return {
            "cwe_id": cwe_id,
            "name": "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')",
            "description": "The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.",
            "likelihood": "High",
            "impact": "High",
            "remediation": "Properly validate and sanitize all user input before including it in web pages.",
            "related_cwe_ids": ["CWE-80", "CWE-83", "CWE-87"],
            "common_platforms": ["Web-based applications"],
            "detection_methods": [
                "Static Analysis",
                "Dynamic Analysis",
                "Manual Code Review"
            ]
        }


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
            
            # Process task based on type
            if task.task_type == "analyze_repository":
                result = await self._analyze_repository(task.task_parameters)
            elif task.task_type == "analyze_file":
                result = await self._analyze_file(task.task_parameters)
            elif task.task_type == "match_patterns":
                result = await self._match_patterns(task.task_parameters)
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
    
    async def _analyze_repository(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a repository for vulnerabilities.
        
        Args:
            parameters: Repository analysis parameters
            
        Returns:
            Analysis results
        """
        repository = parameters.get("repository", "")
        
        logger.debug(f"Analyzing repository: {repository}")
        
        # Set current analysis state
        self.current_analysis = {
            "repository": repository,
            "start_time": time.time(),
            "status": "running",
            "files_analyzed": 0,
            "findings": []
        }
        
        # For now, return mock data - this would connect to analyzer in production
        findings = [
            {
                "file_path": "src/api/auth.js",
                "line_number": 42,
                "vulnerability_type": "XSS",
                "severity": "high",
                "confidence": 0.85,
                "description": "Potential XSS vulnerability with unvalidated user input",
                "cwe_id": "CWE-79",
                "snippet": "document.write('<p>' + req.query.username + '</p>');"
            },
            {
                "file_path": "src/database/queries.py",
                "line_number": 87,
                "vulnerability_type": "SQL Injection",
                "severity": "critical",
                "confidence": 0.92,
                "description": "SQL injection vulnerability with string concatenation",
                "cwe_id": "CWE-89",
                "snippet": "cursor.execute(\"SELECT * FROM users WHERE username = '\" + username + \"'\")"
            }
        ]
        
        # Update analysis state
        self.current_analysis["status"] = "completed"
        self.current_analysis["end_time"] = time.time()
        self.current_analysis["files_analyzed"] = 45
        self.current_analysis["findings"] = findings
        
        return {
            "repository": repository,
            "analysis_time": self.current_analysis["end_time"] - self.current_analysis["start_time"],
            "files_analyzed": 45,
            "findings": findings,
            "summary": "Discovered 2 vulnerabilities: 1 XSS (high) and 1 SQL Injection (critical)"
        }
    
    async def _analyze_file(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze a single file for vulnerabilities.
        
        Args:
            parameters: File analysis parameters
            
        Returns:
            Analysis results
        """
        file_path = parameters.get("file_path", "")
        language = parameters.get("language", "")
        
        logger.debug(f"Analyzing file: {file_path}, language: {language}")
        
        # For now, return mock data - this would connect to analyzer in production
        return {
            "file_path": file_path,
            "language": language,
            "findings": [
                {
                    "line_number": 42,
                    "vulnerability_type": "XSS",
                    "severity": "high",
                    "confidence": 0.85,
                    "description": "Potential XSS vulnerability with unvalidated user input",
                    "cwe_id": "CWE-79",
                    "snippet": "document.write('<p>' + req.query.username + '</p>');"
                }
            ],
            "summary": "Found 1 high severity XSS vulnerability"
        }
    
    async def _match_patterns(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Match vulnerability patterns against code.
        
        Args:
            parameters: Pattern matching parameters
            
        Returns:
            Matching results
        """
        code = parameters.get("code", "")
        language = parameters.get("language", "")
        patterns = parameters.get("patterns", [])
        
        logger.debug(f"Matching patterns for language: {language}, patterns: {len(patterns)}")
        
        # For now, return mock data - this would connect to analyzer in production
        return {
            "matches": [
                {
                    "pattern_id": "XSS-001",
                    "line_number": 42,
                    "match": "document.write('<p>' + req.query.username + '</p>');",
                    "confidence": 0.85
                }
            ],
            "total_matches": 1
        }


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
            
            # Process task based on type
            if task.task_type == "critique_findings":
                result = await self._critique_findings(task.task_parameters)
            elif task.task_type == "prioritize_vulnerabilities":
                result = await self._prioritize_vulnerabilities(task.task_parameters)
            elif task.task_type == "analyze_false_positives":
                result = await self._analyze_false_positives(task.task_parameters)
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
    
    async def _critique_findings(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Critique vulnerability findings.
        
        Args:
            parameters: Critique parameters
            
        Returns:
            Critique results
        """
        findings = parameters.get("findings", [])
        patterns = parameters.get("patterns", [])
        
        logger.debug(f"Critiquing {len(findings)} findings")
        
        # For now, return mock data - this would connect to knowledge in production
        return {
            "evaluation": [
                {
                    "finding_id": 0,  # Index in the findings list
                    "assessment": "valid",
                    "confidence": 0.8,
                    "notes": "This appears to be a genuine XSS vulnerability. The user input from req.query.username is directly inserted into the document without sanitization."
                },
                {
                    "finding_id": 1,
                    "assessment": "valid",
                    "confidence": 0.9,
                    "notes": "This is a clear SQL injection vulnerability with direct string concatenation of user input into an SQL query."
                }
            ],
            "potentially_missed": [
                {
                    "type": "Insecure cookie configuration",
                    "evidence": "Based on the patterns, there might be cookies set without the secure flag in auth.js",
                    "confidence": 0.6
                }
            ],
            "overall_assessment": "The findings appear accurate with high confidence. One additional potential vulnerability was identified that may warrant further investigation."
        }
    
    async def _prioritize_vulnerabilities(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Prioritize vulnerability findings.
        
        Args:
            parameters: Prioritization parameters
            
        Returns:
            Prioritized vulnerabilities
        """
        findings = parameters.get("findings", [])
        
        logger.debug(f"Prioritizing {len(findings)} vulnerabilities")
        
        # For now, return mock data
        return {
            "prioritized_findings": [
                {
                    "finding_id": 1,  # SQL Injection
                    "priority": 1,
                    "reasoning": "Critical severity with high confidence. SQL injection vulnerabilities provide direct database access and can lead to data breaches."
                },
                {
                    "finding_id": 0,  # XSS
                    "priority": 2,
                    "reasoning": "High severity with high confidence. XSS vulnerabilities can lead to theft of user credentials and session hijacking."
                }
            ],
            "recommendation": "Address the SQL injection vulnerability first as it presents the highest risk to the system, followed by the XSS vulnerability."
        }
    
    async def _analyze_false_positives(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze findings for potential false positives.
        
        Args:
            parameters: Analysis parameters
            
        Returns:
            False positive analysis
        """
        findings = parameters.get("findings", [])
        
        logger.debug(f"Analyzing {len(findings)} findings for false positives")
        
        # For now, return mock data
        return {
            "false_positives": [],
            "uncertain_findings": [],
            "confirmed_findings": [0, 1],  # Indices of confirmed findings
            "analysis": "All findings appear to be genuine vulnerabilities. No false positives were identified."
        }