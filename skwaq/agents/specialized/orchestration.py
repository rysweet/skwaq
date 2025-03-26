"""Advanced Orchestration for the Skwaq vulnerability assessment system.

This module provides advanced orchestration capabilities for specialized workflow
agents, coordinating complex multi-agent workflows for vulnerability assessment.
"""

from typing import Dict, List, Any, Optional, Set, Tuple, Union, cast
import asyncio
import json
import enum
import time
import uuid
from dataclasses import dataclass
from datetime import datetime

from ..base import AutogenChatAgent
from ..events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task
from ..communication_patterns.chain_of_thought import ChainOfThoughtPattern
from ..communication_patterns.debate import DebatePattern
from ..communication_patterns.feedback_loop import FeedbackLoopPattern
from ..communication_patterns.parallel_reasoning import ParallelReasoningPattern
from ...events.system_events import EventBus, SystemEvent
from ...utils.config import get_config
from ...utils.logging import get_logger
from ...shared.finding import Finding

# Import specialized agents
from .guided_assessment_agent import GuidedAssessmentAgent, AssessmentStage, AssessmentPlanEvent, AssessmentStageEvent
from .exploitation_agent import ExploitationVerificationAgent, ExploitVerificationEvent, ExploitabilityStatus
from .remediation_agent import RemediationPlanningAgent, RemediationPlanEvent, RemediationPriority, RemediationComplexity
from .policy_agent import SecurityPolicyAgent, PolicyEvaluationEvent, PolicyRecommendationEvent, ComplianceStatus

logger = get_logger(__name__)


class WorkflowType(enum.Enum):
    """Types of vulnerability assessment workflows."""
    
    GUIDED_ASSESSMENT = "guided_assessment"
    TARGETED_ANALYSIS = "targeted_analysis"
    EXPLOITATION_VERIFICATION = "exploitation_verification"
    REMEDIATION_PLANNING = "remediation_planning"
    POLICY_COMPLIANCE = "policy_compliance"
    COMPREHENSIVE = "comprehensive"


class WorkflowStatus(enum.Enum):
    """Status of workflow execution."""
    
    INITIALIZING = "initializing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class WorkflowEvent(SystemEvent):
    """Event for workflow status updates."""

    def __init__(
        self,
        sender_id: str,
        workflow_id: str,
        workflow_type: WorkflowType,
        status: WorkflowStatus,
        progress: float,
        results: Optional[Dict[str, Any]] = None,
        target: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a workflow event.

        Args:
            sender_id: ID of the sending agent
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            status: Current status of the workflow
            progress: Progress percentage (0-1)
            results: Optional current results
            target: Optional target component for the event
            metadata: Additional metadata for the event
        """
        workflow_metadata = metadata or {}
        workflow_metadata.update({
            "workflow_id": workflow_id,
            "workflow_type": workflow_type.value,
            "status": status.value,
            "progress": progress,
            "event_type": "workflow_status"
        })

        message = f"Workflow {workflow_id} ({workflow_type.value}) status: {status.value}"

        super().__init__(
            sender=sender_id,
            message=message,
            target=target,
            metadata=workflow_metadata,
        )
        self.sender_id = sender_id
        self.workflow_id = workflow_id
        self.workflow_type = workflow_type
        self.status = status
        self.progress = progress
        self.results = results or {}


@dataclass
class WorkflowDefinition:
    """Definition of a workflow with its configuration."""
    
    workflow_id: str
    workflow_type: WorkflowType
    name: str
    description: str
    target_id: str
    target_type: str
    parameters: Dict[str, Any]
    agents: List[str]
    stages: List[Dict[str, Any]]
    communication_patterns: List[str]
    created_at: float = time.time()


@dataclass
class WorkflowExecution:
    """Execution status and tracking for a workflow."""
    
    workflow_id: str
    definition: WorkflowDefinition
    status: WorkflowStatus = WorkflowStatus.INITIALIZING
    current_stage: int = 0
    stage_results: Dict[int, Any] = None
    progress: float = 0.0
    start_time: Optional[float] = None
    completion_time: Optional[float] = None
    error: Optional[str] = None
    artifacts: Dict[str, Any] = None
    
    def __post_init__(self):
        """Initialize collections if not provided."""
        if self.stage_results is None:
            self.stage_results = {}
        if self.artifacts is None:
            self.artifacts = {}


class AdvancedOrchestrator(AutogenChatAgent):
    """Advanced orchestration agent for coordinating specialized workflow agents.
    
    This agent coordinates complex vulnerability assessment workflows involving
    multiple specialized agents, advanced communication patterns, and sophisticated
    collaboration strategies.
    """

    def __init__(
        self,
        name: str = "AdvancedOrchestrator",
        description: str = "Coordinates advanced vulnerability assessment workflows",
        config_key: str = "agents.advanced_orchestrator",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the advanced orchestration agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are an Advanced Orchestration Agent for a vulnerability assessment system.
Your purpose is to coordinate complex workflows involving multiple specialized agents,
managing their interactions to achieve comprehensive vulnerability assessments.

Your responsibilities include:
1. Orchestrating workflows across specialized agents (assessment, exploitation, remediation, policy)
2. Managing complex communication patterns between agents
3. Coordinating collaborative problem-solving among specialized agents
4. Ensuring efficient workflow execution and progress tracking
5. Adapting workflows based on interim findings and results
6. Synthesizing insights from multiple specialized agents
7. Providing high-level workflow status and comprehensive results

You should leverage the unique capabilities of each specialized agent while ensuring
their efforts are coordinated and integrated. Your role is to maximize the effectiveness
of the overall vulnerability assessment process by directing agent activities, managing
communication flows, and synthesizing results into actionable intelligence.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )
        
        # Workflow tracking
        self.workflow_definitions: Dict[str, WorkflowDefinition] = {}
        self.workflow_executions: Dict[str, WorkflowExecution] = {}
        self.active_workflows: Set[str] = set()
        
        # Agent tracking
        self.specialized_agents: Dict[str, Any] = {}
        self.agent_statuses: Dict[str, str] = {}
        
        # Communication patterns
        self.communication_patterns: Dict[str, Any] = {
            "chain_of_thought": ChainOfThoughtPattern,
            "debate": DebatePattern,
            "feedback_loop": FeedbackLoopPattern,
            "parallel_reasoning": ParallelReasoningPattern
        }
        
        # Active pattern instances
        self.active_patterns: Dict[str, Any] = {}
        
    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()
        
        # Register event handlers
        self.register_event_handler(WorkflowEvent, self._handle_workflow_event)
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        self.register_event_handler(TaskResultEvent, self._handle_task_result)
        
        # Register specialized agent event handlers
        self.register_event_handler(AssessmentPlanEvent, self._handle_assessment_plan_event)
        self.register_event_handler(AssessmentStageEvent, self._handle_assessment_stage_event)
        self.register_event_handler(ExploitVerificationEvent, self._handle_exploit_verification_event)
        self.register_event_handler(RemediationPlanEvent, self._handle_remediation_plan_event)
        self.register_event_handler(PolicyEvaluationEvent, self._handle_policy_evaluation_event)
        self.register_event_handler(PolicyRecommendationEvent, self._handle_policy_recommendation_event)
        
        # Initialize specialized agents
        await self._initialize_specialized_agents()
        
    async def _initialize_specialized_agents(self):
        """Initialize all specialized workflow agents."""
        logger.info("Initializing specialized workflow agents")
        
        try:
            # Create guided assessment agent
            guided_agent = GuidedAssessmentAgent()
            self.specialized_agents["guided_assessment"] = guided_agent
            
            # Create exploitation verification agent
            exploit_agent = ExploitationVerificationAgent()
            self.specialized_agents["exploitation_verification"] = exploit_agent
            
            # Create remediation planning agent
            remediation_agent = RemediationPlanningAgent()
            self.specialized_agents["remediation_planning"] = remediation_agent
            
            # Create security policy agent
            policy_agent = SecurityPolicyAgent()
            self.specialized_agents["security_policy"] = policy_agent
            
            # Start all agents
            for agent_name, agent in self.specialized_agents.items():
                await agent.start()
                self.agent_statuses[agent_name] = "running"
                logger.info(f"Started specialized agent: {agent_name}")
                
            logger.info("All specialized agents initialized successfully")
            
        except Exception as e:
            logger.error(f"Error initializing specialized agents: {e}")
            raise
        
    async def create_workflow(
        self,
        workflow_type: WorkflowType,
        target_id: str,
        target_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        name: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a new workflow definition.

        Args:
            workflow_type: Type of workflow to create
            target_id: ID of the target (repository, finding, etc.)
            target_type: Type of the target
            parameters: Optional parameters for the workflow
            name: Optional custom name for the workflow
            description: Optional custom description

        Returns:
            Workflow definition details
        """
        # Generate workflow ID
        workflow_id = f"workflow_{workflow_type.value}_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        
        # Set default name and description if not provided
        if not name:
            name = f"{workflow_type.value.replace('_', ' ').title()} Workflow"
        if not description:
            description = f"Automated {workflow_type.value.replace('_', ' ')} workflow for {target_type} {target_id}"
            
        logger.info(f"Creating workflow: {name} ({workflow_type.value}) for {target_type} {target_id}")
        
        try:
            # Generate workflow components based on type
            workflow_components = await self._generate_workflow_components(
                workflow_type,
                target_type,
                parameters or {}
            )
            
            # Create workflow definition
            workflow_def = WorkflowDefinition(
                workflow_id=workflow_id,
                workflow_type=workflow_type,
                name=name,
                description=description,
                target_id=target_id,
                target_type=target_type,
                parameters=parameters or {},
                agents=workflow_components["agents"],
                stages=workflow_components["stages"],
                communication_patterns=workflow_components["communication_patterns"],
                created_at=time.time()
            )
            
            # Store workflow definition
            self.workflow_definitions[workflow_id] = workflow_def
            
            # Create execution tracking
            workflow_exec = WorkflowExecution(
                workflow_id=workflow_id,
                definition=workflow_def,
                status=WorkflowStatus.INITIALIZING,
                current_stage=0,
                progress=0.0
            )
            
            # Store workflow execution
            self.workflow_executions[workflow_id] = workflow_exec
            
            logger.info(f"Created workflow {workflow_id} with {len(workflow_def.stages)} stages")
            
            return {
                "workflow_id": workflow_id,
                "name": name,
                "description": description,
                "workflow_type": workflow_type.value,
                "target_id": target_id,
                "target_type": target_type,
                "stages": len(workflow_def.stages),
                "agents": workflow_def.agents,
                "status": "created"
            }
            
        except Exception as e:
            logger.error(f"Error creating workflow: {e}")
            raise
            
    async def _generate_workflow_components(
        self,
        workflow_type: WorkflowType,
        target_type: str,
        parameters: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Generate workflow components based on workflow type.

        Args:
            workflow_type: Type of workflow
            target_type: Type of target
            parameters: Workflow parameters

        Returns:
            Dictionary with workflow components
        """
        # Define base components for each workflow type
        if workflow_type == WorkflowType.GUIDED_ASSESSMENT:
            return {
                "agents": ["guided_assessment"],
                "stages": [
                    {
                        "name": "initialization",
                        "agent": "guided_assessment",
                        "description": "Initialize guided assessment workflow"
                    },
                    {
                        "name": "assessment",
                        "agent": "guided_assessment",
                        "description": "Perform guided vulnerability assessment"
                    },
                    {
                        "name": "reporting",
                        "agent": "guided_assessment",
                        "description": "Generate assessment report"
                    }
                ],
                "communication_patterns": ["chain_of_thought"]
            }
            
        elif workflow_type == WorkflowType.EXPLOITATION_VERIFICATION:
            return {
                "agents": ["exploitation_verification"],
                "stages": [
                    {
                        "name": "initialization",
                        "agent": "exploitation_verification",
                        "description": "Initialize exploitation verification workflow"
                    },
                    {
                        "name": "analysis",
                        "agent": "exploitation_verification",
                        "description": "Analyze vulnerability exploitability"
                    },
                    {
                        "name": "reporting",
                        "agent": "exploitation_verification",
                        "description": "Generate exploitation report"
                    }
                ],
                "communication_patterns": ["chain_of_thought"]
            }
            
        elif workflow_type == WorkflowType.REMEDIATION_PLANNING:
            return {
                "agents": ["remediation_planning"],
                "stages": [
                    {
                        "name": "initialization",
                        "agent": "remediation_planning",
                        "description": "Initialize remediation planning workflow"
                    },
                    {
                        "name": "analysis",
                        "agent": "remediation_planning",
                        "description": "Develop remediation strategy"
                    },
                    {
                        "name": "planning",
                        "agent": "remediation_planning",
                        "description": "Create detailed remediation plan"
                    }
                ],
                "communication_patterns": ["chain_of_thought"]
            }
            
        elif workflow_type == WorkflowType.POLICY_COMPLIANCE:
            return {
                "agents": ["security_policy"],
                "stages": [
                    {
                        "name": "initialization",
                        "agent": "security_policy",
                        "description": "Initialize policy compliance workflow"
                    },
                    {
                        "name": "evaluation",
                        "agent": "security_policy",
                        "description": "Evaluate policy compliance"
                    },
                    {
                        "name": "recommendations",
                        "agent": "security_policy",
                        "description": "Generate policy recommendations"
                    }
                ],
                "communication_patterns": ["chain_of_thought"]
            }
            
        elif workflow_type == WorkflowType.COMPREHENSIVE:
            # Comprehensive workflow using all specialized agents
            return {
                "agents": [
                    "guided_assessment", 
                    "exploitation_verification", 
                    "remediation_planning", 
                    "security_policy"
                ],
                "stages": [
                    {
                        "name": "initialization",
                        "agent": "guided_assessment",
                        "description": "Initialize comprehensive assessment"
                    },
                    {
                        "name": "assessment",
                        "agent": "guided_assessment",
                        "description": "Perform guided vulnerability assessment"
                    },
                    {
                        "name": "exploitation",
                        "agent": "exploitation_verification",
                        "description": "Verify exploitability of findings",
                        "dependencies": ["assessment"]
                    },
                    {
                        "name": "remediation",
                        "agent": "remediation_planning",
                        "description": "Develop remediation plans",
                        "dependencies": ["assessment", "exploitation"]
                    },
                    {
                        "name": "policy",
                        "agent": "security_policy",
                        "description": "Evaluate policy compliance",
                        "dependencies": ["assessment"]
                    },
                    {
                        "name": "collaborative_analysis",
                        "agents": [
                            "exploitation_verification", 
                            "remediation_planning", 
                            "security_policy"
                        ],
                        "description": "Collaborative analysis of findings",
                        "communication_pattern": "debate",
                        "dependencies": ["exploitation", "remediation", "policy"]
                    },
                    {
                        "name": "reporting",
                        "agent": "guided_assessment",
                        "description": "Generate comprehensive report",
                        "dependencies": ["collaborative_analysis"]
                    }
                ],
                "communication_patterns": [
                    "chain_of_thought", 
                    "debate", 
                    "feedback_loop", 
                    "parallel_reasoning"
                ]
            }
            
        else:  # Default for unknown workflow types
            return {
                "agents": ["guided_assessment"],
                "stages": [
                    {
                        "name": "default",
                        "agent": "guided_assessment",
                        "description": "Default vulnerability assessment"
                    }
                ],
                "communication_patterns": ["chain_of_thought"]
            }
            
    async def start_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Start execution of a defined workflow.

        Args:
            workflow_id: ID of the workflow to start

        Returns:
            Workflow execution status

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_definitions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        if workflow_id in self.active_workflows:
            logger.warning(f"Workflow {workflow_id} is already running")
            return self.get_workflow_status(workflow_id)
            
        logger.info(f"Starting workflow execution: {workflow_id}")
        
        try:
            # Get workflow definition and execution
            workflow_def = self.workflow_definitions[workflow_id]
            workflow_exec = self.workflow_executions[workflow_id]
            
            # Update execution status
            workflow_exec.status = WorkflowStatus.RUNNING
            workflow_exec.start_time = time.time()
            
            # Add to active workflows
            self.active_workflows.add(workflow_id)
            
            # Emit workflow event
            await self._emit_workflow_event(
                workflow_id, 
                workflow_def.workflow_type,
                WorkflowStatus.RUNNING,
                0.0
            )
            
            # Start execution (non-blocking)
            asyncio.create_task(self._execute_workflow(workflow_id))
            
            return {
                "workflow_id": workflow_id,
                "name": workflow_def.name,
                "status": "running",
                "start_time": workflow_exec.start_time,
                "current_stage": 0,
                "total_stages": len(workflow_def.stages)
            }
            
        except Exception as e:
            logger.error(f"Error starting workflow: {e}")
            
            # Update execution status on error
            workflow_exec = self.workflow_executions[workflow_id]
            workflow_exec.status = WorkflowStatus.FAILED
            workflow_exec.error = str(e)
            
            # Emit workflow event
            await self._emit_workflow_event(
                workflow_id, 
                workflow_def.workflow_type,
                WorkflowStatus.FAILED,
                0.0,
                {"error": str(e)}
            )
            
            # Remove from active workflows
            if workflow_id in self.active_workflows:
                self.active_workflows.remove(workflow_id)
                
            raise
            
    async def _execute_workflow(self, workflow_id: str) -> None:
        """Execute a workflow by running its stages in sequence.

        Args:
            workflow_id: ID of the workflow to execute
        """
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        logger.info(f"Executing workflow {workflow_id} with {len(workflow_def.stages)} stages")
        
        try:
            # Execute stages in sequence, respecting dependencies
            executed_stages = set()
            pending_stages = set(range(len(workflow_def.stages)))
            
            while pending_stages and workflow_exec.status == WorkflowStatus.RUNNING:
                # Find eligible stages (all dependencies satisfied)
                eligible_stages = []
                
                for stage_idx in pending_stages:
                    stage = workflow_def.stages[stage_idx]
                    dependencies = stage.get("dependencies", [])
                    
                    # Check if all dependency stages are executed
                    if not dependencies or all(
                        i in executed_stages 
                        for i, s in enumerate(workflow_def.stages) 
                        if s["name"] in dependencies
                    ):
                        eligible_stages.append(stage_idx)
                
                if not eligible_stages:
                    logger.warning(f"Workflow {workflow_id} has dependency cycle, cannot proceed")
                    break
                    
                # Execute eligible stages in parallel
                tasks = [
                    self._execute_workflow_stage(workflow_id, stage_idx)
                    for stage_idx in eligible_stages
                ]
                
                # Wait for all eligible stages to complete
                await asyncio.gather(*tasks)
                
                # Update executed and pending stages
                for stage_idx in eligible_stages:
                    executed_stages.add(stage_idx)
                    pending_stages.remove(stage_idx)
                    
                # Update overall progress
                workflow_exec.progress = len(executed_stages) / len(workflow_def.stages)
                
                # Emit workflow progress event
                await self._emit_workflow_event(
                    workflow_id, 
                    workflow_def.workflow_type,
                    WorkflowStatus.RUNNING,
                    workflow_exec.progress
                )
            
            # Mark workflow as completed if all stages executed
            if len(executed_stages) == len(workflow_def.stages):
                workflow_exec.status = WorkflowStatus.COMPLETED
                workflow_exec.completion_time = time.time()
                workflow_exec.progress = 1.0
                
                # Remove from active workflows
                if workflow_id in self.active_workflows:
                    self.active_workflows.remove(workflow_id)
                    
                # Emit workflow completion event
                await self._emit_workflow_event(
                    workflow_id, 
                    workflow_def.workflow_type,
                    WorkflowStatus.COMPLETED,
                    1.0,
                    self._compile_workflow_results(workflow_id)
                )
                
                logger.info(f"Workflow {workflow_id} completed successfully")
                
        except Exception as e:
            logger.error(f"Error executing workflow {workflow_id}: {e}")
            
            # Update execution status on error
            workflow_exec.status = WorkflowStatus.FAILED
            workflow_exec.error = str(e)
            
            # Emit workflow event
            await self._emit_workflow_event(
                workflow_id, 
                workflow_def.workflow_type,
                WorkflowStatus.FAILED,
                workflow_exec.progress,
                {"error": str(e)}
            )
            
            # Remove from active workflows
            if workflow_id in self.active_workflows:
                self.active_workflows.remove(workflow_id)
                
    async def _execute_workflow_stage(self, workflow_id: str, stage_idx: int) -> Dict[str, Any]:
        """Execute a specific stage of a workflow.

        Args:
            workflow_id: ID of the workflow
            stage_idx: Index of the stage to execute

        Returns:
            Stage execution results
        """
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        stage = workflow_def.stages[stage_idx]
        
        logger.info(f"Executing workflow {workflow_id} stage {stage_idx}: {stage['name']}")
        
        try:
            # Update current stage
            workflow_exec.current_stage = stage_idx
            
            # Determine agent for stage
            agent_name = stage.get("agent")
            agents = stage.get("agents", [])
            
            if not agent_name and not agents:
                raise ValueError(f"No agent specified for stage {stage_idx}")
                
            # Single agent stage
            if agent_name:
                if agent_name not in self.specialized_agents:
                    raise ValueError(f"Agent {agent_name} not found")
                    
                agent = self.specialized_agents[agent_name]
                
                # Execute stage based on agent type and stage name
                result = await self._execute_stage_with_agent(
                    agent_name,
                    stage["name"],
                    workflow_id,
                    workflow_def,
                    stage
                )
                
            # Multi-agent collaborative stage
            else:
                # Determine communication pattern
                pattern_name = stage.get("communication_pattern", "chain_of_thought")
                
                if pattern_name not in self.communication_patterns:
                    raise ValueError(f"Communication pattern {pattern_name} not found")
                    
                # Create pattern instance
                pattern_class = self.communication_patterns[pattern_name]
                pattern_id = f"{workflow_id}_{stage_idx}_{pattern_name}"
                
                pattern = pattern_class(
                    pattern_id=pattern_id,
                    agents=[self.specialized_agents[a] for a in agents if a in self.specialized_agents],
                    task_description=stage["description"],
                    context={
                        "workflow_id": workflow_id,
                        "stage_name": stage["name"],
                        "workflow_type": workflow_def.workflow_type.value,
                        "target_id": workflow_def.target_id,
                        "target_type": workflow_def.target_type
                    }
                )
                
                # Store pattern instance
                self.active_patterns[pattern_id] = pattern
                
                # Execute collaborative stage
                result = await pattern.execute()
                
                # Cleanup pattern instance
                del self.active_patterns[pattern_id]
                
            # Store stage result
            workflow_exec.stage_results[stage_idx] = result
            
            logger.info(f"Completed workflow {workflow_id} stage {stage_idx}: {stage['name']}")
            
            return result
            
        except Exception as e:
            logger.error(f"Error executing workflow {workflow_id} stage {stage_idx}: {e}")
            
            # Store error in stage results
            workflow_exec.stage_results[stage_idx] = {"error": str(e)}
            
            # Don't raise exception to allow other stages to continue
            return {"error": str(e), "status": "failed"}
            
    async def _execute_stage_with_agent(
        self,
        agent_name: str,
        stage_name: str,
        workflow_id: str,
        workflow_def: WorkflowDefinition,
        stage: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a workflow stage with a specific agent.

        Args:
            agent_name: Name of the agent to use
            stage_name: Name of the stage
            workflow_id: ID of the workflow
            workflow_def: Workflow definition
            stage: Stage definition

        Returns:
            Stage execution results
        """
        agent = self.specialized_agents[agent_name]
        
        # Execute stage based on agent type and stage name
        if agent_name == "guided_assessment":
            return await self._execute_guided_assessment_stage(
                agent, stage_name, workflow_id, workflow_def, stage
            )
            
        elif agent_name == "exploitation_verification":
            return await self._execute_exploitation_verification_stage(
                agent, stage_name, workflow_id, workflow_def, stage
            )
            
        elif agent_name == "remediation_planning":
            return await self._execute_remediation_planning_stage(
                agent, stage_name, workflow_id, workflow_def, stage
            )
            
        elif agent_name == "security_policy":
            return await self._execute_security_policy_stage(
                agent, stage_name, workflow_id, workflow_def, stage
            )
            
        else:
            raise ValueError(f"Unknown agent type: {agent_name}")
            
    async def _execute_guided_assessment_stage(
        self,
        agent: GuidedAssessmentAgent,
        stage_name: str,
        workflow_id: str,
        workflow_def: WorkflowDefinition,
        stage: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a guided assessment stage.

        Args:
            agent: The guided assessment agent
            stage_name: Name of the stage
            workflow_id: ID of the workflow
            workflow_def: Workflow definition
            stage: Stage definition

        Returns:
            Stage execution results
        """
        if stage_name == "initialization":
            # Create a new assessment
            assessment_result = await agent.create_assessment(
                repository_id=workflow_def.target_id,
                repository_info=workflow_def.parameters.get("repository_info", {}),
                assessment_parameters=workflow_def.parameters.get("assessment_parameters", {}),
                user_id=workflow_def.parameters.get("user_id")
            )
            
            # Store assessment ID in workflow artifacts
            workflow_exec = self.workflow_executions[workflow_id]
            workflow_exec.artifacts["assessment_id"] = assessment_result["assessment_id"]
            
            return {
                "stage": "initialization",
                "status": "completed",
                "assessment_id": assessment_result["assessment_id"],
                "plan": assessment_result.get("plan")
            }
            
        elif stage_name == "assessment" or stage_name == "reporting":
            # Get assessment ID from artifacts
            workflow_exec = self.workflow_executions[workflow_id]
            assessment_id = workflow_exec.artifacts.get("assessment_id")
            
            if not assessment_id:
                raise ValueError("Assessment ID not found in workflow artifacts")
                
            # Get assessment status
            status_result = await agent.get_assessment_status(assessment_id)
            
            # The assessment is running asynchronously, so we just check status
            return {
                "stage": stage_name,
                "status": "completed",
                "assessment_id": assessment_id,
                "assessment_status": status_result.get("status"),
                "current_stage": status_result.get("current_stage"),
                "progress": status_result.get("progress"),
                "findings_count": status_result.get("findings_count")
            }
            
        else:
            raise ValueError(f"Unknown guided assessment stage: {stage_name}")
            
    async def _execute_exploitation_verification_stage(
        self,
        agent: ExploitationVerificationAgent,
        stage_name: str,
        workflow_id: str,
        workflow_def: WorkflowDefinition,
        stage: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute an exploitation verification stage.

        Args:
            agent: The exploitation verification agent
            stage_name: Name of the stage
            workflow_id: ID of the workflow
            workflow_def: Workflow definition
            stage: Stage definition

        Returns:
            Stage execution results
        """
        if stage_name == "initialization":
            # No specific initialization needed, just return success
            return {
                "stage": "initialization",
                "status": "completed"
            }
            
        elif stage_name == "analysis":
            # Get findings from workflow artifacts or parameters
            workflow_exec = self.workflow_executions[workflow_id]
            findings = workflow_exec.artifacts.get("findings", [])
            
            if not findings:
                # Try to get findings from parameters
                findings = workflow_def.parameters.get("findings", [])
                
            if not findings:
                return {
                    "stage": "analysis",
                    "status": "completed",
                    "message": "No findings to verify",
                    "verifications": []
                }
                
            # Verify each finding
            verifications = []
            
            for finding in findings:
                verification = await agent.verify_exploitability(
                    finding=finding,
                    context=workflow_def.parameters.get("context", {})
                )
                verifications.append(verification)
                
            # Store verifications in workflow artifacts
            workflow_exec.artifacts["verifications"] = verifications
            
            return {
                "stage": "analysis",
                "status": "completed",
                "verifications_count": len(verifications),
                "verification_summary": self._summarize_verifications(verifications)
            }
            
        elif stage_name == "reporting":
            # Get verifications from workflow artifacts
            workflow_exec = self.workflow_executions[workflow_id]
            verifications = workflow_exec.artifacts.get("verifications", [])
            
            # Generate report (in a real implementation, this would create a report)
            return {
                "stage": "reporting",
                "status": "completed",
                "verifications_count": len(verifications),
                "verification_summary": self._summarize_verifications(verifications),
                "report_id": f"exploit_report_{workflow_id}"
            }
            
        else:
            raise ValueError(f"Unknown exploitation verification stage: {stage_name}")
            
    def _summarize_verifications(self, verifications: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize exploitation verification results.

        Args:
            verifications: List of verification results

        Returns:
            Summary of verification results
        """
        # Count verifications by status
        status_counts = {status.value: 0 for status in ExploitabilityStatus}
        
        for verification in verifications:
            status = verification.get("status")
            if status in status_counts:
                status_counts[status] += 1
                
        # Calculate confidence average
        confidence_sum = sum(v.get("confidence", 0) for v in verifications)
        confidence_avg = confidence_sum / len(verifications) if verifications else 0
        
        return {
            "total": len(verifications),
            "by_status": status_counts,
            "average_confidence": confidence_avg
        }
            
    async def _execute_remediation_planning_stage(
        self,
        agent: RemediationPlanningAgent,
        stage_name: str,
        workflow_id: str,
        workflow_def: WorkflowDefinition,
        stage: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a remediation planning stage.

        Args:
            agent: The remediation planning agent
            stage_name: Name of the stage
            workflow_id: ID of the workflow
            workflow_def: Workflow definition
            stage: Stage definition

        Returns:
            Stage execution results
        """
        if stage_name == "initialization":
            # No specific initialization needed, just return success
            return {
                "stage": "initialization",
                "status": "completed"
            }
            
        elif stage_name == "analysis" or stage_name == "planning":
            # Get findings from workflow artifacts or parameters
            workflow_exec = self.workflow_executions[workflow_id]
            findings = workflow_exec.artifacts.get("findings", [])
            
            if not findings:
                # Try to get findings from parameters
                findings = workflow_def.parameters.get("findings", [])
                
            if not findings:
                return {
                    "stage": stage_name,
                    "status": "completed",
                    "message": "No findings for remediation planning",
                    "plans": []
                }
                
            # Create remediation plan for each finding
            remediation_plans = []
            
            for finding in findings:
                plan = await agent.create_remediation_plan(
                    finding=finding,
                    context=workflow_def.parameters.get("context", {}),
                    code_context=workflow_def.parameters.get("code_context", {})
                )
                remediation_plans.append(plan)
                
            # Store remediation plans in workflow artifacts
            workflow_exec.artifacts["remediation_plans"] = remediation_plans
            
            return {
                "stage": stage_name,
                "status": "completed",
                "plans_count": len(remediation_plans),
                "plan_summary": self._summarize_remediation_plans(remediation_plans)
            }
            
        else:
            raise ValueError(f"Unknown remediation planning stage: {stage_name}")
            
    def _summarize_remediation_plans(self, plans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Summarize remediation plan results.

        Args:
            plans: List of remediation plans

        Returns:
            Summary of remediation plans
        """
        # Count plans by priority and complexity
        priority_counts = {priority.value: 0 for priority in RemediationPriority}
        complexity_counts = {complexity.value: 0 for complexity in RemediationComplexity}
        
        for plan in plans:
            priority = plan.get("priority")
            complexity = plan.get("complexity")
            
            if priority in priority_counts:
                priority_counts[priority] += 1
                
            if complexity in complexity_counts:
                complexity_counts[complexity] += 1
                
        return {
            "total": len(plans),
            "by_priority": priority_counts,
            "by_complexity": complexity_counts
        }
            
    async def _execute_security_policy_stage(
        self,
        agent: SecurityPolicyAgent,
        stage_name: str,
        workflow_id: str,
        workflow_def: WorkflowDefinition,
        stage: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute a security policy stage.

        Args:
            agent: The security policy agent
            stage_name: Name of the stage
            workflow_id: ID of the workflow
            workflow_def: Workflow definition
            stage: Stage definition

        Returns:
            Stage execution results
        """
        if stage_name == "initialization":
            # No specific initialization needed, just return success
            return {
                "stage": "initialization",
                "status": "completed"
            }
            
        elif stage_name == "evaluation":
            # Evaluate policy compliance for the target
            target_type = workflow_def.target_type
            target_id = workflow_def.target_id
            target_data = workflow_def.parameters.get("target_data", {})
            
            evaluation = await agent.evaluate_policy_compliance(
                target=target_data,
                target_type=target_type,
                policy_context=workflow_def.parameters.get("policy_context", {})
            )
            
            # Store evaluation in workflow artifacts
            workflow_exec = self.workflow_executions[workflow_id]
            workflow_exec.artifacts["policy_evaluation"] = evaluation
            
            return {
                "stage": "evaluation",
                "status": "completed",
                "evaluation_id": evaluation.get("evaluation_id"),
                "compliance_status": evaluation.get("compliance_status"),
                "gaps_count": len(evaluation.get("compliance_gaps", [])),
                "recommendations_count": len(evaluation.get("recommendations", []))
            }
            
        elif stage_name == "recommendations":
            # Get evaluation from workflow artifacts
            workflow_exec = self.workflow_executions[workflow_id]
            evaluation = workflow_exec.artifacts.get("policy_evaluation", {})
            
            # Generate recommendations based on evaluation
            recommendations = []
            
            for rec_type in PolicyRecommendationType:
                recommendation = await agent.generate_policy_recommendation(
                    input_data=evaluation,
                    recommendation_type=rec_type,
                    policy_context=workflow_def.parameters.get("policy_context", {})
                )
                recommendations.append(recommendation)
                
            # Store recommendations in workflow artifacts
            workflow_exec.artifacts["policy_recommendations"] = recommendations
            
            return {
                "stage": "recommendations",
                "status": "completed",
                "recommendations_count": len(recommendations),
                "recommendation_types": [r.get("recommendation_type") for r in recommendations]
            }
            
        else:
            raise ValueError(f"Unknown security policy stage: {stage_name}")
            
    def _compile_workflow_results(self, workflow_id: str) -> Dict[str, Any]:
        """Compile comprehensive results from a completed workflow.

        Args:
            workflow_id: ID of the workflow

        Returns:
            Compiled workflow results
        """
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        # Base results
        results = {
            "workflow_id": workflow_id,
            "workflow_type": workflow_def.workflow_type.value,
            "target_id": workflow_def.target_id,
            "target_type": workflow_def.target_type,
            "start_time": workflow_exec.start_time,
            "completion_time": workflow_exec.completion_time,
            "execution_time": (
                workflow_exec.completion_time - workflow_exec.start_time
                if workflow_exec.completion_time and workflow_exec.start_time
                else None
            ),
            "status": workflow_exec.status.value,
            "stage_results": {},
            "findings": workflow_exec.artifacts.get("findings", []),
            "artifacts": {}
        }
        
        # Add stage results
        for stage_idx, stage_result in workflow_exec.stage_results.items():
            if stage_idx < len(workflow_def.stages):
                stage_name = workflow_def.stages[stage_idx]["name"]
                results["stage_results"][stage_name] = stage_result
                
        # Add specific artifact types based on workflow type
        if workflow_def.workflow_type == WorkflowType.GUIDED_ASSESSMENT:
            results["artifacts"]["assessment_id"] = workflow_exec.artifacts.get("assessment_id")
            
        elif workflow_def.workflow_type == WorkflowType.EXPLOITATION_VERIFICATION:
            results["artifacts"]["verifications"] = workflow_exec.artifacts.get("verifications", [])
            
        elif workflow_def.workflow_type == WorkflowType.REMEDIATION_PLANNING:
            results["artifacts"]["remediation_plans"] = workflow_exec.artifacts.get("remediation_plans", [])
            
        elif workflow_def.workflow_type == WorkflowType.POLICY_COMPLIANCE:
            results["artifacts"]["policy_evaluation"] = workflow_exec.artifacts.get("policy_evaluation", {})
            results["artifacts"]["policy_recommendations"] = workflow_exec.artifacts.get("policy_recommendations", [])
            
        elif workflow_def.workflow_type == WorkflowType.COMPREHENSIVE:
            # Include all artifacts for comprehensive workflow
            results["artifacts"] = workflow_exec.artifacts
            
        return results
            
    async def get_workflow_status(self, workflow_id: str) -> Dict[str, Any]:
        """Get the current status of a workflow.

        Args:
            workflow_id: ID of the workflow

        Returns:
            Workflow status information

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        return {
            "workflow_id": workflow_id,
            "name": workflow_def.name,
            "description": workflow_def.description,
            "workflow_type": workflow_def.workflow_type.value,
            "target_id": workflow_def.target_id,
            "target_type": workflow_def.target_type,
            "status": workflow_exec.status.value,
            "progress": workflow_exec.progress,
            "current_stage": workflow_exec.current_stage,
            "current_stage_name": (
                workflow_def.stages[workflow_exec.current_stage]["name"]
                if 0 <= workflow_exec.current_stage < len(workflow_def.stages)
                else None
            ),
            "total_stages": len(workflow_def.stages),
            "start_time": workflow_exec.start_time,
            "completion_time": workflow_exec.completion_time,
            "error": workflow_exec.error
        }
        
    async def pause_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Pause a running workflow.

        Args:
            workflow_id: ID of the workflow to pause

        Returns:
            Updated workflow status

        Raises:
            ValueError: If workflow ID is not found or workflow is not running
        """
        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        if workflow_exec.status != WorkflowStatus.RUNNING:
            raise ValueError(f"Workflow {workflow_id} is not running (current status: {workflow_exec.status.value})")
            
        logger.info(f"Pausing workflow: {workflow_id}")
        
        # Update execution status
        workflow_exec.status = WorkflowStatus.PAUSED
        
        # Emit workflow event
        await self._emit_workflow_event(
            workflow_id, 
            workflow_def.workflow_type,
            WorkflowStatus.PAUSED,
            workflow_exec.progress
        )
        
        return self.get_workflow_status(workflow_id)
        
    async def resume_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Resume a paused workflow.

        Args:
            workflow_id: ID of the workflow to resume

        Returns:
            Updated workflow status

        Raises:
            ValueError: If workflow ID is not found or workflow is not paused
        """
        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        if workflow_exec.status != WorkflowStatus.PAUSED:
            raise ValueError(f"Workflow {workflow_id} is not paused (current status: {workflow_exec.status.value})")
            
        logger.info(f"Resuming workflow: {workflow_id}")
        
        # Update execution status
        workflow_exec.status = WorkflowStatus.RUNNING
        
        # Add to active workflows
        self.active_workflows.add(workflow_id)
        
        # Emit workflow event
        await self._emit_workflow_event(
            workflow_id, 
            workflow_def.workflow_type,
            WorkflowStatus.RUNNING,
            workflow_exec.progress
        )
        
        # Resume execution (non-blocking)
        asyncio.create_task(self._execute_workflow(workflow_id))
        
        return self.get_workflow_status(workflow_id)
        
    async def stop_workflow(self, workflow_id: str) -> Dict[str, Any]:
        """Stop a running or paused workflow.

        Args:
            workflow_id: ID of the workflow to stop

        Returns:
            Final workflow status

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        if workflow_exec.status not in (WorkflowStatus.RUNNING, WorkflowStatus.PAUSED):
            logger.warning(f"Workflow {workflow_id} is not running or paused (current status: {workflow_exec.status.value})")
            return self.get_workflow_status(workflow_id)
            
        logger.info(f"Stopping workflow: {workflow_id}")
        
        # Update execution status
        workflow_exec.status = WorkflowStatus.COMPLETED
        workflow_exec.completion_time = time.time()
        
        # Remove from active workflows
        if workflow_id in self.active_workflows:
            self.active_workflows.remove(workflow_id)
            
        # Emit workflow event
        await self._emit_workflow_event(
            workflow_id, 
            workflow_def.workflow_type,
            WorkflowStatus.COMPLETED,
            workflow_exec.progress,
            {"message": "Workflow stopped by user"}
        )
        
        return self.get_workflow_status(workflow_id)
        
    async def get_workflow_results(self, workflow_id: str) -> Dict[str, Any]:
        """Get the current results of a workflow.

        Args:
            workflow_id: ID of the workflow

        Returns:
            Workflow results

        Raises:
            ValueError: If workflow ID is not found
        """
        if workflow_id not in self.workflow_executions:
            raise ValueError(f"Workflow ID {workflow_id} not found")
            
        workflow_def = self.workflow_definitions[workflow_id]
        workflow_exec = self.workflow_executions[workflow_id]
        
        # For completed workflows, compile comprehensive results
        if workflow_exec.status == WorkflowStatus.COMPLETED:
            return self._compile_workflow_results(workflow_id)
            
        # For other statuses, return current partial results
        partial_results = {
            "workflow_id": workflow_id,
            "workflow_type": workflow_def.workflow_type.value,
            "target_id": workflow_def.target_id,
            "target_type": workflow_def.target_type,
            "status": workflow_exec.status.value,
            "progress": workflow_exec.progress,
            "start_time": workflow_exec.start_time,
            "stage_results": {},
            "artifacts": {}
        }
        
        # Add completed stage results
        for stage_idx, stage_result in workflow_exec.stage_results.items():
            if stage_idx < len(workflow_def.stages):
                stage_name = workflow_def.stages[stage_idx]["name"]
                partial_results["stage_results"][stage_name] = stage_result
                
        # Add available artifacts
        for artifact_name, artifact_value in workflow_exec.artifacts.items():
            partial_results["artifacts"][artifact_name] = artifact_value
            
        return partial_results
    
    async def _emit_workflow_event(
        self,
        workflow_id: str,
        workflow_type: WorkflowType,
        status: WorkflowStatus,
        progress: float,
        results: Optional[Dict[str, Any]] = None
    ) -> None:
        """Emit a workflow event.

        Args:
            workflow_id: ID of the workflow
            workflow_type: Type of workflow
            status: Current status
            progress: Progress percentage
            results: Optional results to include
        """
        event = WorkflowEvent(
            sender_id=self.agent_id,
            workflow_id=workflow_id,
            workflow_type=workflow_type,
            status=status,
            progress=progress,
            results=results
        )
        self.emit_event(event)
        
    async def _handle_workflow_event(self, event: WorkflowEvent) -> None:
        """Handle workflow events.

        Args:
            event: Workflow event
        """
        # Log the event
        logger.info(
            f"Received workflow event for {event.workflow_id} "
            f"({event.workflow_type.value}): {event.status.value}"
        )
        
        # Currently no specific handling needed for workflow events from other agents
        
    async def _handle_assessment_plan_event(self, event: AssessmentPlanEvent) -> None:
        """Handle assessment plan events.

        Args:
            event: Assessment plan event
        """
        # Log the event
        logger.info(f"Received assessment plan event for repository {event.repository_id}")
        
        # Find related workflow executions
        for workflow_id, workflow_exec in self.workflow_executions.items():
            workflow_def = self.workflow_definitions[workflow_id]
            
            # Check if this workflow is related to the assessment
            if (
                workflow_def.target_id == event.repository_id and
                workflow_def.workflow_type in (WorkflowType.GUIDED_ASSESSMENT, WorkflowType.COMPREHENSIVE)
            ):
                # Store assessment plan in workflow artifacts
                workflow_exec.artifacts["assessment_plan"] = event.plan
                workflow_exec.artifacts["assessment_id"] = event.assessment_id
                
    async def _handle_assessment_stage_event(self, event: AssessmentStageEvent) -> None:
        """Handle assessment stage events.

        Args:
            event: Assessment stage event
        """
        # Log the event
        logger.info(
            f"Received assessment stage event for repository {event.repository_id}: "
            f"{event.stage.value} {event.status}"
        )
        
        # Find related workflow executions
        for workflow_id, workflow_exec in self.workflow_executions.items():
            workflow_def = self.workflow_definitions[workflow_id]
            
            # Check if this workflow is related to the assessment
            if (
                workflow_def.target_id == event.repository_id and
                workflow_def.workflow_type in (WorkflowType.GUIDED_ASSESSMENT, WorkflowType.COMPREHENSIVE)
            ):
                # Store stage results in workflow artifacts
                assessment_stages = workflow_exec.artifacts.get("assessment_stages", {})
                assessment_stages[event.stage.value] = {
                    "status": event.status,
                    "progress": event.progress,
                    "results": event.results
                }
                workflow_exec.artifacts["assessment_stages"] = assessment_stages
                
                # If findings are in the results, store them
                if event.results and "findings" in event.results:
                    workflow_exec.artifacts["findings"] = event.results["findings"]
                    
    async def _handle_exploit_verification_event(self, event: ExploitVerificationEvent) -> None:
        """Handle exploit verification events.

        Args:
            event: Exploit verification event
        """
        # Log the event
        logger.info(
            f"Received exploit verification event for finding {event.finding_id}: "
            f"{event.status.value}"
        )
        
        # Find related workflow executions
        for workflow_id, workflow_exec in self.workflow_executions.items():
            # Check if this workflow has the verified finding
            findings = workflow_exec.artifacts.get("findings", [])
            
            if any(
                f.get("finding_id", f.get("file_id", "")) == event.finding_id
                for f in findings
            ):
                # Store verification in workflow artifacts
                verifications = workflow_exec.artifacts.get("verifications", [])
                
                verification = {
                    "verification_id": event.verification_id,
                    "finding_id": event.finding_id,
                    "status": event.status.value,
                    "justification": event.justification,
                    "exploitation_path": event.exploitation_path,
                    "risk_factors": event.risk_factors,
                    "sender_id": event.sender_id,
                    "timestamp": event.timestamp
                }
                
                # Update existing verification or add new one
                existing_idx = next(
                    (i for i, v in enumerate(verifications) 
                     if v.get("verification_id") == event.verification_id),
                    None
                )
                
                if existing_idx is not None:
                    verifications[existing_idx] = verification
                else:
                    verifications.append(verification)
                    
                workflow_exec.artifacts["verifications"] = verifications
                
    async def _handle_remediation_plan_event(self, event: RemediationPlanEvent) -> None:
        """Handle remediation plan events.

        Args:
            event: Remediation plan event
        """
        # Log the event
        logger.info(
            f"Received remediation plan event for finding {event.finding_id}: "
            f"{event.priority.value} priority, {event.complexity.value} complexity"
        )
        
        # Find related workflow executions
        for workflow_id, workflow_exec in self.workflow_executions.items():
            # Check if this workflow has the finding
            findings = workflow_exec.artifacts.get("findings", [])
            
            if any(
                f.get("finding_id", f.get("file_id", "")) == event.finding_id
                for f in findings
            ):
                # Store remediation plan in workflow artifacts
                remediation_plans = workflow_exec.artifacts.get("remediation_plans", [])
                
                plan = {
                    "plan_id": event.plan_id,
                    "finding_id": event.finding_id,
                    "priority": event.priority.value,
                    "complexity": event.complexity.value,
                    "steps": event.steps,
                    "code_changes": event.code_changes,
                    "estimated_effort": event.estimated_effort,
                    "sender_id": event.sender_id,
                    "timestamp": event.timestamp
                }
                
                # Update existing plan or add new one
                existing_idx = next(
                    (i for i, p in enumerate(remediation_plans) 
                     if p.get("plan_id") == event.plan_id),
                    None
                )
                
                if existing_idx is not None:
                    remediation_plans[existing_idx] = plan
                else:
                    remediation_plans.append(plan)
                    
                workflow_exec.artifacts["remediation_plans"] = remediation_plans
                
    async def _handle_policy_evaluation_event(self, event: PolicyEvaluationEvent) -> None:
        """Handle policy evaluation events.

        Args:
            event: Policy evaluation event
        """
        # Log the event
        logger.info(
            f"Received policy evaluation event for {event.target_type} {event.target_id}: "
            f"{event.compliance_status.value}"
        )
        
        # Find related workflow executions
        for workflow_id, workflow_exec in self.workflow_executions.items():
            workflow_def = self.workflow_definitions[workflow_id]
            
            # Check if this workflow is related to the target
            if (
                workflow_def.target_id == event.target_id and
                workflow_def.target_type == event.target_type
            ):
                # Store evaluation in workflow artifacts
                workflow_exec.artifacts["policy_evaluation"] = {
                    "evaluation_id": event.evaluation_id,
                    "target_id": event.target_id,
                    "target_type": event.target_type,
                    "compliance_status": event.compliance_status.value,
                    "compliance_gaps": event.compliance_gaps,
                    "policy_references": event.policy_references,
                    "recommendations": event.recommendations,
                    "sender_id": event.sender_id,
                    "timestamp": event.timestamp
                }
                
    async def _handle_policy_recommendation_event(self, event: PolicyRecommendationEvent) -> None:
        """Handle policy recommendation events.

        Args:
            event: Policy recommendation event
        """
        # Log the event
        logger.info(
            f"Received policy recommendation event: {event.title} "
            f"({event.recommendation_type.value})"
        )
        
        # Find related workflow executions with policy artifacts
        for workflow_id, workflow_exec in self.workflow_executions.items():
            if "policy_evaluation" in workflow_exec.artifacts:
                # Store recommendation in workflow artifacts
                recommendations = workflow_exec.artifacts.get("policy_recommendations", [])
                
                recommendation = {
                    "recommendation_id": event.recommendation_id,
                    "recommendation_type": event.recommendation_type.value,
                    "title": event.title,
                    "description": event.description,
                    "justification": event.justification,
                    "implementation_steps": event.implementation_steps,
                    "policy_references": event.policy_references,
                    "sender_id": event.sender_id,
                    "timestamp": event.timestamp
                }
                
                # Update existing recommendation or add new one
                existing_idx = next(
                    (i for i, r in enumerate(recommendations) 
                     if r.get("recommendation_id") == event.recommendation_id),
                    None
                )
                
                if existing_idx is not None:
                    recommendations[existing_idx] = recommendation
                else:
                    recommendations.append(recommendation)
                    
                workflow_exec.artifacts["policy_recommendations"] = recommendations
                
    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment events.

        Args:
            event: Task assignment event
        """
        if event.receiver_id != self.agent_id:
            return
            
        logger.info(f"Received task assignment: {event.task_id} - {event.task_type}")
        
        # Handle different task types
        if event.task_type == "create_workflow":
            # Extract parameters
            params = event.task_parameters
            workflow_type_str = params.get("workflow_type")
            target_id = params.get("target_id")
            target_type = params.get("target_type")
            
            if not workflow_type_str or not target_id or not target_type:
                logger.warning(f"Invalid workflow creation task parameters: {params}")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing required parameters"}
                )
                return
                
            try:
                # Convert workflow type string to enum
                workflow_type = WorkflowType(workflow_type_str)
                
                # Create workflow
                workflow = await self.create_workflow(
                    workflow_type=workflow_type,
                    target_id=target_id,
                    target_type=target_type,
                    parameters=params.get("parameters"),
                    name=params.get("name"),
                    description=params.get("description")
                )
                
                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=workflow
                )
                
            except Exception as e:
                logger.error(f"Error creating workflow: {e}")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)}
                )
                
        elif event.task_type == "start_workflow":
            # Extract parameters
            workflow_id = event.task_parameters.get("workflow_id")
            
            if not workflow_id:
                logger.warning("Missing workflow_id parameter")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing workflow_id parameter"}
                )
                return
                
            try:
                # Start workflow
                result = await self.start_workflow(workflow_id)
                
                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result
                )
                
            except Exception as e:
                logger.error(f"Error starting workflow: {e}")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)}
                )
                
        elif event.task_type == "get_workflow_status":
            # Extract parameters
            workflow_id = event.task_parameters.get("workflow_id")
            
            if not workflow_id:
                logger.warning("Missing workflow_id parameter")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing workflow_id parameter"}
                )
                return
                
            try:
                # Get workflow status
                result = await self.get_workflow_status(workflow_id)
                
                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result
                )
                
            except Exception as e:
                logger.error(f"Error getting workflow status: {e}")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)}
                )
                
        elif event.task_type == "get_workflow_results":
            # Extract parameters
            workflow_id = event.task_parameters.get("workflow_id")
            
            if not workflow_id:
                logger.warning("Missing workflow_id parameter")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": "Missing workflow_id parameter"}
                )
                return
                
            try:
                # Get workflow results
                result = await self.get_workflow_results(workflow_id)
                
                # Emit task result
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="completed",
                    result=result
                )
                
            except Exception as e:
                logger.error(f"Error getting workflow results: {e}")
                
                # Emit task result with error
                await self._emit_task_result(
                    task_id=event.task_id,
                    sender_id=event.sender_id,
                    status="failed",
                    result={"error": str(e)}
                )
        
        else:
            logger.warning(f"Unknown task type: {event.task_type}")
            
            # Emit task result with error
            await self._emit_task_result(
                task_id=event.task_id,
                sender_id=event.sender_id,
                status="failed",
                result={"error": f"Unknown task type: {event.task_type}"}
            )
    
    async def _emit_task_result(
        self,
        task_id: str,
        sender_id: str,
        status: str,
        result: Any
    ) -> None:
        """Emit a task result event.

        Args:
            task_id: ID of the task
            sender_id: ID of the sender
            status: Status of the task
            result: Result of the task
        """
        event = TaskResultEvent(
            sender_id=self.agent_id,
            receiver_id=sender_id,
            task_id=task_id,
            status=status,
            result=result
        )
        self.emit_event(event)
    
    async def _handle_task_result(self, event: TaskResultEvent) -> None:
        """Handle task result events.

        Args:
            event: Task result event
        """
        # Only process results intended for this agent
        if event.receiver_id != self.agent_id:
            return
            
        logger.info(f"Received task result: {event.task_id} - {event.status}")
        
        # Currently no specific handling needed for task results