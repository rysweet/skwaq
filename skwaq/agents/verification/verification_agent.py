"""Verification Agent for the Skwaq vulnerability assessment system.

This module defines a verification agent that validates the work of other
agents, ensuring findings are accurate and well-supported by evidence.
"""

from typing import Dict, List, Any, Optional, Set, Tuple, Union, cast
import asyncio
import json
import enum
import time
import uuid

from ..base import BaseAgent, AutogenChatAgent, AgentState
from ..events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task
from ...events.system_events import EventBus
from ...utils.config import get_config
from ...utils.logging import get_logger, LogEvent
from ...shared.finding import Finding

logger = get_logger(__name__)


class VerificationStatus(enum.Enum):
    """Status of verification for a finding or analysis."""
    
    VERIFIED = "verified"
    PARTIALLY_VERIFIED = "partially_verified"
    UNVERIFIED = "unverified"
    CONTRADICTED = "contradicted"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"


class VerificationEvent(AgentCommunicationEvent):
    """Event for communicating verification results."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        content_id: str,
        status: VerificationStatus,
        justification: str,
        evidence: List[Dict[str, Any]],
        verification_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a verification event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            content_id: Identifier for the content being verified
            status: Verification status result
            justification: Explanation of the verification result
            evidence: Supporting evidence for the verification
            verification_id: Unique identifier for this verification
            metadata: Additional metadata
        """
        verification_metadata = metadata or {}
        verification_metadata.update({
            "content_id": content_id,
            "status": status.value,
            "evidence_count": len(evidence),
            "verification_id": verification_id or str(uuid.uuid4()),
            "event_type": "verification"
        })

        # Format message based on status
        if status == VerificationStatus.VERIFIED:
            message = f"VERIFIED: {justification}"
        elif status == VerificationStatus.PARTIALLY_VERIFIED:
            message = f"PARTIALLY VERIFIED: {justification}"
        elif status == VerificationStatus.UNVERIFIED:
            message = f"UNVERIFIED: {justification}"
        elif status == VerificationStatus.CONTRADICTED:
            message = f"CONTRADICTED: {justification}"
        else:
            message = f"INSUFFICIENT EVIDENCE: {justification}"

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=message,
            message_type="verification",
            metadata=verification_metadata,
        )
        self.content_id = content_id
        self.status = status
        self.justification = justification
        self.evidence = evidence
        self.verification_id = verification_metadata["verification_id"]


class VerificationAgent(AutogenChatAgent):
    """Verification agent for validating findings and analyses.
    
    This agent is responsible for verifying the work of other agents,
    particularly focusing on validating vulnerability findings and
    ensuring they are accurate and well-supported.
    """

    def __init__(
        self,
        name: str = "VerificationAgent",
        description: str = "Verifies and validates findings and analyses",
        config_key: str = "agents.verification",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the verification agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are a verification agent for a vulnerability assessment system.
Your purpose is to verify findings and analyses produced by other agents in the system,
ensuring that they are accurate, well-supported by evidence, and properly contextualized.

Your responsibilities include:
1. Validating the accuracy of vulnerability findings
2. Checking that findings have sufficient supporting evidence
3. Verifying that reported vulnerabilities are exploitable in the given context
4. Challenging findings that appear speculative or poorly supported
5. Providing a verification status for each finding
6. Explaining your verification reasoning and methodology
7. Maintaining a high standard of evidence and verification

You should approach each verification task with skepticism and rigor, demanding
clear evidence and logical reasoning before accepting a finding as verified.
Your work helps ensure that the vulnerability assessment process is reliable
and trustworthy.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )
        
        # Set up verification tracking
        self.verifications: Dict[str, Dict[str, Any]] = {}
        self.verification_tasks: Dict[str, Task] = {}
        
    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()
        
        # Register event handlers
        self.register_event_handler(VerificationEvent, self._handle_verification_event)
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)
        self.register_event_handler(TaskResultEvent, self._handle_task_result)
        
    async def verify_finding(
        self,
        finding: Finding,
        evidence: Optional[List[Dict[str, Any]]] = None,
        context: Optional[Dict[str, Any]] = None,
        task_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify a vulnerability finding.

        Args:
            finding: The finding to verify
            evidence: Optional supporting evidence for verification
            context: Optional additional context
            task_id: Optional task ID for this verification

        Returns:
            Dictionary with verification results
        """
        verification_id = task_id or f"verify_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        content_id = f"finding_{finding.file_id}_{finding.line_number}"
        
        logger.info(f"Starting verification of finding: {finding.vulnerability_type} at line {finding.line_number}")
        
        # Create verification task
        verification_task = Task(
            task_id=verification_id,
            task_type="finding_verification",
            description=f"Verify finding: {finding.vulnerability_type} at line {finding.line_number}",
            parameters={
                "finding_id": finding.file_id,
                "line_number": finding.line_number,
                "vulnerability_type": finding.vulnerability_type
            },
            status="in_progress"
        )
        
        self.verification_tasks[verification_id] = verification_task
        
        try:
            # Prepare the finding for verification
            finding_dict = finding.to_dict()
            
            # Structure for the verification
            verification_result = {
                "finding": finding_dict,
                "content_id": content_id,
                "verification_id": verification_id,
                "timestamp": time.time(),
                "status": None,
                "justification": "",
                "evidence": evidence or [],
                "context": context or {}
            }
            
            # Gather additional context if needed
            if not evidence:
                # For a real implementation, we would gather evidence here
                verification_result["evidence"] = [
                    {"type": "code_snippet", "content": finding.matched_text or "No code snippet available"}
                ]
            
            # Perform verification analysis
            verification_result.update(
                await self._analyze_finding(finding_dict, verification_result["evidence"], context or {})
            )
            
            # Store the verification
            self.verifications[verification_id] = verification_result
            
            # Update task status
            verification_task.status = "completed"
            verification_task.result = verification_result
            
            # Emit verification event
            await self._emit_verification_event(verification_result)
            
            # Log completion
            logger.info(f"Completed verification of finding with status: {verification_result['status']}")
            
            return verification_result
        except Exception as e:
            logger.error(f"Error verifying finding: {e}")
            verification_task.status = "failed"
            verification_task.error = str(e)
            raise
    
    async def _analyze_finding(
        self,
        finding: Dict[str, Any],
        evidence: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze a finding to determine its verification status.

        Args:
            finding: Finding to analyze
            evidence: Supporting evidence
            context: Additional context

        Returns:
            Dictionary with verification analysis
        """
        # Prepare prompt for verification analysis
        finding_str = json.dumps(finding, indent=2)
        evidence_str = json.dumps(evidence, indent=2)
        context_str = json.dumps(context, indent=2)
        
        verification_prompt = (
            f"I need you to verify the following vulnerability finding:\n\n"
            f"FINDING:\n{finding_str}\n\n"
            f"EVIDENCE:\n{evidence_str}\n\n"
            f"CONTEXT:\n{context_str}\n\n"
            f"Please analyze the finding and determine if it is verifiable based on the evidence provided. "
            f"Return your analysis in JSON format with the following fields:\n"
            f"- status: One of 'verified', 'partially_verified', 'unverified', 'contradicted', 'insufficient_evidence'\n"
            f"- justification: Detailed explanation of your verification assessment\n"
            f"- confidence: Your confidence in this verification (0.0-1.0)\n"
            f"- missing_evidence: List of any additional evidence that would be needed for full verification\n"
            f"- issues: List of any issues or problems with the finding itself\n"
        )
        
        # Use the chat model to analyze the finding
        response = await self.openai_client.create_completion(
            prompt=verification_prompt,
            model=self.model,
            temperature=0.1,
            max_tokens=1500,
            response_format={"type": "json"}
        )
        
        # Extract the text response
        response_text = response.get("choices", [{}])[0].get("text", "").strip()
        
        try:
            # Parse the JSON response
            verification = json.loads(response_text)
            
            # Ensure all required fields are present
            if "status" not in verification:
                verification["status"] = "insufficient_evidence"
            if "justification" not in verification:
                verification["justification"] = "No justification provided"
            if "confidence" not in verification:
                verification["confidence"] = 0.5
            if "missing_evidence" not in verification:
                verification["missing_evidence"] = []
            if "issues" not in verification:
                verification["issues"] = []
                
            # Convert status string to enum
            try:
                status = VerificationStatus(verification["status"])
            except ValueError:
                # Default to insufficient evidence if invalid status
                status = VerificationStatus.INSUFFICIENT_EVIDENCE
                
            verification["status"] = status.value
            
            return verification
        except json.JSONDecodeError:
            logger.error(f"Failed to parse verification result: {response_text}")
            # Return a default verification on parsing error
            return {
                "status": VerificationStatus.INSUFFICIENT_EVIDENCE.value,
                "justification": "Error analyzing finding for verification",
                "confidence": 0.0,
                "missing_evidence": ["Valid analysis result"],
                "issues": ["Could not process verification"]
            }
    
    async def _emit_verification_event(self, verification: Dict[str, Any]) -> None:
        """Emit a verification event with results.

        Args:
            verification: Verification result to emit
        """
        try:
            # Convert status string to enum if needed
            if isinstance(verification["status"], str):
                try:
                    status = VerificationStatus(verification["status"])
                except ValueError:
                    status = VerificationStatus.INSUFFICIENT_EVIDENCE
            else:
                status = verification["status"]
                
            # Create verification event
            event = VerificationEvent(
                sender_id=self.agent_id,
                receiver_id="all",  # Broadcast to all interested agents
                content_id=verification["content_id"],
                status=status,
                justification=verification["justification"],
                evidence=verification.get("evidence", []),
                verification_id=verification["verification_id"]
            )
            
            # Emit the event
            await self.emit_event(event)
            
        except Exception as e:
            logger.error(f"Error emitting verification event: {e}")
    
    async def _handle_verification_event(self, event: VerificationEvent) -> None:
        """Handle incoming verification events.

        Args:
            event: Incoming verification event
        """
        if not isinstance(event, VerificationEvent):
            return
            
        # Log the received verification
        logger.info(f"Received verification event for content {event.content_id} with status {event.status.value}")
        
        # Store the verification for reference
        self.verifications[event.verification_id] = {
            "verification_id": event.verification_id,
            "content_id": event.content_id,
            "status": event.status.value,
            "justification": event.justification,
            "evidence": event.evidence,
            "sender_id": event.sender_id,
            "timestamp": time.time()
        }
        
    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment events.

        Args:
            event: Task assignment event
        """
        if event.receiver_id != self.agent_id:
            return
            
        if event.task_type == "finding_verification":
            # Extract finding information from task parameters
            params = event.task_parameters
            finding_id = params.get("finding_id")
            
            if not finding_id:
                logger.warning(f"Received verification task without finding_id: {event.task_id}")
                return
                
            # Create a placeholder Finding object
            finding = Finding(
                type=params.get("type", "unknown"),
                vulnerability_type=params.get("vulnerability_type", "unknown"),
                description=params.get("description", ""),
                file_id=finding_id,
                line_number=params.get("line_number", 0)
            )
            
            # Begin verification process
            asyncio.create_task(self.verify_finding(
                finding=finding,
                task_id=event.task_id
            ))
            
    async def _handle_task_result(self, event: TaskResultEvent) -> None:
        """Handle task result events.

        Args:
            event: Task result event
        """
        # Currently no specific handling needed
        pass
        
    def get_verification(self, verification_id: str) -> Optional[Dict[str, Any]]:
        """Get a verification result by ID.

        Args:
            verification_id: ID of the verification to retrieve

        Returns:
            Verification result or None if not found
        """
        return self.verifications.get(verification_id)