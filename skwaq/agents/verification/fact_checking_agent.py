"""Fact Checking Agent for the Skwaq vulnerability assessment system.

This module defines a specialized fact checking agent that verifies
factual statements, claims, and references made during the vulnerability
assessment process.
"""

from typing import Dict, List, Any, Optional, Set, Tuple, Union, cast
import asyncio
import json
import enum
import time
import uuid
import re

from ..base import BaseAgent, AutogenChatAgent, AgentState
from ..events import AgentCommunicationEvent, TaskAssignmentEvent, TaskResultEvent, Task
from ...events.system_events import EventBus
from ...utils.config import get_config
from ...utils.logging import get_logger, LogEvent

logger = get_logger(__name__)


class FactStatus(enum.Enum):
    """Status of a fact check."""

    TRUE = "true"
    PARTIALLY_TRUE = "partially_true"
    FALSE = "false"
    UNVERIFIABLE = "unverifiable"
    MISLEADING = "misleading"
    OUTDATED = "outdated"


class FactCheckEvent(AgentCommunicationEvent):
    """Event for communicating fact check results."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        claim: str,
        status: FactStatus,
        explanation: str,
        sources: List[Dict[str, Any]],
        fact_check_id: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a fact check event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            claim: The claim being fact-checked
            status: Fact check status result
            explanation: Explanation of the fact check result
            sources: Supporting sources for the fact check
            fact_check_id: Unique identifier for this fact check
            metadata: Additional metadata
        """
        fact_check_metadata = metadata or {}
        fact_check_metadata.update(
            {
                "claim": claim,
                "status": status.value,
                "source_count": len(sources),
                "fact_check_id": fact_check_id or str(uuid.uuid4()),
                "event_type": "fact_check",
            }
        )

        # Format message based on status
        message = f"FACT CHECK [{status.value.upper()}]: {claim}"

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=message,
            message_type="fact_check",
            metadata=fact_check_metadata,
        )
        self.claim = claim
        self.status = status
        self.explanation = explanation
        self.sources = sources
        self.fact_check_id = fact_check_metadata["fact_check_id"]


class FactCheckingAgent(AutogenChatAgent):
    """Fact checking agent for verifying factual claims.

    This agent is responsible for checking factual statements made
    during the vulnerability assessment process, including technical
    claims, references to standards, and statements about security trends.
    """

    def __init__(
        self,
        name: str = "FactCheckingAgent",
        description: str = "Verifies factual statements and claims",
        config_key: str = "agents.fact_checking",
        system_message: Optional[str] = None,
        agent_id: Optional[str] = None,
        model: Optional[str] = None,
    ):
        """Initialize the fact checking agent.

        Args:
            name: Name of the agent
            description: Description of the agent's purpose
            config_key: Configuration key for this agent
            system_message: Custom system message for the agent
            agent_id: Optional unique identifier for the agent
            model: Optional model override
        """
        if system_message is None:
            system_message = """You are a fact checking agent for a vulnerability assessment system.
Your purpose is to verify factual statements and claims made by other agents
during the vulnerability assessment process.

Your responsibilities include:
1. Checking technical claims about programming languages, frameworks, and libraries
2. Verifying references to security standards, best practices, and documentation
3. Validating statements about security trends and prevalence of vulnerability types
4. Confirming the accuracy of cited CVEs, CWEs, and other security references
5. Checking version-specific claims about software behavior and vulnerabilities
6. Providing a fact check status for each claim
7. Explaining your fact check reasoning and citing authoritative sources

You should approach each fact check with rigor and skepticism, consulting
authoritative sources before determining whether a claim is true, partially true,
false, unverifiable, misleading, or outdated.

When checking facts, always consider:
- The specific context in which the claim is made
- The date or version relevance of the claim
- Common misunderstandings in the security community
- Whether qualifiers or caveats should be applied
- If generalizations are being made inappropriately

Your fact checks help ensure that the vulnerability assessment process
is based on accurate technical and security information.
"""

        super().__init__(
            name=name,
            description=description,
            config_key=config_key,
            system_message=system_message,
            agent_id=agent_id,
            model=model,
        )

        # Set up fact check tracking
        self.fact_checks: Dict[str, Dict[str, Any]] = {}
        self.fact_check_tasks: Dict[str, Task] = {}

        # Knowledge base for common facts
        self.knowledge_base: Dict[str, Dict[str, Any]] = {
            "languages": {},
            "frameworks": {},
            "vulnerabilities": {},
            "standards": {},
            "cves": {},
        }

    async def _start(self):
        """Initialize the agent on startup."""
        await super()._start()

        # Register event handlers
        self.register_event_handler(FactCheckEvent, self._handle_fact_check_event)
        self.register_event_handler(TaskAssignmentEvent, self._handle_task_assignment)

        # Initialize knowledge base
        await self._initialize_knowledge_base()

    async def _initialize_knowledge_base(self):
        """Initialize the knowledge base with common facts."""
        # In a real implementation, this would load from a database or file
        # For this implementation, we'll just add a few examples

        # Languages
        self.knowledge_base["languages"]["python"] = {
            "versions": ["3.6", "3.7", "3.8", "3.9", "3.10", "3.11", "3.12"],
            "latest_version": "3.12",
            "type_system": "dynamic, duck typing",
            "memory_management": "garbage collection, reference counting",
            "common_vulnerabilities": [
                "sql_injection",
                "command_injection",
                "deserialization",
            ],
        }

        # Frameworks
        self.knowledge_base["frameworks"]["django"] = {
            "language": "python",
            "latest_version": "5.0",
            "security_features": [
                "CSRF protection",
                "XSS protection",
                "SQL injection protection",
            ],
            "common_vulnerabilities": ["template_injection", "authorization_bypass"],
        }

        # Vulnerabilities
        self.knowledge_base["vulnerabilities"]["sql_injection"] = {
            "cwe": "CWE-89",
            "description": "SQL injection is a code injection technique that exploits a security vulnerability",
            "prevention": [
                "Parameterized queries",
                "Prepared statements",
                "Input validation",
            ],
            "impacts": ["Data theft", "Authentication bypass", "Data manipulation"],
        }

        # Standards
        self.knowledge_base["standards"]["owasp_top_10_2021"] = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable and Outdated Components",
            "A07": "Identification and Authentication Failures",
            "A08": "Software and Data Integrity Failures",
            "A09": "Security Logging and Monitoring Failures",
            "A10": "Server-Side Request Forgery",
        }

        logger.info(
            f"Knowledge base initialized with {sum(len(v) for v in self.knowledge_base.values())} items"
        )

    async def check_fact(
        self,
        claim: str,
        context: Optional[Dict[str, Any]] = None,
        sources: Optional[List[Dict[str, Any]]] = None,
        task_id: Optional[str] = None,
        target_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Check a factual claim.

        Args:
            claim: The claim text to verify
            context: Optional context for the claim
            sources: Optional sources provided with the claim
            task_id: Optional task ID for this fact check
            target_id: Optional ID of the agent to send the result to

        Returns:
            Dictionary with fact check results
        """
        fact_check_id = (
            task_id or f"fact_check_{int(time.time())}_{str(uuid.uuid4())[:8]}"
        )

        logger.info(
            f"Starting fact check: {claim[:100]}{'...' if len(claim) > 100 else ''}"
        )

        # Create fact check task
        fact_check_task = Task(
            task_id=fact_check_id,
            task_type="fact_check",
            description=f"Check fact: {claim[:50]}{'...' if len(claim) > 50 else ''}",
            parameters={"claim": claim, "context": context or {}},
            status="in_progress",
        )

        self.fact_check_tasks[fact_check_id] = fact_check_task

        try:
            # Structure for the fact check
            fact_check_result = {
                "claim": claim,
                "fact_check_id": fact_check_id,
                "timestamp": time.time(),
                "status": None,
                "explanation": "",
                "sources": sources or [],
                "context": context or {},
            }

            # Perform the fact check
            fact_check_result.update(
                await self._analyze_claim(
                    claim, fact_check_result["sources"], context or {}
                )
            )

            # Store the fact check
            self.fact_checks[fact_check_id] = fact_check_result

            # Update task status
            fact_check_task.status = "completed"
            fact_check_task.result = fact_check_result

            # Emit fact check event
            await self._emit_fact_check_event(fact_check_result, target_id=target_id)

            # Log completion
            logger.info(
                f"Completed fact check with status: {fact_check_result['status']}"
            )

            return fact_check_result
        except Exception as e:
            logger.error(f"Error checking fact: {e}")
            fact_check_task.status = "failed"
            fact_check_task.error = str(e)
            raise

    async def _analyze_claim(
        self,
        claim: str,
        sources: List[Dict[str, Any]],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Analyze a claim to determine its factual status.

        Args:
            claim: Claim to analyze
            sources: Provided sources
            context: Additional context

        Returns:
            Dictionary with fact check analysis
        """
        # First, check if the claim matches any entries in our knowledge base
        knowledge_base_check = self._check_against_knowledge_base(claim)
        if knowledge_base_check:
            return knowledge_base_check

        # For claims not in our knowledge base, use the LLM
        fact_check_prompt = (
            f"I need you to fact check the following claim:\n\n" f"CLAIM: {claim}\n\n"
        )

        if context:
            context_str = json.dumps(context, indent=2)
            fact_check_prompt += f"CONTEXT: {context_str}\n\n"

        if sources:
            sources_str = json.dumps(sources, indent=2)
            fact_check_prompt += f"PROVIDED SOURCES: {sources_str}\n\n"

        fact_check_prompt += (
            f"Please analyze this claim and determine its factual accuracy. "
            f"Return your analysis in JSON format with the following fields:\n"
            f"- status: One of 'true', 'partially_true', 'false', 'unverifiable', 'misleading', 'outdated'\n"
            f"- explanation: Detailed explanation of your fact check assessment\n"
            f"- sources: List of authoritative sources that support your assessment\n"
            f"- confidence: Your confidence in this fact check (0.0-1.0)\n"
        )

        # Use the chat model to analyze the claim
        response = await self.openai_client.create_completion(
            prompt=fact_check_prompt,
            model=self.model,
            temperature=0.1,
            max_tokens=1500,
            response_format={"type": "json"},
        )

        # Extract the text response
        response_text = response.get("choices", [{}])[0].get("text", "").strip()

        try:
            # Parse the JSON response
            fact_check = json.loads(response_text)

            # Ensure all required fields are present
            if "status" not in fact_check:
                fact_check["status"] = "unverifiable"
            if "explanation" not in fact_check:
                fact_check["explanation"] = "No explanation provided"
            if "sources" not in fact_check:
                fact_check["sources"] = []
            if "confidence" not in fact_check:
                fact_check["confidence"] = 0.5

            # Convert status string to enum
            try:
                status = FactStatus(fact_check["status"])
            except ValueError:
                # Default to unverifiable if invalid status
                status = FactStatus.UNVERIFIABLE

            fact_check["status"] = status.value

            return fact_check
        except json.JSONDecodeError:
            logger.error(f"Failed to parse fact check result: {response_text}")
            # Return a default fact check on parsing error
            return {
                "status": FactStatus.UNVERIFIABLE.value,
                "explanation": "Error analyzing claim for fact checking",
                "sources": [],
                "confidence": 0.0,
            }

    def _check_against_knowledge_base(self, claim: str) -> Optional[Dict[str, Any]]:
        """Check if a claim matches entries in the knowledge base.

        Args:
            claim: The claim to check

        Returns:
            Fact check result or None if not found in knowledge base
        """
        # Convert claim to lowercase for easier matching
        claim_lower = claim.lower()

        # Check for programming language claims
        for lang, info in self.knowledge_base["languages"].items():
            if lang in claim_lower:
                # Check version claims
                version_match = re.search(rf"{lang}\s+(\d+\.\d+)", claim_lower)
                if version_match:
                    mentioned_version = version_match.group(1)
                    if mentioned_version in info["versions"]:
                        if mentioned_version == info["latest_version"]:
                            return {
                                "status": FactStatus.TRUE.value,
                                "explanation": f"{lang} {mentioned_version} is a valid and current version.",
                                "sources": [
                                    {
                                        "name": f"Official {lang} documentation",
                                        "url": f"https://www.{lang}.org/downloads/",
                                    }
                                ],
                                "confidence": 0.95,
                            }
                        else:
                            return {
                                "status": FactStatus.PARTIALLY_TRUE.value,
                                "explanation": f"{lang} {mentioned_version} is a valid version, but not the latest. Current version is {info['latest_version']}.",
                                "sources": [
                                    {
                                        "name": f"Official {lang} documentation",
                                        "url": f"https://www.{lang}.org/downloads/",
                                    }
                                ],
                                "confidence": 0.9,
                            }
                    else:
                        return {
                            "status": FactStatus.FALSE.value,
                            "explanation": f"{lang} {mentioned_version} is not a valid version. Valid versions are: {', '.join(info['versions'])}.",
                            "sources": [
                                {
                                    "name": f"Official {lang} documentation",
                                    "url": f"https://www.{lang}.org/downloads/",
                                }
                            ],
                            "confidence": 0.9,
                        }

                # Check for type system claims
                if "type" in claim_lower and info.get("type_system"):
                    dynamic_claimed = "dynamic" in claim_lower
                    static_claimed = "static" in claim_lower

                    is_dynamic = "dynamic" in info["type_system"]
                    is_static = "static" in info["type_system"]

                    if (dynamic_claimed and is_dynamic) or (
                        static_claimed and is_static
                    ):
                        return {
                            "status": FactStatus.TRUE.value,
                            "explanation": f"{lang} does use a {info['type_system']} type system.",
                            "sources": [
                                {
                                    "name": f"Official {lang} documentation",
                                    "url": f"https://www.{lang}.org/doc/",
                                }
                            ],
                            "confidence": 0.9,
                        }
                    elif (dynamic_claimed and not is_dynamic) or (
                        static_claimed and not is_static
                    ):
                        return {
                            "status": FactStatus.FALSE.value,
                            "explanation": f"{lang} does not use the type system described. It uses {info['type_system']}.",
                            "sources": [
                                {
                                    "name": f"Official {lang} documentation",
                                    "url": f"https://www.{lang}.org/doc/",
                                }
                            ],
                            "confidence": 0.9,
                        }

        # Check vulnerability claims
        for vuln, info in self.knowledge_base["vulnerabilities"].items():
            if (
                vuln in claim_lower.replace(" ", "_")
                or vuln.replace("_", " ") in claim_lower
            ):
                # Check for CWE references
                if "cwe" in claim_lower:
                    cwe_match = re.search(r"cwe-?(\d+)", claim_lower)
                    if cwe_match:
                        mentioned_cwe = f"CWE-{cwe_match.group(1)}"
                        if mentioned_cwe == info["cwe"]:
                            return {
                                "status": FactStatus.TRUE.value,
                                "explanation": f"{vuln.replace('_', ' ')} is correctly classified as {info['cwe']}.",
                                "sources": [
                                    {
                                        "name": "MITRE CWE",
                                        "url": f"https://cwe.mitre.org/data/definitions/{cwe_match.group(1)}.html",
                                    }
                                ],
                                "confidence": 0.95,
                            }
                        else:
                            return {
                                "status": FactStatus.FALSE.value,
                                "explanation": f"{vuln.replace('_', ' ')} is not {mentioned_cwe}, it is classified as {info['cwe']}.",
                                "sources": [
                                    {
                                        "name": "MITRE CWE",
                                        "url": f"https://cwe.mitre.org/data/definitions/{info['cwe'].split('-')[1]}.html",
                                    }
                                ],
                                "confidence": 0.9,
                            }

                # Check for general descriptions
                for impact in info["impacts"]:
                    if impact.lower() in claim_lower:
                        return {
                            "status": FactStatus.TRUE.value,
                            "explanation": f"{vuln.replace('_', ' ')} can indeed lead to {impact}.",
                            "sources": [
                                {
                                    "name": "OWASP",
                                    "url": f"https://owasp.org/www-community/attacks/{vuln}",
                                }
                            ],
                            "confidence": 0.85,
                        }

        # Check OWASP Top 10 claims
        if (
            "owasp" in claim_lower
            and "top" in claim_lower
            and ("10" in claim_lower or "ten" in claim_lower)
        ):
            for id, name in self.knowledge_base["standards"][
                "owasp_top_10_2021"
            ].items():
                if id.lower() in claim_lower or name.lower() in claim_lower:
                    position = id[1:]  # Extract number from A01, etc.

                    # Check if claim correctly states the position
                    position_match = re.search(
                        r"(#\s*\d+|\d+(?:st|nd|rd|th)|\bnumber \d+\b)", claim_lower
                    )
                    if position_match:
                        claimed_position = re.sub(r"[^\d]", "", position_match.group(0))

                        if claimed_position == position.lstrip("0"):
                            return {
                                "status": FactStatus.TRUE.value,
                                "explanation": f"{name} is indeed #{position.lstrip('0')} in the OWASP Top 10 (2021).",
                                "sources": [
                                    {
                                        "name": "OWASP Top 10 2021",
                                        "url": "https://owasp.org/Top10/",
                                    }
                                ],
                                "confidence": 0.95,
                            }
                        else:
                            return {
                                "status": FactStatus.FALSE.value,
                                "explanation": f"{name} is not #{claimed_position} in the OWASP Top 10 (2021). It is #{position.lstrip('0')}.",
                                "sources": [
                                    {
                                        "name": "OWASP Top 10 2021",
                                        "url": "https://owasp.org/Top10/",
                                    }
                                ],
                                "confidence": 0.95,
                            }

                    # If claim is just mentioning the vulnerability is in the Top 10
                    return {
                        "status": FactStatus.TRUE.value,
                        "explanation": f"{name} is indeed part of the OWASP Top 10 (2021) at position #{position.lstrip('0')}.",
                        "sources": [
                            {
                                "name": "OWASP Top 10 2021",
                                "url": "https://owasp.org/Top10/",
                            }
                        ],
                        "confidence": 0.9,
                    }

        # No match found in the knowledge base
        return None

    async def _emit_fact_check_event(
        self, fact_check: Dict[str, Any], target_id: Optional[str] = None
    ) -> None:
        """Emit a fact check event with results.

        Args:
            fact_check: Fact check result to emit
            target_id: Optional target agent ID
        """
        try:
            # Convert status string to enum if needed
            if isinstance(fact_check["status"], str):
                try:
                    status = FactStatus(fact_check["status"])
                except ValueError:
                    status = FactStatus.UNVERIFIABLE
            else:
                status = fact_check["status"]

            # Create fact check event
            event = FactCheckEvent(
                sender_id=self.agent_id,
                receiver_id=target_id or "all",  # Target or broadcast
                claim=fact_check["claim"],
                status=status,
                explanation=fact_check["explanation"],
                sources=fact_check.get("sources", []),
                fact_check_id=fact_check["fact_check_id"],
            )

            # Emit the event
            await self.emit_event(event)

        except Exception as e:
            logger.error(f"Error emitting fact check event: {e}")

    async def _handle_fact_check_event(self, event: FactCheckEvent) -> None:
        """Handle incoming fact check events.

        Args:
            event: Incoming fact check event
        """
        if not isinstance(event, FactCheckEvent):
            return

        # Log the received fact check
        logger.info(
            f"Received fact check event for claim: {event.claim[:50]}... with status {event.status.value}"
        )

        # Store the fact check for reference
        self.fact_checks[event.fact_check_id] = {
            "fact_check_id": event.fact_check_id,
            "claim": event.claim,
            "status": event.status.value,
            "explanation": event.explanation,
            "sources": event.sources,
            "sender_id": event.sender_id,
            "timestamp": time.time(),
        }

    async def _handle_task_assignment(self, event: TaskAssignmentEvent) -> None:
        """Handle task assignment events.

        Args:
            event: Task assignment event
        """
        if event.receiver_id != self.agent_id:
            return

        if event.task_type == "fact_check":
            # Extract claim from task parameters
            params = event.task_parameters
            claim = params.get("claim")

            if not claim:
                logger.warning(
                    f"Received fact check task without claim: {event.task_id}"
                )
                return

            # Begin fact checking process
            asyncio.create_task(
                self.check_fact(
                    claim=claim,
                    context=params.get("context"),
                    task_id=event.task_id,
                    target_id=event.sender_id,
                )
            )

    def get_fact_check(self, fact_check_id: str) -> Optional[Dict[str, Any]]:
        """Get a fact check result by ID.

        Args:
            fact_check_id: ID of the fact check to retrieve

        Returns:
            Fact check result or None if not found
        """
        return self.fact_checks.get(fact_check_id)
