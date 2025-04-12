"""Debate communication pattern for agents.

This module implements the Debate pattern, which enables agents to
discuss and argue different perspectives on a topic to reach better conclusions.
"""

import asyncio
import enum
import time
from typing import Any, Dict, List, Optional, Tuple

from ...utils.logging import LogEvent, get_logger
from ..base import BaseAgent
from ..events import AgentCommunicationEvent, Task

logger = get_logger(__name__)


class DebateRole(enum.Enum):
    """Roles that agents can take in a debate."""

    PROPONENT = "proponent"
    OPPONENT = "opponent"
    MEDIATOR = "mediator"
    SUMMARIZER = "summarizer"


class DebateArgumentEvent(AgentCommunicationEvent):
    """Event for transmitting an argument in a debate."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        argument: str,
        role: DebateRole,
        evidence: Optional[List[str]] = None,
        debate_id: str = "",
        round_number: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a debate argument event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            argument: The text of the argument
            role: The role of the agent making the argument
            evidence: Supporting evidence for the argument
            debate_id: Unique identifier for this debate
            round_number: Current round in the debate
            metadata: Additional metadata
        """
        debate_metadata = metadata or {}
        debate_metadata.update(
            {
                "role": role.value,
                "evidence": evidence or [],
                "debate_id": debate_id,
                "round_number": round_number,
                "pattern": "debate",
            }
        )

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=argument,
            message_type="debate_argument",
            metadata=debate_metadata,
        )
        self.argument = argument
        self.role = role
        self.evidence = evidence or []
        self.debate_id = debate_id
        self.round_number = round_number


class DebatePattern:
    """Implements the Debate communication pattern.

    This pattern enables structured debates between agents to explore
    multiple perspectives and reach more robust conclusions.
    """

    def __init__(
        self,
        max_rounds: int = 3,
        round_timeout: float = 60.0,
        require_evidence: bool = True,
    ):
        """Initialize the Debate pattern.

        Args:
            max_rounds: Maximum number of debate rounds
            round_timeout: Timeout in seconds for each debate round
            require_evidence: Whether arguments must include supporting evidence
        """
        self.max_rounds = max_rounds
        self.round_timeout = round_timeout
        self.require_evidence = require_evidence
        self.current_debates: Dict[str, Dict[str, Any]] = {}

    @LogEvent("debate_started")
    async def execute(
        self,
        proponent: BaseAgent,
        opponent: BaseAgent,
        mediator: Optional[BaseAgent] = None,
        topic: str = "",
        initial_context: Optional[Dict[str, Any]] = None,
        task: Optional[Task] = None,
    ) -> Dict[str, Any]:
        """Execute a structured debate between agents.

        Args:
            proponent: The agent arguing for the position
            opponent: The agent arguing against the position
            mediator: Optional agent to moderate the debate
            topic: The topic or question being debated
            initial_context: Initial context for the debate
            task: Optional task associated with this debate

        Returns:
            Dictionary with debate results and analysis
        """
        # Generate unique debate ID
        debate_id = f"debate_{int(time.time())}_{hash(topic)}"[:32]

        # Initialize debate structure
        debate_structure = {
            "debate_id": debate_id,
            "topic": topic,
            "task_id": task.task_id if task else None,
            "context": initial_context or {},
            "participants": {
                "proponent": proponent.agent_id,
                "opponent": opponent.agent_id,
                "mediator": mediator.agent_id if mediator else None,
            },
            "rounds": [],
            "current_round": 0,
            "conclusion": None,
            "completed": False,
        }

        self.current_debates[debate_id] = debate_structure

        # Set up coordination primitives
        round_complete = asyncio.Event()
        debate_complete = asyncio.Event()

        # Track arguments by role and round
        arguments: Dict[Tuple[DebateRole, int], DebateArgumentEvent] = {}

        # Define event handler for debate arguments
        async def _handle_debate_argument(event: DebateArgumentEvent) -> None:
            if not isinstance(event, DebateArgumentEvent):
                return

            if event.debate_id != debate_id:
                return

            # Record this argument
            round_num = event.round_number
            role = event.role

            # Store the argument
            arguments[(role, round_num)] = event

            # Check if we have received all arguments for this round
            expected_args_for_round = 2  # Proponent and opponent
            if mediator and round_num > 1:  # Mediator only speaks in round 2+
                expected_args_for_round = 3

            current_round_args = sum(
                1 for (r, rn) in arguments.keys() if rn == round_num
            )

            if current_round_args >= expected_args_for_round:
                # Add to debate structure
                round_data = {
                    "round_number": round_num,
                    "arguments": {
                        arg.role.value: {
                            "text": arg.argument,
                            "evidence": arg.evidence,
                            "agent_id": arg.sender_id,
                        }
                        for arg in arguments.values()
                        if arg.round_number == round_num
                    },
                }

                debate_structure["rounds"].append(round_data)
                debate_structure["current_round"] = round_num

                # Mark round as complete
                round_complete.set()

                # Check if debate is complete
                if round_num >= self.max_rounds:
                    debate_structure["completed"] = True
                    debate_complete.set()

        # Register event handlers for all participants
        proponent.register_event_handler(DebateArgumentEvent, _handle_debate_argument)
        opponent.register_event_handler(DebateArgumentEvent, _handle_debate_argument)
        if mediator:
            mediator.register_event_handler(
                DebateArgumentEvent, _handle_debate_argument
            )

        try:
            # Start the debate
            for round_num in range(1, self.max_rounds + 1):
                # Reset round complete event
                round_complete.clear()

                # Initiate arguments for this round
                await self._initiate_round(
                    proponent,
                    opponent,
                    mediator,
                    round_num,
                    debate_id,
                    topic,
                    debate_structure,
                )

                # Wait for round to complete or timeout
                try:
                    await asyncio.wait_for(round_complete.wait(), self.round_timeout)
                    logger.info(f"Debate round {round_num} completed")
                except asyncio.TimeoutError:
                    logger.warning(f"Debate round {round_num} timed out")
                    debate_structure["timeout"] = True
                    break

            # Wait for debate completion or force conclusion
            if not debate_structure["completed"]:
                try:
                    await asyncio.wait_for(
                        debate_complete.wait(), 10.0
                    )  # Short timeout
                except asyncio.TimeoutError:
                    # Force conclusion
                    debate_structure["completed"] = True
                    debate_structure["forced_conclusion"] = True

            # Generate conclusion if we have a mediator
            if mediator:
                conclusion = await self._generate_conclusion(
                    mediator, debate_id, topic, debate_structure
                )
                debate_structure["conclusion"] = conclusion

            logger.info(
                f"Debate completed with {len(debate_structure['rounds'])} rounds"
            )

            return debate_structure
        finally:
            # Clean up event handlers
            proponent.deregister_event_handler(
                DebateArgumentEvent, _handle_debate_argument
            )
            opponent.deregister_event_handler(
                DebateArgumentEvent, _handle_debate_argument
            )
            if mediator:
                mediator.deregister_event_handler(
                    DebateArgumentEvent, _handle_debate_argument
                )

    async def _initiate_round(
        self,
        proponent: BaseAgent,
        opponent: BaseAgent,
        mediator: Optional[BaseAgent],
        round_num: int,
        debate_id: str,
        topic: str,
        debate_structure: Dict[str, Any],
    ) -> None:
        """Initiate a new round of debate.

        Args:
            proponent: Proponent agent
            opponent: Opponent agent
            mediator: Optional mediator agent
            round_num: Current round number
            debate_id: Unique debate ID
            topic: Debate topic
            debate_structure: Current debate state
        """
        # For the first round, the proponent starts
        if round_num == 1:
            # Create proponent's initial argument
            proponent_event = DebateArgumentEvent(
                sender_id=proponent.agent_id,
                receiver_id=opponent.agent_id,
                argument=f"I'll present my initial argument on the topic: {topic}",
                role=DebateRole.PROPONENT,
                debate_id=debate_id,
                round_number=round_num,
            )

            # Emit the event
            await proponent.emit_event(proponent_event)

            # Opponent will respond through the event handler system
        else:
            # For subsequent rounds, we use the mediator to guide the discussion
            if mediator:
                # Mediator provides instructions for the round
                mediator_event = DebateArgumentEvent(
                    sender_id=mediator.agent_id,
                    receiver_id="all",  # Special receiver ID for broadcasts
                    argument=f"Let's continue the discussion for round {round_num}. Please address points raised in the previous round.",
                    role=DebateRole.MEDIATOR,
                    debate_id=debate_id,
                    round_number=round_num,
                )

                await mediator.emit_event(mediator_event)

            # Both proponent and opponent respond independently through event handlers

    async def _generate_conclusion(
        self,
        mediator: BaseAgent,
        debate_id: str,
        topic: str,
        debate_structure: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Generate a conclusion for the debate.

        Args:
            mediator: Mediator agent to generate the conclusion
            debate_id: Unique debate ID
            topic: Debate topic
            debate_structure: Current debate state

        Returns:
            Dictionary with conclusion information
        """
        # Create a task for the mediator to generate a conclusion
        conclusion_task = Task(
            task_id=f"{debate_id}_conclusion",
            task_type="generate_debate_conclusion",
            description=f"Generate a conclusion for the debate on: {topic}",
            parameters={
                "debate_id": debate_id,
                "topic": topic,
                "rounds": debate_structure["rounds"],
                "participants": debate_structure["participants"],
            },
            status="pending",
        )

        # Create a conclusion event that the mediator will use to respond
        conclusion_event = DebateArgumentEvent(
            sender_id=mediator.agent_id,
            receiver_id="all",
            argument=f"Based on the debate about {topic}, I'll now provide a conclusion...",
            role=DebateRole.MEDIATOR,
            debate_id=debate_id,
            round_number=debate_structure["current_round"] + 1,
            metadata={"is_conclusion": True},
        )

        # Emit the event
        await mediator.emit_event(conclusion_event)

        # Return basic conclusion info - the full conclusion will be captured by event handlers
        return {
            "mediator_id": mediator.agent_id,
            "timestamp": time.time(),
            "topic": topic,
            "rounds_considered": debate_structure["current_round"],
        }

    def get_debate(self, debate_id: str) -> Dict[str, Any]:
        """Get a specific debate by ID.

        Args:
            debate_id: The ID of the debate to retrieve

        Returns:
            Dictionary with debate information
        """
        return self.current_debates.get(debate_id, {})
