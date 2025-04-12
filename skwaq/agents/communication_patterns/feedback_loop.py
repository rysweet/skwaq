"""Feedback Loop communication pattern for agents.

This module implements the Feedback Loop pattern, which enables iterative
refinement of outputs through structured feedback and revision cycles.
"""

import asyncio
import enum
import time
from typing import Any, Dict, List, Optional

from ...utils.logging import LogEvent, get_logger
from ..base import BaseAgent
from ..events import AgentCommunicationEvent, Task

logger = get_logger(__name__)


class FeedbackType(enum.Enum):
    """Types of feedback that can be provided in the feedback loop."""

    CORRECTION = "correction"
    SUGGESTION = "suggestion"
    QUESTION = "question"
    CLARIFICATION = "clarification"
    IMPROVEMENT = "improvement"


class FeedbackEvent(AgentCommunicationEvent):
    """Event for providing feedback in a feedback loop."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        feedback: str,
        feedback_type: FeedbackType,
        content_reference: str,
        loop_id: str,
        iteration: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a feedback event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            feedback: The text of the feedback
            feedback_type: The type of feedback being provided
            content_reference: Reference to the content being commented on
            loop_id: Unique identifier for this feedback loop
            iteration: Current iteration in the feedback loop
            metadata: Additional metadata
        """
        feedback_metadata = metadata or {}
        feedback_metadata.update(
            {
                "feedback_type": feedback_type.value,
                "content_reference": content_reference,
                "loop_id": loop_id,
                "iteration": iteration,
                "pattern": "feedback_loop",
            }
        )

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=feedback,
            message_type="feedback",
            metadata=feedback_metadata,
        )
        self.feedback = feedback
        self.feedback_type = feedback_type
        self.content_reference = content_reference
        self.loop_id = loop_id
        self.iteration = iteration


class RevisionEvent(AgentCommunicationEvent):
    """Event for submitting a revision in a feedback loop."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        revised_content: str,
        original_content_reference: str,
        changes_made: List[str],
        loop_id: str,
        iteration: int = 1,
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a revision event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            revised_content: The revised content
            original_content_reference: Reference to the original content
            changes_made: List of changes made in this revision
            loop_id: Unique identifier for this feedback loop
            iteration: Current iteration in the feedback loop
            metadata: Additional metadata
        """
        revision_metadata = metadata or {}
        revision_metadata.update(
            {
                "original_content_reference": original_content_reference,
                "changes_made": changes_made,
                "loop_id": loop_id,
                "iteration": iteration,
                "pattern": "feedback_loop",
            }
        )

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=revised_content,
            message_type="revision",
            metadata=revision_metadata,
        )
        self.revised_content = revised_content
        self.original_content_reference = original_content_reference
        self.changes_made = changes_made
        self.loop_id = loop_id
        self.iteration = iteration


class FeedbackLoopPattern:
    """Implements the Feedback Loop communication pattern.

    This pattern enables iterative improvement through structured
    feedback and revision cycles.
    """

    def __init__(
        self,
        max_iterations: int = 3,
        iteration_timeout: float = 120.0,
        improvement_threshold: float = 0.1,
    ):
        """Initialize the Feedback Loop pattern.

        Args:
            max_iterations: Maximum number of feedback iterations
            iteration_timeout: Timeout in seconds for each iteration
            improvement_threshold: Minimum improvement required to continue iterations
        """
        self.max_iterations = max_iterations
        self.iteration_timeout = iteration_timeout
        self.improvement_threshold = improvement_threshold
        self.current_loops: Dict[str, Dict[str, Any]] = {}

    @LogEvent("feedback_loop_started")
    async def execute(
        self,
        creator_agent: BaseAgent,
        reviewer_agent: BaseAgent,
        initial_content: str,
        content_id: str,
        task: Optional[Task] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Execute a feedback loop between creator and reviewer agents.

        Args:
            creator_agent: The agent that creates content
            reviewer_agent: The agent that reviews and provides feedback
            initial_content: The initial content to be refined
            content_id: Identifier for the content being refined
            task: Optional task associated with this feedback loop
            context: Additional context information

        Returns:
            Dictionary with feedback loop results and final content
        """
        # Generate unique loop ID
        loop_id = f"feedback_{int(time.time())}_{content_id}"[:32]

        # Initialize feedback loop structure
        loop_structure = {
            "loop_id": loop_id,
            "content_id": content_id,
            "task_id": task.task_id if task else None,
            "context": context or {},
            "participants": {
                "creator": creator_agent.agent_id,
                "reviewer": reviewer_agent.agent_id,
            },
            "iterations": [],
            "current_iteration": 0,
            "current_content": initial_content,
            "initial_content": initial_content,
            "final_content": None,
            "completed": False,
            "improvement_scores": [],
        }

        self.current_loops[loop_id] = loop_structure

        # Set up coordination primitives
        feedback_received = asyncio.Event()
        revision_received = asyncio.Event()

        # Track events by iteration
        feedbacks: Dict[int, FeedbackEvent] = {}
        revisions: Dict[int, RevisionEvent] = {}

        # Define event handler for feedback events
        async def _handle_feedback(event: FeedbackEvent) -> None:
            if not isinstance(event, FeedbackEvent):
                return

            if event.loop_id != loop_id:
                return

            # Record this feedback
            feedbacks[event.iteration] = event

            # Signal that feedback has been received
            feedback_received.set()

        # Define event handler for revision events
        async def _handle_revision(event: RevisionEvent) -> None:
            if not isinstance(event, RevisionEvent):
                return

            if event.loop_id != loop_id:
                return

            # Record this revision
            revisions[event.iteration] = event

            # Update the current content
            loop_structure["current_content"] = event.revised_content

            # Signal that revision has been received
            revision_received.set()

        # Register event handlers
        creator_agent.register_event_handler(FeedbackEvent, _handle_feedback)
        reviewer_agent.register_event_handler(RevisionEvent, _handle_revision)

        try:
            # Start with the initial content
            current_content = initial_content

            # Run feedback loops for specified iterations
            for iteration in range(1, self.max_iterations + 1):
                # Reset event flags
                feedback_received.clear()
                revision_received.clear()

                # Update current iteration
                loop_structure["current_iteration"] = iteration

                # Initiate feedback for this iteration
                await self._request_feedback(
                    reviewer_agent,
                    creator_agent,
                    current_content,
                    content_id,
                    loop_id,
                    iteration,
                )

                # Wait for feedback or timeout
                try:
                    await asyncio.wait_for(
                        feedback_received.wait(), self.iteration_timeout
                    )
                    logger.info(f"Feedback received for iteration {iteration}")
                except asyncio.TimeoutError:
                    logger.warning(f"Feedback timed out for iteration {iteration}")
                    loop_structure["timeout"] = True
                    break

                # Extract the feedback for this iteration
                feedback = feedbacks.get(iteration)
                if not feedback:
                    logger.warning(f"No feedback found for iteration {iteration}")
                    break

                # Request revision based on feedback
                await self._request_revision(
                    creator_agent,
                    reviewer_agent,
                    current_content,
                    feedback,
                    content_id,
                    loop_id,
                    iteration,
                )

                # Wait for revision or timeout
                try:
                    await asyncio.wait_for(
                        revision_received.wait(), self.iteration_timeout
                    )
                    logger.info(f"Revision received for iteration {iteration}")
                except asyncio.TimeoutError:
                    logger.warning(f"Revision timed out for iteration {iteration}")
                    loop_structure["timeout"] = True
                    break

                # Extract the revision for this iteration
                revision = revisions.get(iteration)
                if not revision:
                    logger.warning(f"No revision found for iteration {iteration}")
                    break

                # Update current content
                current_content = revision.revised_content

                # Record this iteration
                iteration_data = {
                    "iteration": iteration,
                    "feedback": {
                        "text": feedback.feedback,
                        "type": feedback.feedback_type.value,
                        "agent_id": feedback.sender_id,
                    },
                    "revision": {
                        "content": revision.revised_content,
                        "changes": revision.changes_made,
                        "agent_id": revision.sender_id,
                    },
                }

                loop_structure["iterations"].append(iteration_data)

                # Calculate improvement score
                improvement_score = await self._calculate_improvement(
                    reviewer_agent,
                    loop_structure["initial_content"],
                    current_content,
                    loop_id,
                    iteration,
                )

                loop_structure["improvement_scores"].append(improvement_score)

                # Check if we've reached diminishing returns
                if iteration > 1 and improvement_score < self.improvement_threshold:
                    logger.info(
                        f"Stopping feedback loop due to diminishing returns (score: {improvement_score})"
                    )
                    break

            # Mark as completed and set final content
            loop_structure["completed"] = True
            loop_structure["final_content"] = current_content

            # Calculate overall improvement
            if loop_structure["improvement_scores"]:
                loop_structure["total_improvement"] = sum(
                    loop_structure["improvement_scores"]
                )
            else:
                loop_structure["total_improvement"] = 0.0

            logger.info(
                f"Feedback loop completed with {len(loop_structure['iterations'])} iterations"
            )

            return loop_structure
        finally:
            # Clean up event handlers
            creator_agent.deregister_event_handler(FeedbackEvent, _handle_feedback)
            reviewer_agent.deregister_event_handler(RevisionEvent, _handle_revision)

    async def _request_feedback(
        self,
        reviewer_agent: BaseAgent,
        creator_agent: BaseAgent,
        content: str,
        content_id: str,
        loop_id: str,
        iteration: int,
    ) -> None:
        """Request feedback from the reviewer agent.

        Args:
            reviewer_agent: Agent providing the feedback
            creator_agent: Agent that created the content
            content: Content to provide feedback on
            content_id: Identifier for the content
            loop_id: Unique loop ID
            iteration: Current iteration number
        """
        # Create a feedback request event
        request_event = AgentCommunicationEvent(
            sender_id=creator_agent.agent_id,
            receiver_id=reviewer_agent.agent_id,
            message=f"Please review this content and provide feedback:\n\n{content}",
            message_type="feedback_request",
            metadata={
                "content_id": content_id,
                "loop_id": loop_id,
                "iteration": iteration,
                "pattern": "feedback_loop",
                "action": "request_feedback",
            },
        )

        # Emit the event
        await creator_agent.emit_event(request_event)

    async def _request_revision(
        self,
        creator_agent: BaseAgent,
        reviewer_agent: BaseAgent,
        content: str,
        feedback: FeedbackEvent,
        content_id: str,
        loop_id: str,
        iteration: int,
    ) -> None:
        """Request a revision from the creator agent.

        Args:
            creator_agent: Agent creating the revision
            reviewer_agent: Agent that provided feedback
            content: Current content to revise
            feedback: Feedback event with suggestions
            content_id: Identifier for the content
            loop_id: Unique loop ID
            iteration: Current iteration number
        """
        # Create a revision request event
        request_event = AgentCommunicationEvent(
            sender_id=reviewer_agent.agent_id,
            receiver_id=creator_agent.agent_id,
            message=f"Please revise this content based on feedback:\n\nFeedback: {feedback.feedback}\n\nContent:\n{content}",
            message_type="revision_request",
            metadata={
                "content_id": content_id,
                "feedback_type": feedback.feedback_type.value,
                "loop_id": loop_id,
                "iteration": iteration,
                "pattern": "feedback_loop",
                "action": "request_revision",
            },
        )

        # Emit the event
        await reviewer_agent.emit_event(request_event)

    async def _calculate_improvement(
        self,
        reviewer_agent: BaseAgent,
        original_content: str,
        current_content: str,
        loop_id: str,
        iteration: int,
    ) -> float:
        """Calculate improvement score between original and current content.

        Args:
            reviewer_agent: Agent to evaluate improvement
            original_content: Initial content
            current_content: Current revised content
            loop_id: Unique loop ID
            iteration: Current iteration number

        Returns:
            Improvement score between 0.0 and 1.0
        """
        # Create a task for improvement calculation
        improvement_task = Task(
            task_id=f"{loop_id}_improvement_{iteration}",
            task_type="calculate_improvement",
            description="Calculate improvement between original and revised content",
            parameters={
                "original_content": original_content,
                "revised_content": current_content,
                "loop_id": loop_id,
                "iteration": iteration,
            },
            status="pending",
        )

        # In a real implementation, we would have the reviewer agent
        # calculate the improvement. For simplicity, we're using a
        # simple length-based heuristic here.
        original_length = len(original_content)
        current_length = len(current_content)

        # Simple heuristic: normalized length difference
        if original_length == 0:
            return 0.0

        # Higher score for longer content, but with diminishing returns
        length_ratio = current_length / original_length
        if length_ratio < 1.0:
            # Shorter content gets a negative score
            return -0.1
        elif length_ratio > 2.0:
            # Cap the benefit of longer content
            return 0.5
        else:
            # Linear scaling between 1.0x and 2.0x with diminishing returns
            return 0.5 * (length_ratio - 1.0)

    def get_loop(self, loop_id: str) -> Dict[str, Any]:
        """Get a specific feedback loop by ID.

        Args:
            loop_id: The ID of the feedback loop to retrieve

        Returns:
            Dictionary with feedback loop information
        """
        return self.current_loops.get(loop_id, {})
