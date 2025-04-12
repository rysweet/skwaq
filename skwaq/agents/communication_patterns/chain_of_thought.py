"""Chain of Thought communication pattern for agents.

This module implements the Chain of Thought pattern, which encourages
agents to show their reasoning process step by step before reaching a conclusion.
"""

import asyncio
import time
from typing import Any, Dict, List, Optional

from ...utils.logging import LogEvent, get_logger
from ..base import BaseAgent
from ..events import AgentCommunicationEvent, Task

logger = get_logger(__name__)


class CognitiveStepEvent(AgentCommunicationEvent):
    """Event for transmitting a cognitive step in a reasoning chain."""

    def __init__(
        self,
        sender_id: str,
        receiver_id: str,
        step_number: int,
        reasoning: str,
        context: Dict[str, Any],
        metadata: Optional[Dict[str, Any]] = None,
    ):
        """Initialize a cognitive step event.

        Args:
            sender_id: ID of the sending agent
            receiver_id: ID of the receiving agent
            step_number: The position of this step in the reasoning chain
            reasoning: The reasoning text for this cognitive step
            context: Context information for this reasoning step
            metadata: Additional metadata
        """
        step_message = f"Step {step_number}: {reasoning}"
        step_metadata = metadata or {}
        step_metadata.update(
            {
                "step_number": step_number,
                "context": context,
                "pattern": "chain_of_thought",
            }
        )

        super().__init__(
            sender_id=sender_id,
            receiver_id=receiver_id,
            message=step_message,
            message_type="reasoning_step",
            metadata=step_metadata,
        )
        self.step_number = step_number
        self.reasoning = reasoning
        self.context = context


class ChainOfThoughtPattern:
    """Implements the Chain of Thought communication pattern.

    This pattern structures communication to show step-by-step reasoning,
    helping to improve analysis quality and enabling better verification.
    """

    def __init__(self, max_steps: int = 5, step_timeout: float = 30.0):
        """Initialize the Chain of Thought pattern.

        Args:
            max_steps: Maximum number of reasoning steps to allow
            step_timeout: Timeout in seconds for each reasoning step
        """
        self.max_steps = max_steps
        self.step_timeout = step_timeout
        self.current_chains: Dict[str, List[Dict[str, Any]]] = {}

    @LogEvent("chain_of_thought_started")
    async def execute(
        self,
        initial_agent: BaseAgent,
        target_agent: BaseAgent,
        task: Task,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Execute a Chain of Thought reasoning process.

        Args:
            initial_agent: The agent that will perform the reasoning
            target_agent: The agent that will receive the reasoning
            task: The task to reason about
            context: Additional context information

        Returns:
            Dictionary with reasoning results and analysis
        """
        chain_id = f"{task.task_id}_{int(time.time())}"
        self.current_chains[chain_id] = []

        # Initialize the reasoning context
        reasoning_context = {
            "task": task.to_dict(),
            "initial_context": context,
            "chain_id": chain_id,
            "steps_completed": 0,
            "final_result": None,
        }

        # Create the first cognitive step event
        first_step = CognitiveStepEvent(
            sender_id=initial_agent.agent_id,
            receiver_id=target_agent.agent_id,
            step_number=1,
            reasoning="I'll analyze this task step by step to ensure thoroughness.",
            context=reasoning_context,
        )

        # Emit the first event
        await initial_agent.emit_event(first_step)
        self.current_chains[chain_id].append(first_step.to_dict())

        # Set up event handlers to track the chain of thought
        step_complete_event = asyncio.Event()

        # Define handler for cognitive step events
        async def _handle_cognitive_step(event: CognitiveStepEvent) -> None:
            if not isinstance(event, CognitiveStepEvent):
                return

            if event.context.get("chain_id") != chain_id:
                return

            self.current_chains[chain_id].append(event.to_dict())
            reasoning_context["steps_completed"] = event.step_number

            if event.step_number >= self.max_steps or "conclusion" in event.metadata:
                reasoning_context["final_result"] = event.reasoning
                step_complete_event.set()

        # Register event handler
        initial_agent.register_event_handler(CognitiveStepEvent, _handle_cognitive_step)

        try:
            # Wait for chain to complete or timeout
            try:
                await asyncio.wait_for(
                    step_complete_event.wait(), self.max_steps * self.step_timeout
                )
            except asyncio.TimeoutError:
                logger.warning(
                    f"Chain of thought reasoning timed out after {self.max_steps * self.step_timeout} seconds"
                )
                reasoning_context["timeout"] = True

            # Compile results
            result = {
                "chain_id": chain_id,
                "steps": self.current_chains[chain_id],
                "result": reasoning_context.get("final_result"),
                "completed_steps": reasoning_context.get("steps_completed", 0),
                "timed_out": reasoning_context.get("timeout", False),
                "task_id": task.task_id,
            }

            # Log completion
            logger.info(
                f"Chain of thought reasoning completed with {len(self.current_chains[chain_id])} steps"
            )

            return result
        finally:
            # Clean up
            initial_agent.deregister_event_handler(
                CognitiveStepEvent, _handle_cognitive_step
            )

    def get_chain(self, chain_id: str) -> List[Dict[str, Any]]:
        """Get the steps in a specific reasoning chain.

        Args:
            chain_id: The ID of the chain to retrieve

        Returns:
            List of reasoning steps
        """
        return self.current_chains.get(chain_id, [])
