"""Workflow chaining functionality for seamless transitions.

This module implements components for creating chains of workflows that can
execute in sequence with automatic handoffs and data sharing between them.
"""

import time
import uuid
from enum import Enum
from typing import Any, AsyncGenerator, Callable, Dict, List, Optional, Type, TypeVar

from ...utils.logging import get_logger
from ..base import Workflow
from .context_manager import WorkflowContext, get_context_manager

logger = get_logger(__name__)

# Type variable for workflow types
T = TypeVar("T", bound=Workflow)


class TransitionType(Enum):
    """Types of workflow transitions."""

    SEQUENTIAL = "sequential"  # Normal flow, move to next workflow automatically
    CONDITIONAL = "conditional"  # Move based on condition evaluation
    MANUAL = "manual"  # Requires explicit user action to move forward
    ERROR = "error"  # Error handling transition


class WorkflowTransition:
    """Defines a transition between two workflows.

    This class represents a transition from a source workflow to a
    destination workflow, with optional conditions and data transformations.
    """

    def __init__(
        self,
        from_workflow_type: Type[Workflow],
        to_workflow_type: Type[Workflow],
        transition_type: TransitionType = TransitionType.SEQUENTIAL,
        condition: Optional[Callable[[Workflow, WorkflowContext], bool]] = None,
        data_transformer: Optional[
            Callable[[Workflow, WorkflowContext], Dict[str, Any]]
        ] = None,
        name: Optional[str] = None,
    ):
        """Initialize a workflow transition.

        Args:
            from_workflow_type: The source workflow type
            to_workflow_type: The destination workflow type
            transition_type: The type of transition
            condition: Optional condition function that must return True for transition to occur
            data_transformer: Optional function to transform data for the destination workflow
            name: Optional name for this transition
        """
        self.from_workflow_type = from_workflow_type
        self.to_workflow_type = to_workflow_type
        self.transition_type = transition_type
        self.condition = condition
        self.data_transformer = data_transformer
        self.name = (
            name or f"{from_workflow_type.__name__}To{to_workflow_type.__name__}"
        )

    def evaluate_condition(self, workflow: Workflow, context: WorkflowContext) -> bool:
        """Evaluate whether the transition condition is met.

        Args:
            workflow: The source workflow instance
            context: The current workflow context

        Returns:
            True if the transition should occur, False otherwise
        """
        if self.condition is None:
            return True

        try:
            return self.condition(workflow, context)
        except Exception as e:
            logger.error(f"Error evaluating transition condition: {e}")
            return False

    def transform_data(
        self, workflow: Workflow, context: WorkflowContext
    ) -> Dict[str, Any]:
        """Transform data for the destination workflow.

        Args:
            workflow: The source workflow instance
            context: The current workflow context

        Returns:
            Dictionary of transformed data for the destination workflow
        """
        if self.data_transformer is None:
            return {}

        try:
            return self.data_transformer(workflow, context)
        except Exception as e:
            logger.error(f"Error transforming workflow data: {e}")
            return {}


class WorkflowChain:
    """A chain of connected workflows with automatic transitions.

    This class manages a sequence of workflows that can be executed in order,
    with automatic transitions between them based on defined conditions.
    """

    def __init__(self, name: Optional[str] = None):
        """Initialize a workflow chain.

        Args:
            name: Optional name for this workflow chain
        """
        self.name = name or f"chain-{uuid.uuid4().hex[:8]}"
        self.transitions: List[WorkflowTransition] = []
        self.current_index = 0
        self.current_workflow: Optional[Workflow] = None
        self.context: Optional[WorkflowContext] = None
        self._is_running = False

    def add_transition(self, transition: WorkflowTransition) -> "WorkflowChain":
        """Add a workflow transition to the chain.

        Args:
            transition: The workflow transition to add

        Returns:
            Self for method chaining
        """
        self.transitions.append(transition)
        return self

    def add_sequential_transition(
        self,
        from_workflow_type: Type[Workflow],
        to_workflow_type: Type[Workflow],
        data_transformer: Optional[
            Callable[[Workflow, WorkflowContext], Dict[str, Any]]
        ] = None,
    ) -> "WorkflowChain":
        """Add a sequential transition to the chain.

        Args:
            from_workflow_type: The source workflow type
            to_workflow_type: The destination workflow type
            data_transformer: Optional function to transform data

        Returns:
            Self for method chaining
        """
        transition = WorkflowTransition(
            from_workflow_type=from_workflow_type,
            to_workflow_type=to_workflow_type,
            transition_type=TransitionType.SEQUENTIAL,
            data_transformer=data_transformer,
        )
        return self.add_transition(transition)

    def add_conditional_transition(
        self,
        from_workflow_type: Type[Workflow],
        to_workflow_type: Type[Workflow],
        condition: Callable[[Workflow, WorkflowContext], bool],
        data_transformer: Optional[
            Callable[[Workflow, WorkflowContext], Dict[str, Any]]
        ] = None,
    ) -> "WorkflowChain":
        """Add a conditional transition to the chain.

        Args:
            from_workflow_type: The source workflow type
            to_workflow_type: The destination workflow type
            condition: Function that must return True for transition to occur
            data_transformer: Optional function to transform data

        Returns:
            Self for method chaining
        """
        transition = WorkflowTransition(
            from_workflow_type=from_workflow_type,
            to_workflow_type=to_workflow_type,
            transition_type=TransitionType.CONDITIONAL,
            condition=condition,
            data_transformer=data_transformer,
        )
        return self.add_transition(transition)

    def add_manual_transition(
        self,
        from_workflow_type: Type[Workflow],
        to_workflow_type: Type[Workflow],
        data_transformer: Optional[
            Callable[[Workflow, WorkflowContext], Dict[str, Any]]
        ] = None,
    ) -> "WorkflowChain":
        """Add a manual transition to the chain.

        Args:
            from_workflow_type: The source workflow type
            to_workflow_type: The destination workflow type
            data_transformer: Optional function to transform data

        Returns:
            Self for method chaining
        """
        transition = WorkflowTransition(
            from_workflow_type=from_workflow_type,
            to_workflow_type=to_workflow_type,
            transition_type=TransitionType.MANUAL,
            data_transformer=data_transformer,
        )
        return self.add_transition(transition)

    def add_error_transition(
        self,
        from_workflow_type: Type[Workflow],
        to_workflow_type: Type[Workflow],
        data_transformer: Optional[
            Callable[[Workflow, WorkflowContext], Dict[str, Any]]
        ] = None,
    ) -> "WorkflowChain":
        """Add an error transition to the chain.

        Args:
            from_workflow_type: The source workflow type
            to_workflow_type: The destination workflow type
            data_transformer: Optional function to transform data

        Returns:
            Self for method chaining
        """
        transition = WorkflowTransition(
            from_workflow_type=from_workflow_type,
            to_workflow_type=to_workflow_type,
            transition_type=TransitionType.ERROR,
            data_transformer=data_transformer,
        )
        return self.add_transition(transition)

    def _create_workflow_instance(
        self,
        workflow_type: Type[Workflow],
        repository_id: Optional[str] = None,
        **kwargs,
    ) -> Workflow:
        """Create a new workflow instance.

        Args:
            workflow_type: The type of workflow to create
            repository_id: Optional repository ID
            **kwargs: Additional arguments for the workflow constructor

        Returns:
            A new workflow instance
        """
        if repository_id:
            kwargs["repository_id"] = repository_id

        return workflow_type(**kwargs)

    def start(
        self,
        initial_workflow_type: Type[Workflow],
        repository_id: Optional[str] = None,
        context_id: Optional[str] = None,
        context: Optional[WorkflowContext] = None,
        **workflow_args,
    ) -> None:
        """Start the workflow chain with an initial workflow.

        Args:
            initial_workflow_type: The type of the first workflow to start
            repository_id: Optional repository ID
            context_id: Optional context ID to use
            context: Optional existing workflow context
            **workflow_args: Additional arguments for the initial workflow
        """
        if self._is_running:
            logger.warning("Workflow chain is already running")
            return

        # Set up context
        if context:
            self.context = context
        elif context_id:
            context_manager = get_context_manager()
            self.context = context_manager.get_context(context_id)
            if not self.context:
                self.context = context_manager.create_context(
                    repository_id=repository_id, context_id=context_id
                )
        else:
            context_manager = get_context_manager()
            self.context = context_manager.create_context(repository_id=repository_id)

        # Create the initial workflow
        self.current_workflow = self._create_workflow_instance(
            initial_workflow_type, repository_id=repository_id, **workflow_args
        )

        self.current_index = 0
        self._is_running = True

        # Record the start of this workflow in the context
        if self.context and self.current_workflow:
            workflow_id = getattr(
                self.current_workflow, "workflow_id", str(uuid.uuid4())
            )
            self.context.add_shared_data("current_workflow_id", workflow_id)
            self.context.add_shared_data("chain_name", self.name)
            # Get current time without using event loop (for compatibility with sync context)
            self.context.add_shared_data("chain_started_at", time.time())
            self.context.save()

        logger.info(
            f"Started workflow chain {self.name} with {initial_workflow_type.__name__}"
        )

    def find_next_transition(
        self, current_workflow: Workflow
    ) -> Optional[WorkflowTransition]:
        """Find the next valid transition from the current workflow.

        Args:
            current_workflow: The current workflow instance

        Returns:
            The next transition, or None if no valid transition exists
        """
        if not self.context:
            logger.error("Cannot find next transition: no context available")
            return None

        current_type = type(current_workflow)

        # Find transitions that match the current workflow type
        matching_transitions = [
            t for t in self.transitions if t.from_workflow_type == current_type
        ]

        # Evaluate conditions to find valid transitions
        valid_transitions = []
        for transition in matching_transitions:
            if transition.evaluate_condition(current_workflow, self.context):
                valid_transitions.append(transition)

        # If no valid transitions, return None
        if not valid_transitions:
            return None

        # Return the first valid transition (for now)
        # Could be extended to support more complex selection logic
        return valid_transitions[0]

    async def execute_next(self) -> Optional[Dict[str, Any]]:
        """Execute the next workflow in the chain.

        Returns:
            The result of the workflow, or None if chain is complete
        """
        if not self._is_running or not self.current_workflow or not self.context:
            logger.warning("Workflow chain is not running or missing components")
            return None

        # Find the next transition
        transition = self.find_next_transition(self.current_workflow)
        if not transition:
            logger.info(f"Workflow chain {self.name} completed - no more transitions")
            self._is_running = False
            return None

        # Transform data for the next workflow
        transformed_data = transition.transform_data(
            self.current_workflow, self.context
        )

        # Get workflow IDs for context recording
        from_workflow_id = getattr(
            self.current_workflow, "workflow_id", str(uuid.uuid4())
        )

        # Create the next workflow instance
        next_workflow = self._create_workflow_instance(
            transition.to_workflow_type,
            repository_id=self.context.repository_id,
            **transformed_data,
        )

        to_workflow_id = getattr(next_workflow, "workflow_id", str(uuid.uuid4()))

        # Record the transition in the context
        context_manager = get_context_manager()
        context_manager.transition_workflow(
            self.context.context_id,
            from_workflow_id,
            to_workflow_id,
            reason=transition.name,
        )

        # Update the current workflow
        self.current_workflow = next_workflow
        self.current_index += 1

        logger.info(
            f"Transitioned to {transition.to_workflow_type.__name__} in chain {self.name}"
        )

        # Initialize the workflow
        await self.current_workflow.setup()

        return {"transition": transition.name, "workflow": self.current_workflow}

    async def run(self) -> AsyncGenerator[Dict[str, Any], None]:
        """Run the entire workflow chain.

        Yields:
            Progress updates and results from each workflow
        """
        if not self._is_running or not self.current_workflow:
            logger.warning("Cannot run workflow chain - not properly initialized")
            return

        try:
            # Initialize the first workflow
            await self.current_workflow.setup()

            # Run the current workflow
            async for result in self.current_workflow.run():
                # Add context information to the result
                result["chain_name"] = self.name
                result["workflow_index"] = self.current_index
                result["workflow_type"] = type(self.current_workflow).__name__

                # Check if this is the final update from this workflow
                is_final_update = result.get("status") in ["complete", "error"]

                # Yield the result
                yield result

                # If this is the final update, transition to the next workflow
                if is_final_update:
                    next_state = await self.execute_next()
                    if not next_state:
                        return  # Chain is complete

                    # If manual transition, stop and wait for explicit continuation
                    transition = next_state["transition"]
                    if (
                        transition
                        and getattr(transition, "transition_type", None)
                        == TransitionType.MANUAL
                    ):
                        yield {
                            "chain_name": self.name,
                            "workflow_index": self.current_index,
                            "status": "paused",
                            "message": "Workflow chain paused for manual transition",
                            "next_workflow": type(self.current_workflow).__name__,
                        }
                        return

            # If we get here, either the workflow didn't yield any results
            # or it completed without a final status. Try to transition anyway.
            next_state = await self.execute_next()
            if next_state:
                async for result in self.run():
                    yield result

        except Exception as e:
            logger.error(f"Error in workflow chain execution: {e}")
            yield {
                "chain_name": self.name,
                "workflow_index": self.current_index,
                "status": "error",
                "message": f"Workflow chain execution error: {e}",
                "error": str(e),
            }

    def pause(self) -> None:
        """Pause the workflow chain."""
        if not self._is_running or not self.current_workflow:
            logger.warning("Cannot pause workflow chain - not running")
            return

        try:
            # Pause the current workflow
            self.current_workflow.pause()

            # Mark chain as not running
            self._is_running = False

            # Update context
            if self.context:
                # Use time.time() instead of event loop time for sync compatibility
                import time

                self.context.add_shared_data("chain_paused_at", time.time())
                self.context.add_shared_data("chain_status", "paused")
                self.context.save()

            logger.info(f"Paused workflow chain {self.name}")

        except Exception as e:
            logger.error(f"Error pausing workflow chain: {e}")

    def resume(self) -> None:
        """Resume the workflow chain."""
        if self._is_running or not self.current_workflow:
            logger.warning(
                "Cannot resume workflow chain - already running or no current workflow"
            )
            return

        try:
            # Resume the current workflow
            self.current_workflow.resume()

            # Mark chain as running
            self._is_running = True

            # Update context
            if self.context:
                # Use time.time() instead of event loop time for sync compatibility
                import time

                self.context.add_shared_data("chain_resumed_at", time.time())
                self.context.add_shared_data("chain_status", "running")
                self.context.save()

            logger.info(f"Resumed workflow chain {self.name}")

        except Exception as e:
            logger.error(f"Error resuming workflow chain: {e}")

    def stop(self) -> None:
        """Stop the workflow chain."""
        if not self.current_workflow:
            logger.warning("Cannot stop workflow chain - no current workflow")
            return

        try:
            # Call cleanup on the current workflow
            self.current_workflow.cleanup()

            # Mark chain as not running
            self._is_running = False

            # Update context
            if self.context:
                # Use time.time() instead of event loop time for sync compatibility
                import time

                self.context.add_shared_data("chain_stopped_at", time.time())
                self.context.add_shared_data("chain_status", "stopped")
                self.context.save()

            logger.info(f"Stopped workflow chain {self.name}")

        except Exception as e:
            logger.error(f"Error stopping workflow chain: {e}")


class WorkflowExecutionPlan:
    """Defines a complete plan for executing multiple workflows.

    This class provides a higher-level abstraction for defining complex
    workflow execution plans with multiple chains and conditional branching.
    """

    def __init__(self, name: Optional[str] = None):
        """Initialize a workflow execution plan.

        Args:
            name: Optional name for this execution plan
        """
        self.name = name or f"plan-{uuid.uuid4().hex[:8]}"
        self.chains: Dict[str, WorkflowChain] = {}
        self.entry_points: Dict[str, str] = {}  # scenario -> chain_name

    def add_chain(self, chain: WorkflowChain) -> "WorkflowExecutionPlan":
        """Add a workflow chain to the plan.

        Args:
            chain: The workflow chain to add

        Returns:
            Self for method chaining
        """
        self.chains[chain.name] = chain
        return self

    def set_entry_point(
        self, scenario: str, chain_name: str
    ) -> "WorkflowExecutionPlan":
        """Set an entry point for a specific scenario.

        Args:
            scenario: The scenario name (e.g., "vulnerability_assessment")
            chain_name: The name of the chain to use for this scenario

        Returns:
            Self for method chaining
        """
        if chain_name not in self.chains:
            raise ValueError(f"Chain '{chain_name}' does not exist in this plan")

        self.entry_points[scenario] = chain_name
        return self

    def get_chain_for_scenario(self, scenario: str) -> Optional[WorkflowChain]:
        """Get the workflow chain for a specific scenario.

        Args:
            scenario: The scenario name

        Returns:
            The workflow chain, or None if no entry point exists
        """
        chain_name = self.entry_points.get(scenario)
        if not chain_name:
            return None

        return self.chains.get(chain_name)

    async def execute_scenario(
        self,
        scenario: str,
        repository_id: Optional[str] = None,
        context_id: Optional[str] = None,
        **workflow_args,
    ) -> AsyncGenerator[Dict[str, Any], None]:
        """Execute a specific scenario in the plan.

        Args:
            scenario: The scenario name
            repository_id: Optional repository ID
            context_id: Optional context ID
            **workflow_args: Additional arguments for the initial workflow

        Yields:
            Progress updates and results from the workflow chain
        """
        chain = self.get_chain_for_scenario(scenario)
        if not chain:
            logger.error(f"No entry point defined for scenario: {scenario}")
            yield {
                "plan_name": self.name,
                "scenario": scenario,
                "status": "error",
                "message": f"No entry point defined for scenario: {scenario}",
            }
            return

        # Get the initial workflow type from the chain
        if not chain.transitions:
            logger.error(f"Chain {chain.name} has no transitions defined")
            yield {
                "plan_name": self.name,
                "scenario": scenario,
                "status": "error",
                "message": f"Chain {chain.name} has no transitions defined",
            }
            return

        # Use the first transition's from_workflow_type as the initial workflow
        initial_workflow_type = chain.transitions[0].from_workflow_type

        # Start the chain
        chain.start(
            initial_workflow_type,
            repository_id=repository_id,
            context_id=context_id,
            **workflow_args,
        )

        # Execute the chain
        async for result in chain.run():
            # Add execution plan information to the result
            result["plan_name"] = self.name
            result["scenario"] = scenario

            yield result
