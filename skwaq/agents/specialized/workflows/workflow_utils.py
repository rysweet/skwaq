"""Utility functions for workflow management.

This module provides utility functions for workflow management, including
workflow ID generation and validation.
"""

import uuid
from typing import Any, Dict

from .workflow_types import WorkflowDefinition


def create_workflow_id() -> str:
    """Create a unique workflow ID.

    Returns:
        str: Unique workflow ID
    """
    return f"wf-{uuid.uuid4().hex[:8]}"


def validate_workflow_definition(workflow_def: WorkflowDefinition) -> None:
    """Validate a workflow definition.

    Args:
        workflow_def: Workflow definition to validate

    Raises:
        ValueError: If workflow definition is invalid
    """
    # Verify required fields
    if not workflow_def.workflow_id:
        raise ValueError("Workflow ID is required")

    if not workflow_def.workflow_type:
        raise ValueError("Workflow type is required")

    if not workflow_def.name:
        raise ValueError("Workflow name is required")

    if not workflow_def.target_id:
        raise ValueError("Target ID is required")

    if not workflow_def.target_type:
        raise ValueError("Target type is required")

    # Verify agents
    if not workflow_def.agents:
        raise ValueError("At least one agent is required")

    # Verify stages
    if not workflow_def.stages:
        raise ValueError("At least one stage is required")

    # Verify each stage
    for i, stage in enumerate(workflow_def.stages):
        if "name" not in stage:
            raise ValueError(f"Stage {i} name is required")

        if "description" not in stage:
            raise ValueError(f"Stage {i} description is required")

        # Check for agent or agents (for collaborative stages)
        if "agent" not in stage and "agents" not in stage:
            raise ValueError(f"Stage {i} must specify either 'agent' or 'agents'")

        if "agent" in stage and stage["agent"] not in workflow_def.agents:
            raise ValueError(
                f"Stage {i} agent '{stage['agent']}' is not in the workflow agents list"
            )

        if "agents" in stage:
            for agent in stage["agents"]:
                if agent not in workflow_def.agents:
                    raise ValueError(
                        f"Stage {i} agent '{agent}' is not in the workflow agents list"
                    )

            # Collaborative stages must specify a communication pattern
            if "communication_pattern" not in stage:
                raise ValueError(
                    f"Collaborative stage {i} must specify a communication pattern"
                )

            if (
                stage["communication_pattern"]
                not in workflow_def.communication_patterns
            ):
                raise ValueError(
                    f"Communication pattern '{stage['communication_pattern']}' not in workflow patterns"
                )

        # Check for stage dependencies
        if "dependencies" in stage:
            for dependency in stage["dependencies"]:
                found = False
                for j, prev_stage in enumerate(workflow_def.stages[:i]):
                    if prev_stage["name"] == dependency:
                        found = True
                        break

                if not found:
                    raise ValueError(
                        f"Stage {i} dependency '{dependency}' not found in previous stages"
                    )

    # Verify communication patterns
    if not workflow_def.communication_patterns:
        raise ValueError("At least one communication pattern is required")


def merge_workflow_components(
    base_components: Dict[str, Any], override_components: Dict[str, Any]
) -> Dict[str, Any]:
    """Merge workflow components.

    Args:
        base_components: Base components
        override_components: Override components

    Returns:
        Dict[str, Any]: Merged components
    """
    result = base_components.copy()

    # Merge agents
    if "agents" in override_components:
        # Create a set to avoid duplicates
        agents = set(result.get("agents", []))
        agents.update(override_components["agents"])
        result["agents"] = list(agents)

    # Merge stages
    if "stages" in override_components:
        if "stages" in result:
            # Create a mapping of stage names to avoid duplicates
            stage_map = {stage["name"]: stage for stage in result["stages"]}

            for stage in override_components["stages"]:
                stage_map[stage["name"]] = stage

            # Recreate stages list
            result["stages"] = list(stage_map.values())
        else:
            result["stages"] = override_components["stages"]

    # Merge communication patterns
    if "communication_patterns" in override_components:
        # Create a set to avoid duplicates
        patterns = set(result.get("communication_patterns", []))
        patterns.update(override_components["communication_patterns"])
        result["communication_patterns"] = list(patterns)

    return result
