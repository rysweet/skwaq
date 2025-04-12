"""Workflow routes for the Flask API."""

import asyncio
import uuid

from flask import Blueprint, Response, jsonify, request

from skwaq.api.middleware.auth import login_required
from skwaq.api.middleware.error_handling import BadRequestError, NotFoundError
from skwaq.api.services import event_service, workflow_service
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("workflows", __name__, url_prefix="/api/workflows")


@bp.route("", methods=["GET"])
@login_required
def get_workflows() -> Response:
    """Get all available workflows.

    Returns:
        JSON response with list of available workflows
    """
    # Run asynchronous function in event loop
    workflows = asyncio.run(workflow_service.get_all_workflows())
    return jsonify(workflows)


@bp.route("/<workflow_id>", methods=["GET"])
@login_required
def get_workflow(workflow_id: str) -> Response:
    """Get a specific workflow by ID.

    Args:
        workflow_id: Workflow ID

    Returns:
        JSON response with workflow details

    Raises:
        NotFoundError: If workflow is not found
    """
    workflow = asyncio.run(workflow_service.get_workflow_by_id(workflow_id))
    if workflow is None:
        raise NotFoundError(f"Workflow {workflow_id} not found")

    return jsonify(workflow)


@bp.route("/repository/<repo_id>", methods=["GET"])
@login_required
def get_repository_workflows(repo_id: str) -> Response:
    """Get all workflow executions for a repository.

    Args:
        repo_id: Repository ID

    Returns:
        JSON response with list of workflow executions
    """
    executions = asyncio.run(workflow_service.get_repository_workflows(repo_id))
    return jsonify(executions)


@bp.route("/execution/<execution_id>", methods=["GET"])
@login_required
def get_workflow_execution(execution_id: str) -> Response:
    """Get details of a workflow execution.

    Args:
        execution_id: Workflow execution ID

    Returns:
        JSON response with execution details

    Raises:
        NotFoundError: If execution is not found
    """
    execution = asyncio.run(workflow_service.get_execution_by_id(execution_id))
    if execution is None:
        raise NotFoundError(f"Workflow execution {execution_id} not found")

    return jsonify(execution)


@bp.route("/execution/<execution_id>/cancel", methods=["POST"])
@login_required
def cancel_workflow_execution(execution_id: str) -> Response:
    """Cancel a workflow execution.

    Args:
        execution_id: Workflow execution ID

    Returns:
        JSON response with updated execution status

    Raises:
        NotFoundError: If execution is not found
        BadRequestError: If execution cannot be cancelled
    """
    execution = asyncio.run(workflow_service.get_execution_by_id(execution_id))
    if execution is None:
        raise NotFoundError(f"Workflow execution {execution_id} not found")

    if execution.get("status") not in ["running", "queued"]:
        raise BadRequestError(
            f"Cannot cancel workflow in state: {execution.get('status')}"
        )

    result = asyncio.run(workflow_service.cancel_workflow_execution(execution_id))
    if not result:
        raise BadRequestError(f"Failed to cancel workflow execution {execution_id}")

    # Get updated execution details
    updated_execution = asyncio.run(workflow_service.get_execution_by_id(execution_id))

    return jsonify(updated_execution)


@bp.route("/execution/<execution_id>/results", methods=["GET"])
@login_required
def get_workflow_results(execution_id: str) -> Response:
    """Get results of a completed workflow execution.

    Args:
        execution_id: Workflow execution ID

    Returns:
        JSON response with execution results

    Raises:
        NotFoundError: If execution is not found
        BadRequestError: If execution is not complete
    """
    execution = asyncio.run(workflow_service.get_execution_by_id(execution_id))
    if execution is None:
        raise NotFoundError(f"Workflow execution {execution_id} not found")

    if execution.get("status") != "completed":
        raise BadRequestError(
            f"Workflow execution is not complete: {execution.get('status')}"
        )

    results = asyncio.run(workflow_service.get_workflow_results(execution_id))

    return jsonify(
        {
            "executionId": execution_id,
            "status": execution.get("status"),
            "results": results,
        }
    )


@bp.route("/execute", methods=["POST"])
@login_required
def execute_workflow() -> Response:
    """Execute a workflow on a repository.

    Returns:
        JSON response with execution details

    Raises:
        BadRequestError: If request is invalid
    """
    if not request.is_json:
        raise BadRequestError("Content-Type must be application/json")

    data = request.get_json()
    workflow_type = data.get("workflowType")
    repo_id = data.get("repositoryId")
    parameters = data.get("parameters", {})

    if not workflow_type:
        raise BadRequestError("workflowType is required")

    if not repo_id:
        raise BadRequestError("repositoryId is required")

    # Check if repository exists
    from skwaq.api.services.repository_service import get_repository_by_id

    repository = asyncio.run(get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")

    # Check if workflow type exists
    workflow = asyncio.run(workflow_service.get_workflow_by_type(workflow_type))
    if workflow is None:
        raise NotFoundError(f"Workflow type {workflow_type} not found")

    # Generate a unique ID for this execution
    execution_id = f"exec-{str(uuid.uuid4())}"

    # Start workflow execution in background
    result = asyncio.run(
        workflow_service.execute_workflow(
            execution_id=execution_id,
            workflow_type=workflow_type,
            repo_id=repo_id,
            parameters=parameters,
        )
    )

    if not result:
        raise BadRequestError("Failed to start workflow execution")

    # Publish event for workflow started
    event_service.publish_event(
        "workflow",
        "workflow_started",
        {
            "executionId": execution_id,
            "workflowType": workflow_type,
            "repositoryId": repo_id,
        },
    )

    return (
        jsonify(
            {
                "executionId": execution_id,
                "workflowType": workflow_type,
                "status": "queued",
                "repositoryId": repo_id,
                "parameters": parameters,
                "message": f"Workflow {workflow_type} started for repository {repo_id}",
            }
        ),
        201,
    )
