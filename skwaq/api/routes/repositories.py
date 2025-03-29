"""Repository routes for the Flask API."""

from flask import Blueprint, jsonify, request, Response
import asyncio

from skwaq.api.middleware.auth import login_required
from skwaq.api.middleware.error_handling import (
    APIError, 
    NotFoundError, 
    BadRequestError
)
from skwaq.api.services import repository_service
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("repositories", __name__, url_prefix="/api/repositories")


@bp.route("", methods=["GET"])
@login_required
def get_repositories() -> Response:
    """Get all repositories.
    
    Returns:
        JSON response with list of repositories
    """
    # Run asynchronous function in event loop
    repositories = asyncio.run(repository_service.get_all_repositories())
    return jsonify(repositories)


@bp.route("/<repo_id>", methods=["GET"])
@login_required
def get_repository(repo_id: str) -> Response:
    """Get a specific repository by ID.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        JSON response with repository details
        
    Raises:
        NotFoundError: If repository is not found
    """
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    return jsonify(repository)


@bp.route("", methods=["POST"])
@login_required
def add_repository() -> Response:
    """Add a new repository.
    
    Returns:
        JSON response with repository details
        
    Raises:
        BadRequestError: If request is invalid
    """
    if not request.is_json:
        raise BadRequestError("Content-Type must be application/json")
    
    data = request.get_json()
    url = data.get("url")
    options = data.get("options", {})
    
    if not url:
        raise BadRequestError("URL is required")
    
    # Add repository
    repository = asyncio.run(repository_service.add_repository(url, options))
    
    return jsonify(repository), 201


@bp.route("/<repo_id>", methods=["DELETE"])
@login_required
def delete_repository(repo_id: str) -> Response:
    """Delete a repository.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        Empty response with 204 status code
        
    Raises:
        NotFoundError: If repository is not found
    """
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    success = asyncio.run(repository_service.delete_repository(repo_id))
    if not success:
        # If deletion fails, still return a success since the repository might not exist anymore
        logger.warning(f"Error deleting repository {repo_id}, but continuing")
    
    return "", 204


@bp.route("/<repo_id>/vulnerabilities", methods=["GET"])
@login_required
def get_vulnerabilities(repo_id: str) -> Response:
    """Get vulnerabilities for a repository.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        JSON response with list of vulnerabilities
        
    Raises:
        NotFoundError: If repository is not found
    """
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    vulnerabilities = asyncio.run(repository_service.get_repository_vulnerabilities(repo_id))
    return jsonify(vulnerabilities)


@bp.route("/<repo_id>/analyze", methods=["POST"])
@login_required
def analyze_repository(repo_id: str) -> Response:
    """Start analysis for a repository.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        JSON response with repository and task information
        
    Raises:
        NotFoundError: If repository is not found
        BadRequestError: If repository is already being analyzed
    """
    if not request.is_json:
        request_data = {}
    else:
        request_data = request.get_json() or {}
        
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    # Check if analysis is already running
    if repository.get("status") == "Analyzing":
        raise BadRequestError("Repository is already being analyzed")
    
    # For now, we'll just update the repository status
    # In a future implementation, we'll start the actual analysis process
    repository["status"] = "Analyzing"
    
    # Create a task ID for tracking
    task_id = "task-" + repo_id
    
    # In the future, this would create a background task
    # For now, we'll just return the repository status
    
    return jsonify({
        "repository": repository,
        "task": {
            "id": task_id,
            "status": "running",
            "progress": 0
        }
    })


@bp.route("/<repo_id>/cancel", methods=["POST"])
@login_required
def cancel_analysis(repo_id: str) -> Response:
    """Cancel ongoing repository analysis.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        Empty response with 204 status code
        
    Raises:
        NotFoundError: If repository is not found
        BadRequestError: If repository is not being analyzed
    """
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    # Check if analysis is running
    if repository.get("status") != "Analyzing":
        raise BadRequestError("Repository is not being analyzed")
    
    # For now, we'll just update the repository status
    # In a future implementation, we'll actually cancel the analysis process
    repository["status"] = "Cancelled"
    
    return "", 204


@bp.route("/<repo_id>/analysis/status", methods=["GET"])
@login_required
def get_analysis_status(repo_id: str) -> Response:
    """Get status of ongoing repository analysis.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        JSON response with analysis status
        
    Raises:
        NotFoundError: If repository is not found
    """
    repository = asyncio.run(repository_service.get_repository_by_id(repo_id))
    if repository is None:
        raise NotFoundError(f"Repository {repo_id} not found")
    
    # For now, we'll just return a simple status
    # In a future implementation, we'll track the actual analysis progress
    status = repository.get("status", "Unknown")
    progress = repository.get("progress", 0)
    
    response = {
        "repoId": repo_id,
        "status": status,
    }
    
    # Include analysis details if available
    if status == "Analyzing":
        response["analysis"] = {
            "taskId": "task-" + repo_id,
            "startTime": repository.get("lastAnalyzed", ""),
            "status": "running",
            "progress": progress
        }
    else:
        response["analysis"] = None
    
    return jsonify(response)