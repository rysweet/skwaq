"""API routes for repository management."""

from datetime import datetime
import uuid
import asyncio
from typing import Dict, Any, List, Optional

from flask import Blueprint, jsonify, request, abort, Response, current_app
from skwaq.api.events import publish_repository_event, publish_analysis_event

from skwaq.api.auth import login_required, require_permission
from skwaq.core.openai_client import get_openai_client
from skwaq.ingestion import Ingestion
from skwaq.security.authorization import Permission
from skwaq.db.neo4j_connector import get_connector, Neo4jConnector
from skwaq.db.schema import NodeLabels
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("repositories", __name__, url_prefix="/api/repositories")

# In-memory repository cache for demo purposes
# In production, this would be stored in Neo4j
REPOSITORIES = [
    {
        "id": "repo1",
        "name": "example/vuln-repo",
        "description": "Example vulnerable repository",
        "status": "Analyzed",
        "vulnerabilities": 8,
        "lastAnalyzed": "2025-03-24T10:30:00Z",
        "url": "https://github.com/example/vuln-repo",
    },
    {
        "id": "repo2",
        "name": "example/secure-app",
        "description": "Secure application example",
        "status": "Analyzing",
        "vulnerabilities": None,
        "lastAnalyzed": None,
        "url": "https://github.com/example/secure-app",
    },
    {
        "id": "repo3",
        "name": "example/legacy-code",
        "description": "Legacy code base with technical debt",
        "status": "Analyzed",
        "vulnerabilities": 15,
        "lastAnalyzed": "2025-03-22T14:45:00Z",
        "url": "https://github.com/example/legacy-code",
    },
]

# Track active analysis tasks
ACTIVE_ANALYSES = {}  # repo_id -> task_info


def get_repositories_from_db() -> List[Dict[str, Any]]:
    """Get repositories from Neo4j database.

    Fetches actual repositories from the Neo4j database.

    Returns:
        List of repository dictionaries
    """
    try:
        # Get database connector
        connector = get_connector()

        # Query repositories
        query = f"""
        MATCH (r:{NodeLabels.REPOSITORY})
        RETURN r.ingestion_id as id, 
               r.name as name, 
               r.url as url,
               r.state as status,
               r.files_processed as file_count,
               r.end_time as lastAnalyzed
        """

        results = connector.run_query(query)

        if not results:
            return REPOSITORIES  # Return mock data if no repositories found

        # Format for API response
        repos = []
        for repo in results:
            # Determine vulnerabilities count (to be implemented in the future)
            vulnerabilities = None

            # Convert to standard format
            repos.append(
                {
                    "id": repo.get("id", str(uuid.uuid4())),
                    "name": repo.get("name", "Unknown Repository"),
                    "description": f"Repository from {repo.get('url', 'unknown source')}",
                    "status": repo.get("status", "Unknown"),
                    "vulnerabilities": vulnerabilities,
                    "lastAnalyzed": repo.get("lastAnalyzed"),
                    "url": repo.get("url"),
                }
            )

        return repos
    except Exception as e:
        logger.error(f"Error retrieving repositories: {e}")
        return REPOSITORIES  # Return mock data on error


def get_repository_by_id(repo_id: str) -> Optional[Dict[str, Any]]:
    """Get a repository by ID from Neo4j database.

    Fetches repository details from Neo4j database by ingestion ID.

    Args:
        repo_id: Repository ID (ingestion_id)

    Returns:
        Repository dictionary or None if not found
    """
    try:
        # Try the mock data first for backward compatibility
        mock_repo = next((repo for repo in REPOSITORIES if repo["id"] == repo_id), None)

        # Get database connector
        connector = get_connector()

        # Query repositories by ingestion_id
        query = f"""
        MATCH (r:{NodeLabels.REPOSITORY})
        WHERE r.ingestion_id = $id
        RETURN r.ingestion_id as id, 
               r.name as name, 
               r.url as url,
               r.state as status,
               r.files_processed as file_count,
               r.error as error,
               r.end_time as lastAnalyzed,
               r.progress as progress
        """

        results = connector.run_query(query, {"id": repo_id})

        if not results:
            return mock_repo  # Return mock data if not found

        # Format for API response
        repo = results[0]

        # Determine vulnerabilities count (to be implemented in the future)
        vulnerabilities = None

        # Convert to standard format
        return {
            "id": repo.get("id", repo_id),
            "name": repo.get("name", "Unknown Repository"),
            "description": f"Repository from {repo.get('url', 'unknown source')}",
            "status": repo.get("status", "Unknown"),
            "progress": repo.get("progress", 0),
            "error": repo.get("error"),
            "vulnerabilities": vulnerabilities,
            "lastAnalyzed": repo.get("lastAnalyzed"),
            "fileCount": repo.get("file_count", 0),
            "url": repo.get("url"),
        }
    except Exception as e:
        logger.error(f"Error retrieving repository {repo_id}: {e}")
        return mock_repo  # Return mock data on error


@bp.route("", methods=["GET"])
@login_required
@require_permission(Permission.LIST_REPOSITORIES)
def get_repositories() -> Response:
    """Get all repositories."""
    repos = get_repositories_from_db()
    return jsonify(repos)


@bp.route("/<repo_id>", methods=["GET"])
@login_required
@require_permission(Permission.VIEW_REPOSITORY)
def get_repository(repo_id: str) -> Response:
    """Get a specific repository by ID."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")
    return jsonify(repository)


@bp.route("", methods=["POST"])
@login_required
@require_permission(Permission.ADD_REPOSITORY)
def add_repository() -> Response:
    """Add a new repository."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")

    data = request.get_json()
    url = data.get("url")
    options = data.get("options", {})

    if not url:
        abort(400, description="URL is required")

    # Create a background task to ingest the repository
    def ingest_repo_task(repo_url, branch=None, parse_only=False):
        """Background task to ingest repository."""

        async def _run_ingestion():
            try:
                # Get OpenAI client
                model_client = None
                if not parse_only:
                    try:
                        model_client = get_openai_client(async_mode=True)
                    except Exception as e:
                        logger.error(f"Failed to initialize OpenAI client: {e}")
                        logger.info("Falling back to parse-only mode")

                # Create ingestion instance
                ingestion = Ingestion(
                    repo=repo_url,
                    branch=branch,
                    model_client=model_client,
                    parse_only=parse_only,
                )

                # Start ingestion
                ingestion_id = await ingestion.ingest()
                logger.info(f"Started ingestion with ID: {ingestion_id}")

                # Track ingestion and send status updates
                completed = False
                while not completed:
                    try:
                        status = await ingestion.get_status(ingestion_id)

                        # Send status update
                        publish_repository_event(
                            "repository_status_update",
                            {
                                "id": ingestion_id,
                                "status": status.state,
                                "progress": status.progress,
                                "message": status.message,
                                "files_processed": status.files_processed,
                                "total_files": status.total_files,
                            },
                        )

                        if status.state in ["completed", "failed"]:
                            completed = True
                            logger.info(
                                f"Ingestion {status.state} in {status.time_elapsed:.2f} seconds"
                            )
                        else:
                            await asyncio.sleep(2)
                    except Exception as e:
                        logger.error(f"Error checking ingestion status: {e}")
                        completed = True

                return ingestion_id
            except Exception as e:
                logger.error(f"Error in ingestion task: {e}")
                return None

        # Create asyncio event loop and run the task
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        try:
            return loop.run_until_complete(_run_ingestion())
        finally:
            loop.close()

    # Create a thread to run the ingestion task
    import threading

    branch = options.get("branch")
    parse_only = options.get("parse_only", False)

    # Generate a temporary ID for the repository
    ingestion_id = str(uuid.uuid4())
    repo_name = url.split("/")[-2] + "/" + url.split("/")[-1] if "/" in url else url

    # Create initial repository representation
    new_repo = {
        "id": ingestion_id,
        "name": repo_name,
        "description": f"Repository from {url}",
        "status": "Initializing",
        "progress": 0,
        "vulnerabilities": None,
        "lastAnalyzed": None,
        "url": url,
    }

    # Start ingestion in a background thread
    thread = threading.Thread(
        target=ingest_repo_task, args=(url, branch, parse_only), daemon=True
    )
    thread.start()

    # Send real-time update
    publish_repository_event("repository_added", new_repo)

    return jsonify(new_repo), 201


@bp.route("/<repo_id>/analyze", methods=["POST"])
@login_required
@require_permission(Permission.RUN_TOOLS)
def analyze_repository(repo_id: str) -> Response:
    """Start analysis for a repository."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")

    options = request.get_json() or {}

    # Check if analysis is already running
    if repo_id in ACTIVE_ANALYSES:
        return (
            jsonify(
                {
                    "error": "Analysis already in progress",
                    "taskId": ACTIVE_ANALYSES[repo_id]["taskId"],
                }
            ),
            409,
        )

    # In a real implementation, this would start the analysis process in a background task
    # For now, we'll just update the repository status
    repository["status"] = "Analyzing"

    # Create a task ID for tracking
    task_id = str(uuid.uuid4())

    # Track the analysis task
    ACTIVE_ANALYSES[repo_id] = {
        "taskId": task_id,
        "startTime": datetime.utcnow().isoformat(),
        "status": "running",
        "progress": 0,
    }

    # Send real-time update
    publish_analysis_event(
        "analysis_started",
        {"repoId": repo_id, "taskId": task_id, "status": "running", "progress": 0},
    )

    return jsonify(
        {
            "repository": repository,
            "task": {"id": task_id, "status": "running", "progress": 0},
        }
    )


@bp.route("/<repo_id>", methods=["DELETE"])
@login_required
@require_permission(Permission.DELETE_REPOSITORY)
def delete_repository(repo_id: str) -> Response:
    """Delete a repository."""
    global REPOSITORIES
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")

    # Check if analysis is running
    if repo_id in ACTIVE_ANALYSES:
        # Cancel the analysis
        ACTIVE_ANALYSES.pop(repo_id)

    # Remove from in-memory cache
    REPOSITORIES = [repo for repo in REPOSITORIES if repo["id"] != repo_id]

    # Send real-time update
    publish_repository_event("repository_deleted", {"repoId": repo_id})

    return "", 204


@bp.route("/<repo_id>/vulnerabilities", methods=["GET"])
@login_required
@require_permission(Permission.LIST_FINDINGS)
def get_vulnerabilities(repo_id: str) -> Response:
    """Get vulnerabilities for a repository."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")

    # In a real implementation, this would fetch vulnerabilities from Neo4j
    # Mock vulnerabilities for demonstration
    vulnerabilities = [
        {
            "id": "vuln1",
            "name": "SQL Injection",
            "type": "Injection",
            "severity": "High",
            "file": "src/auth.py",
            "line": 42,
            "description": "Unsanitized user input used in SQL query",
            "cweId": "CWE-89",
            "remediation": "Use parameterized queries or prepared statements",
        },
        {
            "id": "vuln2",
            "name": "Cross-Site Scripting",
            "type": "XSS",
            "severity": "Medium",
            "file": "src/templates/index.html",
            "line": 23,
            "description": "Unescaped user data rendered in HTML",
            "cweId": "CWE-79",
            "remediation": "Use context-aware escaping for user data",
        },
    ]

    return jsonify(vulnerabilities)


@bp.route("/<repo_id>/cancel", methods=["POST"])
@login_required
@require_permission(Permission.RUN_TOOLS)
def cancel_analysis(repo_id: str) -> Response:
    """Cancel ongoing repository analysis."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")

    # Check if analysis is running
    if repo_id not in ACTIVE_ANALYSES:
        return jsonify({"error": "No active analysis found"}), 404

    # In a real implementation, this would cancel the analysis process
    # For now, we'll just update the repository status
    repository["status"] = "Cancelled"

    # Update task status
    task = ACTIVE_ANALYSES.pop(repo_id)
    task["status"] = "cancelled"

    # Send real-time update
    publish_analysis_event(
        "analysis_cancelled",
        {"repoId": repo_id, "taskId": task["taskId"], "status": "cancelled"},
    )

    return "", 204


@bp.route("/<repo_id>/analysis/status", methods=["GET"])
@login_required
@require_permission(Permission.VIEW_REPOSITORY)
def get_analysis_status(repo_id: str) -> Response:
    """Get status of ongoing repository analysis."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")

    # Check if analysis is running
    if repo_id not in ACTIVE_ANALYSES:
        return jsonify(
            {"repoId": repo_id, "status": repository["status"], "analysis": None}
        )

    return jsonify(
        {
            "repoId": repo_id,
            "status": repository["status"],
            "analysis": ACTIVE_ANALYSES[repo_id],
        }
    )
