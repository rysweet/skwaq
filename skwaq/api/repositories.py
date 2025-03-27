"""API routes for repository management."""

from datetime import datetime
import uuid
from typing import Dict, Any, List, Optional

from flask import Blueprint, jsonify, request, abort, Response, current_app
from skwaq.api.events import publish_repository_event, publish_analysis_event

from skwaq.api.auth import login_required, require_permission
from skwaq.core.openai_client import get_openai_client
from skwaq.ingestion.code_ingestion import CodeIngestionManager
from skwaq.code_analysis.analyzer import CodeAnalyzer
from skwaq.security.authorization import Permission
from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint('repositories', __name__, url_prefix='/api/repositories')

# In-memory repository cache for demo purposes
# In production, this would be stored in Neo4j
REPOSITORIES = [
    {
        'id': 'repo1',
        'name': 'example/vuln-repo',
        'description': 'Example vulnerable repository',
        'status': 'Analyzed',
        'vulnerabilities': 8,
        'lastAnalyzed': '2025-03-24T10:30:00Z',
        'url': 'https://github.com/example/vuln-repo'
    },
    {
        'id': 'repo2',
        'name': 'example/secure-app',
        'description': 'Secure application example',
        'status': 'Analyzing',
        'vulnerabilities': None,
        'lastAnalyzed': None,
        'url': 'https://github.com/example/secure-app'
    },
    {
        'id': 'repo3',
        'name': 'example/legacy-code',
        'description': 'Legacy code base with technical debt',
        'status': 'Analyzed',
        'vulnerabilities': 15,
        'lastAnalyzed': '2025-03-22T14:45:00Z',
        'url': 'https://github.com/example/legacy-code'
    },
]

# Track active analysis tasks
ACTIVE_ANALYSES = {}  # repo_id -> task_info


def get_repositories_from_db() -> List[Dict[str, Any]]:
    """Get repositories from Neo4j database.
    
    In a real implementation, this would fetch data from Neo4j.
    For now, we'll use our in-memory cache.
    
    Returns:
        List of repository dictionaries
    """
    try:
        # This is a placeholder for actual Neo4j code
        # connector = Neo4jConnector()
        # result = connector.query(
        #     "MATCH (r:Repository) "
        #     "RETURN r.id AS id, r.name AS name, r.description AS description, "
        #     "r.status AS status, r.vulnerabilities AS vulnerabilities, "
        #     "r.lastAnalyzed AS lastAnalyzed, r.url AS url"
        # )
        # return result
        return REPOSITORIES
    except Exception as e:
        logger.error(f"Error retrieving repositories: {e}")
        return []


def get_repository_by_id(repo_id: str) -> Optional[Dict[str, Any]]:
    """Get a repository by ID from Neo4j database.
    
    In a real implementation, this would fetch data from Neo4j.
    For now, we'll use our in-memory cache.
    
    Args:
        repo_id: Repository ID
        
    Returns:
        Repository dictionary or None if not found
    """
    try:
        # This is a placeholder for actual Neo4j code
        # connector = Neo4jConnector()
        # result = connector.query_single(
        #     "MATCH (r:Repository {id: $id}) "
        #     "RETURN r.id AS id, r.name AS name, r.description AS description, "
        #     "r.status AS status, r.vulnerabilities AS vulnerabilities, "
        #     "r.lastAnalyzed AS lastAnalyzed, r.url AS url",
        #     {"id": repo_id}
        # )
        # return result
        return next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    except Exception as e:
        logger.error(f"Error retrieving repository {repo_id}: {e}")
        return None


@bp.route('', methods=['GET'])
@login_required
@require_permission(Permission.LIST_REPOSITORIES)
def get_repositories() -> Response:
    """Get all repositories."""
    repos = get_repositories_from_db()
    return jsonify(repos)


@bp.route('/<repo_id>', methods=['GET'])
@login_required
@require_permission(Permission.VIEW_REPOSITORY)
def get_repository(repo_id: str) -> Response:
    """Get a specific repository by ID."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")
    return jsonify(repository)


@bp.route('', methods=['POST'])
@login_required
@require_permission(Permission.ADD_REPOSITORY)
def add_repository() -> Response:
    """Add a new repository."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")
    
    data = request.get_json()
    url = data.get('url')
    options = data.get('options', {})
    
    if not url:
        abort(400, description="URL is required")
    
    # In a real implementation, this would start the repository ingestion in a background task
    # and store the repository in Neo4j
    new_repo = {
        'id': str(uuid.uuid4()),
        'name': url.split('/')[-2] + '/' + url.split('/')[-1],
        'description': f'Repository from {url}',
        'status': 'Analyzing',
        'vulnerabilities': None,
        'lastAnalyzed': None,
        'url': url
    }
    
    # Add to in-memory cache
    REPOSITORIES.append(new_repo)
    
    # Send real-time update
    publish_repository_event("repository_added", new_repo)
    
    return jsonify(new_repo), 201


@bp.route('/<repo_id>/analyze', methods=['POST'])
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
        return jsonify({
            "error": "Analysis already in progress",
            "taskId": ACTIVE_ANALYSES[repo_id]["taskId"]
        }), 409
    
    # In a real implementation, this would start the analysis process in a background task
    # For now, we'll just update the repository status
    repository['status'] = 'Analyzing'
    
    # Create a task ID for tracking
    task_id = str(uuid.uuid4())
    
    # Track the analysis task
    ACTIVE_ANALYSES[repo_id] = {
        "taskId": task_id,
        "startTime": datetime.utcnow().isoformat(),
        "status": "running",
        "progress": 0
    }
    
    # Send real-time update
    publish_analysis_event("analysis_started", {
        "repoId": repo_id,
        "taskId": task_id,
        "status": "running",
        "progress": 0
    })
    
    return jsonify({
        "repository": repository,
        "task": {
            "id": task_id,
            "status": "running",
            "progress": 0
        }
    })


@bp.route('/<repo_id>', methods=['DELETE'])
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
    REPOSITORIES = [repo for repo in REPOSITORIES if repo['id'] != repo_id]
    
    # Send real-time update
    publish_repository_event("repository_deleted", {"repoId": repo_id})
    
    return '', 204


@bp.route('/<repo_id>/vulnerabilities', methods=['GET'])
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
            'id': 'vuln1',
            'name': 'SQL Injection',
            'type': 'Injection',
            'severity': 'High',
            'file': 'src/auth.py',
            'line': 42,
            'description': 'Unsanitized user input used in SQL query',
            'cweId': 'CWE-89',
            'remediation': 'Use parameterized queries or prepared statements'
        },
        {
            'id': 'vuln2',
            'name': 'Cross-Site Scripting',
            'type': 'XSS',
            'severity': 'Medium',
            'file': 'src/templates/index.html',
            'line': 23,
            'description': 'Unescaped user data rendered in HTML',
            'cweId': 'CWE-79',
            'remediation': 'Use context-aware escaping for user data'
        }
    ]
    
    return jsonify(vulnerabilities)


@bp.route('/<repo_id>/cancel', methods=['POST'])
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
    repository['status'] = 'Cancelled'
    
    # Update task status
    task = ACTIVE_ANALYSES.pop(repo_id)
    task["status"] = "cancelled"
    
    # Send real-time update
    publish_analysis_event("analysis_cancelled", {
        "repoId": repo_id,
        "taskId": task["taskId"],
        "status": "cancelled"
    })
    
    return '', 204


@bp.route('/<repo_id>/analysis/status', methods=['GET'])
@login_required
@require_permission(Permission.VIEW_REPOSITORY)
def get_analysis_status(repo_id: str) -> Response:
    """Get status of ongoing repository analysis."""
    repository = get_repository_by_id(repo_id)
    if repository is None:
        abort(404, description="Repository not found")
    
    # Check if analysis is running
    if repo_id not in ACTIVE_ANALYSES:
        return jsonify({
            "repoId": repo_id,
            "status": repository['status'],
            "analysis": None
        })
    
    return jsonify({
        "repoId": repo_id,
        "status": repository['status'],
        "analysis": ACTIVE_ANALYSES[repo_id]
    })