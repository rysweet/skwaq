"""API routes for repository management."""

from flask import Blueprint, jsonify, request, abort
from skwaq.core.openai_client import get_openai_client
from skwaq.ingestion.code_ingestion import CodeIngestionManager
from skwaq.code_analysis.analyzer import CodeAnalyzer

bp = Blueprint('repositories', __name__, url_prefix='/api/repositories')

# Mock data for demonstration purposes
# In a real implementation, this would be stored in a database
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

@bp.route('', methods=['GET'])
def get_repositories():
    """Get all repositories."""
    return jsonify(REPOSITORIES)

@bp.route('/<repo_id>', methods=['GET'])
def get_repository(repo_id):
    """Get a specific repository by ID."""
    repository = next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    if repository is None:
        abort(404, description="Repository not found")
    return jsonify(repository)

@bp.route('', methods=['POST'])
def add_repository():
    """Add a new repository."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")
    
    data = request.get_json()
    url = data.get('url')
    options = data.get('options', {})
    
    if not url:
        abort(400, description="URL is required")
    
    # In a real implementation, this would validate the URL and start the ingestion process
    # For demonstration, we'll create a mock repository
    import uuid
    from datetime import datetime
    
    new_repo = {
        'id': str(uuid.uuid4()),
        'name': url.split('/')[-2] + '/' + url.split('/')[-1],
        'description': f'Repository from {url}',
        'status': 'Analyzing',
        'vulnerabilities': None,
        'lastAnalyzed': None,
        'url': url
    }
    
    REPOSITORIES.append(new_repo)
    return jsonify(new_repo), 201

@bp.route('/<repo_id>/analyze', methods=['POST'])
def analyze_repository(repo_id):
    """Start analysis for a repository."""
    repository = next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    if repository is None:
        abort(404, description="Repository not found")
    
    options = request.get_json() or {}
    
    # In a real implementation, this would start the analysis process
    # For demonstration, we'll just update the repository status
    repository['status'] = 'Analyzing'
    
    return jsonify(repository)

@bp.route('/<repo_id>', methods=['DELETE'])
def delete_repository(repo_id):
    """Delete a repository."""
    global REPOSITORIES
    repository = next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    if repository is None:
        abort(404, description="Repository not found")
    
    REPOSITORIES = [repo for repo in REPOSITORIES if repo['id'] != repo_id]
    return '', 204

@bp.route('/<repo_id>/vulnerabilities', methods=['GET'])
def get_vulnerabilities(repo_id):
    """Get vulnerabilities for a repository."""
    repository = next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    if repository is None:
        abort(404, description="Repository not found")
    
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
            'cweId': 'CWE-89'
        },
        {
            'id': 'vuln2',
            'name': 'Cross-Site Scripting',
            'type': 'XSS',
            'severity': 'Medium',
            'file': 'src/templates/index.html',
            'line': 23,
            'description': 'Unescaped user data rendered in HTML',
            'cweId': 'CWE-79'
        }
    ]
    
    return jsonify(vulnerabilities)

@bp.route('/<repo_id>/cancel', methods=['POST'])
def cancel_analysis(repo_id):
    """Cancel ongoing repository analysis."""
    repository = next((repo for repo in REPOSITORIES if repo['id'] == repo_id), None)
    if repository is None:
        abort(404, description="Repository not found")
    
    # In a real implementation, this would cancel the analysis process
    # For demonstration, we'll just update the repository status
    repository['status'] = 'Failed'
    
    return '', 204