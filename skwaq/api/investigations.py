"""API routes for investigation management."""

import uuid
from typing import Dict, Any, List, Optional
from datetime import datetime

from flask import Blueprint, jsonify, request, abort, Response
from skwaq.api.auth import login_required, require_permission
from skwaq.security.authorization import Permission
from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

bp = Blueprint("investigations", __name__, url_prefix="/api/investigations")

# Mock investigations for demonstration purposes
INVESTIGATIONS = [
    {
        "id": "inv-46dac8c5-ef32-4870-adc8-5858aa0da556",
        "title": "SQL Injection Analysis",
        "repository_id": "repo1",
        "repository_name": "example/vuln-repo",
        "creation_date": "2025-03-26T09:15:30Z",
        "status": "completed",
        "findings_count": 3,
        "vulnerabilities_count": 2,
        "description": "Investigation of SQL injection vulnerabilities in the application."
    },
    {
        "id": "inv-6f2e7d4c-1a3b-4c5d-9e8f-7g6h5i4j3k2l",
        "title": "Security Assessment",
        "repository_id": "repo3",
        "repository_name": "example/legacy-code",
        "creation_date": "2025-03-25T14:20:45Z",
        "status": "in_progress",
        "findings_count": 7,
        "vulnerabilities_count": 4,
        "description": "Comprehensive security assessment of legacy codebase."
    },
    {
        "id": "inv-a1b2c3d4-e5f6-7g8h-9i0j-k1l2m3n4o5p6",
        "title": "Cross-Site Scripting Review",
        "repository_id": "repo1",
        "repository_name": "example/vuln-repo",
        "creation_date": "2025-03-24T11:05:15Z",
        "status": "completed",
        "findings_count": 5,
        "vulnerabilities_count": 3,
        "description": "Review of XSS vulnerabilities and implementation of CSP."
    }
]

def get_investigations_from_db() -> List[Dict[str, Any]]:
    """Get investigations from Neo4j database.
    
    Returns:
        List of investigation dictionaries
    """
    try:
        # Get database connector
        connector = get_connector()
        
        # Query investigations
        query = """
        MATCH (i:Investigation)
        OPTIONAL MATCH (i)-[:ANALYZES]->(r:Repository)
        OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
        OPTIONAL MATCH (f)-[:IDENTIFIES]->(v:Vulnerability)
        RETURN i.id as id, 
               i.title as title,
               i.description as description,
               i.created_at as creation_date,
               i.status as status,
               r.id as repository_id,
               r.name as repository_name,
               count(DISTINCT f) as findings_count,
               count(DISTINCT v) as vulnerabilities_count
        GROUP BY i.id, i.title, i.description, i.created_at, i.status, r.id, r.name
        """
        
        results = connector.run_query(query)
        
        if not results:
            return INVESTIGATIONS  # Return mock data if no investigations found
        
        # Format for API response
        investigations = []
        for inv in results:
            investigations.append({
                "id": inv.get("id", str(uuid.uuid4())),
                "title": inv.get("title", "Untitled Investigation"),
                "repository_id": inv.get("repository_id"),
                "repository_name": inv.get("repository_name", "Unknown Repository"),
                "creation_date": inv.get("creation_date", datetime.utcnow().isoformat()),
                "status": inv.get("status", "unknown"),
                "findings_count": inv.get("findings_count", 0),
                "vulnerabilities_count": inv.get("vulnerabilities_count", 0),
                "description": inv.get("description", "")
            })
        
        return investigations
    except Exception as e:
        logger.error(f"Error retrieving investigations: {e}")
        return INVESTIGATIONS  # Return mock data on error

def get_investigation_by_id(investigation_id: str) -> Optional[Dict[str, Any]]:
    """Get an investigation by ID from Neo4j database.
    
    Args:
        investigation_id: Investigation ID
        
    Returns:
        Investigation dictionary or None if not found
    """
    try:
        # Try mock data first for backward compatibility
        mock_inv = next((inv for inv in INVESTIGATIONS if inv["id"] == investigation_id), None)
        
        # Get database connector
        connector = get_connector()
        
        # Query investigation by ID
        query = """
        MATCH (i:Investigation {id: $id})
        OPTIONAL MATCH (i)-[:ANALYZES]->(r:Repository)
        OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
        OPTIONAL MATCH (f)-[:IDENTIFIES]->(v:Vulnerability)
        RETURN i.id as id, 
               i.title as title,
               i.description as description,
               i.created_at as creation_date,
               i.updated_at as update_date,
               i.status as status,
               i.workflow_id as workflow_id,
               r.id as repository_id,
               r.name as repository_name,
               count(DISTINCT f) as findings_count,
               count(DISTINCT v) as vulnerabilities_count
        """
        
        results = connector.run_query(query, {"id": investigation_id})
        
        if not results:
            return mock_inv  # Return mock data if not found
        
        # Format for API response
        inv = results[0]
        return {
            "id": inv.get("id", investigation_id),
            "title": inv.get("title", "Untitled Investigation"),
            "repository_id": inv.get("repository_id"),
            "repository_name": inv.get("repository_name", "Unknown Repository"),
            "workflow_id": inv.get("workflow_id"),
            "creation_date": inv.get("creation_date", datetime.utcnow().isoformat()),
            "update_date": inv.get("update_date"),
            "status": inv.get("status", "unknown"),
            "findings_count": inv.get("findings_count", 0),
            "vulnerabilities_count": inv.get("vulnerabilities_count", 0),
            "description": inv.get("description", "")
        }
    except Exception as e:
        logger.error(f"Error retrieving investigation {investigation_id}: {e}")
        return mock_inv  # Return mock data on error

@bp.route("", methods=["GET"])
@login_required
@require_permission(Permission.LIST_FINDINGS)
def get_investigations() -> Response:
    """Get all investigations."""
    investigations = get_investigations_from_db()
    return jsonify(investigations)

@bp.route("/<investigation_id>", methods=["GET"])
@login_required
@require_permission(Permission.VIEW_FINDING)
def get_investigation(investigation_id: str) -> Response:
    """Get a specific investigation by ID."""
    investigation = get_investigation_by_id(investigation_id)
    if investigation is None:
        abort(404, description="Investigation not found")
    return jsonify(investigation)

@bp.route("", methods=["POST"])
@login_required
@require_permission(Permission.ADD_FINDING)
def create_investigation() -> Response:
    """Create a new investigation."""
    if not request.is_json:
        abort(400, description="Content-Type must be application/json")
    
    data = request.get_json()
    title = data.get("title")
    repository_id = data.get("repository_id")
    description = data.get("description", "")
    
    if not title:
        abort(400, description="Title is required")
    
    if not repository_id:
        abort(400, description="Repository ID is required")
    
    # Create a new investigation
    investigation_id = str(uuid.uuid4())
    now = datetime.utcnow().isoformat()
    
    new_investigation = {
        "id": f"inv-{investigation_id}",
        "title": title,
        "repository_id": repository_id,
        "creation_date": now,
        "status": "new",
        "findings_count": 0,
        "vulnerabilities_count": 0,
        "description": description
    }
    
    # In a real implementation, this would store the investigation in Neo4j
    INVESTIGATIONS.append(new_investigation)
    
    return jsonify(new_investigation), 201

@bp.route("/<investigation_id>/findings", methods=["GET"])
@login_required
@require_permission(Permission.LIST_FINDINGS)
def get_investigation_findings(investigation_id: str) -> Response:
    """Get findings for a specific investigation."""
    investigation = get_investigation_by_id(investigation_id)
    if investigation is None:
        abort(404, description="Investigation not found")
    
    # In a real implementation, this would fetch findings from Neo4j
    # Mock findings for demonstration
    findings = [
        {
            "id": "finding1",
            "title": "SQL Injection in Login Form",
            "type": "Injection",
            "severity": "High",
            "confidence": "High",
            "file_path": "src/auth.py",
            "line": 42,
            "description": "Unsanitized user input used in SQL query",
            "cwe_id": "CWE-89",
            "remediation": "Use parameterized queries or prepared statements"
        },
        {
            "id": "finding2",
            "title": "Stored XSS in User Profile",
            "type": "XSS",
            "severity": "Medium",
            "confidence": "Medium",
            "file_path": "src/templates/profile.html",
            "line": 23,
            "description": "Unescaped user data rendered in HTML",
            "cwe_id": "CWE-79",
            "remediation": "Use context-aware escaping for user data"
        }
    ]
    
    return jsonify(findings)