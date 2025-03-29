"""API routes for handling investigations."""

import json
from datetime import datetime
import neo4j.time
from flask import Blueprint, jsonify, request, g
from uuid import uuid4

from skwaq.db.neo4j_connector import get_connector
from skwaq.api.middleware.error_handling import APIError, NotFoundError, BadRequestError
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

# Blueprint for investigation routes
bp = Blueprint('investigations', __name__, url_prefix='/api/investigations')


@bp.route('', methods=['GET'])
def get_investigations():
    """Get all investigations.
    
    Returns:
        JSON response with investigation list
    """
    try:
        connector = get_connector()
        
        # Query to get all investigations with additional fields like repository name
        query = """
        MATCH (i:Investigation)
        OPTIONAL MATCH (i)-[:ANALYZED]->(r:Repository)
        RETURN 
            i.id AS id,
            i.title AS title,
            i.description AS description,
            i.status AS status,
            i.created_at AS creation_date,
            i.updated_at AS update_date,
            i.finding_count AS findings_count,
            0 AS vulnerabilities_count,
            CASE WHEN r IS NOT NULL THEN r.id ELSE NULL END AS repository_id,
            CASE WHEN r IS NOT NULL THEN r.name ELSE 'Unknown Repository' END AS repository_name
        ORDER BY i.created_at DESC
        """
        
        results = connector.run_query(query)
        
        # Process results to ensure proper format
        investigations = []
        for result in results:
            # Convert datetime objects to strings if needed
            creation_date = result.get('creation_date')
            if isinstance(creation_date, (datetime, neo4j.time.DateTime)):
                creation_date = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)
                
            update_date = result.get('update_date')
            if isinstance(update_date, (datetime, neo4j.time.DateTime)):
                update_date = update_date.isoformat() if hasattr(update_date, 'isoformat') else str(update_date)
            
            investigation = {
                'id': result.get('id'),
                'title': result.get('title', 'Untitled Investigation'),
                'description': result.get('description', ''),
                'status': result.get('status', 'Unknown'),
                'creation_date': creation_date,
                'update_date': update_date,
                'findings_count': result.get('findings_count', 0),
                'vulnerabilities_count': result.get('vulnerabilities_count', 0),
                'repository_id': result.get('repository_id', ''),
                'repository_name': result.get('repository_name', 'Unknown Repository')
            }
            investigations.append(investigation)
        
        return jsonify(investigations)
    except Exception as e:
        logger.error(f"Error retrieving investigations: {str(e)}")
        raise APIError(f"Failed to retrieve investigations: {str(e)}")


@bp.route('/<investigation_id>', methods=['GET'])
def get_investigation(investigation_id):
    """Get a specific investigation.
    
    Args:
        investigation_id: ID of the investigation
        
    Returns:
        JSON response with investigation details
    """
    try:
        connector = get_connector()
        
        # Query to get a specific investigation with additional details
        query = """
        MATCH (i:Investigation {id: $id})
        OPTIONAL MATCH (i)-[:ANALYZED]->(r:Repository)
        OPTIONAL MATCH (i)-[:HAS_FINDING]->(f:Finding)
        OPTIONAL MATCH (f)-[:DETECTED_IN]->(v:Vulnerability)
        RETURN 
            i.id AS id,
            i.title AS title,
            i.description AS description,
            i.status AS status,
            i.created_at AS creation_date,
            i.updated_at AS update_date,
            i.workflow_id AS workflow_id,
            i.finding_count AS findings_count,
            COUNT(DISTINCT v) AS vulnerabilities_count,
            CASE WHEN r IS NOT NULL THEN r.id ELSE NULL END AS repository_id,
            CASE WHEN r IS NOT NULL THEN r.name ELSE 'Unknown Repository' END AS repository_name
        """
        
        results = connector.run_query(query, {"id": investigation_id})
        
        if not results:
            raise NotFoundError(f"Investigation {investigation_id} not found")
        
        result = results[0]
        
        # Convert datetime objects to strings if needed
        creation_date = result.get('creation_date')
        if isinstance(creation_date, (datetime, neo4j.time.DateTime)):
            creation_date = creation_date.isoformat() if hasattr(creation_date, 'isoformat') else str(creation_date)
            
        update_date = result.get('update_date')
        if isinstance(update_date, (datetime, neo4j.time.DateTime)):
            update_date = update_date.isoformat() if hasattr(update_date, 'isoformat') else str(update_date)
        
        investigation = {
            'id': result.get('id'),
            'title': result.get('title', 'Untitled Investigation'),
            'description': result.get('description', ''),
            'status': result.get('status', 'Unknown'),
            'creation_date': creation_date,
            'update_date': update_date,
            'workflow_id': result.get('workflow_id'),
            'findings_count': result.get('findings_count', 0),
            'vulnerabilities_count': result.get('vulnerabilities_count', 0),
            'repository_id': result.get('repository_id', ''),
            'repository_name': result.get('repository_name', 'Unknown Repository')
        }
        
        # Get findings for this investigation
        findings_query = """
        MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)
        RETURN 
            f.id AS id,
            f.title AS title,
            f.description AS description,
            f.location AS location,
            f.severity AS severity,
            f.type AS type,
            f.status AS status
        """
        
        findings_results = connector.run_query(findings_query, {"id": investigation_id})
        findings = [dict(finding) for finding in findings_results]
        
        investigation['findings'] = findings
        
        return jsonify(investigation)
    except NotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error retrieving investigation {investigation_id}: {str(e)}")
        raise APIError(f"Failed to retrieve investigation: {str(e)}")


@bp.route('', methods=['POST'])
def create_investigation():
    """Create a new investigation.
    
    Returns:
        JSON response with the created investigation
    """
    try:
        data = request.json
        
        if not data:
            raise BadRequestError("No data provided")
        
        # Required fields
        title = data.get('title')
        if not title:
            raise BadRequestError("Title is required")
        
        repository_id = data.get('repository_id')
        description = data.get('description', f"Investigation of {title}")
        
        # Generate a new ID if not provided
        investigation_id = data.get('id', f"inv-{uuid4().hex[:8]}")
        
        connector = get_connector()
        
        # Create the investigation node
        now = datetime.utcnow().isoformat()
        investigation_data = {
            "id": investigation_id,
            "title": title,
            "description": description,
            "status": "Pending",
            "created_at": now,
            "updated_at": now,
            "finding_count": 0
        }
        
        investigation_id = connector.create_node(
            "Investigation", investigation_data
        )
        
        # If repository ID is provided, create relationship
        if repository_id:
            relationship_query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (r:Repository {id: $repository_id})
            CREATE (i)-[:ANALYZED]->(r)
            """
            connector.run_query(relationship_query, {
                "investigation_id": investigation_id,
                "repository_id": repository_id
            })
        
        # Return the created investigation
        return jsonify({
            "id": investigation_id,
            "title": title,
            "description": description,
            "status": "Pending",
            "creation_date": now,
            "update_date": now,
            "findings_count": 0,
            "vulnerabilities_count": 0,
            "repository_id": repository_id,
            "repository_name": "Unknown Repository" if not repository_id else ""
        }), 201
    except BadRequestError as e:
        raise e
    except Exception as e:
        logger.error(f"Error creating investigation: {str(e)}")
        raise APIError(f"Failed to create investigation: {str(e)}")


@bp.route('/<investigation_id>', methods=['DELETE'])
def delete_investigation(investigation_id):
    """Delete an investigation.
    
    Args:
        investigation_id: ID of the investigation to delete
        
    Returns:
        JSON response indicating success
    """
    try:
        connector = get_connector()
        
        # Check if investigation exists
        exists_query = "MATCH (i:Investigation {id: $id}) RETURN i"
        results = connector.run_query(exists_query, {"id": investigation_id})
        
        if not results:
            raise NotFoundError(f"Investigation {investigation_id} not found")
        
        # Delete the investigation and all its relationships
        delete_query = """
        MATCH (i:Investigation {id: $id})
        DETACH DELETE i
        """
        
        connector.run_query(delete_query, {"id": investigation_id})
        
        return jsonify({"message": f"Investigation {investigation_id} deleted successfully"})
    except NotFoundError as e:
        raise e
    except Exception as e:
        logger.error(f"Error deleting investigation {investigation_id}: {str(e)}")
        raise APIError(f"Failed to delete investigation: {str(e)}")