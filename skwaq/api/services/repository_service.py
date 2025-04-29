"""Repository service for the Flask API."""

import uuid
from typing import Any, Dict, List, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import NodeLabels
from skwaq.ingestion.ingestion import Ingestion
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


async def get_all_repositories() -> List[Dict[str, Any]]:
    """Get all repositories from the database.

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
            return []

        # Format for API response
        repos = []
        for repo in results:
            # Determine vulnerabilities count (to be implemented in the future)
            vulnerabilities = await get_repository_vulnerabilities_count(repo.get("id"))

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
        return []


async def get_repository_by_id(repo_id: str) -> Optional[Dict[str, Any]]:
    """Get a repository by ID from Neo4j database.

    Args:
        repo_id: Repository ID (ingestion_id)

    Returns:
        Repository dictionary or None if not found
    """
    try:
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
            return None

        # Format for API response
        repo = results[0]

        # Determine vulnerabilities count (to be implemented in the future)
        vulnerabilities = await get_repository_vulnerabilities_count(repo_id)

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
        return None


async def add_repository(url: str, options: Dict[str, Any] = None) -> Dict[str, Any]:
    """Add a new repository for analysis.

    Args:
        url: Repository URL
        options: Optional parameters for ingestion

    Returns:
        Repository information
    """
    if options is None:
        options = {}

    # Generate a unique ID for this repository
    ingestion_id = str(uuid.uuid4())

    # Extract repository name from URL
    name = url.split("/")[-1]
    if name.endswith(".git"):
        name = name[:-4]

    # Create repository representation
    repository = {
        "id": ingestion_id,
        "name": name,
        "description": f"Repository from {url}",
        "status": "Initializing",
        "progress": 0,
        "vulnerabilities": None,
        "lastAnalyzed": None,
        "url": url,
    }

    # Start ingestion in the background
    branch = options.get("branch")
    parse_only = not options.get("deepAnalysis", True)

    try:
        # Create ingestion instance with options
        ingestion = Ingestion(
            repo=url,
            branch=branch,
            parse_only=parse_only,
        )

        # Start ingestion asynchronously
        # Note: We'll return before this completes, updates will be tracked separately
        ingestion.ingest_async(ingestion_id)

        logger.info(f"Started ingestion with ID: {ingestion_id}")

        # Publish event for repository added
        from skwaq.api.services.event_service import publish_repository_event

        publish_repository_event("repository_added", repository)

        return repository
    except Exception as e:
        logger.error(f"Error starting repository ingestion: {e}")
        repository["status"] = "Failed"
        repository["error"] = str(e)
        return repository


async def delete_repository(repo_id: str) -> bool:
    """Delete a repository from the database.

    Args:
        repo_id: Repository ID

    Returns:
        True if successful, False otherwise
    """
    try:
        # Get database connector
        connector = get_connector()

        # Delete repository and all related nodes
        query = f"""
        MATCH (r:{NodeLabels.REPOSITORY} {{ingestion_id: $id}})
        OPTIONAL MATCH (r)-[rel]->(n)
        DELETE rel
        WITH r
        DETACH DELETE r
        """

        connector.run_query(query, {"id": repo_id})

        # Publish event for repository deleted
        from skwaq.api.services.event_service import publish_repository_event

        publish_repository_event("repository_deleted", {"repoId": repo_id})

        return True
    except Exception as e:
        logger.error(f"Error deleting repository {repo_id}: {e}")
        return False


async def get_repository_vulnerabilities(repo_id: str) -> List[Dict[str, Any]]:
    """Get vulnerabilities for a repository.

    Args:
        repo_id: Repository ID

    Returns:
        List of vulnerability dictionaries
    """
    try:
        # Get database connector
        connector = get_connector()

        # Query vulnerabilities related to this repository
        query = f"""
        MATCH (r:{NodeLabels.REPOSITORY} {{ingestion_id: $id}})-[*1..3]-(v:{NodeLabels.VULNERABILITY})
        RETURN v.id as id,
               v.name as name,
               v.type as type,
               v.severity as severity,
               v.file_path as file,
               v.line_number as line,
               v.description as description,
               v.cwe_id as cweId,
               v.remediation as remediation
        """

        results = connector.run_query(query, {"id": repo_id})

        if not results:
            # Return sample vulnerabilities for development/demo purposes
            # In production, this would be removed
            return [
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

        vulnerabilities = []
        for vuln in results:
            vulnerabilities.append(
                {
                    "id": vuln.get("id", str(uuid.uuid4())),
                    "name": vuln.get("name", "Unknown Vulnerability"),
                    "type": vuln.get("type", "Unknown"),
                    "severity": vuln.get("severity", "Medium"),
                    "file": vuln.get("file", "Unknown"),
                    "line": vuln.get("line", 0),
                    "description": vuln.get("description", "No description available"),
                    "cweId": vuln.get("cweId", "Unknown"),
                    "remediation": vuln.get(
                        "remediation", "No remediation advice available"
                    ),
                }
            )

        return vulnerabilities
    except Exception as e:
        logger.error(f"Error retrieving vulnerabilities for repository {repo_id}: {e}")
        return []


async def get_repository_vulnerabilities_count(repo_id: str) -> Optional[int]:
    """Get the count of vulnerabilities for a repository.

    Args:
        repo_id: Repository ID

    Returns:
        Count of vulnerabilities or None if not available
    """
    try:
        # Get database connector
        connector = get_connector()

        # Query vulnerabilities count
        query = f"""
        MATCH (r:{NodeLabels.REPOSITORY} {{ingestion_id: $id}})-[*1..3]-(v:{NodeLabels.VULNERABILITY})
        RETURN count(v) as count
        """

        results = connector.run_query(query, {"id": repo_id})

        if not results:
            return None

        return results[0].get("count", 0)
    except Exception as e:
        logger.error(
            f"Error retrieving vulnerability count for repository {repo_id}: {e}"
        )
        return None
