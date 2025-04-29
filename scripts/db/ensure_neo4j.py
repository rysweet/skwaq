#!/usr/bin/env python3
"""
Script to ensure Neo4j is running and initialized with the proper schema.
Optionally seeds the database with mock data for testing.
"""

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Add the project root to the Python path
script_dir = Path(__file__).resolve().parent
project_root = script_dir.parent.parent
sys.path.insert(0, str(project_root))

# Import after path modification
from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import initialize_schema
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


def check_docker_running():
    """Check if Docker is running on the system."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        return result.returncode == 0
    except FileNotFoundError:
        logger.error("Docker not found. Please install Docker to use Neo4j container.")
        return False


def check_neo4j_container_running():
    """Check if the Neo4j container is already running."""
    try:
        result = subprocess.run(
            ["docker", "ps", "--filter", "name=neo4j", "--format", "{{.Names}}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )
        return "neo4j" in result.stdout
    except subprocess.CalledProcessError:
        return False


def start_neo4j_container():
    """Start the Neo4j container using docker-compose."""
    logger.info("Starting Neo4j container...")
    try:
        # Go to project root directory
        os.chdir(project_root)

        # Check if there's a running container first and remove it if so
        subprocess.run(
            ["docker-compose", "rm", "-f", "-s", "neo4j"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )

        # Start the Neo4j container
        subprocess.run(
            ["docker-compose", "up", "-d", "neo4j"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True,
        )

        # Give Neo4j some time to start up
        logger.info("Waiting for Neo4j to start...")
        time.sleep(10)

        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to start Neo4j container: {e}")
        logger.error(f"Error output: {e.stderr}")
        return False


def check_neo4j_connection(max_retries=5, retry_delay=2.0):
    """Check if we can connect to Neo4j."""
    connector = get_connector()
    for attempt in range(1, max_retries + 1):
        logger.info(
            f"Attempting to connect to Neo4j (attempt {attempt}/{max_retries})..."
        )
        if connector.connect():
            logger.info("Successfully connected to Neo4j")
            return True

        if attempt < max_retries:
            logger.info(f"Retrying in {retry_delay} seconds...")
            time.sleep(retry_delay)

    logger.error(f"Failed to connect to Neo4j after {max_retries} attempts")
    return False


def init_neo4j_schema():
    """Initialize the Neo4j schema."""
    logger.info("Initializing Neo4j schema...")
    success = initialize_schema()
    if success:
        logger.info("Schema initialization successful")
    else:
        logger.error("Schema initialization failed")
    return success


def seed_mock_data():
    """Seed the database with mock data for testing."""
    logger.info("Seeding database with mock data...")
    connector = get_connector()

    try:
        # Create mock repositories
        repos = [
            {
                "id": "repo-001",
                "name": "example/repo",
                "url": "https://github.com/example/repo",
                "description": "Example repository for testing",
            },
            {
                "id": "repo-002",
                "name": "another/project",
                "url": "https://github.com/another/project",
                "description": "Another test project",
            },
            {
                "id": "repo-003",
                "name": "test/project",
                "url": "https://github.com/test/project",
                "description": "Test project for visualization",
            },
        ]

        for repo in repos:
            repo_id = connector.create_node("Repository", repo)
            if not repo_id:
                logger.error(f"Failed to create repository node for {repo['name']}")

        # Create mock investigations
        investigations = [
            {
                "id": "inv-46dac8c5",
                "workflow_id": "workflow-001",
                "repository_id": "repo-001",
                "created_at": "2023-01-01T12:00:00Z",
                "updated_at": "2023-01-02T15:30:00Z",
                "state": '{"current_phase": 3, "completed": true}',
                "findings_count": 12,
            },
            {
                "id": "inv-72fbe991",
                "workflow_id": "workflow-002",
                "repository_id": "repo-002",
                "created_at": "2023-01-03T09:45:00Z",
                "updated_at": "2023-01-03T16:20:00Z",
                "state": '{"current_phase": 1, "completed": false}',
                "findings_count": 7,
            },
            {
                "id": "inv-a3e45f12",
                "workflow_id": "workflow-003",
                "repository_id": "repo-003",
                "created_at": "2023-01-04T14:30:00Z",
                "updated_at": "2023-01-04T14:35:00Z",
                "state": '{"current_phase": 0, "completed": false}',
                "findings_count": 0,
            },
        ]

        for inv in investigations:
            inv_id = connector.create_node("Investigation", inv)
            if not inv_id:
                logger.error(f"Failed to create investigation node for {inv['id']}")

            # Connect investigation to repository
            repo_query = "MATCH (r:Repository {id: $repo_id}) RETURN id(r) as id"
            repo_result = connector.run_query(
                repo_query, {"repo_id": inv["repository_id"]}
            )

            if repo_result:
                repo_id = repo_result[0]["id"]
                connector.create_relationship(
                    inv_id, repo_id, "ANALYZES", {"created_at": inv["created_at"]}
                )

        # Create mock findings for the first investigation
        findings = [
            {
                "id": "find-001",
                "type": "pattern_match",
                "vulnerability_type": "SQL Injection",
                "description": "Potential SQL injection vulnerability in query construction",
                "file_path": "src/db/query.py",
                "line_number": 45,
                "severity": "High",
                "confidence": 0.85,
                "remediation": "Use parameterized queries instead of string concatenation",
            },
            {
                "id": "find-002",
                "type": "semantic_analysis",
                "vulnerability_type": "Cross-Site Scripting (XSS)",
                "description": "Unfiltered user input rendered in HTML template",
                "file_path": "src/templates/user.html",
                "line_number": 23,
                "severity": "Medium",
                "confidence": 0.75,
                "remediation": "Use template escaping mechanisms for user-supplied data",
            },
            {
                "id": "find-003",
                "type": "ast_analysis",
                "vulnerability_type": "Insecure Deserialization",
                "description": "Use of pickle.loads with untrusted data",
                "file_path": "src/util/serialization.py",
                "line_number": 67,
                "severity": "Critical",
                "confidence": 0.9,
                "remediation": "Use JSON or another secure serialization format for untrusted data",
            },
        ]

        # Get the first investigation ID
        inv_query = "MATCH (i:Investigation {id: 'inv-46dac8c5'}) RETURN id(i) as id"
        inv_result = connector.run_query(inv_query)

        if not inv_result:
            logger.error("Failed to find investigation for adding findings")
            return False

        inv_id = inv_result[0]["id"]

        for finding in findings:
            finding_id = connector.create_node(["Finding", "Vulnerability"], finding)

            if finding_id:
                # Connect finding to investigation
                connector.create_relationship(
                    finding_id,
                    inv_id,
                    "BELONGS_TO",
                    {"timestamp": "2023-01-02T12:00:00Z"},
                )

                # Create a vulnerability node and connect to the finding
                vuln_props = {
                    "id": f"vuln-{finding['id'].split('-')[1]}",
                    "type": finding["vulnerability_type"],
                    "severity": finding["severity"],
                    "cwe_id": f"CWE-{100 + int(finding['id'].split('-')[1])}",
                }

                vuln_id = connector.create_node("Vulnerability", vuln_props)
                if vuln_id:
                    connector.create_relationship(finding_id, vuln_id, "IDENTIFIES", {})

                # Create a file node and connect to the finding
                file_props = {
                    "path": finding["file_path"],
                    "name": finding["file_path"].split("/")[-1],
                    "language": (
                        "python" if finding["file_path"].endswith(".py") else "html"
                    ),
                }

                file_id = connector.create_node("File", file_props)
                if file_id:
                    connector.create_relationship(finding_id, file_id, "FOUND_IN", {})

        logger.info("Successfully seeded mock data")
        return True
    except Exception as e:
        logger.error(f"Error seeding mock data: {e}")
        return False


def clear_database():
    """Clear all data from the Neo4j database."""
    logger.info("Clearing all data from Neo4j database...")
    connector = get_connector()

    if not connector.connect():
        logger.error("Failed to connect to Neo4j database")
        return False

    try:
        # Delete all nodes and relationships
        clear_query = "MATCH (n) DETACH DELETE n"
        connector.run_query(clear_query)
        logger.info("Database cleared successfully")
        return True
    except Exception as e:
        logger.error(f"Failed to clear database: {e}")
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Ensure Neo4j is running and initialized"
    )
    parser.add_argument(
        "--seed", action="store_true", help="Seed the database with mock data"
    )
    parser.add_argument(
        "--clear",
        action="store_true",
        help="Clear all data from the database before initializing",
    )
    parser.add_argument(
        "--force-restart",
        action="store_true",
        help="Force restart Neo4j container even if it's running",
    )
    args = parser.parse_args()

    # Check if Docker is running
    if not check_docker_running():
        logger.error("Docker is not running. Please start Docker and try again.")
        return 1

    # Check if Neo4j container is running
    neo4j_running = check_neo4j_container_running()

    # Start Neo4j if not running or force restart requested
    if not neo4j_running or args.force_restart:
        if not start_neo4j_container():
            logger.error("Failed to start Neo4j container")
            return 1
    else:
        logger.info("Neo4j container is already running")

    # Check connection to Neo4j
    if not check_neo4j_connection():
        logger.error("Failed to connect to Neo4j")
        return 1

    # Clear database if requested
    if args.clear:
        if not clear_database():
            logger.error("Failed to clear database")
            return 1

    # Initialize schema
    if not init_neo4j_schema():
        logger.error("Failed to initialize Neo4j schema")
        return 1

    # Seed with mock data if requested
    if args.seed:
        if not seed_mock_data():
            logger.error("Failed to seed mock data")
            return 1

    logger.info("Neo4j setup completed successfully")
    return 0


if __name__ == "__main__":
    sys.exit(main())
