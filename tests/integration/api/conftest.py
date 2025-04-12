"""Pytest fixtures for API integration tests."""


# Add custom path for imports
import os
import sys
import uuid
from typing import Any, Dict

import pytest
from neo4j import GraphDatabase

sys.path.append(
    os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    )
)

from skwaq.api import create_app


@pytest.fixture(scope="session")
def app():
    """Create a Flask app for testing."""
    # Create a test configuration
    test_config = {"TESTING": True, "SECRET_KEY": "test", "JWT_EXPIRATION": 3600}

    # Create the app with test config
    app = create_app(test_config)

    # Disable authentication for testing
    @app.before_request
    def disable_auth():
        """Set fake authentication data for testing."""
        from flask import g

        g.user_id = "test-user"
        g.username = "testuser"
        g.roles = ["admin"]

    # Return the app
    return app


@pytest.fixture
def client(app):
    """Create a test client for the app."""
    return app.test_client()


@pytest.fixture
def neo4j_test_connection():
    """Connect to Neo4j database for testing."""
    # Get connection settings from environment or use defaults
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "password")
    database = os.environ.get("NEO4J_DATABASE", "neo4j")

    # Try to connect to the database
    try:
        driver = GraphDatabase.driver(uri, auth=(user, password))

        # Verify connectivity
        with driver.session(database=database) as session:
            result = session.run("RETURN 1 as test")
            record = result.single()

            if not record or record["test"] != 1:
                pytest.skip("Neo4j test query failed")
                return None, {}

        connection_details = {
            "uri": uri,
            "user": user,
            "password": password,
            "database": database,
        }

        yield driver, connection_details

        # Close the driver
        driver.close()

    except Exception as e:
        pytest.skip(f"Neo4j connection failed: {str(e)}")
        yield None, {}


@pytest.fixture
def test_investigation(client, neo4j_test_connection) -> Dict[str, Any]:
    """Create a test investigation in the database."""
    driver, connection_details = neo4j_test_connection
    if driver is None:
        pytest.skip("Neo4j connection not available")

    # Generate a unique ID for the test investigation
    test_id = f"test-{uuid.uuid4()}"  # Use a unique test ID to tag all created nodes
    investigation_id = f"inv-{test_id}"
    repository_id = f"repo-{test_id}"
    repository_name = "Test Repository"

    # First clean up any existing test data with the same test_id (shouldn't happen, but just in case)
    try:
        with driver.session(database=connection_details["database"]) as session:
            cleanup_query = """
            MATCH (n {test_id: $test_id})
            DETACH DELETE n
            """
            session.run(cleanup_query, {"test_id": test_id})
    except Exception as e:
        print(f"Warning during initial cleanup: {e}")

    try:
        with driver.session(database=connection_details["database"]) as session:
            # Create repository node
            repo_query = """
            CREATE (r:Repository {
                id: $repository_id,
                name: $repository_name,
                url: 'https://github.com/test/test-repo',
                cloned: false,
                test_id: $test_id
            })
            RETURN r.id as repository_id
            """
            repo_result = session.run(
                repo_query,
                {
                    "repository_id": repository_id,
                    "repository_name": repository_name,
                    "test_id": test_id,
                },
            )
            repo_record = repo_result.single()

            # Create investigation node
            investigation_query = """
            CREATE (i:Investigation {
                id: $investigation_id,
                title: $title,
                description: $description,
                created_at: datetime(),
                status: 'new',
                test_id: $test_id
            })
            WITH i
            MATCH (r:Repository {id: $repository_id})
            CREATE (i)-[:ANALYZES]->(r)
            RETURN i.id as investigation_id
            """

            investigation_result = session.run(
                investigation_query,
                {
                    "investigation_id": investigation_id,
                    "title": "Test Investigation",
                    "description": "This is a test investigation created for API integration tests",
                    "repository_id": repository_id,
                    "test_id": test_id,
                },
            )
            investigation_record = investigation_result.single()

            # Add a test finding
            finding_id = f"finding-{test_id}"
            finding_query = """
            MATCH (i:Investigation {id: $investigation_id})
            CREATE (f:Finding {
                id: $finding_id,
                title: $title,
                vulnerability_type: $type,
                severity: $severity,
                confidence: $confidence,
                file_path: $file_path,
                line: 42,
                description: $description,
                remediation: $remediation,
                test_id: $test_id
            })
            CREATE (i)-[:HAS_FINDING]->(f)
            RETURN f.id as finding_id
            """

            finding_result = session.run(
                finding_query,
                {
                    "investigation_id": investigation_id,
                    "finding_id": finding_id,
                    "title": "Test SQL Injection",
                    "type": "SQL Injection",
                    "severity": "High",
                    "confidence": "High",
                    "file_path": "/app/routes.py",
                    "description": "Potential SQL injection vulnerability in user input",
                    "remediation": "Use parameterized queries",
                    "test_id": test_id,
                },
            )
            finding_record = finding_result.single()

            # Add a vulnerability node
            vulnerability_id = f"vuln-{test_id}"
            vuln_query = """
            MATCH (f:Finding {id: $finding_id})
            CREATE (v:Vulnerability {
                id: $vulnerability_id,
                cwe_id: 'CWE-89',
                name: 'SQL Injection',
                description: 'SQL injection vulnerability',
                test_id: $test_id
            })
            CREATE (f)-[:IDENTIFIES]->(v)
            RETURN v.id as vulnerability_id
            """

            vuln_result = session.run(
                vuln_query,
                {
                    "finding_id": finding_id,
                    "vulnerability_id": vulnerability_id,
                    "test_id": test_id,
                },
            )
            vuln_record = vuln_result.single()

    except Exception as e:
        pytest.fail(f"Failed to create test investigation: {str(e)}")

    # Return details about the created investigation
    investigation_details = {
        "investigation_id": investigation_id,
        "repository_id": repository_id,
        "finding_id": finding_id,
        "vulnerability_id": vulnerability_id,
        "test_id": test_id,
    }

    yield investigation_details

    # Clean up test data
    try:
        with driver.session(database=connection_details["database"]) as session:
            # Delete all test nodes created for this test
            cleanup_query = """
            MATCH (n {test_id: $test_id})
            DETACH DELETE n
            """
            session.run(cleanup_query, {"test_id": test_id})
            print(f"Test data cleaned up for test_id: {test_id}")
    except Exception as e:
        print(f"Warning: Failed to clean up test investigation: {str(e)}")
