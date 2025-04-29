"""Integration test configuration.

This module provides fixtures for integration tests that need to connect
to external systems like Neo4j, OpenAI, and GitHub.
"""

import json
import os
import sys
import tempfile
import uuid
from typing import Any, Dict, Generator, Tuple
from unittest.mock import MagicMock

import neo4j
import pytest

try:
    from dotenv import find_dotenv, load_dotenv

    HAS_DOTENV = True
except ImportError:
    HAS_DOTENV = False

# Load environment variables from .env file
if HAS_DOTENV:
    dotenv_path = find_dotenv()
    if dotenv_path:
        print(f"Loading configuration from .env file: {dotenv_path}")
        load_dotenv(dotenv_path)


@pytest.fixture(scope="session")
def neo4j_connection() -> Tuple[neo4j.Driver, Dict[str, str]]:
    """Create a Neo4j connection for integration tests.

    Returns:
        Tuple containing the Neo4j driver and connection details
    """
    # Get connection settings from environment variables or use defaults
    uri = os.environ.get("NEO4J_URI", "bolt://localhost:7687")
    user = os.environ.get("NEO4J_USER", "neo4j")
    password = os.environ.get("NEO4J_PASSWORD", "password")
    database = os.environ.get("NEO4J_DATABASE", "neo4j")

    connection_details = {
        "uri": uri,
        "user": user,
        "password": password,
        "database": database,
    }

    # Try to connect to the database
    try:
        driver = neo4j.GraphDatabase.driver(uri, auth=(user, password))

        # Verify connectivity
        with driver.session(database=database) as session:
            result = session.run("RETURN 1 as test")
            record = result.single()

            if not record or record["test"] != 1:
                pytest.skip("Neo4j test query failed")
                return None, connection_details

        yield driver, connection_details

        # Close the driver
        driver.close()

    except Exception as e:
        pytest.skip(f"Neo4j connection failed: {str(e)}")
        yield None, connection_details


@pytest.fixture
def neo4j_test_nodes(
    neo4j_connection: Tuple[neo4j.Driver, Dict[str, str]],
) -> Generator[Dict[str, Any], None, None]:
    """Create test nodes in Neo4j and clean them up after the test.

    This fixture creates a set of test nodes with a unique identifier that can be
    used in tests, then ensures they are deleted when the test is complete.

    Returns:
        Dictionary with test node IDs and data
    """
    driver, connection_details = neo4j_connection
    if driver is None:
        pytest.skip("Neo4j connection not available")
        return

    # Generate a unique identifier for test nodes
    test_id = f"test-{uuid.uuid4()}"
    test_nodes = {"test_id": test_id, "node_ids": []}

    try:
        with driver.session(database=connection_details["database"]) as session:
            # Create a test repository node
            create_query = (
                "CREATE (r:Repository {name: 'Test Repository', test_id: $test_id}) "
                "RETURN id(r) as node_id"
            )
            result = session.run(create_query, {"test_id": test_id})
            record = result.single()
            if record:
                repo_id = record["node_id"]
                test_nodes["repo_id"] = repo_id
                test_nodes["node_ids"].append(repo_id)

            # Create some test file nodes
            for i in range(3):
                file_query = (
                    "MATCH (r:Repository {test_id: $test_id}) "
                    "CREATE (f:File {name: $name, path: $path, test_id: $test_id})-[:BELONGS_TO]->(r) "
                    "RETURN id(f) as node_id"
                )
                file_params = {
                    "test_id": test_id,
                    "name": f"test_file_{i}.py",
                    "path": f"/test/repo/test_file_{i}.py",
                }
                result = session.run(file_query, file_params)
                record = result.single()
                if record:
                    file_id = record["node_id"]
                    test_nodes["node_ids"].append(file_id)
                    test_nodes[f"file_id_{i}"] = file_id

        yield test_nodes

    finally:
        # Clean up test nodes
        try:
            with driver.session(database=connection_details["database"]) as session:
                cleanup_query = "MATCH (n {test_id: $test_id}) DETACH DELETE n"
                session.run(cleanup_query, {"test_id": test_id})
        except Exception as e:
            print(f"Error cleaning up test nodes: {str(e)}")


@pytest.fixture
def temp_repo_dir() -> Generator[str, None, None]:
    """Create a temporary directory for a mock repository.

    Returns:
        Path to the temporary directory
    """
    temp_dir = tempfile.mkdtemp()
    try:
        # Create a basic directory structure
        os.makedirs(os.path.join(temp_dir, "src"))
        os.makedirs(os.path.join(temp_dir, "src", "utils"))
        os.makedirs(os.path.join(temp_dir, "tests"))

        # Create some sample files
        with open(os.path.join(temp_dir, "src", "main.py"), "w") as f:
            f.write(
                "def main():\n    print('Hello, world!')\n\nif __name__ == '__main__':\n    main()"
            )

        with open(os.path.join(temp_dir, "src", "utils", "helpers.py"), "w") as f:
            f.write("def helper_function():\n    return 'Helper function called'")

        with open(os.path.join(temp_dir, "tests", "test_main.py"), "w") as f:
            f.write("def test_main():\n    assert True")

        with open(os.path.join(temp_dir, "README.md"), "w") as f:
            f.write("# Test Project\n\nThis is a test project for integration tests.")

        yield temp_dir

    finally:
        # Clean up the temp directory
        import shutil

        shutil.rmtree(temp_dir)


@pytest.fixture
def openai_api_credentials() -> Dict[str, str]:
    """Get OpenAI API credentials from environment variables.

    This fixture supports both standard OpenAI and Azure OpenAI configurations.
    For Azure OpenAI, it supports both API key and Entra ID (Azure AD) authentication.

    Returns:
        Dictionary with API credentials
    """
    # Check for standard OpenAI credentials
    api_key = os.environ.get("OPENAI_API_KEY", "")
    org_id = os.environ.get("OPENAI_ORG_ID", "")

    # Check for Azure OpenAI credentials
    azure_api_key = os.environ.get("AZURE_OPENAI_API_KEY", "")
    azure_endpoint = os.environ.get("AZURE_OPENAI_ENDPOINT", "")
    azure_api_version = os.environ.get("AZURE_OPENAI_API_VERSION", "2023-07-01-preview")
    use_entra_id = os.environ.get("AZURE_OPENAI_USE_ENTRA_ID", "").lower() in (
        "true",
        "yes",
        "1",
        "y",
    )
    auth_method = os.environ.get("AZURE_OPENAI_AUTH_METHOD", "")

    # Get model deployments if defined
    model_deployments_str = os.environ.get("AZURE_OPENAI_MODEL_DEPLOYMENTS", "{}")
    try:
        model_deployments = json.loads(model_deployments_str)
    except json.JSONDecodeError:
        model_deployments = {}

    # Determine which API type to use
    if azure_endpoint:
        api_type = "azure"
        api_base = azure_endpoint
        if azure_api_key:
            api_key = azure_api_key
    else:
        api_type = "openai"
        api_base = "https://api.openai.com/v1"

    credentials = {
        "api_key": api_key,
        "api_base": api_base,
        "api_type": api_type,
        "api_version": azure_api_version,
        "org_id": org_id,
        "use_entra_id": use_entra_id,
        "auth_method": auth_method,
        "model_deployments": model_deployments,
    }

    # For Azure OpenAI with Entra ID, we don't need an API key
    if api_type == "azure" and use_entra_id:
        if auth_method == "bearer_token":
            credentials["token_scope"] = os.environ.get("AZURE_OPENAI_TOKEN_SCOPE", "")
        else:
            credentials["tenant_id"] = os.environ.get("AZURE_TENANT_ID", "")
            credentials["client_id"] = os.environ.get("AZURE_CLIENT_ID", "")
            credentials["client_secret"] = os.environ.get("AZURE_CLIENT_SECRET", "")

    # Skip if we don't have either a standard OpenAI key or Azure endpoint
    if not api_key and not (api_type == "azure" and use_entra_id and azure_endpoint):
        pytest.skip("No valid OpenAI credentials available")

    # Print which configuration we're using (without sensitive values)
    safe_creds = {
        k: v for k, v in credentials.items() if k not in ["api_key", "client_secret"]
    }
    print(f"Using OpenAI configuration: {safe_creds}")

    return credentials


@pytest.fixture
def github_credentials() -> Dict[str, str]:
    """Get GitHub credentials from environment variables.

    Returns:
        Dictionary with GitHub credentials
    """
    token = os.environ.get("GITHUB_TOKEN")

    credentials = {"token": token}

    if not token:
        pytest.skip("GitHub token not available")

    return credentials


@pytest.fixture(scope="function", autouse=True)
def unmock_autogen_core():
    """Unmock autogen_core for integration tests to use the real package.

    This is critical for OpenAI integration tests where we need to connect
    to the real API.
    """
    # Store the mock if it exists
    original_mock = sys.modules.get("autogen_core")

    if original_mock and isinstance(original_mock, MagicMock):
        # Remove the mock
        del sys.modules["autogen_core"]

        try:
            # Import the real module

            print("Using real autogen_core for OpenAI integration tests")

            # Run the test with the real module
            yield

        finally:
            # Restore the mock after the test
            if "autogen_core" in sys.modules:
                del sys.modules["autogen_core"]
            sys.modules["autogen_core"] = original_mock
    else:
        # No mock exists, just run the test
        yield
