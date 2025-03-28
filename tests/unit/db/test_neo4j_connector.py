"""Test the Neo4j connector module."""

import pytest
from unittest import mock

from neo4j.exceptions import ServiceUnavailable

from skwaq.db.neo4j_connector import Neo4jConnector, get_connector


@pytest.fixture
def mock_neo4j_driver():
    """Mock the Neo4j driver and session."""
    with mock.patch("skwaq.db.neo4j_connector.GraphDatabase") as mock_graph_db:
        # Create mock driver and session
        mock_driver = mock.MagicMock()
        mock_session = mock.MagicMock()
        mock_result = mock.MagicMock()
        mock_record = mock.MagicMock()

        # Configure mocks
        mock_graph_db.driver.return_value = mock_driver
        mock_driver.session.return_value.__enter__.return_value = mock_session
        mock_session.run.return_value = mock_result
        mock_result.single.return_value = mock_record
        mock_record.__getitem__.return_value = 1

        yield {
            "driver": mock_driver,
            "session": mock_session,
            "result": mock_result,
            "record": mock_record,
            "graph_db": mock_graph_db,
        }


@pytest.fixture
def mock_config():
    """Mock the configuration for Neo4j."""
    with mock.patch("skwaq.db.neo4j_connector.get_config") as mock_get_config:
        mock_config = mock.MagicMock()
        mock_config.neo4j = {
            "uri": "bolt://localhost:7687",
            "user": "neo4j",
            "password": "password",
            "database": "neo4j",
        }
        mock_get_config.return_value = mock_config
        yield mock_config


def test_init_with_config(mock_config, mock_neo4j_driver):
    """Test initializing the connector with config."""
    connector = Neo4jConnector()

    # Verify config was used
    assert connector._uri == "bolt://localhost:7687"
    assert connector._user == "neo4j"
    assert connector._password == "password"
    assert connector._database == "neo4j"

    # Verify driver was created
    mock_neo4j_driver["graph_db"].driver.assert_called_once_with(
        "bolt://localhost:7687", auth=("neo4j", "password")
    )


def test_init_with_params(mock_config, mock_neo4j_driver):
    """Test initializing the connector with parameters."""
    connector = Neo4jConnector(
        uri="bolt://custom:7687", user="custom_user", password="custom_password"
    )

    # Verify params were used instead of config
    assert connector._uri == "bolt://custom:7687"
    assert connector._user == "custom_user"
    assert connector._password == "custom_password"

    # Verify driver was created with custom params
    mock_neo4j_driver["graph_db"].driver.assert_called_once_with(
        "bolt://custom:7687", auth=("custom_user", "custom_password")
    )


def test_connect_success(mock_neo4j_driver):
    """Test successful connection to Neo4j."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )

    # Mock execute_read to return a valid result
    mock_session = mock_neo4j_driver["session"]
    mock_session.execute_read.return_value = [{"test": 1}]

    # Set up mock for server info
    with mock.patch.object(connector, "get_server_info") as mock_server_info:
        mock_server_info.return_value = {"version": "5.0.0"}

        # Connect
        result = connector.connect()

        # Verify connection was successful
        assert result is True
        assert connector._connected is True

        # Verify driver's session was used
        mock_neo4j_driver["driver"].session.assert_called_once()
        mock_session.execute_read.assert_called_once()


def test_connect_failure(mock_neo4j_driver):
    """Test failed connection to Neo4j."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )

    # Configure session to raise an exception
    mock_neo4j_driver["driver"].session.side_effect = ServiceUnavailable(
        "Connection refused"
    )

    # Connect with fewer retries
    result = connector.connect(max_retries=2, retry_delay=0.1)

    # Verify connection failed
    assert result is False
    assert connector._connected is False

    # Verify retry was attempted
    assert mock_neo4j_driver["driver"].session.call_count == 2


def test_is_connected(mock_neo4j_driver):
    """Test the is_connected method."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )

    # Test 1: Already connected
    connector._connected = True
    # Reset the session side effect to not raise exceptions
    mock_neo4j_driver["driver"].session.side_effect = None

    # Mock execute_read to return a valid result
    mock_session = mock_neo4j_driver["session"]
    mock_session.execute_read.return_value = [{"test": 1}]

    result = connector.is_connected()
    assert result is True

    # Test 2: Not connected but can connect
    connector._connected = False
    with mock.patch.object(connector, "connect") as mock_connect:
        mock_connect.return_value = True
        result = connector.is_connected()
        assert result is True
        mock_connect.assert_called_once_with(max_retries=1, retry_delay=0.5)

    # Test 3: Not connected and cannot connect
    connector._connected = False
    with mock.patch.object(connector, "connect") as mock_connect:
        mock_connect.return_value = False
        result = connector.is_connected()
        assert result is False
        mock_connect.assert_called_once_with(max_retries=1, retry_delay=0.5)

    # Test 4: Connected but session fails
    connector._connected = True
    mock_neo4j_driver["driver"].session.side_effect = Exception("Test error")
    result = connector.is_connected()
    assert result is False
    assert connector._connected is False  # It should update the flag


def test_run_query(mock_neo4j_driver):
    """Test running a Cypher query."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )

    # Set up connection status
    connector._connected = True

    # Create test records
    test_records = [{"name": "node1", "value": 42}, {"name": "node2", "value": 43}]

    # Mock session's execute_read/execute_write methods
    mock_session = mock_neo4j_driver["session"]
    mock_session.execute_read.return_value = test_records
    mock_session.execute_write.return_value = test_records

    # Run a read query
    result = connector.run_query(
        "MATCH (n) WHERE n.name = $name RETURN n.name, n.value", {"name": "test"}
    )

    # Verify query was run with execute_read for a SELECT query
    mock_neo4j_driver["driver"].session.assert_called_once()
    mock_session.execute_read.assert_called_once()

    # Verify results
    assert len(result) == 2
    assert result[0]["name"] == "node1"
    assert result[0]["value"] == 42
    assert result[1]["name"] == "node2"
    assert result[1]["value"] == 43

    # Reset mocks for testing a write query
    mock_neo4j_driver["driver"].session.reset_mock()
    mock_session.execute_read.reset_mock()

    # Run a write query
    result = connector.run_query(
        "CREATE (n:Node {name: $name}) RETURN n", {"name": "test"}
    )

    # Verify execute_write was used for CREATE query
    mock_neo4j_driver["driver"].session.assert_called_once()
    mock_session.execute_write.assert_called_once()


def test_create_node(mock_neo4j_driver):
    """Test creating a node in the graph."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )
    connector._connected = True

    # Mock the run_query method
    with mock.patch.object(connector, "run_query") as mock_run_query:
        mock_run_query.return_value = [{"node_id": 123}]

        # Create a node
        node_id = connector.create_node(
            labels=["Person", "Employee"], properties={"name": "John", "age": 30}
        )

        # Verify query was constructed correctly
        mock_run_query.assert_called_once_with(
            "CREATE (n:Person:Employee $properties) RETURN elementId(n) AS node_id",
            {"properties": {"name": "John", "age": 30}},
        )

        # Verify node ID was returned
        assert node_id == 123


def test_vector_search(mock_neo4j_driver):
    """Test vector similarity search."""
    connector = Neo4jConnector(
        uri="bolt://localhost:7687", user="neo4j", password="password"
    )
    connector._connected = True

    # Mock the run_query method
    with mock.patch.object(connector, "run_query") as mock_run_query:
        # The data structure returned by run_query - match implementation
        mock_run_query.return_value = [
            {
                "n": {"name": "doc1", "content": "test content"},
                "score": 0.95,
                "labels": ["Document"],
            },
            {
                "n": {"name": "doc2", "content": "more content"},
                "score": 0.85,
                "labels": ["Document"],
            },
        ]

        # Perform vector search
        results = connector.vector_search(
            node_label="Document",
            vector_property="embedding",
            query_vector=[0.1, 0.2, 0.3],
            similarity_cutoff=0.8,
            limit=2,
        )

        # Verify query was constructed correctly
        mock_run_query.assert_called_once()
        args, kwargs = mock_run_query.call_args
        assert "MATCH (n:Document)" in args[0]
        assert "vector.similarity" in args[0]
        assert "ORDER BY score DESC" in args[0]
        assert "LIMIT 2" in args[0]

        # Check parameters - they're passed as a single unnamed dict
        params = args[1] if len(args) > 1 else {}
        assert "query_vector" in params
        assert "cutoff" in params
        assert params["query_vector"] == [0.1, 0.2, 0.3]
        assert params["cutoff"] == 0.8

        # Verify results format matches implementation
        assert len(results) == 2

        # First result checking
        assert "name" in results[0]
        assert "content" in results[0]
        assert "similarity_score" in results[0]
        assert "labels" in results[0]
        assert results[0]["name"] == "doc1"
        assert results[0]["similarity_score"] == 0.95

        # Second result checking
        assert "name" in results[1]
        assert "content" in results[1]
        assert "similarity_score" in results[1]
        assert "labels" in results[1]
        assert results[1]["name"] == "doc2"
        assert results[1]["similarity_score"] == 0.85


def test_get_connector(mock_config, mock_neo4j_driver):
    """Test the global connector getter."""
    # Reset the global connector
    import skwaq.db.neo4j_connector

    skwaq.db.neo4j_connector._connector = None

    # Mock the Neo4jConnector class
    with mock.patch("skwaq.db.neo4j_connector.Neo4jConnector") as mock_connector_class:
        mock_connector_instance = mock.MagicMock()
        mock_connector_class.return_value = mock_connector_instance

        # First call should create a new instance
        connector1 = get_connector()
        mock_connector_class.assert_called_once()

        # Second call should return the same instance
        connector2 = get_connector()
        assert connector1 is connector2
        assert mock_connector_class.call_count == 1
