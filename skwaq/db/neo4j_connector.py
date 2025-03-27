"""Neo4j database connector for the Skwaq vulnerability assessment copilot.

This module provides a connection to the Neo4j graph database and
essential graph operations.
"""

import time
from typing import Any, Dict, List, Optional, Tuple, Union

from neo4j import GraphDatabase, Session
from neo4j.exceptions import ServiceUnavailable

from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

# Get logger for this module
logger = get_logger(__name__)


class Neo4jConnector:
    """Connector for Neo4j graph database operations.

    This class manages connections to the Neo4j database and provides methods
    for common graph operations used by the vulnerability assessment system.
    """

    def __init__(
        self,
        uri: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
    ):
        """Initialize the Neo4j connector.

        Args:
            uri: Neo4j connection URI (e.g., bolt://localhost:7687)
            user: Neo4j username
            password: Neo4j password

        If any of these parameters are not provided, they will be loaded from
        the configuration.
        """
        config = get_config()

        # Use provided values or fall back to configuration
        self._uri = uri or config.neo4j.get("uri")
        self._user = user or config.neo4j.get("user")
        self._password = password or config.neo4j.get("password")
        self._database = config.neo4j.get("database", "neo4j")

        if not all([self._uri, self._user, self._password]):
            error_msg = "Missing Neo4j connection parameters"
            logger.error(error_msg)
            raise ValueError(error_msg)

        # Create the driver but don't connect yet
        self._driver = GraphDatabase.driver(
            self._uri, auth=(self._user, self._password)
        )

        # Initialize connection status
        self._connected = False

    def connect(self, max_retries: int = 5, retry_delay: float = 2.0) -> bool:
        """Connect to the Neo4j database.

        Args:
            max_retries: Maximum number of connection attempts
            retry_delay: Delay between retry attempts in seconds

        Returns:
            True if connected successfully, False otherwise
        """
        if self._connected:
            logger.debug("Already connected to Neo4j database")
            return True

        # Try to connect with retries
        for attempt in range(1, max_retries + 1):
            try:
                # Verify connectivity
                with self._driver.session(database=self._database) as session:
                    result = session.run("RETURN 1 AS test")
                    if result.single()["test"] == 1:
                        self._connected = True
                        logger.info(f"Connected to Neo4j database at {self._uri}")

                        # Log server version
                        server_info = self.get_server_info()
                        if server_info:
                            logger.info(
                                f"Neo4j Server: {server_info.get('version', 'Unknown')}"
                            )

                        return True
            except ServiceUnavailable as e:
                logger.warning(
                    f"Connection attempt {attempt}/{max_retries} failed: {e}"
                )
                if attempt < max_retries:
                    logger.info(f"Retrying in {retry_delay} seconds...")
                    time.sleep(retry_delay)
                else:
                    logger.error(
                        f"Failed to connect to Neo4j database after {max_retries} attempts"
                    )
                    return False
            except Exception as e:
                logger.error(f"Unexpected error connecting to Neo4j: {e}")
                return False

        return False

    def close(self) -> None:
        """Close the database connection."""
        if hasattr(self, "_driver"):
            self._driver.close()
            self._connected = False
            logger.info("Neo4j database connection closed")

    def is_connected(self) -> bool:
        """Check if the connector is connected to the database.

        Returns:
            True if connected, False otherwise
        """
        if not self._connected:
            # Try connecting once if not already connected
            try:
                return self.connect(max_retries=1, retry_delay=0.5)
            except Exception:
                return False
                
        # Even if connected flag is True, verify with a quick test query
        try:
            with self._driver.session(database=self._database) as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception:
            self._connected = False
            return False
        
    def get_server_info(self) -> Optional[Dict[str, str]]:
        """Get information about the Neo4j server.

        Returns:
            Dictionary with server information or None if unable to get info
        """
        if not self._connected and not self.connect():
            return None

        try:
            with self._driver.session(database=self._database) as session:
                result = session.run(
                    "CALL dbms.components() YIELD name, versions, edition RETURN name, versions, edition"
                )
                record = result.single()
                if record:
                    return {
                        "name": record["name"],
                        "version": record["versions"][0],
                        "edition": record["edition"],
                    }
        except Exception as e:
            logger.error(f"Failed to get server info: {e}")

        return None

    def run_query(
        self, query: str, parameters: Optional[Dict[str, Any]] = None
    ) -> List[Dict[str, Any]]:
        """Run a Cypher query against the Neo4j database.

        Args:
            query: Cypher query to execute
            parameters: Query parameters

        Returns:
            List of records as dictionaries
        """
        if not self._connected and not self.connect():
            logger.error("Cannot run query - not connected to database")
            return []

        results = []
        with self._driver.session(database=self._database) as session:
            try:
                result = session.run(query, parameters or {})
                for record in result:
                    results.append(dict(record))
            except Exception as e:
                logger.error(f"Query failed: {e}")
                logger.debug(f"Failed query: {query}")
                logger.debug(f"Parameters: {parameters}")

        return results

    def create_node(
        self, labels: Union[str, List[str]], properties: Dict[str, Any]
    ) -> Optional[int]:
        """Create a node in the graph.

        Args:
            labels: Node label(s)
            properties: Node properties

        Returns:
            Node ID if created successfully, None otherwise
        """
        if isinstance(labels, str):
            labels = [labels]

        # Construct the Cypher query
        label_str = ":".join(labels)
        query = f"CREATE (n:{label_str} $properties) RETURN id(n) AS node_id"

        try:
            result = self.run_query(query, {"properties": properties})
            if result and "node_id" in result[0]:
                node_id = result[0]["node_id"]
                logger.debug(f"Created node with ID {node_id} and labels {labels}")
                return node_id
        except Exception as e:
            logger.error(f"Failed to create node: {e}")

        return None

    def merge_node(
        self,
        labels: Union[str, List[str]],
        match_properties: Dict[str, Any],
        set_properties: Optional[Dict[str, Any]] = None,
    ) -> Optional[int]:
        """Merge a node in the graph (create if not exists, update if exists).

        Args:
            labels: Node label(s)
            match_properties: Properties to match existing nodes
            set_properties: Additional properties to set on the node

        Returns:
            Node ID if merged successfully, None otherwise
        """
        if isinstance(labels, str):
            labels = [labels]

        # Construct the Cypher query
        label_str = ":".join(labels)
        query = f"MERGE (n:{label_str} {self._dict_to_props(match_properties)})"

        if set_properties:
            query += f" ON CREATE SET n += $set_props ON MATCH SET n += $set_props"
            params = {"set_props": set_properties}
        else:
            params = {}

        query += " RETURN id(n) AS node_id"

        try:
            result = self.run_query(query, params)
            if result and "node_id" in result[0]:
                node_id = result[0]["node_id"]
                logger.debug(f"Merged node with ID {node_id} and labels {labels}")
                return node_id
        except Exception as e:
            logger.error(f"Failed to merge node: {e}")

        return None

    def create_relationship(
        self,
        start_node_id: int,
        end_node_id: int,
        rel_type: str,
        properties: Optional[Dict[str, Any]] = None,
    ) -> bool:
        """Create a relationship between two nodes.

        Args:
            start_node_id: ID of the start node
            end_node_id: ID of the end node
            rel_type: Relationship type
            properties: Relationship properties

        Returns:
            True if relationship was created successfully, False otherwise
        """
        properties = properties or {}

        query = (
            "MATCH (a), (b) "
            "WHERE id(a) = $start_id AND id(b) = $end_id "
            f"CREATE (a)-[r:{rel_type} $properties]->(b) "
            "RETURN id(r) AS rel_id"
        )

        params = {
            "start_id": start_node_id,
            "end_id": end_node_id,
            "properties": properties,
        }

        try:
            result = self.run_query(query, params)
            success = bool(result and "rel_id" in result[0])
            if success:
                logger.debug(
                    f"Created relationship {rel_type} from node {start_node_id} to {end_node_id}"
                )
            return success
        except Exception as e:
            logger.error(f"Failed to create relationship: {e}")
            return False

    def get_node_by_id(self, node_id: int) -> Optional[Dict[str, Any]]:
        """Get a node by its ID.

        Args:
            node_id: The node ID

        Returns:
            Node data if found, None otherwise
        """
        query = "MATCH (n) WHERE id(n) = $node_id " "RETURN n, labels(n) AS labels"

        result = self.run_query(query, {"node_id": node_id})
        if result:
            # Process the result
            node_data = dict(result[0]["n"])
            node_data["labels"] = result[0]["labels"]
            return node_data

        return None

    def find_nodes(
        self,
        labels: Optional[Union[str, List[str]]] = None,
        properties: Optional[Dict[str, Any]] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """Find nodes matching the given criteria.

        Args:
            labels: Node label(s) to match
            properties: Property conditions to match
            limit: Maximum number of results to return

        Returns:
            List of matching nodes
        """
        # Build the query
        query_parts = ["MATCH (n)"]
        params = {}

        # Add label filter if provided
        if labels:
            if isinstance(labels, str):
                labels = [labels]
            query_parts[0] = f"MATCH (n:{':'.join(labels)})"

        # Add property filters if provided
        if properties:
            conditions = []
            for key, value in properties.items():
                param_name = f"prop_{key}"
                conditions.append(f"n.{key} = ${param_name}")
                params[param_name] = value

            if conditions:
                query_parts.append("WHERE " + " AND ".join(conditions))

        # Add return and limit
        query_parts.append("RETURN n, labels(n) AS labels")
        query_parts.append(f"LIMIT {limit}")

        # Execute the query
        query = " ".join(query_parts)
        results = self.run_query(query, params)

        # Process the results
        nodes = []
        for record in results:
            node_data = dict(record["n"])
            node_data["labels"] = record["labels"]
            nodes.append(node_data)

        return nodes

    def create_vector_index(
        self,
        index_name: str,
        node_label: str,
        vector_property: str,
        embedding_dimension: int = 768,
    ) -> bool:
        """Create a vector index for semantic search.

        Args:
            index_name: Name of the index
            node_label: Label of nodes to index
            vector_property: Property containing the vector embeddings
            embedding_dimension: Dimension of the embedding vectors

        Returns:
            True if index was created successfully, False otherwise
        """
        # Check if index already exists
        index_query = "SHOW INDEXES WHERE name = $index_name"
        result = self.run_query(index_query, {"index_name": index_name})

        if result:
            logger.info(f"Vector index {index_name} already exists")
            return True

        # Create the vector index
        create_query = (
            f"CREATE VECTOR INDEX {index_name} FOR (n:{node_label}) "
            f"ON (n.{vector_property}) "
            f"OPTIONS {{ indexConfig: {{ `vector.dimensions`: {embedding_dimension}, "
            f"`vector.similarity_function`: 'cosine' }} }}"
        )

        try:
            self.run_query(create_query)
            logger.info(f"Created vector index {index_name} for {node_label} nodes")
            return True
        except Exception as e:
            logger.error(f"Failed to create vector index: {e}")
            return False

    def vector_search(
        self,
        node_label: str,
        vector_property: str,
        query_vector: List[float],
        similarity_cutoff: float = 0.7,
        limit: int = 5,
    ) -> List[Dict[str, Any]]:
        """Perform a vector similarity search.

        Args:
            node_label: Label of nodes to search
            vector_property: Property containing the vector embeddings
            query_vector: The query vector to search for
            similarity_cutoff: Minimum similarity score (0-1)
            limit: Maximum number of results

        Returns:
            List of matching nodes with similarity scores
        """
        query = (
            f"MATCH (n:{node_label}) "
            f"WHERE n.{vector_property} IS NOT NULL "
            f"WITH n, vector.similarity(n.{vector_property}, $query_vector) AS score "
            f"WHERE score >= $cutoff "
            "RETURN n, score, labels(n) AS labels "
            "ORDER BY score DESC "
            f"LIMIT {limit}"
        )

        params = {"query_vector": query_vector, "cutoff": similarity_cutoff}

        try:
            results = self.run_query(query, params)

            # Process the results
            nodes = []
            for record in results:
                node_data = dict(record["n"])
                node_data["similarity_score"] = record["score"]
                node_data["labels"] = record["labels"]
                nodes.append(node_data)

            return nodes
        except Exception as e:
            logger.error(f"Vector search failed: {e}")
            return []

    def _dict_to_props(self, props: Dict[str, Any]) -> str:
        """Convert a dictionary of properties to a Cypher property string.

        Args:
            props: Dictionary of properties

        Returns:
            Cypher property string in the format {key1: "value1", key2: value2}
        """
        if not props:
            return ""

        parts = []
        for key, value in props.items():
            if isinstance(value, str):
                parts.append(f'{key}: "{value}"')
            else:
                parts.append(f"{key}: {value}")

        return "{" + ", ".join(parts) + "}"

    def __enter__(self) -> "Neo4jConnector":
        """Context manager enter method."""
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        """Context manager exit method."""
        self.close()


# Use a connector registry instead of global instance
_connector_registry: Dict[str, Neo4jConnector] = {}


def get_connector(
    uri: Optional[str] = None,
    user: Optional[str] = None,
    password: Optional[str] = None,
    registry_key: str = "default",
) -> Neo4jConnector:
    """Get a Neo4j connector instance from the registry or create a new one.

    This function provides backward compatibility with the previous singleton pattern
    while allowing for proper dependency injection and testing.

    Args:
        uri: Neo4j connection URI (e.g., bolt://localhost:7687)
        user: Neo4j username
        password: Neo4j password
        registry_key: Key to use for storing the connector in the registry

    Returns:
        A Neo4jConnector instance
    """
    global _connector_registry

    if registry_key in _connector_registry:
        return _connector_registry[registry_key]

    connector = Neo4jConnector(uri, user, password)
    _connector_registry[registry_key] = connector
    return connector


def reset_connector_registry() -> None:
    """Reset the connector registry - primarily for testing.

    This function clears all stored connector instances from the registry.
    """
    global _connector_registry
    _connector_registry.clear()
