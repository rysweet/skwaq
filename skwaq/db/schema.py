"""Database schema definitions for Skwaq.

This module defines the schema initialization for the Neo4j graph database,
including constraints, indexes, and other structural elements to support
vulnerability assessment workflows.
"""

from enum import Enum
from typing import List, Dict, Any, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class NodeLabels(str, Enum):
    """Node labels used in the graph database schema."""

    # Knowledge nodes
    KNOWLEDGE = "Knowledge"
    CWE = "CWE"
    VULNERABILITY_PATTERN = "VulnerabilityPattern"
    DOCUMENT = "Document"
    DOCUMENT_SECTION = "DocumentSection"

    # Code nodes
    REPOSITORY = "Repository"
    FILE = "File"
    FUNCTION = "Function"
    CLASS = "Class"
    METHOD = "Method"
    PARAMETER = "Parameter"
    VARIABLE = "Variable"

    # Analysis nodes
    VULNERABILITY = "Vulnerability"
    FINDING = "Finding"
    ANALYSIS_RESULT = "AnalysisResult"
    INVESTIGATION = "Investigation"

    # Agent nodes
    AGENT = "Agent"
    WORKFLOW = "Workflow"
    TASK = "Task"


class RelationshipTypes(str, Enum):
    """Relationship types used in the graph database schema."""

    # Code structure relationships
    CONTAINS = "CONTAINS"
    IMPORTS = "IMPORTS"
    CALLS = "CALLS"
    DEFINES = "DEFINES"
    REFERENCES = "REFERENCES"
    INHERITS_FROM = "INHERITS_FROM"

    # Knowledge relationships
    RELATES_TO = "RELATES_TO"
    PART_OF = "PART_OF"
    DESCRIBES = "DESCRIBES"
    EXAMPLE_OF = "EXAMPLE_OF"

    # Analysis relationships
    DETECTED_IN = "DETECTED_IN"
    ANALYZED_BY = "ANALYZED_BY"
    EVIDENCE_FOR = "EVIDENCE_FOR"
    SIMILAR_TO = "SIMILAR_TO"

    # Workflow relationships
    CREATED_BY = "CREATED_BY"
    ASSIGNED_TO = "ASSIGNED_TO"
    DEPENDS_ON = "DEPENDS_ON"
    RESULTED_IN = "RESULTED_IN"


class SchemaManager:
    """Manages the Neo4j database schema for Skwaq."""

    def __init__(self, connector=None):
        """Initialize the schema manager with a database connector.

        Args:
            connector: Optional Neo4j connector instance. If not provided,
                       the global connector will be used.
        """
        self._connector = connector or get_connector()

    def create_constraints(self) -> bool:
        """Create the constraints needed for the graph database.

        Returns:
            True if all constraints were created successfully, False otherwise.
        """
        if not self._connector.connect():
            logger.error("Could not connect to Neo4j to create constraints")
            return False

        # Map of node label to property for unique constraints
        unique_constraints = {
            NodeLabels.CWE: "id",
            NodeLabels.REPOSITORY: "url",
            NodeLabels.FILE: "path",
            NodeLabels.INVESTIGATION: "id",
            NodeLabels.AGENT: "id",
        }

        success = True
        for label, property_name in unique_constraints.items():
            # Check if constraint already exists
            constraint_name = f"{label.lower()}__{property_name}__unique"
            check_query = "SHOW CONSTRAINTS WHERE name = $constraint_name"
            result = self._connector.run_query(
                check_query, {"constraint_name": constraint_name}
            )

            if not result:
                # Create the constraint
                create_query = (
                    f"CREATE CONSTRAINT {constraint_name} IF NOT EXISTS "
                    f"FOR (n:{label}) REQUIRE n.{property_name} IS UNIQUE"
                )
                try:
                    self._connector.run_query(create_query)
                    logger.info(
                        f"Created unique constraint on :{label}({property_name})"
                    )
                except Exception as e:
                    logger.error(
                        f"Failed to create constraint on :{label}({property_name}): {e}"
                    )
                    success = False
            else:
                logger.debug(f"Constraint on :{label}({property_name}) already exists")

        return success

    def create_indexes(self) -> bool:
        """Create the indexes needed for the graph database.

        Returns:
            True if all indexes were created successfully, False otherwise.
        """
        if not self._connector.connect():
            logger.error("Could not connect to Neo4j to create indexes")
            return False

        # Map of node label to list of properties for standard indexes
        standard_indexes = {
            NodeLabels.KNOWLEDGE: ["title", "type"],
            NodeLabels.DOCUMENT: ["name", "source"],
            NodeLabels.FILE: ["name", "language"],
            NodeLabels.FUNCTION: ["name", "signature"],
            NodeLabels.CLASS: ["name"],
            NodeLabels.VULNERABILITY: ["severity", "type"],
            NodeLabels.FINDING: ["confidence", "type"],
        }

        success = True
        for label, properties in standard_indexes.items():
            for property_name in properties:
                # Check if index already exists
                index_name = f"{label.lower()}__{property_name}__index"
                check_query = "SHOW INDEXES WHERE name = $index_name"
                result = self._connector.run_query(
                    check_query, {"index_name": index_name}
                )

                if not result:
                    # Create the index
                    create_query = (
                        f"CREATE INDEX {index_name} IF NOT EXISTS "
                        f"FOR (n:{label}) ON (n.{property_name})"
                    )
                    try:
                        self._connector.run_query(create_query)
                        logger.info(f"Created index on :{label}({property_name})")
                    except Exception as e:
                        logger.error(
                            f"Failed to create index on :{label}({property_name}): {e}"
                        )
                        success = False
                else:
                    logger.debug(f"Index on :{label}({property_name}) already exists")

        return success

    def create_vector_indexes(self) -> bool:
        """Create vector indexes for similarity search.

        Returns:
            True if all vector indexes were created successfully, False otherwise.
        """
        if not self._connector.connect():
            logger.error("Could not connect to Neo4j to create vector indexes")
            return False

        # Map of node label to vector property and dimensions
        vector_indexes = {
            NodeLabels.DOCUMENT: ("embedding", 1536),
            NodeLabels.DOCUMENT_SECTION: ("embedding", 1536),
            NodeLabels.FUNCTION: ("embedding", 1536),
            NodeLabels.VULNERABILITY_PATTERN: ("embedding", 1536),
        }

        success = True
        for label, (property_name, dimension) in vector_indexes.items():
            index_name = f"{label.lower()}__{property_name}__vector"

            try:
                result = self._connector.create_vector_index(
                    index_name=index_name,
                    node_label=label,
                    vector_property=property_name,
                    embedding_dimension=dimension,
                )

                if result:
                    logger.info(
                        f"Created or verified vector index on :{label}({property_name})"
                    )
                else:
                    logger.warning(
                        f"Failed to create vector index on :{label}({property_name})"
                    )
                    success = False
            except Exception as e:
                logger.error(
                    f"Error creating vector index on :{label}({property_name}): {e}"
                )
                success = False

        return success

    def initialize_schema_components(self) -> Dict[str, bool]:
        """Initialize all schema components and return status.

        Returns:
            Dictionary mapping component name to initialization status
        """
        results = {}

        # Create constraints
        results["constraints"] = self.create_constraints()

        # Create indexes
        results["indexes"] = self.create_indexes()

        # Create vector indexes
        results["vector_indexes"] = self.create_vector_indexes()

        # Log overall status
        if all(results.values()):
            logger.info("Schema initialization completed successfully")
        else:
            failed = [k for k, v in results.items() if not v]
            logger.warning(
                f"Schema initialization completed with issues in: {', '.join(failed)}"
            )

        return results


def initialize_schema() -> bool:
    """Initialize the Neo4j database schema.

    Creates necessary constraints and indexes for the graph database.

    Returns:
        True if initialization was successful, False otherwise.
    """
    try:
        schema_manager = SchemaManager()
        results = schema_manager.initialize_schema_components()
        return all(results.values())
    except Exception as e:
        logger.error(f"Schema initialization failed: {e}")
        return False


def get_schema_info() -> Dict[str, Any]:
    """Get information about the current database schema.

    Returns:
        Dictionary containing schema information
    """
    connector = get_connector()
    if not connector.connect():
        logger.error("Could not connect to Neo4j to get schema information")
        return {"error": "Connection failed"}

    schema_info = {"constraints": [], "indexes": [], "statistics": {}}

    # Get constraints
    constraint_query = "SHOW CONSTRAINTS"
    constraints = connector.run_query(constraint_query)
    schema_info["constraints"] = constraints

    # Get indexes
    index_query = "SHOW INDEXES"
    indexes = connector.run_query(index_query)
    schema_info["indexes"] = indexes

    # Get basic database statistics
    stats_query = """
    MATCH (n)
    RETURN
      count(n) AS nodeCount,
      apoc.meta.stats() AS stats
    """
    try:
        stats = connector.run_query(stats_query)
        if stats:
            schema_info["statistics"] = stats[0]
    except Exception as e:
        logger.error(f"Failed to get database statistics: {e}")
        schema_info["statistics"] = {"error": str(e)}

    return schema_info


def clear_database(confirm_code: str) -> bool:
    """Clear all data from the database.

    Args:
        confirm_code: Must be "CONFIRM_CLEAR_DATABASE" to proceed

    Returns:
        True if database was cleared successfully, False otherwise
    """
    if confirm_code != "CONFIRM_CLEAR_DATABASE":
        logger.error("Invalid confirmation code for database clear operation")
        return False

    connector = get_connector()
    if not connector.connect():
        logger.error("Could not connect to Neo4j to clear database")
        return False

    try:
        # Delete all nodes and relationships
        clear_query = "MATCH (n) DETACH DELETE n"
        connector.run_query(clear_query)
        logger.warning("Database cleared - all nodes and relationships deleted")
        return True
    except Exception as e:
        logger.error(f"Failed to clear database: {e}")
        return False
