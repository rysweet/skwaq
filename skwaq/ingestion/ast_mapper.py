"""AST to filesystem mapping for code ingestion.

This module provides functionality to map between AST nodes and filesystem nodes
in the graph database.
"""

from typing import Dict, List, Any, Optional, Set

from skwaq.db.neo4j_connector import Neo4jConnector
from skwaq.db.schema import RelationshipTypes
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)


class ASTFileMapper:
    """Maps AST nodes to filesystem file nodes.

    This class provides methods to establish relationships between syntax tree nodes
    and the corresponding filesystem file nodes.
    """

    def __init__(self, connector: Neo4jConnector):
        """Initialize the AST-to-file mapper.

        Args:
            connector: Neo4j connector instance
        """
        self.connector = connector

    async def map_ast_to_files(
        self, repo_node_id: int, file_nodes: Dict[str, int]
    ) -> Dict[str, Any]:
        """Connect AST nodes to their corresponding file nodes.

        Args:
            repo_node_id: ID of the repository node
            file_nodes: Mapping of file paths to file node IDs

        Returns:
            Dictionary with mapping statistics
        """
        logger.info(f"Mapping AST nodes to file nodes for repository {repo_node_id}")

        # Query to find AST nodes with file paths
        query = (
            "MATCH (n) "
            "WHERE n.file_path IS NOT NULL "
            "RETURN elementId(n) as node_id, n.file_path as file_path"
        )

        ast_nodes = self.connector.run_query(query)
        logger.info(f"Found {len(ast_nodes)} AST nodes with file paths")

        # Set up statistics
        stats = {
            "ast_nodes_found": len(ast_nodes),
            "mapped_nodes": 0,
            "unmapped_nodes": 0,
        }

        # Create relationships between AST nodes and file nodes
        for ast_node in ast_nodes:
            node_id = ast_node["node_id"]
            file_path = ast_node["file_path"]
            mapped = False

            # Try to find the corresponding file node
            for path, file_id in file_nodes.items():
                # Different normalization approaches for matching paths
                if (
                    file_path.endswith(path)
                    or path.endswith(file_path)
                    or path.replace("\\", "/") == file_path.replace("\\", "/")
                    or path.split("/")[-1] == file_path.split("/")[-1]
                ):

                    # Create relationship from file to AST node
                    success = self.connector.create_relationship(
                        file_id, node_id, RelationshipTypes.DEFINES
                    )

                    if success:
                        stats["mapped_nodes"] += 1
                        mapped = True
                        break

            if not mapped:
                stats["unmapped_nodes"] += 1
                logger.debug(f"Could not map AST node to file: {file_path}")

        # Log mapping statistics
        logger.info(f"Mapped {stats['mapped_nodes']} AST nodes to file nodes")
        if stats["unmapped_nodes"] > 0:
            logger.warning(
                f"Could not map {stats['unmapped_nodes']} AST nodes to file nodes"
            )

        return stats
