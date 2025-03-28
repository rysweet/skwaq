"""Blarify parser implementation for code ingestion.

This module provides a parser implementation using Blarify to extract the syntax
structure of a codebase and store it in the graph database.
"""

import os
from typing import Dict, List, Any, Optional, Set

from skwaq.db.neo4j_connector import get_connector, Neo4jConnector
from skwaq.db.schema import RelationshipTypes
from skwaq.utils.logging import get_logger

from . import CodeParser

try:
    from blarify.prebuilt.graph_builder import GraphBuilder
    from blarify.db_managers.neo4j_manager import Neo4jManager
    HAS_BLARIFY = True
except ImportError:
    HAS_BLARIFY = False

logger = get_logger(__name__)


class BlarifyParser(CodeParser):
    """Blarify parser implementation for code analysis.

    This parser uses the Blarify library to extract the syntax structure of a codebase
    and store it in the Neo4j graph database.
    """

    def __init__(self):
        """Initialize the Blarify parser.

        Raises:
            ImportError: If Blarify is not installed
        """
        if not HAS_BLARIFY:
            logger.error("Blarify is not installed. Please install it with: pip install blarify")
            raise ImportError("Blarify is not installed")
        
        self.connector = get_connector()

    async def parse(self, codebase_path: str) -> Dict[str, Any]:
        """Parse a codebase using Blarify and create a graph representation.

        Args:
            codebase_path: Path to the codebase to parse

        Returns:
            Dictionary with parsing results and statistics
        
        Raises:
            ValueError: If codebase path is invalid or if parsing fails
        """
        if not os.path.exists(codebase_path) or not os.path.isdir(codebase_path):
            error_msg = f"Invalid codebase path: {codebase_path}"
            logger.error(error_msg)
            raise ValueError(error_msg)
        
        logger.info(f"Parsing codebase at {codebase_path} with Blarify")
        
        # Set up statistics
        stats = {
            "files_processed": 0,
            "nodes_created": 0,
            "relationships_created": 0,
            "errors": 0,
        }
        
        try:
            # Create a Blarify graph builder
            graph_builder = GraphBuilder(
                root_path=codebase_path,
                extensions_to_skip=[".json", ".md", ".txt", ".html", ".css"],
                names_to_skip=["__pycache__", "node_modules", "venv", ".git"]
            )
            
            # Build the graph
            logger.info("Building AST graph with Blarify")
            graph = graph_builder.build()
            
            # Get nodes and relationships
            nodes = graph.get_nodes_as_objects()
            relationships = graph.get_relationships_as_objects()
            
            logger.info(f"Built graph with {len(nodes)} nodes and {len(relationships)} relationships")
            
            # Save the graph to Neo4j
            logger.info("Saving AST graph to Neo4j")
            
            # Get the database URI, username, and password from the connector
            db_config = {
                "uri": self.connector._uri,
                "user": self.connector._user,
                "password": self.connector._password,
                "database": self.connector._database,
            }
            
            # Create a Blarify Neo4j manager
            graph_manager = Neo4jManager(
                repo_id="repo",
                entity_id="organization",
                uri=db_config["uri"],
                user=db_config["user"],
                password=db_config["password"],
                database=db_config["database"],
            )
            
            # Save the graph
            graph_manager.save_graph(nodes, relationships)
            graph_manager.close()
            
            # Update statistics
            stats["files_processed"] = len(set(node.file_path for node in nodes if hasattr(node, "file_path")))
            stats["nodes_created"] = len(nodes)
            stats["relationships_created"] = len(relationships)
            
            logger.info(f"Successfully parsed codebase with Blarify: {stats}")
            
            return {
                "success": True,
                "stats": stats,
                "files_processed": stats["files_processed"],
            }
            
        except Exception as e:
            error_msg = f"Failed to parse codebase with Blarify: {str(e)}"
            logger.error(error_msg)
            stats["errors"] += 1
            raise ValueError(error_msg)

    async def connect_ast_to_files(self, repo_node_id: int, file_path_mapping: Dict[str, int]) -> None:
        """Connect AST nodes to their corresponding file nodes.

        Note:
            This method is deprecated. Use the ASTFileMapper instead.

        Args:
            repo_node_id: ID of the repository node
            file_path_mapping: Mapping of file paths to file node IDs
        """
        logger.warning("This method is deprecated. Use the ASTFileMapper instead.")
        # This functionality has been moved to the ASTFileMapper class
        pass