"""Blarify parser implementation for code ingestion.

This module provides a parser implementation using Blarify to extract the syntax
structure of a codebase and store it in the graph database.
"""

import os
import sys
import json
import tempfile
import subprocess
import platform
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
        self.use_docker = platform.system() == "Darwin"  # Use Docker on macOS
        
        # Check if Docker is available if needed
        if self.use_docker:
            try:
                result = subprocess.run(["docker", "--version"], 
                                    capture_output=True, 
                                    text=True, 
                                    check=False)
                self.docker_available = result.returncode == 0
                if not self.docker_available:
                    logger.warning("Docker is not available but would be needed for Blarify on macOS.")
            except FileNotFoundError:
                self.docker_available = False
                logger.warning("Docker command not found. It's needed for Blarify on macOS.")

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
            "docker_mode": False
        }
        
        # Check if we should use Docker
        if self.use_docker and self.docker_available:
            logger.info("Using Docker for Blarify parsing on macOS")
            return await self._parse_with_docker(codebase_path, stats)
        
        # Try direct parsing if we're not using Docker or Docker isn't available
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
            
            # If Docker is available, try with Docker
            if not stats.get("docker_mode") and self.docker_available:
                logger.info("Direct parsing failed, attempting to use Docker")
                return await self._parse_with_docker(codebase_path, stats)
            
            raise ValueError(error_msg)
    
    async def _parse_with_docker(self, codebase_path: str, stats: Dict[str, Any]) -> Dict[str, Any]:
        """Parse a codebase using Blarify in a Docker container.
        
        Args:
            codebase_path: Path to the codebase to parse
            stats: Statistics dictionary to update
            
        Returns:
            Dictionary with parsing results and statistics
        """
        stats["docker_mode"] = True
        
        # Create a Dockerfile in a temp directory
        with tempfile.TemporaryDirectory() as docker_dir:
            logger.info("Creating Docker environment for Blarify")
            
            # Write Dockerfile
            dockerfile_path = os.path.join(docker_dir, "Dockerfile")
            with open(dockerfile_path, 'w') as f:
                f.write("""
FROM python:3.10-slim

# Install dependencies for language servers
RUN apt-get update && apt-get install -y \\
    git \\
    golang \\
    dotnet-sdk-7.0 \\
    nodejs \\
    npm

# Install Blarify
RUN pip install blarify

# Install language servers
RUN go install golang.org/x/tools/gopls@latest
ENV PATH="/root/go/bin:${PATH}"

# Create script that will run Blarify and output the results
COPY run_blarify.py /run_blarify.py

WORKDIR /code
ENTRYPOINT ["python", "/run_blarify.py"]
                """)
            
            # Write the Python script that will run inside the container
            script_path = os.path.join(docker_dir, "run_blarify.py")
            with open(script_path, 'w') as f:
                f.write("""
import os
import sys
import json
from blarify.prebuilt.graph_builder import GraphBuilder

def main():
    # Get the repository path from args
    if len(sys.argv) < 2:
        print(json.dumps({"error": "No repository path provided"}))
        sys.exit(1)
    
    codebase_path = sys.argv[1]
    
    try:
        # Create a Blarify graph builder
        graph_builder = GraphBuilder(
            root_path=codebase_path,
            extensions_to_skip=[".json", ".md", ".txt", ".html", ".css"],
            names_to_skip=["__pycache__", "node_modules", "venv", ".git"]
        )
        
        # Build the graph
        graph = graph_builder.build()
        
        # Get nodes and relationships
        nodes = graph.get_nodes_as_objects()
        relationships = graph.get_relationships_as_objects()
        
        # We need to serialize the data to send back as JSON
        # Create a simplified representation
        serialized_nodes = []
        for node in nodes:
            node_data = {
                "id": getattr(node, "id", None),
                "type": node.__class__.__name__,
                "labels": getattr(node, "labels", []),
                "file_path": getattr(node, "file_path", ""),
                "name": getattr(node, "name", ""),
                "properties": {
                    # Add more properties as needed
                    "language": getattr(node, "language", ""),
                    "start_line": getattr(node, "start_line", 0),
                    "end_line": getattr(node, "end_line", 0),
                }
            }
            serialized_nodes.append(node_data)
        
        serialized_relationships = []
        for rel in relationships:
            rel_data = {
                "source_id": getattr(rel.source_node, "id", None),
                "target_id": getattr(rel.target_node, "id", None),
                "type": rel.type,
                "properties": {}  # Add properties if needed
            }
            serialized_relationships.append(rel_data)
        
        # Output the graph data as JSON
        result = {
            "success": True,
            "stats": {
                "files_processed": len(set(node.file_path for node in nodes if hasattr(node, "file_path"))),
                "nodes_created": len(nodes),
                "relationships_created": len(relationships),
                "errors": 0,
            },
            "nodes": serialized_nodes,
            "relationships": serialized_relationships
        }
        print(json.dumps(result))
        
    except Exception as e:
        error_msg = f"Failed to parse codebase with Blarify: {str(e)}"
        print(json.dumps({"error": error_msg}))
        sys.exit(1)

if __name__ == "__main__":
    main()
                """)
            
            # Build the Docker image
            try:
                logger.info("Building Docker image for Blarify")
                build_cmd = ["docker", "build", "-t", "skwaq-blarify", docker_dir]
                subprocess.run(build_cmd, check=True, capture_output=True)
                
                # Run Blarify in the Docker container
                logger.info("Running Blarify in Docker container")
                
                # Create a temporary output file
                with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_output:
                    output_path = temp_output.name
                
                # Run the Docker container
                docker_cmd = [
                    "docker", "run", "--rm",
                    "-v", f"{codebase_path}:/code",
                    "skwaq-blarify", "/code"
                ]
                result = subprocess.run(docker_cmd, capture_output=True, text=True, check=False)
                
                # Process the result
                if result.returncode != 0:
                    error_msg = f"Docker run failed: {result.stderr}"
                    logger.error(error_msg)
                    stats["errors"] += 1
                    raise ValueError(error_msg)
                
                try:
                    # Parse the output JSON
                    blarify_result = json.loads(result.stdout)
                    
                    # Check if there was an error
                    if "error" in blarify_result:
                        error_msg = blarify_result["error"]
                        logger.error(error_msg)
                        stats["errors"] += 1
                        raise ValueError(error_msg)
                    
                    # Process the nodes and relationships
                    self._process_docker_result(blarify_result)
                    
                    # Update statistics
                    stats.update(blarify_result["stats"])
                    
                    logger.info(f"Successfully parsed codebase with Blarify in Docker: {stats}")
                    
                    return {
                        "success": True,
                        "stats": stats,
                        "files_processed": stats["files_processed"],
                        "docker_mode": True
                    }
                    
                except json.JSONDecodeError:
                    error_msg = f"Failed to parse Docker output as JSON: {result.stdout}"
                    logger.error(error_msg)
                    stats["errors"] += 1
                    raise ValueError(error_msg)
                
            except subprocess.CalledProcessError as e:
                error_msg = f"Docker command failed: {e.stderr.decode() if e.stderr else str(e)}"
                logger.error(error_msg)
                stats["errors"] += 1
                raise ValueError(error_msg)
            except Exception as e:
                error_msg = f"Docker processing failed: {str(e)}"
                logger.error(error_msg)
                stats["errors"] += 1
                raise ValueError(error_msg)
    
    def _process_docker_result(self, result: Dict[str, Any]) -> None:
        """Process the result from Docker and save to Neo4j.
        
        Args:
            result: Dictionary with nodes and relationships from Docker
        """
        logger.info("Processing Docker result and saving to Neo4j")
        
        # Get the database URI, username, and password from the connector
        db_config = {
            "uri": self.connector._uri,
            "user": self.connector._user,
            "password": self.connector._password,
            "database": self.connector._database,
        }
        
        # Process and create nodes
        node_id_mapping = {}  # Map Blarify node IDs to Neo4j node IDs
        
        for node in result.get("nodes", []):
            # Create node properties
            node_props = {
                "name": node.get("name", ""),
                "path": node.get("file_path", ""),
                "type": node.get("type", ""),
                "language": node.get("properties", {}).get("language", ""),
                "start_line": node.get("properties", {}).get("start_line", 0),
                "end_line": node.get("properties", {}).get("end_line", 0),
            }
            
            # Convert labels to Neo4j node labels
            labels = node.get("labels", [])
            if not labels:
                # Use the type as a label if no labels are provided
                labels = [node.get("type", "Node")]
            
            # Create the node in Neo4j
            node_id = self.connector.create_node(labels, node_props)
            if node_id and node.get("id"):
                node_id_mapping[node["id"]] = node_id
        
        # Process and create relationships
        for rel in result.get("relationships", []):
            source_id = node_id_mapping.get(rel.get("source_id"))
            target_id = node_id_mapping.get(rel.get("target_id"))
            rel_type = rel.get("type")
            
            if source_id and target_id and rel_type:
                self.connector.create_relationship(
                    source_id, target_id, rel_type, rel.get("properties", {})
                )

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