"""AST to filesystem mapping for code ingestion.

This module provides functionality to map between AST nodes and filesystem nodes
in the graph database.
"""

import os
from typing import Any, Dict, Optional

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
        self.logger = logger

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
        self.logger.info(f"Mapping AST nodes to file nodes for repository {repo_node_id}")

        # Query to find AST nodes with various path properties
        query = (
            "MATCH (n) "
            "WHERE (n:Function OR n:Method OR n:Class) AND "
            "(n.file_path IS NOT NULL OR n.path IS NOT NULL OR n.full_path IS NOT NULL) "
            "RETURN elementId(n) as node_id, "
            "COALESCE(n.file_path, n.path, n.full_path) as file_path, "
            "n.start_line as start_line, n.end_line as end_line, "
            "labels(n) as labels, n.name as name"
        )

        ast_nodes = self.connector.run_query(query)
        self.logger.info(f"Found {len(ast_nodes)} AST nodes with file paths")

        # Get repository file path
        repo_query = """
        MATCH (r:Repository) WHERE elementId(r) = $repo_id
        RETURN r.path as repo_path
        """
        repo_result = self.connector.run_query(repo_query, {"repo_id": repo_node_id})
        repo_path = repo_result[0]["repo_path"] if repo_result and repo_result[0].get("repo_path") else None
        
        if not repo_path:
            self.logger.warning(f"Could not find path for repository {repo_node_id}")
        else:
            self.logger.info(f"Repository path: {repo_path}")

        # Set up statistics
        stats = {
            "ast_nodes_found": len(ast_nodes),
            "mapped_nodes": 0,
            "unmapped_nodes": 0,
            "nodes_with_code": 0,
            "code_extraction_failures": 0
        }

        # Create relationships between AST nodes and file nodes
        for ast_node in ast_nodes:
            node_id = ast_node["node_id"]
            file_path = ast_node["file_path"]
            start_line = ast_node.get("start_line")
            end_line = ast_node.get("end_line")
            node_type = ast_node.get("labels", [])[0] if ast_node.get("labels") else "Unknown"
            node_name = ast_node.get("name", "")
            
            mapped = False

            # Try to find the corresponding file node
            for path, file_id in file_nodes.items():
                # Extract basenames for more reliable matching
                file_path_basename = file_path.split("/")[-1] if "/" in file_path else file_path.split("\\")[-1]
                path_basename = path.split("/")[-1] if "/" in path else path.split("\\")[-1]
                
                # Different normalization approaches for matching paths
                if (
                    file_path.endswith(path)
                    or path.endswith(file_path)
                    or path.replace("\\", "/") == file_path.replace("\\", "/")
                    or file_path_basename == path_basename
                    or (file_path_basename.endswith('.py') and path_basename.endswith('.py') and 
                        file_path_basename.split('.')[0] == path_basename.split('.')[0])
                ):
                    # Create relationship from AST to file node (AST node is PART_OF file)
                    # Create both relationships in a single transaction to ensure consistency
                    query = """
                    MATCH (ast) WHERE elementId(ast) = $ast_id
                    MATCH (file) WHERE elementId(file) = $file_id
                    MERGE (ast)-[r1:PART_OF]->(file)
                    MERGE (file)-[r2:DEFINES]->(ast)
                    RETURN count(r1) + count(r2) as rel_count, file.path as file_path
                    """
                    
                    result = self.connector.run_query(
                        query, 
                        {"ast_id": node_id, "file_id": file_id}
                    )
                    
                    success = result and len(result) > 0 and result[0].get("rel_count", 0) == 2

                    if success:
                        stats["mapped_nodes"] += 1
                        mapped = True
                        
                        # Extract code content if we have line information
                        if start_line is not None and end_line is not None and repo_path:
                            try:
                                # Get the file path from the DB
                                db_file_path = result[0].get("file_path")
                                if db_file_path:
                                    # Try multiple ways to construct the full path
                                    possible_paths = [
                                        os.path.join(repo_path, db_file_path),
                                        db_file_path,
                                        os.path.join(repo_path, file_path),
                                        file_path
                                    ]
                                    
                                    # For Windows compatibility
                                    normalized_paths = []
                                    for p in possible_paths:
                                        normalized_paths.append(p)
                                        normalized_paths.append(p.replace('/', '\\'))
                                        normalized_paths.append(p.replace('\\', '/'))
                                    
                                    possible_paths = list(set(normalized_paths))  # Remove duplicates
                                    
                                    content = None
                                    used_path = None
                                    
                                    for test_path in possible_paths:
                                        if os.path.isfile(test_path):
                                            try:
                                                with open(test_path, 'r', encoding='utf-8') as f:
                                                    all_lines = f.readlines()
                                                
                                                # Extract the code between start and end lines
                                                # Convert from 1-based (Neo4j) to 0-based (Python)
                                                line_start = max(0, start_line - 1)
                                                line_end = min(len(all_lines), end_line)
                                                
                                                if line_start < len(all_lines) and line_start <= line_end:
                                                    content = ''.join(all_lines[line_start:line_end])
                                                    used_path = test_path
                                                    break
                                            except Exception as e:
                                                self.logger.debug(f"Error reading {test_path}: {e}")
                                    
                                    if content and used_path:
                                        # Update AST node with code content
                                        update_query = """
                                        MATCH (ast) WHERE elementId(ast) = $ast_id
                                        SET ast.code = $code
                                        """
                                        self.connector.run_query(
                                            update_query,
                                            {"ast_id": node_id, "code": content}
                                        )
                                        stats["nodes_with_code"] += 1
                                        self.logger.debug(f"Added code to {node_type} {node_name} from {used_path}")
                                    else:
                                        stats["code_extraction_failures"] += 1
                                        self.logger.debug(f"Failed to extract code for {node_type} {node_name} - file not found")
                            except Exception as e:
                                stats["code_extraction_failures"] += 1
                                self.logger.warning(f"Error extracting code for {node_type} {node_name}: {e}")
                        
                        break

            if not mapped:
                stats["unmapped_nodes"] += 1
                self.logger.debug(f"Could not map AST node to file: {file_path}")

        # Log mapping statistics
        self.logger.info(f"Mapped {stats['mapped_nodes']} AST nodes to file nodes")
        self.logger.info(f"Added code property to {stats['nodes_with_code']} AST nodes")
        
        if stats["unmapped_nodes"] > 0:
            self.logger.warning(
                f"Could not map {stats['unmapped_nodes']} AST nodes to file nodes"
            )
        
        if stats["code_extraction_failures"] > 0:
            self.logger.warning(
                f"Failed to extract code for {stats['code_extraction_failures']} AST nodes"
            )

        return stats
