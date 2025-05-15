#!/usr/bin/env python3

"""Generate a visualization of the file tree from Neo4j."""

import sys
import os
import json
from pathlib import Path
from collections import defaultdict

from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


def create_file_tree_visualization(output_path="file_tree_visualization.html"):
    """Create a visualization of the file tree structure from Neo4j."""
    connector = get_connector()
    
    # First, check what properties we have on File nodes
    file_props_query = """
    MATCH (f:File)
    RETURN keys(f) as properties
    LIMIT 1
    """
    
    file_props_result = connector.run_query(file_props_query)
    file_properties = []
    if file_props_result and len(file_props_result) > 0:
        file_properties = file_props_result[0].get("properties", [])
    
    print(f"File node properties: {file_properties}")
    
    # Get repository information
    repo_query = """
    MATCH (r:Repository)
    RETURN r
    """
    
    repo_result = connector.run_query(repo_query)
    repositories = []
    if repo_result and len(repo_result) > 0:
        for row in repo_result:
            repo = row.get("r", {})
            repositories.append(repo)
    
    print(f"Found {len(repositories)} repositories")
    for repo in repositories:
        print(f"Repository: {repo.get('name', 'Unknown')}")
        print(f"Properties: {dict(repo)}")
    
    # Get files with path if available
    file_query = """
    MATCH (f:File)
    RETURN f
    LIMIT 1000
    """
    
    file_results = connector.run_query(file_query)
    files = []
    if file_results and len(file_results) > 0:
        for row in file_results:
            file_node = row.get("f", {})
            files.append(file_node)
    
    print(f"Found {len(files)} files")
    
    # Extract path or name information
    file_paths = []
    for file_node in files:
        path = file_node.get("path", file_node.get("name", ""))
        file_paths.append(path)
    
    print("Sample file paths:")
    for path in file_paths[:10]:
        print(f"  {path}")
    
    # Get AST nodes and their relationships to files
    ast_query = """
    MATCH (ast)-[r:PART_OF]->(f:File)
    RETURN count(ast) AS ast_count, count(DISTINCT f) AS file_count
    """
    
    ast_result = connector.run_query(ast_query)
    ast_count = 0
    ast_file_count = 0
    if ast_result and len(ast_result) > 0:
        ast_count = ast_result[0].get("ast_count", 0)
        ast_file_count = ast_result[0].get("file_count", 0)
    
    print(f"Found {ast_count} AST nodes connected to {ast_file_count} files")
    
    # Find label distribution for AST nodes
    label_query = """
    MATCH (n)
    WHERE EXISTS((n)-[:PART_OF]->(:File))
    WITH labels(n) AS node_labels, count(*) AS count
    RETURN node_labels, count
    ORDER BY count DESC
    """
    
    label_result = connector.run_query(label_query)
    print("\nAST Node label distribution:")
    for row in label_result:
        labels = row.get("node_labels", [])
        count = row.get("count", 0)
        print(f"  {', '.join(labels)}: {count}")
    
    # Find a working property to build a file tree
    path_property = "path"
    if "path" not in file_properties and "name" in file_properties:
        path_property = "name"
    
    # Build a simple file tree based on path information
    file_tree = {}
    for file_node in files:
        path = file_node.get(path_property, "")
        if not path:
            continue
        
        path_parts = path.split('/')
        if len(path_parts) < 2:  # Skip very short paths
            continue
        
        current = file_tree
        for i, part in enumerate(path_parts):
            if i == len(path_parts) - 1:  # Last part is the file name
                if "__files" not in current:
                    current["__files"] = []
                current["__files"].append({
                    "name": part,
                    "path": path,
                    "node": file_node
                })
            else:  # Directory
                if part not in current:
                    current[part] = {}
                current = current[part]
    
    # Build visualization nodes and links
    nodes = []
    links = []
    node_ids = {}
    
    # Add repository as root
    repo_id = "repository"
    repo_name = repositories[0].get("name", "Repository") if repositories else "Repository"
    nodes.append({
        "id": repo_id,
        "label": repo_name,
        "type": "Repository",
        "properties": {k: v for k, v in repositories[0].items()} if repositories else {}
    })
    node_ids[repo_id] = True
    
    # Helper to add directory structure to visualization
    def add_directory_structure(tree, parent_id, depth=0, max_depth=3, path_prefix=""):
        if depth >= max_depth:
            return
        
        # Add directories
        for dir_name, dir_contents in tree.items():
            if dir_name == "__files":
                continue
            
            dir_path = f"{path_prefix}/{dir_name}" if path_prefix else dir_name
            dir_id = f"dir:{dir_path}"
            
            # Add directory node
            nodes.append({
                "id": dir_id,
                "label": dir_name,
                "type": "Directory",
                "properties": {"path": dir_path}
            })
            node_ids[dir_id] = True
            
            # Link to parent
            links.append({
                "source": dir_id,
                "target": parent_id,
                "type": "CONTAINS"
            })
            
            # Recursively add subdirectories
            add_directory_structure(dir_contents, dir_id, depth + 1, max_depth, dir_path)
        
        # Add files at this level
        if "__files" in tree:
            for file_info in tree["__files"][:50]:  # Limit to 50 files per directory
                file_node = file_info.get("node", {})
                file_name = file_info.get("name", "")
                file_id = f"file:{file_info.get('path')}"
                
                # Add file node
                nodes.append({
                    "id": file_id,
                    "label": file_name,
                    "type": "File",
                    "properties": {k: v for k, v in file_node.items()}
                })
                node_ids[file_id] = True
                
                # Link to parent directory
                links.append({
                    "source": file_id,
                    "target": parent_id,
                    "type": "CONTAINS"
                })
                
                # Find AST nodes for this file
                try:
                    ast_query = """
                    MATCH (ast)-[:PART_OF]->(f:File)
                    WHERE id(f) = $file_id
                    RETURN ast
                    LIMIT 10
                    """
                    ast_results = connector.run_query(ast_query, {"file_id": id(file_node)})
                    
                    for ast_row in ast_results:
                        ast_node = ast_row.get("ast")
                        if ast_node:
                            ast_id = f"ast:{id(ast_node)}"
                            ast_type = next((label for label in ["Function", "Class", "Method"] 
                                           if label.lower() in str(ast_node).lower()), "ASTNode")
                            
                            # Add AST node
                            nodes.append({
                                "id": ast_id,
                                "label": ast_node.get("name", "Unknown"),
                                "type": ast_type,
                                "properties": {k: v for k, v in ast_node.items()}
                            })
                            node_ids[ast_id] = True
                            
                            # Link to file
                            links.append({
                                "source": ast_id,
                                "target": file_id,
                                "type": "PART_OF"
                            })
                except Exception as e:
                    print(f"Error finding AST nodes for file: {e}")
    
    # Generate the visualization structure
    add_directory_structure(file_tree, repo_id)
    
    print(f"Built graph with {len(nodes)} nodes and {len(links)} links")
    
    # Create graph data
    graph_data = {
        "nodes": nodes,
        "links": links
    }
    
    # Create visualization
    visualizer = GraphVisualizer()
    output_path = visualizer.create_interactive_ast_visualization(
        graph_data,
        output_path=output_path,
        title=f"File Tree Visualization: {repo_name}"
    )
    
    print(f"Created file tree visualization at {output_path}")
    return 0


if __name__ == "__main__":
    output_path = "file_tree_visualization.html"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    
    sys.exit(create_file_tree_visualization(output_path))