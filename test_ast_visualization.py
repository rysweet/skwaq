#!/usr/bin/env python3

"""Test script for the interactive AST visualization."""

import sys
import os
import json
from pathlib import Path
import argparse

from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


def find_repository_by_name(repo_name):
    """Find a repository by name in the database."""
    connector = get_connector()
    
    # Find repository by name
    query = """
    MATCH (r:Repository)
    WHERE r.name CONTAINS $name
    RETURN r
    LIMIT 1
    """
    
    result = connector.run_query(query, {"name": repo_name})
    if not result:
        return None
    
    return result[0].get("r", {})


def build_ast_graph(repo_id):
    """Build AST graph data for visualization."""
    connector = get_connector()
    
    # First, find the repository by name if repo_id is a name
    if not repo_id.startswith("neo4j:"):
        repo_query = """
        MATCH (r:Repository)
        WHERE r.name = $repo_name OR r.path CONTAINS $repo_name
        RETURN id(r) as neo4j_id, r
        LIMIT 1
        """
        repo_result = connector.run_query(repo_query, {"repo_name": repo_id})
        if repo_result and len(repo_result) > 0:
            neo4j_id = repo_result[0].get("neo4j_id")
            if neo4j_id:
                repo_id = f"neo4j:{neo4j_id}"
                print(f"Found repository with Neo4j ID: {repo_id}")
    
    # Find all AST nodes related to files in the repository
    query = """
    MATCH (r:Repository)
    WHERE (r.name = $repo_id OR r.path CONTAINS $repo_id OR ID(r) = toInteger($neo4j_id))
    MATCH (f:File)-[:PART_OF]->(r)
    OPTIONAL MATCH (ast)-[:PART_OF]->(f)
    WHERE ast:Function OR ast:Class OR ast:Method OR ast:Module OR ast:Variable OR ast:Parameter
    OPTIONAL MATCH (cs:CodeSummary)-[:DESCRIBES]->(ast)
    RETURN r, collect(DISTINCT f) as files, 
           collect(DISTINCT ast) as ast_nodes,
           collect(DISTINCT cs) as code_summaries
    """
    
    # Extract Neo4j ID if present
    neo4j_id = None
    if repo_id.startswith("neo4j:"):
        neo4j_id = repo_id[6:]
    
    params = {"repo_id": repo_id, "neo4j_id": neo4j_id}
    result = connector.run_query(query, params)
    if not result or len(result) == 0:
        print(f"No AST data found for repository ID: {repo_id}")
        # Try a more generic query to see if we can find any AST nodes at all
        generic_query = """
        MATCH (ast)
        WHERE ast:Function OR ast:Class OR ast:Method OR ast:Module OR ast:Variable OR ast:Parameter
        RETURN count(ast) as ast_count
        """
        generic_result = connector.run_query(generic_query)
        if generic_result and len(generic_result) > 0:
            ast_count = generic_result[0].get("ast_count", 0)
            print(f"Found {ast_count} AST nodes in the database in total")
            
            # Try to find files
            file_query = """
            MATCH (f:File)
            RETURN count(f) as file_count
            """
            file_result = connector.run_query(file_query)
            if file_result and len(file_result) > 0:
                file_count = file_result[0].get("file_count", 0)
                print(f"Found {file_count} File nodes in the database in total")
                
                # Check relationships
                rel_query = """
                MATCH (ast)-[r:PART_OF]->(f:File)
                RETURN count(r) as rel_count
                """
                rel_result = connector.run_query(rel_query)
                if rel_result and len(rel_result) > 0:
                    rel_count = rel_result[0].get("rel_count", 0)
                    print(f"Found {rel_count} PART_OF relationships from AST to File nodes")
        
        return None
    
    # Build nodes and links for the visualization
    nodes = []
    links = []
    node_ids = set()
    
    # First, add the repository node
    repo = result[0].get("r", {})
    repo_id_str = repo.get("id")
    
    if repo_id_str:
        nodes.append({
            "id": repo_id_str,
            "label": repo.get("name", "Unknown Repository"),
            "type": "Repository",
            "properties": {k: v for k, v in repo.items() if k not in ["id"]}
        })
        node_ids.add(repo_id_str)
    
    # Add File nodes
    files = result[0].get("files", [])
    for file_node in files:
        if not file_node:
            continue
        
        file_id = str(id(file_node))
        file_props = {k: v for k, v in file_node.items()}
        
        nodes.append({
            "id": file_id,
            "label": file_props.get("name", "Unknown File"),
            "type": "File",
            "properties": file_props
        })
        node_ids.add(file_id)
        
        # Link file to repository
        if repo_id_str:
            links.append({
                "source": file_id,
                "target": repo_id_str,
                "type": "PART_OF"
            })
    
    # Add AST nodes
    ast_nodes = result[0].get("ast_nodes", [])
    for ast_node in ast_nodes:
        if not ast_node:
            continue
        
        # Get node properties
        ast_id = str(id(ast_node))
        ast_props = {k: v for k, v in ast_node.items()}
        ast_type = next((label for label in ["Function", "Class", "Method", "Module", "Variable", "Parameter"] 
                        if label.lower() in str(ast_node).lower()), "ASTNode")
        
        # Add the AST node
        nodes.append({
            "id": ast_id,
            "label": ast_props.get("name", "Unknown AST Node"),
            "type": ast_type,
            "properties": ast_props
        })
        node_ids.add(ast_id)
        
        # Find the file this AST node belongs to
        file_query = """
        MATCH (ast)-[:PART_OF]->(f:File)
        WHERE id(ast) = $ast_id
        RETURN f
        LIMIT 1
        """
        
        file_result = connector.run_query(file_query, {"ast_id": id(ast_node)})
        if file_result and len(file_result) > 0:
            file_node = file_result[0].get("f")
            if file_node:
                file_id = str(id(file_node))
                if file_id in node_ids:
                    links.append({
                        "source": ast_id,
                        "target": file_id,
                        "type": "PART_OF"
                    })
    
    # Add CodeSummary nodes
    code_summaries = result[0].get("code_summaries", [])
    for cs_node in code_summaries:
        if not cs_node:
            continue
        
        # Get node properties
        cs_id = str(id(cs_node))
        cs_props = {k: v for k, v in cs_node.items()}
        
        # Add the CodeSummary node
        nodes.append({
            "id": cs_id,
            "label": "Summary: " + cs_props.get("name", "Unknown Summary"),
            "type": "CodeSummary",
            "properties": cs_props
        })
        node_ids.add(cs_id)
        
        # Find the AST node this summary describes
        ast_query = """
        MATCH (cs:CodeSummary)-[:DESCRIBES]->(ast)
        WHERE id(cs) = $cs_id
        RETURN ast
        LIMIT 1
        """
        
        ast_result = connector.run_query(ast_query, {"cs_id": id(cs_node)})
        if ast_result and len(ast_result) > 0:
            ast_node = ast_result[0].get("ast")
            if ast_node:
                ast_id = str(id(ast_node))
                if ast_id in node_ids:
                    links.append({
                        "source": cs_id,
                        "target": ast_id,
                        "type": "DESCRIBES"
                    })
    
    # Return the graph data
    return {"nodes": nodes, "links": links}


def list_repositories():
    """List all repositories in the database."""
    connector = get_connector()
    
    query = """
    MATCH (r:Repository)
    RETURN r
    """
    
    result = connector.run_query(query)
    if not result:
        print("No repositories found in the database")
        return []
    
    repos = []
    print("Repositories in the database:")
    for i, row in enumerate(result):
        repo = row.get("r", {})
        repo_name = repo.get("name", "Unknown")
        repo_id = repo.get("id", "No ID")
        repo_path = repo.get("path", "No path")
        print(f"{i+1}. {repo_name} (ID: {repo_id}) - Path: {repo_path}")
        repos.append(repo)
    
    return repos

def main():
    """Main function for testing AST visualization."""
    parser = argparse.ArgumentParser(description="Test AST visualization")
    parser.add_argument("--repo-name", type=str, help="Repository name to visualize", default="AttackBot")
    parser.add_argument("--output", type=str, help="Output file path", default="ast_visualization.html")
    parser.add_argument("--list", action="store_true", help="List repositories in the database")
    parser.add_argument("--repo-index", type=int, help="Use repository at specified index from list")
    args = parser.parse_args()
    
    # List repositories if requested
    repos = list_repositories()
    if args.list:
        return 0
    
    # Use repository at index if specified
    if args.repo_index is not None:
        if args.repo_index < 1 or args.repo_index > len(repos):
            print(f"Invalid repository index: {args.repo_index}. Must be between 1 and {len(repos)}")
            return 1
        repo = repos[args.repo_index - 1]
    else:
        # Find repository by name
        repo = find_repository_by_name(args.repo_name)
        if not repo:
            print(f"Repository with name containing '{args.repo_name}' not found in the database")
            return 1
    
    # Use Neo4j node ID if repository doesn't have id property
    repo_id = repo.get("id")
    if not repo_id:
        # Use the name of the repository as the ID
        repo_id = repo.get("name")
        if not repo_id:
            print(f"Repository found but has no id or name property. Available properties: {list(repo.keys())}")
            return 1
        print(f"Using repository name as ID: {repo_id}")
    
    print(f"Found repository: {repo.get('name')} (ID: {repo_id})")
    
    # Build AST graph data
    graph_data = build_ast_graph(repo_id)
    if not graph_data:
        print(f"No AST graph data could be built for repository ID: {repo_id}")
        return 1
    
    print(f"Built graph with {len(graph_data['nodes'])} nodes and {len(graph_data['links'])} links")
    
    # Create and export the visualization
    visualizer = GraphVisualizer()
    output_path = visualizer.create_interactive_ast_visualization(
        graph_data,
        output_path=args.output,
        title=f"AST Visualization for {repo.get('name')}"
    )
    
    print(f"Visualization exported to: {output_path}")
    
    # No explicit disconnect needed with newer connector
    return 0


if __name__ == "__main__":
    sys.exit(main())