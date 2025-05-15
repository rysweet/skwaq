#!/usr/bin/env python3

"""Create a direct AST visualization using all available nodes."""

import sys
from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


def create_direct_visualization(output_path="direct_ast_visualization.html"):
    """Create a direct AST visualization using all available nodes in the database."""
    connector = get_connector()
    
    # Find all AST and File nodes
    query = """
    MATCH (ast)
    WHERE ast:ASTNode OR ast:Function OR ast:Method OR ast:Class
    WITH collect(ast) as asts
    MATCH (f:File)
    WITH asts, collect(f) as files
    MATCH (r:Repository)
    WITH asts, files, collect(r) as repos
    OPTIONAL MATCH (cs:CodeSummary)
    RETURN asts, files, repos, collect(cs) as summaries
    """
    
    result = connector.run_query(query)
    if not result or len(result) == 0:
        print("No nodes found in the database")
        return 1
    
    first_row = result[0]
    ast_nodes = first_row.get("asts", [])
    files = first_row.get("files", [])
    repos = first_row.get("repos", [])
    code_summaries = first_row.get("summaries", [])
    
    print(f"Found {len(ast_nodes)} AST nodes")
    print(f"Found {len(files)} File nodes")
    print(f"Found {len(repos)} Repository nodes")
    print(f"Found {len(code_summaries)} CodeSummary nodes")
    
    # Build graph data
    nodes = []
    links = []
    node_ids = {}
    
    # Helper function to add a node
    def add_node(node, node_type):
        node_id = str(id(node))
        if node_id in node_ids:
            return node_id
        
        # Get node properties
        props = {k: v for k, v in node.items()}
        label = props.get("name", "Unknown")
        
        # Generate a unique ID
        node_ids[node_id] = len(nodes)
        
        # Create node
        nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
            "properties": props
        })
        
        return node_id
    
    # Add repository nodes
    for repo in repos:
        add_node(repo, "Repository")
    
    # Add file nodes
    for file_node in files:
        file_id = add_node(file_node, "File")
        
        # Try to find repository for this file
        try:
            file_query = """
            MATCH (f:File)-[:PART_OF]->(r:Repository)
            WHERE id(f) = $file_id
            RETURN r
            LIMIT 1
            """
            file_result = connector.run_query(file_query, {"file_id": id(file_node)})
            if file_result and len(file_result) > 0:
                repo = file_result[0].get("r")
                if repo:
                    repo_id = add_node(repo, "Repository")
                    links.append({
                        "source": file_id,
                        "target": repo_id,
                        "type": "PART_OF"
                    })
        except Exception as e:
            print(f"Error finding repository for file: {e}")
    
    # Add AST nodes
    for ast_node in ast_nodes:
        ast_id = add_node(ast_node, "ASTNode")
        
        # Try to find file for this AST node
        try:
            ast_query = """
            MATCH (ast)-[:PART_OF]->(f:File)
            WHERE id(ast) = $ast_id
            RETURN f
            LIMIT 1
            """
            ast_result = connector.run_query(ast_query, {"ast_id": id(ast_node)})
            if ast_result and len(ast_result) > 0:
                file_node = ast_result[0].get("f")
                if file_node:
                    file_id = add_node(file_node, "File")
                    links.append({
                        "source": ast_id,
                        "target": file_id,
                        "type": "PART_OF"
                    })
        except Exception as e:
            print(f"Error finding file for AST node: {e}")
    
    # Add CodeSummary nodes
    for cs_node in code_summaries:
        cs_id = add_node(cs_node, "CodeSummary")
        
        # Try to find AST node for this summary
        try:
            cs_query = """
            MATCH (cs:CodeSummary)-[:DESCRIBES]->(ast)
            WHERE id(cs) = $cs_id
            RETURN ast
            LIMIT 1
            """
            cs_result = connector.run_query(cs_query, {"cs_id": id(cs_node)})
            if cs_result and len(cs_result) > 0:
                ast_node = cs_result[0].get("ast")
                if ast_node:
                    ast_id = add_node(ast_node, "ASTNode")
                    links.append({
                        "source": cs_id,
                        "target": ast_id,
                        "type": "DESCRIBES"
                    })
        except Exception as e:
            print(f"Error finding AST node for CodeSummary: {e}")
    
    # Build graph data
    graph_data = {
        "nodes": nodes,
        "links": links
    }
    
    # Create visualization
    visualizer = GraphVisualizer()
    output_path = visualizer.create_interactive_ast_visualization(
        graph_data,
        output_path=output_path,
        title="AST Visualization"
    )
    
    print(f"Created visualization at {output_path} with {len(nodes)} nodes and {len(links)} links")
    return 0


if __name__ == "__main__":
    output_path = "direct_ast_visualization.html"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    
    sys.exit(create_direct_visualization(output_path))