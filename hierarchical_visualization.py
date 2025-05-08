#!/usr/bin/env python3

"""Create a hierarchical visualization of the codebase structure."""

import sys
import os
import json
from pathlib import Path
from skwaq.db.neo4j_connector import get_connector
from skwaq.visualization.graph_visualizer import GraphVisualizer


def create_hierarchical_visualization(output_path="hierarchical_visualization.html"):
    """Create a hierarchical visualization starting with top-level directories."""
    connector = get_connector()
    
    # Get repository information
    repo_query = """
    MATCH (r:Repository)
    RETURN r
    LIMIT 1
    """
    
    repo_result = connector.run_query(repo_query)
    repository = None
    if repo_result and len(repo_result) > 0:
        repository = repo_result[0].get("r")
    
    if not repository:
        print("No repository found in the database")
        return 1
    
    repo_path = repository.get("path", "")
    print(f"Found repository: {repository.get('name', 'Unknown')} at {repo_path}")
    
    # Get top-level directories and files
    structure_query = """
    MATCH (f:File)-[:PART_OF]->(r:Repository)
    WITH f
    ORDER BY f.path
    RETURN f
    """
    
    file_results = connector.run_query(structure_query)
    
    # Build directory structure
    directories = {}
    all_files = []
    
    # Process files into a directory structure
    for row in file_results:
        file_node = row.get("f")
        if file_node:
            file_path = file_node.get("path", "")
            
            # Skip empty paths
            if not file_path:
                continue
                
            # Normalize path
            if repo_path and file_path.startswith(repo_path):
                rel_path = file_path[len(repo_path):].lstrip('/')
            else:
                rel_path = file_path
                
            # Skip paths that don't look valid
            if not rel_path or len(rel_path) < 3:  # Skip very short paths
                continue
                
            # Create path parts
            path_parts = rel_path.split('/')
            
            # Track this file
            all_files.append({
                "path": rel_path,
                "file_node": file_node,
                "level": len(path_parts)
            })
            
            # Process directory structure (up to 3 levels deep)
            current_dir = directories
            
            # Process directory parts (up to a maximum depth)
            max_depth = min(3, len(path_parts) - 1)
            for i in range(max_depth):
                dir_name = path_parts[i]
                if dir_name not in current_dir:
                    current_dir[dir_name] = {"__files": [], "__subdirs": {}}
                
                # If this is the last directory level, add the file
                if i == max_depth - 1 and len(path_parts) > i + 1:
                    file_name = path_parts[i + 1]
                    current_dir[dir_name]["__files"].append({
                        "name": file_name,
                        "path": rel_path,
                        "node": file_node
                    })
                
                current_dir = current_dir[dir_name]["__subdirs"]
    
    print(f"Processed {len(all_files)} files into directory structure")
    
    # Calculate directory statistics
    def count_in_directory(dir_dict):
        file_count = len(dir_dict.get("__files", []))
        dir_count = 0
        sub_file_count = 0
        
        for subdir_name, subdir in dir_dict.get("__subdirs", {}).items():
            dir_count += 1
            subdir_files, subdir_dirs, _ = count_in_directory(subdir)
            sub_file_count += subdir_files + subdir_dirs
        
        return file_count, dir_count, sub_file_count
    
    # Build visualization nodes and links
    nodes = []
    links = []
    node_ids = {}
    
    # Add repository node
    repo_id = str(id(repository))
    repo_name = repository.get("name", "Repository")
    nodes.append({
        "id": repo_id,
        "label": repo_name,
        "type": "Repository",
        "properties": {k: v for k, v in repository.items()}
    })
    node_ids[repo_id] = True
    
    # Add top-level directories
    def add_directory_nodes(dir_dict, parent_id, parent_path="", level=1):
        for dir_name, dir_content in dir_dict.items():
            # Skip special keys
            if dir_name.startswith("__"):
                continue
                
            current_path = os.path.join(parent_path, dir_name)
            dir_id = f"dir_{current_path}"
            
            # Count items in this directory
            file_count, subdir_count, nested_count = count_in_directory(dir_content)
            total_items = file_count + subdir_count + nested_count
            
            # Add directory node
            nodes.append({
                "id": dir_id,
                "label": dir_name,
                "type": "Directory",
                "level": level,
                "file_count": file_count,
                "subdir_count": subdir_count,
                "nested_count": nested_count,
                "total_items": total_items,
                "properties": {
                    "path": current_path,
                    "file_count": file_count,
                    "subdir_count": subdir_count,
                    "nested_count": nested_count
                }
            })
            node_ids[dir_id] = True
            
            # Link to parent
            links.append({
                "source": dir_id,
                "target": parent_id,
                "type": "CONTAINS",
                "direction": "backward"
            })
            
            # Add files in this directory (limited to keep visualization manageable)
            for i, file_info in enumerate(dir_content.get("__files", [])[:50]):  # Limit to 50 files per directory
                file_node = file_info.get("node", {})
                file_name = file_info.get("name", "")
                file_id = str(id(file_node))
                
                # Add file node
                nodes.append({
                    "id": file_id,
                    "label": file_name,
                    "type": "File",
                    "level": level + 1,
                    "properties": {k: v for k, v in file_node.items()}
                })
                node_ids[file_id] = True
                
                # Link to directory
                links.append({
                    "source": file_id,
                    "target": dir_id,
                    "type": "CONTAINS",
                    "direction": "backward"
                })
                
                # Find AST nodes for this file
                try:
                    ast_query = """
                    MATCH (ast)-[:PART_OF]->(f:File)
                    WHERE id(f) = $file_id
                    RETURN ast
                    LIMIT 20
                    """
                    ast_results = connector.run_query(ast_query, {"file_id": id(file_node)})
                    
                    for ast_row in ast_results:
                        ast_node = ast_row.get("ast")
                        if ast_node:
                            ast_id = str(id(ast_node))
                            ast_type = [label for label in ["Function", "Class", "Method"] 
                                        if label.lower() in str(ast_node).lower()][0] if any(label.lower() in str(ast_node).lower() 
                                                                                           for label in ["Function", "Class", "Method"]) else "ASTNode"
                            
                            # Add AST node
                            nodes.append({
                                "id": ast_id,
                                "label": ast_node.get("name", "Unknown"),
                                "type": ast_type,
                                "level": level + 2,
                                "properties": {k: v for k, v in ast_node.items()}
                            })
                            node_ids[ast_id] = True
                            
                            # Link to file
                            links.append({
                                "source": ast_id,
                                "target": file_id,
                                "type": "PART_OF"
                            })
                            
                            # Check for code summary
                            try:
                                summary_query = """
                                MATCH (cs:CodeSummary)-[:DESCRIBES]->(ast)
                                WHERE id(ast) = $ast_id
                                RETURN cs
                                LIMIT 1
                                """
                                summary_results = connector.run_query(summary_query, {"ast_id": id(ast_node)})
                                
                                for summary_row in summary_results:
                                    summary_node = summary_row.get("cs")
                                    if summary_node:
                                        summary_id = str(id(summary_node))
                                        
                                        # Add summary node
                                        nodes.append({
                                            "id": summary_id,
                                            "label": f"Summary: {ast_node.get('name', 'Unknown')}",
                                            "type": "CodeSummary",
                                            "level": level + 3,
                                            "properties": {k: v for k, v in summary_node.items()}
                                        })
                                        node_ids[summary_id] = True
                                        
                                        # Link to AST node
                                        links.append({
                                            "source": summary_id,
                                            "target": ast_id,
                                            "type": "DESCRIBES"
                                        })
                            except Exception as e:
                                print(f"Error finding code summary: {e}")
                                
                except Exception as e:
                    print(f"Error finding AST nodes for file: {e}")
            
            # Recursively add subdirectories (up to level 3)
            if level < 3:
                add_directory_nodes(dir_content.get("__subdirs", {}), dir_id, current_path, level + 1)
    
    # Start building from top-level directories
    add_directory_nodes(directories, repo_id)
    
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
        title=f"Hierarchical Visualization: {repository.get('name', 'Repository')}"
    )
    
    print(f"Created hierarchical visualization at {output_path}")
    return 0


if __name__ == "__main__":
    output_path = "hierarchical_visualization.html"
    if len(sys.argv) > 1:
        output_path = sys.argv[1]
    
    sys.exit(create_hierarchical_visualization(output_path))