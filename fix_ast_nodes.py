"""
Fix AST nodes to ensure they have the code property required for summarization.
This script extracts code from files and updates AST nodes with the corresponding code.
"""

import asyncio
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from skwaq.db.neo4j_connector import get_connector
from skwaq.ingestion.filesystem import CodebaseFileSystem
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

async def fix_ast_nodes(codebase_path: str):
    """Fix AST nodes by adding code property from corresponding files.
    
    Args:
        codebase_path: Path to the codebase that was ingested
    """
    try:
        connector = get_connector()
        print(f"Connected to Neo4j database")
        
        # Check if the codebase path exists
        if not os.path.exists(codebase_path):
            print(f"Error: Codebase path {codebase_path} does not exist")
            return False
        
        print(f"Using codebase at: {codebase_path}")
        
        # Create filesystem interface
        fs = CodebaseFileSystem(codebase_path)
        
        # Get repository node
        repo_query = """
        MATCH (r:Repository)
        RETURN elementId(r) as id, r.name as name, r.path as path
        LIMIT 1
        """
        
        repos = connector.run_query(repo_query)
        if not repos:
            print("No repository found in the database")
            return False
        
        repo_id = repos[0]["id"]
        repo_name = repos[0]["name"]
        print(f"Found repository: {repo_name} (ID: {repo_id})")
        
        # Get all file nodes
        file_query = """
        MATCH (f:File)
        RETURN f.path as path, elementId(f) as id
        """
        
        file_nodes = connector.run_query(file_query)
        print(f"Found {len(file_nodes)} file nodes")
        
        # Build a map of file paths to IDs
        file_map = {file_node["path"]: file_node["id"] for file_node in file_nodes}
        
        # Get AST nodes that need code property
        ast_query = """
        MATCH (n)-[:PART_OF]->(f:File)
        WHERE (n:Function OR n:Class OR n:Method) AND n.code IS NULL
        RETURN 
            labels(n) as labels,
            n.name as name, 
            n.path as path,
            elementId(n) as id,
            f.path as file_path,
            elementId(f) as file_id,
            n.start_line as start_line,
            n.end_line as end_line
        """
        
        ast_nodes = connector.run_query(ast_query)
        print(f"Found {len(ast_nodes)} AST nodes without code property")
        
        # Count how many nodes we update
        updated_count = 0
        failed_count = 0
        
        # Process each AST node
        for node in ast_nodes:
            node_id = node["id"]
            file_path = node["file_path"]
            start_line = node.get("start_line")
            end_line = node.get("end_line")
            
            # Skip nodes without line information
            if start_line is None or end_line is None:
                print(f"Skipping node {node['name']} - missing line information")
                failed_count += 1
                continue
            
            try:
                # Try to find the complete file path
                full_paths = [path for path in fs.get_all_files() if path.endswith(file_path)]
                
                if not full_paths:
                    print(f"File not found for {file_path}")
                    failed_count += 1
                    continue
                
                full_path = full_paths[0]
                
                # Read the file content
                content = fs.read_file(full_path)
                
                if not content:
                    print(f"Could not read content from {full_path}")
                    failed_count += 1
                    continue
                
                # Split into lines and extract the relevant portion
                lines = content.split('\n')
                
                # Adjust line numbers (1-based to 0-based index)
                start_idx = max(0, start_line - 1)
                end_idx = min(len(lines), end_line)
                
                # Extract the code
                code_lines = lines[start_idx:end_idx]
                code = '\n'.join(code_lines)
                
                if not code.strip():
                    print(f"Empty code extracted for {node['name']} in {file_path}")
                    failed_count += 1
                    continue
                
                # Update the AST node with the code
                update_query = """
                MATCH (n)
                WHERE elementId(n) = $node_id
                SET n.code = $code
                RETURN n.name as name
                """
                
                result = connector.run_query(update_query, {"node_id": node_id, "code": code})
                
                if result:
                    updated_count += 1
                    if updated_count % 100 == 0:
                        print(f"Updated {updated_count} nodes...")
                
            except Exception as e:
                print(f"Error processing node {node['name']}: {e}")
                failed_count += 1
        
        print(f"\nUpdate complete:")
        print(f"- {updated_count} nodes updated with code property")
        print(f"- {failed_count} nodes failed to update")
        
        # Verify updated nodes
        verify_query = """
        MATCH (n)
        WHERE (n:Function OR n:Class OR n:Method)
        RETURN 
            count(n) as total,
            count(n.code) as with_code
        """
        
        verify = connector.run_query(verify_query)[0]
        print(f"\nVerification:")
        print(f"- Total AST nodes: {verify['total']}")
        print(f"- Nodes with code property: {verify['with_code']}")
        print(f"- Percentage complete: {(verify['with_code'] / verify['total']) * 100:.2f}%")
        
        return updated_count > 0
        
    except Exception as e:
        print(f"Error fixing AST nodes: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    if len(sys.argv) < 2:
        print("Usage: python fix_ast_nodes.py <codebase_path>")
        sys.exit(1)
    
    codebase_path = sys.argv[1]
    print(f"Starting to fix AST nodes for codebase at: {codebase_path}")
    
    success = await fix_ast_nodes(codebase_path)
    
    if success:
        print("\nSuccessfully updated AST nodes with code property")
        print("You can now run the summarization process with the updated nodes")
    else:
        print("\nFailed to update AST nodes")
        print("Please check the error messages above")

if __name__ == "__main__":
    asyncio.run(main())