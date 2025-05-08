#!/usr/bin/env python3
"""Generate AST visualization for a repository."""

import json
from typing import Dict, Any, List

from skwaq.db.neo4j_connector import get_connector

def get_ast_structure(repo_id: str) -> Dict[str, Any]:
    """Get AST structure for a repository."""
    connector = get_connector()
    
    # Get AST node types and counts
    query = """
    MATCH (r:Repository)-[:CONTAINS*]->(f:File)<-[:DEFINED_IN]-(n)
    WHERE r.ingestion_id = $id
    WITH labels(n) AS type, COUNT(n) AS count
    RETURN type, count
    ORDER BY count DESC
    """
    
    ast_types = connector.run_query(query, {"id": repo_id})
    
    # Get method and function nodes
    code_query = """
    MATCH (r:Repository)-[:CONTAINS*]->(f:File)<-[:DEFINED_IN]-(n)
    WHERE r.ingestion_id = $id AND (n:Method OR n:Function OR n:Class)
    RETURN DISTINCT labels(n) as type, n.name as name, f.path as file_path
    LIMIT 1000
    """
    
    code_nodes = connector.run_query(code_query, {"id": repo_id})
    
    # Convert results to useful structure
    type_counts = {}
    for result in ast_types:
        node_type = result["type"][0] if isinstance(result["type"], list) and result["type"] else "Unknown"
        type_counts[node_type] = result["count"]
    
    # Build method/function list
    code_entities = []
    for node in code_nodes:
        node_type = node.get("type", ["Unknown"])[0] if isinstance(node.get("type"), list) else "Unknown"
        code_entities.append({
            "type": node_type,
            "name": node.get("name", "Unnamed"),
            "file_path": node.get("file_path", "Unknown")
        })
    
    return {
        "type_counts": type_counts,
        "code_entities": code_entities
    }

def main():
    """Main function."""
    # Repository ID
    repo_id = "b781d211-b946-4253-9048-3eefd241adf0"
    
    # Get AST structure
    result = get_ast_structure(repo_id)
    
    # Print AST node type statistics
    print("AST Node Types:")
    for node_type, count in result["type_counts"].items():
        print(f"  {node_type}: {count}")
    
    # Create a simple HTML visualization
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AttackBot AST Structure</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #666; margin-top: 20px; }}
            table {{ border-collapse: collapse; width: 100%; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            tr:nth-child(even) {{ background-color: #f9f9f9; }}
            .stats {{ display: flex; flex-wrap: wrap; }}
            .stat-box {{ background-color: #e9f7fe; padding: 15px; margin: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 150px; }}
            .stat-title {{ font-weight: bold; margin-bottom: 10px; }}
            .language-stats {{ max-width: 600px; margin-top: 20px; }}
            .bar {{ height: 20px; background-color: #4a90e2; margin: 5px 0; }}
            .bar-label {{ display: flex; justify-content: space-between; margin-bottom: 2px; }}
            .search-box {{ margin: 20px 0; }}
            input {{ padding: 8px; width: 300px; }}
        </style>
    </head>
    <body>
        <h1>AttackBot AST Structure</h1>
        
        <div class="stats">
    """
    
    # Add stats boxes for each AST node type
    for node_type, count in result["type_counts"].items():
        html_content += f"""
            <div class="stat-box">
                <div class="stat-title">{node_type}</div>
                <div>{count}</div>
            </div>
        """
    
    html_content += """
        </div>
        
        <h2>Code Entities</h2>
        <div class="search-box">
            <input type="text" id="search" placeholder="Search entities...">
        </div>
        <table id="entities-table">
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Name</th>
                    <th>File Path</th>
                </tr>
            </thead>
            <tbody>
    """
    
    # Add rows for code entities
    for entity in result["code_entities"]:
        html_content += f"""
                <tr>
                    <td>{entity["type"]}</td>
                    <td>{entity["name"]}</td>
                    <td>{entity["file_path"]}</td>
                </tr>
        """
    
    html_content += """
            </tbody>
        </table>
        
        <script>
            // Simple search functionality
            document.getElementById('search').addEventListener('keyup', function() {
                const searchText = this.value.toLowerCase();
                const rows = document.querySelectorAll('#entities-table tbody tr');
                
                rows.forEach(row => {
                    const type = row.cells[0].textContent.toLowerCase();
                    const name = row.cells[1].textContent.toLowerCase();
                    const path = row.cells[2].textContent.toLowerCase();
                    
                    if (type.includes(searchText) || name.includes(searchText) || path.includes(searchText)) {
                        row.style.display = '';
                    } else {
                        row.style.display = 'none';
                    }
                });
            });
        </script>
    </body>
    </html>
    """
    
    with open("attackbot_ast_visualization.html", "w") as f:
        f.write(html_content)
    
    print("\nFile saved: attackbot_ast_visualization.html")
    print(f"\nTotal code entities found: {len(result['code_entities'])}")

if __name__ == "__main__":
    main()