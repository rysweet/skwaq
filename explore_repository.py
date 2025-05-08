#!/usr/bin/env python3
"""Generate a visualization of the repository structure."""

import json
import os
from typing import Dict, Any, List

from skwaq.db.neo4j_connector import get_connector

def get_directory_structure(repo_id: str) -> Dict[str, Any]:
    """Get directory and file structure for a repository."""
    connector = get_connector()
    
    # First get the repository node
    query = """
    MATCH (r:Repository)
    WHERE r.ingestion_id = $id
    RETURN elementId(r) as id, r.name as name, r.ingestion_id as ingestion_id
    """
    
    repo_result = connector.run_query(query, {"id": repo_id})
    if not repo_result:
        print(f"Repository with ID {repo_id} not found")
        return {"nodes": [], "links": []}
    
    repo = repo_result[0]
    repo_node_id = repo["id"]
    
    # Get directory nodes
    dir_query = """
    MATCH (r:Repository)-[:CONTAINS*]->(d:Directory)
    WHERE elementId(r) = $repo_id
    RETURN elementId(d) as id, d.path as path, d.name as name
    """
    
    dir_results = connector.run_query(dir_query, {"repo_id": repo_node_id})
    
    # Get file nodes
    file_query = """
    MATCH (r:Repository)-[:CONTAINS*]->(f:File)
    WHERE elementId(r) = $repo_id
    RETURN elementId(f) as id, f.path as path, f.name as name, f.language as language
    """
    
    file_results = connector.run_query(file_query, {"repo_id": repo_node_id})
    
    # Create a simple directory structure
    structure = {
        "name": repo["name"],
        "type": "repository",
        "id": repo["ingestion_id"],
        "children": []
    }
    
    # Build path-based tree
    paths = {}
    for dir_node in dir_results:
        if dir_node["path"]:
            paths[dir_node["path"]] = {
                "name": dir_node["name"],
                "type": "directory",
                "path": dir_node["path"],
                "children": []
            }
    
    # Add files to their parent directories
    for file_node in file_results:
        if file_node["path"]:
            parent_path = os.path.dirname(file_node["path"])
            file_obj = {
                "name": file_node["name"],
                "type": "file",
                "path": file_node["path"],
                "language": file_node["language"]
            }
            
            if parent_path in paths:
                paths[parent_path]["children"].append(file_obj)
            else:
                # If parent directory not found, add directly to repository
                structure["children"].append(file_obj)
    
    # Build hierarchy by connecting child directories to parents
    for path, dir_obj in paths.items():
        parent_path = os.path.dirname(path)
        if parent_path in paths:
            paths[parent_path]["children"].append(dir_obj)
        else:
            # If parent directory not found, add to repository root
            structure["children"].append(dir_obj)
    
    # Count different node types
    node_counts = {
        "repository": 1,
        "directory": len(dir_results),
        "file": len(file_results)
    }
    
    # Get language statistics
    languages = {}
    for file_node in file_results:
        lang = file_node.get("language")
        if lang:
            languages[lang] = languages.get(lang, 0) + 1
    
    return {
        "structure": structure,
        "counts": node_counts,
        "languages": languages
    }

def main():
    """Main function."""
    # Repository ID
    repo_id = "b781d211-b946-4253-9048-3eefd241adf0"
    
    # Get repository structure
    result = get_directory_structure(repo_id)
    
    # Print statistics
    print("Repository Structure:")
    for node_type, count in result["counts"].items():
        print(f"  {node_type}: {count}")
    
    print("\nLanguage Statistics:")
    languages = sorted(result["languages"].items(), key=lambda x: x[1], reverse=True)
    for language, count in languages:
        print(f"  {language}: {count}")
    
    # Save to JSON file
    with open("attackbot_repository_structure.json", "w") as f:
        json.dump(result["structure"], f, indent=2)
    
    # Create a simple HTML visualization
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <title>AttackBot Repository Structure</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            h2 {{ color: #666; margin-top: 20px; }}
            pre {{ background-color: #f5f5f5; padding: 10px; border-radius: 5px; overflow: auto; max-height: 600px; }}
            .stats {{ display: flex; flex-wrap: wrap; }}
            .stat-box {{ background-color: #e9f7fe; padding: 15px; margin: 10px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); min-width: 200px; }}
            .stat-title {{ font-weight: bold; margin-bottom: 10px; }}
            .language-stats {{ max-width: 600px; margin-top: 20px; }}
            .bar {{ height: 20px; background-color: #4a90e2; margin: 5px 0; }}
            .bar-label {{ display: flex; justify-content: space-between; margin-bottom: 2px; }}
        </style>
    </head>
    <body>
        <h1>AttackBot Repository Structure</h1>
        
        <div class="stats">
            <div class="stat-box">
                <div class="stat-title">Repository</div>
                <div>{result["counts"]["repository"]}</div>
            </div>
            <div class="stat-box">
                <div class="stat-title">Directories</div>
                <div>{result["counts"]["directory"]}</div>
            </div>
            <div class="stat-box">
                <div class="stat-title">Files</div>
                <div>{result["counts"]["file"]}</div>
            </div>
        </div>
        
        <h2>Language Distribution</h2>
        <div class="language-stats">
    """
    
    # Calculate maximum language count for scale
    max_count = max(result["languages"].values()) if result["languages"] else 1
    
    # Add language bars
    for language, count in languages[:10]:  # Top 10 languages
        percentage = (count / max_count) * 100
        html_content += f"""
            <div class="bar-label">
                <span>{language}</span>
                <span>{count} files</span>
            </div>
            <div class="bar" style="width: {percentage}%;"></div>
        """
    
    html_content += """
        </div>
        
        <h2>Directory Structure</h2>
        <pre id="structure"></pre>
        
        <script>
            // Load and display the structure
            fetch('attackbot_repository_structure.json')
                .then(response => response.json())
                .then(data => {
                    document.getElementById('structure').textContent = JSON.stringify(data, null, 2);
                });
        </script>
    </body>
    </html>
    """
    
    with open("attackbot_repository_visualization.html", "w") as f:
        f.write(html_content)
    
    print("\nFiles saved:")
    print("  - attackbot_repository_structure.json")
    print("  - attackbot_repository_visualization.html")

if __name__ == "__main__":
    main()