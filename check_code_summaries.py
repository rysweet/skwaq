#!/usr/bin/env python3
"""Script to check for code summaries in the repository."""

import json
import sys
from typing import Dict, Any, List

from skwaq.db.neo4j_connector import get_connector
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

def check_code_summaries(repo_id: str) -> Dict[str, Any]:
    """Check for code summaries in the repository.
    
    Args:
        repo_id: Repository ingestion ID
        
    Returns:
        Dictionary with summary information
    """
    connector = get_connector()
    
    print(f"Checking code summaries for repository {repo_id}")
    
    # Get repository information
    query = """
    MATCH (r:Repository {ingestion_id: $id})
    RETURN r.name as name, r.ingestion_start_time as start_time
    """
    
    repo_results = connector.run_query(query, {"id": repo_id})
    
    if not repo_results:
        print(f"Repository with ID {repo_id} not found")
        return {}
    
    repo_name = repo_results[0]["name"]
    start_time = repo_results[0]["start_time"]
    
    print(f"Repository: {repo_name}")
    print(f"Ingestion started: {start_time}")
    
    # Count files
    file_query = """
    MATCH (r:Repository {ingestion_id: $id})-[:CONTAINS*]->(f:File)
    RETURN count(f) as file_count
    """
    
    file_results = connector.run_query(file_query, {"id": repo_id})
    file_count = file_results[0]["file_count"] if file_results else 0
    
    print(f"Total files: {file_count}")
    
    # Check AST structures
    ast_query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (n)-[:DEFINED_IN]->(:File)-[:PART_OF*]->(r)
    WHERE n:Function OR n:Method OR n:Class
    RETURN count(n) as ast_count, collect(distinct labels(n)) as node_types
    """
    
    ast_results = connector.run_query(ast_query, {"id": repo_id})
    ast_count = ast_results[0]["ast_count"] if ast_results else 0
    
    node_types = []
    if ast_results and ast_results[0]["node_types"]:
        for types in ast_results[0]["node_types"]:
            node_types.extend(types)
        node_types = list(set(node_types))
    
    print(f"AST nodes: {ast_count}")
    print(f"AST node types: {', '.join(node_types)}")
    
    # Check for code summaries
    summary_query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary)
    RETURN count(s) as summary_count
    """
    
    summary_results = connector.run_query(summary_query, {"id": repo_id})
    summary_count = summary_results[0]["summary_count"] if summary_results else 0
    
    print(f"Code summaries: {summary_count}")
    
    # Get AST nodes with summaries
    ast_summary_query = """
    MATCH (r:Repository {ingestion_id: $id})
    MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary), (n)-[:DEFINED_IN]->(f:File)
    RETURN count(distinct n) as nodes_with_summaries
    """
    
    ast_summary_results = connector.run_query(ast_summary_query, {"id": repo_id})
    ast_summary_count = ast_summary_results[0]["nodes_with_summaries"] if ast_summary_results else 0
    
    print(f"AST nodes with summaries: {ast_summary_count}")
    
    if summary_count > 0:
        # Get some sample summaries
        sample_query = """
        MATCH (r:Repository {ingestion_id: $id})
        MATCH (n)-[:HAS_SUMMARY]->(s:CodeSummary), (n)-[:DEFINED_IN]->(f:File)
        RETURN distinct labels(n) as node_type, n.name as name, f.path as file_path, s.summary as summary
        LIMIT 5
        """
        
        sample_results = connector.run_query(sample_query, {"id": repo_id})
        
        print("\nSample summaries:")
        for result in sample_results:
            node_type = result["node_type"][0] if result["node_type"] else "Unknown"
            name = result["name"] or "Unnamed"
            file_path = result["file_path"] or "Unknown path"
            summary = result["summary"] or "No summary"
            print(f"  {node_type} '{name}' in {file_path}")
            print(f"    Summary: {summary[:100]}..." if len(summary) > 100 else f"    Summary: {summary}")
            print()
    
    return {
        "repository": repo_name,
        "files": file_count,
        "ast_nodes": ast_count,
        "code_summaries": summary_count,
        "ast_nodes_with_summaries": ast_summary_count
    }

def check_ast_structure(repo_id: str) -> Dict[str, Any]:
    """Check the AST structure in the repository.
    
    Args:
        repo_id: Repository ingestion ID
        
    Returns:
        Dictionary with AST structure information
    """
    connector = get_connector()
    
    print(f"\nChecking AST structure for repository {repo_id}")
    
    # Get AST node types and counts
    query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (n)-[:DEFINED_IN]->(:File)-[:PART_OF*]->(r)
    WHERE n:Function OR n:Method OR n:Class
    WITH labels(n) as node_type, count(n) as count
    RETURN node_type, count
    ORDER BY count DESC
    """
    
    ast_results = connector.run_query(query, {"id": repo_id})
    
    ast_counts = {}
    for result in ast_results:
        node_type = result["node_type"][0] if result["node_type"] else "Unknown"
        ast_counts[node_type] = result["count"]
    
    print("AST node types and counts:")
    for node_type, count in ast_counts.items():
        print(f"  {node_type}: {count}")
    
    # Check the AST hierarchy
    hierarchy_query = """
    MATCH (r:Repository {ingestion_id: $id})
    OPTIONAL MATCH (c:Class)-[:DEFINED_IN]->(f:File)-[:PART_OF*]->(r)
    OPTIONAL MATCH (m:Method)-[:DEFINED_IN]->(c)
    RETURN count(c) as class_count, count(m) as method_in_class_count
    """
    
    hierarchy_results = connector.run_query(hierarchy_query, {"id": repo_id})
    class_count = hierarchy_results[0]["class_count"] if hierarchy_results else 0
    method_in_class_count = hierarchy_results[0]["method_in_class_count"] if hierarchy_results else 0
    
    print(f"\nClass count: {class_count}")
    print(f"Methods in classes: {method_in_class_count}")
    
    # Check orphaned methods
    orphaned_query = """
    MATCH (r:Repository {ingestion_id: $id})
    MATCH (m:Method)-[:DEFINED_IN]->(f:File)-[:PART_OF*]->(r)
    WHERE NOT (m)-[:DEFINED_IN]->(:Class)
    RETURN count(m) as orphaned_method_count
    """
    
    orphaned_results = connector.run_query(orphaned_query, {"id": repo_id})
    orphaned_method_count = orphaned_results[0]["orphaned_method_count"] if orphaned_results else 0
    
    print(f"Orphaned methods: {orphaned_method_count}")
    
    return {
        "ast_counts": ast_counts,
        "class_count": class_count,
        "method_in_class_count": method_in_class_count,
        "orphaned_method_count": orphaned_method_count
    }

def main():
    """Main function."""
    if len(sys.argv) < 2:
        print("Usage: python check_code_summaries.py <repository_id>")
        
        # List repositories
        connector = get_connector()
        query = """
        MATCH (r:Repository)
        RETURN r.ingestion_id as id, r.name as name
        """
        
        repo_results = connector.run_query(query)
        
        if repo_results:
            print("\nAvailable repositories:")
            for result in repo_results:
                print(f"  {result['name']}: {result['id']}")
        
        sys.exit(1)
    
    repo_id = sys.argv[1]
    
    # Check code summaries
    summary_info = check_code_summaries(repo_id)
    
    # Check AST structure
    ast_info = check_ast_structure(repo_id)
    
    # Combine results
    results = {
        **summary_info,
        "ast_structure": ast_info
    }
    
    # Save to JSON
    output_path = f"code_summary_info_{repo_id}.json"
    with open(output_path, "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to {output_path}")

if __name__ == "__main__":
    main()