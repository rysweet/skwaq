#!/usr/bin/env python3

"""Check for CodeSummary nodes in the database."""

from skwaq.db.neo4j_connector import get_connector

def check_summaries():
    """Check for CodeSummary nodes in the database."""
    connector = get_connector()
    
    # Check for CodeSummary nodes
    summary_query = """
    MATCH (cs:CodeSummary)
    RETURN count(cs) as summary_count
    """
    
    summary_result = connector.run_query(summary_query)
    if summary_result and len(summary_result) > 0:
        summary_count = summary_result[0].get("summary_count", 0)
        print(f"Found {summary_count} CodeSummary nodes in the database")
    
    # Check for AST node types
    ast_query = """
    MATCH (n)
    WHERE (n)-[:PART_OF]->(:File)
    WITH labels(n) AS node_labels, count(*) AS count
    RETURN node_labels, count
    ORDER BY count DESC
    """
    
    ast_result = connector.run_query(ast_query)
    print("\nAST Node label distribution:")
    for row in ast_result:
        labels = row.get("node_labels", [])
        count = row.get("count", 0)
        print(f"  {', '.join(labels)}: {count}")
    
    # Check if any AST nodes have code property
    code_query = """
    MATCH (n)
    WHERE (n)-[:PART_OF]->(:File) AND EXISTS(n.code)
    RETURN count(n) as code_count
    """
    
    code_result = connector.run_query(code_query)
    if code_result and len(code_result) > 0:
        code_count = code_result[0].get("code_count", 0)
        print(f"\nFound {code_count} AST nodes with code property")
    
    # Sample some AST nodes
    sample_query = """
    MATCH (n:Function)-[:PART_OF]->(f:File)
    RETURN n.name as name, f.path as file_path, n.code as code
    LIMIT 5
    """
    
    sample_result = connector.run_query(sample_query)
    print("\nSample Function nodes:")
    for row in sample_result:
        name = row.get("name", "Unknown")
        file_path = row.get("file_path", "Unknown")
        code = row.get("code", "No code available")
        print(f"  Function: {name}")
        print(f"  File: {file_path}")
        print(f"  Code: {code[:100]}..." if len(str(code)) > 100 else f"  Code: {code}")
        print()

if __name__ == "__main__":
    check_summaries()