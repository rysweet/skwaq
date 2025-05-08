#!/usr/bin/env python3
"""Check if AST nodes have both PART_OF and DEFINES relationships."""

from skwaq.db.neo4j_connector import get_connector

def check_ast_relationships():
    """Check if AST nodes have both PART_OF and DEFINES relationships."""
    connector = get_connector()
    
    # Count AST nodes
    ast_count_query = """
    MATCH (n) WHERE n:Function OR n:Class OR n:Method
    RETURN count(n) as ast_count
    """
    ast_count = connector.run_query(ast_count_query)[0]["ast_count"]
    
    # Count PART_OF relationships
    part_of_query = """
    MATCH (ast)-[:PART_OF]->(file:File)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as part_of_count
    """
    part_of_count = connector.run_query(part_of_query)[0]["part_of_count"]
    
    # Count DEFINES relationships
    defines_query = """
    MATCH (file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as defines_count
    """
    defines_count = connector.run_query(defines_query)[0]["defines_count"]
    
    # Check AI summaries
    summary_query = """
    MATCH (s:CodeSummary)-[r]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(s) as summary_count, type(r) as rel_type
    """
    summary_results = connector.run_query(summary_query)
    summary_count = summary_results[0]["summary_count"] if summary_results else 0
    
    # Check for nodes with both relationships
    both_rel_query = """
    MATCH (ast)-[:PART_OF]->(file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as both_count
    """
    both_count = connector.run_query(both_rel_query)[0]["both_count"]
    
    print(f"Total AST nodes: {ast_count}")
    print(f"Nodes with PART_OF relationships: {part_of_count}")
    print(f"Nodes with DEFINES relationships: {defines_count}")
    print(f"Nodes with both relationships: {both_count}")
    print(f"AI summary nodes: {summary_count}")
    
    return {
        "ast_count": ast_count,
        "part_of_count": part_of_count,
        "defines_count": defines_count,
        "summary_count": summary_count,
        "both_count": both_count
    }

if __name__ == "__main__":
    check_ast_relationships()