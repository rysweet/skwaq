#!/usr/bin/env python3
"""Query Neo4j to examine AST to file node relationships."""

import asyncio
import json
from skwaq.db.neo4j_connector import get_connector

async def main():
    """Run queries to examine AST to file node mapping."""
    connector = get_connector()
    
    # Query 1: Get all file nodes
    print("\n=== File Nodes ===")
    query = "MATCH (f:File) RETURN f.name as name, f.path as path, elementId(f) as id"
    result = connector.run_query(query)
    print(f"Found {len(result)} file nodes:")
    for r in result:
        print(f"  ID: {r['id']}, Name: {r['name']}, Path: {r['path']}")
    
    # Query 2: Get all AST nodes
    print("\n=== AST Nodes ===")
    query = "MATCH (n) WHERE n:Function OR n:Class OR n:Method RETURN labels(n) as labels, n.name as name, elementId(n) as id"
    result = connector.run_query(query)
    print(f"Found {len(result)} AST nodes:")
    for r in result:
        print(f"  ID: {r['id']}, Name: {r['name']}, Labels: {r['labels']}")
    
    # Query 3: Get all relationships between AST nodes and files
    print("\n=== AST-File Relationships ===")
    query = """
    MATCH (ast)-[r:PART_OF]->(file:File)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN type(r) as rel_type, elementId(ast) as ast_id, elementId(file) as file_id, 
           ast.name as ast_name, file.name as file_name
    """
    result = connector.run_query(query)
    print(f"Found {len(result)} AST-file relationships:")
    for r in result:
        print(f"  {r['ast_name']} ({r['ast_id']}) --[{r['rel_type']}]--> {r['file_name']} ({r['file_id']})")
    
    # Query 4: Get all relationships between files and AST nodes (reverse direction)
    print("\n=== File-AST Relationships (Reverse) ===")
    query = """
    MATCH (file:File)-[r:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN type(r) as rel_type, elementId(file) as file_id, elementId(ast) as ast_id, 
           file.name as file_name, ast.name as ast_name
    """
    result = connector.run_query(query)
    print(f"Found {len(result)} file-AST relationships:")
    for r in result:
        print(f"  {r['file_name']} ({r['file_id']}) --[{r['rel_type']}]--> {r['ast_name']} ({r['ast_id']})")
    
    # Query 5: Count AST nodes without file relationships
    print("\n=== AST Nodes Without File Relationships ===")
    query = """
    MATCH (ast)
    WHERE (ast:Function OR ast:Class OR ast:Method)
    AND NOT (ast)-[:PART_OF]->(:File)
    RETURN labels(ast) as labels, ast.name as name, elementId(ast) as id
    """
    result = connector.run_query(query)
    print(f"Found {len(result)} AST nodes without file relationships:")
    for r in result:
        print(f"  ID: {r['id']}, Name: {r['name']}, Labels: {r['labels']}")
    
    # Query 6: Get properties of AST nodes
    print("\n=== AST Node Properties ===")
    query = """
    MATCH (ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN elementId(ast) as id, ast.name as name, ast.file_path as file_path, ast.path as path, ast.full_path as full_path
    """
    result = connector.run_query(query)
    print(f"AST node properties:")
    for r in result:
        print(f"  ID: {r['id']}, Name: {r['name']}")
        print(f"    file_path: {r['file_path']}")
        print(f"    path: {r['path']}")
        print(f"    full_path: {r['full_path']}")

if __name__ == "__main__":
    asyncio.run(main())