#\!/usr/bin/env python3
"""Check PART_OF and DEFINES relationships between AST nodes and files."""

import sys
from skwaq.db.neo4j_connector import get_connector

def check_relationships():
    """Check for PART_OF and DEFINES relationships."""
    print("Checking AST node relationships...")
    
    # Get the database connector
    connector = get_connector()
    
    # Count AST nodes
    ast_count_query = """
    MATCH (n) WHERE n:Function OR n:Class OR n:Method
    RETURN count(n) as ast_count
    """
    ast_count = connector.run_query(ast_count_query)[0]["ast_count"]
    print(f"Total AST nodes: {ast_count}")
    
    # Count PART_OF relationships
    part_of_query = """
    MATCH (ast)-[:PART_OF]->(file:File)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as part_of_count
    """
    part_of_count = connector.run_query(part_of_query)[0]["part_of_count"]
    print(f"Nodes with PART_OF relationships: {part_of_count}")
    
    # Count DEFINES relationships
    defines_query = """
    MATCH (file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as defines_count
    """
    defines_count = connector.run_query(defines_query)[0]["defines_count"]
    print(f"Nodes with DEFINES relationships: {defines_count}")
    
    # Check for nodes with both relationships
    both_rel_query = """
    MATCH (ast)-[:PART_OF]->(file:File)-[:DEFINES]->(ast)
    WHERE ast:Function OR ast:Class OR ast:Method
    RETURN count(ast) as both_count
    """
    both_count = connector.run_query(both_rel_query)[0]["both_count"]
    print(f"Nodes with both relationships: {both_count}")
    
    # Add missing PART_OF relationships if needed
    if part_of_count < defines_count:
        print(f"\nMissing {defines_count - part_of_count} PART_OF relationships")
        
        # Get AST nodes with DEFINES but no PART_OF
        missing_part_of_query = """
        MATCH (file:File)-[:DEFINES]->(ast)
        WHERE (ast:Function OR ast:Class OR ast:Method) AND NOT (ast)-[:PART_OF]->(:File)
        RETURN elementId(file) as file_id, elementId(ast) as ast_id
        LIMIT 1000
        """
        
        missing_part_of = connector.run_query(missing_part_of_query)
        print(f"Found {len(missing_part_of)} nodes missing PART_OF relationships")
        
        # Add missing PART_OF relationships
        if missing_part_of:
            print("Adding missing PART_OF relationships...")
            
            for i, rel in enumerate(missing_part_of):
                if i % 100 == 0:
                    print(f"Progress: {i}/{len(missing_part_of)}")
                    
                # Create PART_OF relationship
                add_query = """
                MATCH (ast) WHERE elementId(ast) = $ast_id
                MATCH (file) WHERE elementId(file) = $file_id
                MERGE (ast)-[r:PART_OF]->(file)
                RETURN type(r) as rel_type
                """
                
                connector.run_query(add_query, {"ast_id": rel["ast_id"], "file_id": rel["file_id"]})
    
    # Add missing DEFINES relationships if needed
    if defines_count < part_of_count:
        print(f"\nMissing {part_of_count - defines_count} DEFINES relationships")
        
        # Get AST nodes with PART_OF but no DEFINES
        missing_defines_query = """
        MATCH (ast)-[:PART_OF]->(file:File)
        WHERE (ast:Function OR ast:Class OR ast:Method) AND NOT (file)-[:DEFINES]->(ast)
        RETURN elementId(file) as file_id, elementId(ast) as ast_id
        LIMIT 1000
        """
        
        missing_defines = connector.run_query(missing_defines_query)
        print(f"Found {len(missing_defines)} nodes missing DEFINES relationships")
        
        # Add missing DEFINES relationships
        if missing_defines:
            print("Adding missing DEFINES relationships...")
            
            for i, rel in enumerate(missing_defines):
                if i % 100 == 0:
                    print(f"Progress: {i}/{len(missing_defines)}")
                    
                # Create DEFINES relationship
                add_query = """
                MATCH (ast) WHERE elementId(ast) = $ast_id
                MATCH (file) WHERE elementId(file) = $file_id
                MERGE (file)-[r:DEFINES]->(ast)
                RETURN type(r) as rel_type
                """
                
                connector.run_query(add_query, {"ast_id": rel["ast_id"], "file_id": rel["file_id"]})
    
    # Check relationships after fixes
    if part_of_count < defines_count or defines_count < part_of_count:
        # Count PART_OF relationships
        part_of_count = connector.run_query(part_of_query)[0]["part_of_count"]
        print(f"Nodes with PART_OF relationships (after fix): {part_of_count}")
        
        # Count DEFINES relationships
        defines_count = connector.run_query(defines_query)[0]["defines_count"]
        print(f"Nodes with DEFINES relationships (after fix): {defines_count}")
        
        # Check for nodes with both relationships
        both_count = connector.run_query(both_rel_query)[0]["both_count"]
        print(f"Nodes with both relationships (after fix): {both_count}")
    
    print("\nRelationship check complete\!")
    
    return 0

if __name__ == "__main__":
    sys.exit(check_relationships())
