#\!/usr/bin/env python3
"""Add files to the investigation."""

import sys
from skwaq.db.neo4j_connector import get_connector

def add_files_to_investigation():
    """Add files to the most recent investigation."""
    print("Adding files to investigation...")
    
    # Get the most recent investigation
    connector = get_connector()
    query = """
    MATCH (i:Investigation)
    RETURN i.id as id
    ORDER BY i.created_at DESC
    LIMIT 1
    """
    
    results = connector.run_query(query)
    if not results:
        print("No investigations found\!")
        return 1
    
    investigation_id = results[0]["id"]
    print(f"Found investigation: {investigation_id}")
    
    # Get files
    file_query = """
    MATCH (f:File)
    WHERE NOT f:Directory
    RETURN DISTINCT elementId(f) as file_id, f.path as path
    LIMIT 300
    """
    
    files = connector.run_query(file_query)
    print(f"Found {len(files)} files to include in investigation")
    
    # Link files to investigation
    for i, file in enumerate(files):
        if i % 50 == 0:
            print(f"Adding files to investigation: {i}/{len(files)}")
            
        file_id = file["file_id"]
        
        # Create relationship between investigation and file
        rel_query = """
        MATCH (i:Investigation {id: $investigation_id})
        MATCH (f:File) WHERE elementId(f) = $file_id
        MERGE (i)-[r:INCLUDES]->(f)
        RETURN type(r) as rel_type
        """
        
        connector.run_query(
            rel_query, {"investigation_id": investigation_id, "file_id": file_id}
        )
    
    print(f"Added {len(files)} files to investigation {investigation_id}")
    
    # Count relationships
    count_query = """
    MATCH (i:Investigation {id: $id})-[r:INCLUDES]->()
    RETURN count(r) as rel_count
    """
    
    count_result = connector.run_query(count_query, {"id": investigation_id})
    rel_count = count_result[0]["rel_count"] if count_result else 0
    
    print(f"Total relationships created: {rel_count}")
    
    return 0

if __name__ == "__main__":
    exit_code = add_files_to_investigation()
    sys.exit(exit_code)
