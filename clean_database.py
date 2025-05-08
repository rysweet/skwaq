#!/usr/bin/env python3

"""Clean the Neo4j database."""

from skwaq.db.neo4j_connector import get_connector

def clean_database():
    """Delete all nodes and relationships from the database."""
    connector = get_connector()
    
    # Delete all nodes and relationships
    query = """
    MATCH (n)
    DETACH DELETE n
    """
    
    result = connector.run_query(query)
    print("Database cleaned successfully.")

if __name__ == "__main__":
    clean_database()