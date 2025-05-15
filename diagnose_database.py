"""
Diagnose database issues to understand why AST nodes don't have code property
and why AI summaries aren't being generated.
"""

import os
import sys
import subprocess
import json
from pathlib import Path

def run_neo4j_query(query, params=None):
    """Run a Neo4j query using the neo4j-client command line tool."""
    try:
        # Check if neo4j is available
        try:
            cmd = ["cypher-shell", "-u", "neo4j", "-p", "password", "-d", "neo4j", 
                   f"MATCH (n) RETURN COUNT(n) as count LIMIT 1"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if "count" in result.stdout:
                print("Connected to Neo4j database using cypher-shell")
                
                # Run the actual query
                query_cmd = ["cypher-shell", "-u", "neo4j", "-p", "password", "-d", "neo4j", 
                           f"{query}"]
                query_result = subprocess.run(query_cmd, capture_output=True, text=True)
                return query_result.stdout
        except:
            # Try using neo4j-client as fallback
            cmd = ["neo4j-client", "-u", "neo4j", "-p", "password", "localhost:7687", 
                   f"MATCH (n) RETURN COUNT(n) as count LIMIT 1"]
            result = subprocess.run(cmd, capture_output=True, text=True)
            if "count" in result.stdout:
                print("Connected to Neo4j database using neo4j-client")
                
                # Run the actual query
                query_cmd = ["neo4j-client", "-u", "neo4j", "-p", "password", "localhost:7687", 
                           f"{query}"]
                query_result = subprocess.run(query_cmd, capture_output=True, text=True)
                return query_result.stdout
    except Exception as e:
        print(f"Error connecting to Neo4j database: {e}")
        return None

def check_ast_nodes():
    """Check if AST nodes have code property."""
    print("Checking AST nodes for code property...")
    
    query = """
    MATCH (n) 
    WHERE n:Function OR n:Class OR n:Method
    RETURN 
        labels(n) as labels,
        n.name as name, 
        n.path as path,
        n.code as code,
        id(n) as id
    LIMIT 10
    """
    
    result = run_neo4j_query(query)
    
    if result:
        print(result)
        return True
    else:
        print("Failed to query AST nodes")
        return False

def check_summaries():
    """Check for CodeSummary nodes in the database."""
    print("Checking for CodeSummary nodes...")
    
    query = """
    MATCH (s:CodeSummary)
    RETURN count(s) as count
    """
    
    result = run_neo4j_query(query)
    
    if result:
        print(result)
        return True
    else:
        print("Failed to query CodeSummary nodes")
        return False

def check_relationships():
    """Check relationships between AST nodes and files."""
    print("Checking relationships between AST nodes and files...")
    
    query = """
    MATCH (n)-[r:PART_OF]->(f:File)
    WHERE n:Function OR n:Class OR n:Method
    RETURN count(r) as rel_count
    """
    
    result = run_neo4j_query(query)
    
    if result:
        print(result)
        
        # Check bidirectional relationships
        query2 = """
        MATCH (f:File)-[r:DEFINES]->(n)
        WHERE n:Function OR n:Class OR n:Method
        RETURN count(r) as rel_count
        """
        
        result2 = run_neo4j_query(query2)
        
        if result2:
            print("DEFINES relationships:")
            print(result2)
        
        return True
    else:
        print("Failed to query relationships")
        return False

def check_openai_config():
    """Check OpenAI configuration."""
    print("Checking OpenAI configuration...")
    
    # Check environment variables
    openai_vars = {
        "OPENAI_API_KEY": os.environ.get("OPENAI_API_KEY"),
        "AZURE_OPENAI_API_KEY": os.environ.get("AZURE_OPENAI_API_KEY"),
        "AZURE_OPENAI_ENDPOINT": os.environ.get("AZURE_OPENAI_ENDPOINT"),
        "AZURE_OPENAI_API_VERSION": os.environ.get("AZURE_OPENAI_API_VERSION"),
    }
    
    print("OpenAI Environment Variables:")
    for var, value in openai_vars.items():
        if value:
            print(f"  {var}: {'*' * 10}")  # Don't print actual keys
        else:
            print(f"  {var}: Not set")
    
    # Check config file
    config_path = Path("/Users/ryan/src/msechackathon/vuln-researcher/config/default_config.json")
    
    if config_path.exists():
        try:
            with open(config_path) as f:
                config = json.load(f)
            
            print("\nConfig file:")
            if "openai" in config:
                openai_config = config["openai"]
                for key, value in openai_config.items():
                    print(f"  {key}: {value}")
            else:
                print("  No OpenAI configuration found in config file")
        except Exception as e:
            print(f"Error reading config file: {e}")
    else:
        print(f"Config file not found at {config_path}")
    
    return True

def main():
    print("Starting database diagnosis...")
    
    # Check AST nodes
    check_ast_nodes()
    
    # Check CodeSummary nodes
    check_summaries()
    
    # Check relationships
    check_relationships()
    
    # Check OpenAI configuration
    check_openai_config()
    
    print("Diagnosis complete")

if __name__ == "__main__":
    main()