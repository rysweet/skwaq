"""
Check if AST nodes have the code property and diagnose summarization issues.
"""

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional

from skwaq.core.openai_client import get_openai_client, test_openai_connection
from skwaq.db.neo4j_connector import get_connector
from skwaq.ingestion.summarizers.llm_summarizer import LLMSummarizer
from skwaq.utils.config import get_config
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

async def check_ast_code_property():
    """Check if AST nodes have the code property required for summarization."""
    try:
        connector = get_connector()
        print("Connected to Neo4j database")
        
        # Check if Function nodes have code property
        query = """
        MATCH (n) 
        WHERE n:Function OR n:Class OR n:Method
        RETURN 
            labels(n) as labels,
            n.name as name, 
            n.path as path,
            n.code as code,
            elementId(n) as id
        LIMIT 10
        """
        
        results = connector.run_query(query)
        
        print(f"Found {len(results)} AST nodes")
        
        for i, result in enumerate(results):
            node_type = ", ".join(result["labels"])
            print(f"\nNode {i+1} ({node_type}):")
            print(f"  Name: {result['name']}")
            print(f"  Path: {result['path']}")
            print(f"  Has code property: {result['code'] is not None}")
            if result['code'] is not None:
                print(f"  Code length: {len(result['code'])} characters")
                print(f"  Code snippet: {result['code'][:100]}...")
            
        # Check for existing CodeSummary nodes
        summary_query = """
        MATCH (s:CodeSummary)
        RETURN count(s) as count
        """
        
        summary_count = connector.run_query(summary_query)[0]["count"]
        print(f"\nFound {summary_count} CodeSummary nodes in the database")
        
        # Check relationships between files and AST nodes
        relationship_query = """
        MATCH (n)-[r:PART_OF]->(f:File)
        WHERE n:Function OR n:Class OR n:Method
        RETURN count(r) as rel_count
        """
        
        rel_count = connector.run_query(relationship_query)[0]["rel_count"]
        print(f"Found {rel_count} PART_OF relationships from AST nodes to files")
        
        return results, summary_count, rel_count
        
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None, 0, 0

async def test_summarization():
    """Test if the summarizer can generate summaries."""
    # First test OpenAI connection
    print("\nTesting OpenAI connection:")
    connection_ok = await test_openai_connection()
    
    if not connection_ok:
        print("Error: Failed to connect to OpenAI API")
        print("Please check your OpenAI API configuration and credentials")
        return False
    
    print("OpenAI connection successful!")
    
    # Get OpenAI client
    try:
        config = get_config()
        print(f"\nOpenAI configuration:")
        print(f"  API type: {config.openai.get('api_type', 'not set')}")
        print(f"  API version: {config.openai.get('api_version', 'not set')}")
        print(f"  Model: {config.openai.get('chat_model', 'not set')}")
        print(f"  Has API key: {bool(config.openai_api_key)}")
        print(f"  Has org ID: {bool(config.openai_org_id)}")
        
        model_client = get_openai_client(async_mode=True)
        
        # Test if we can get a simple completion
        print("\nTesting simple completion:")
        test_prompt = "Return only the word 'SUCCESS' if you can see this message."
        response = await model_client.get_completion(test_prompt, temperature=0.0)
        
        print(f"Response: {response}")
        
        if "SUCCESS" in response:
            print("Completion test successful!")
        else:
            print("Warning: Test completion returned unexpected response")
            
        # Initialize the summarizer
        print("\nInitializing LLM summarizer...")
        summarizer = LLMSummarizer()
        summarizer.configure(model_client=model_client, max_parallel=1)
        
        # Test summarizing a code snippet
        test_code = """
        def test_function():
            \"\"\"This is a test function.\"\"\"
            print("Hello, world!")
            return True
        """
        
        print("Testing manual summarization with sample code...")
        # Create a custom prompt
        prompt = summarizer._create_summary_prompt(
            file_name="test_function.py",
            content=test_code,
            language="python"
        )
        
        print("Calling OpenAI to generate summary...")
        summary = await model_client.get_completion(prompt, temperature=0.3)
        
        print("\nTest summary result:")
        print(summary)
        
        return True
    
    except Exception as e:
        print(f"Error testing summarization: {e}")
        import traceback
        traceback.print_exc()
        return False
    
async def analyze_ast_nodes_in_db():
    """Analyze AST nodes in the database and check if they can be summarized."""
    try:
        connector = get_connector()
        
        # Get repository node
        repo_query = """
        MATCH (r:Repository)
        RETURN elementId(r) as id, r.name as name
        LIMIT 1
        """
        
        repos = connector.run_query(repo_query)
        if not repos:
            print("No repository found in the database")
            return None
        
        repo_id = repos[0]["id"]
        repo_name = repos[0]["name"]
        print(f"\nFound repository: {repo_name} (ID: {repo_id})")
        
        # Get AST nodes with code property
        ast_query = """
        MATCH (n)
        WHERE (n:Function OR n:Class OR n:Method) AND n.code IS NOT NULL
        RETURN 
            labels(n) as labels,
            n.name as name, 
            elementId(n) as id,
            size(n.code) as code_size
        LIMIT 10
        """
        
        ast_nodes = connector.run_query(ast_query)
        print(f"Found {len(ast_nodes)} AST nodes with code property")
        
        # Get AST nodes without code property
        missing_code_query = """
        MATCH (n)
        WHERE (n:Function OR n:Class OR n:Method) AND n.code IS NULL
        RETURN 
            labels(n) as labels,
            n.name as name, 
            elementId(n) as id
        LIMIT 10
        """
        
        missing_code = connector.run_query(missing_code_query)
        print(f"Found {len(missing_code)} AST nodes without code property")
        
        # Count total AST nodes
        count_query = """
        MATCH (n)
        WHERE n:Function OR n:Class OR n:Method
        RETURN count(n) as total
        """
        
        total_ast = connector.run_query(count_query)[0]["total"]
        print(f"Total AST nodes in database: {total_ast}")
        
        # Calculate percentage with code property
        if total_ast > 0:
            with_code_query = """
            MATCH (n)
            WHERE (n:Function OR n:Class OR n:Method) AND n.code IS NOT NULL
            RETURN count(n) as with_code
            """
            
            with_code = connector.run_query(with_code_query)[0]["with_code"]
            percentage = (with_code / total_ast) * 100
            print(f"Percentage of AST nodes with code property: {percentage:.2f}%")
        
        return {
            "repo_id": repo_id,
            "repo_name": repo_name,
            "ast_with_code": ast_nodes,
            "ast_without_code": missing_code,
            "total_ast": total_ast
        }
        
    except Exception as e:
        print(f"Error analyzing AST nodes: {e}")
        import traceback
        traceback.print_exc()
        return None

async def main():
    print("Checking for AST nodes with code property...")
    nodes, summary_count, rel_count = await check_ast_code_property()
    
    if nodes is None:
        print("Failed to query AST nodes. Make sure Neo4j is running and properly configured.")
        return
    
    print("\nAnalyzing AST nodes in database...")
    ast_analysis = await analyze_ast_nodes_in_db()
    
    print("\nTesting OpenAI integration and summarization...")
    summarization_ok = await test_summarization()
    
    print("\n================ DIAGNOSIS ================")
    if summary_count == 0:
        print("Issue: No CodeSummary nodes found in the database")
        
        # Check if AST nodes have code property
        if nodes and all(node["code"] is None for node in nodes):
            print("Problem: AST nodes are missing the code property required for summarization")
            print("Solution: Fix the AST mapper to ensure code content is extracted and stored in AST nodes")
        else:
            if summarization_ok:
                print("Code property and OpenAI integration both seem to be working")
                print("Problem: Summarization process is not being triggered or completed during ingestion")
                print("Check if parse_only flag is set to True in the ingestion process")
            else:
                print("Problem: OpenAI integration is not working properly")
                print("Check your OpenAI API configuration and credentials")
    else:
        print(f"Found {summary_count} CodeSummary nodes in the database")
        print("Code summaries exist, but may not be properly displayed in the visualization")
    
    print("===========================================")

if __name__ == "__main__":
    asyncio.run(main())