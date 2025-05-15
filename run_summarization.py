"""
Run the AI summarization process on AST nodes with code property.
"""

import asyncio
import os
import sys
from typing import Any, Dict, List, Optional

from skwaq.core.openai_client import get_openai_client
from skwaq.db.neo4j_connector import get_connector
from skwaq.ingestion.filesystem import CodebaseFileSystem
from skwaq.ingestion.summarizers import get_summarizer
from skwaq.utils.logging import get_logger

logger = get_logger(__name__)

async def run_summarization(codebase_path: str, max_parallel: int = 1):
    """Run the AI summarization process on AST nodes with code property.
    
    Args:
        codebase_path: Path to the codebase that was ingested
        max_parallel: Maximum number of parallel summarization tasks
    """
    try:
        connector = get_connector()
        print(f"Connected to Neo4j database")
        
        # Check if the codebase path exists
        if not os.path.exists(codebase_path):
            print(f"Error: Codebase path {codebase_path} does not exist")
            return False
        
        print(f"Using codebase at: {codebase_path}")
        
        # Create filesystem interface
        fs = CodebaseFileSystem(codebase_path)
        
        # Get repository node
        repo_query = """
        MATCH (r:Repository)
        RETURN elementId(r) as id, r.name as name
        LIMIT 1
        """
        
        repos = connector.run_query(repo_query)
        if not repos:
            print("No repository found in the database")
            return False
        
        repo_id = repos[0]["id"]
        repo_name = repos[0]["name"]
        print(f"Found repository: {repo_name} (ID: {repo_id})")
        
        # Get file nodes with AST nodes that have code property
        file_query = """
        MATCH (f:File)<-[:PART_OF]-(n)
        WHERE (n:Function OR n:Class OR n:Method) AND n.code IS NOT NULL
        RETURN DISTINCT
            elementId(f) as file_id,
            f.path as path,
            f.language as language
        """
        
        file_nodes = connector.run_query(file_query)
        print(f"Found {len(file_nodes)} file nodes with AST nodes that have code property")
        
        # Initialize the OpenAI client
        print("Initializing OpenAI client...")
        model_client = get_openai_client(async_mode=True)
        
        # Test the OpenAI connection
        test_prompt = "Return only the word 'OK' if you can see this message."
        response = await model_client.get_completion(test_prompt, temperature=0.0)
        
        if "OK" not in response:
            print(f"Error: OpenAI connection test failed. Response: {response}")
            return False
        
        print("OpenAI connection test successful")
        
        # Get the LLM summarizer
        summarizer = get_summarizer("llm")
        if not summarizer:
            print("Error: LLM summarizer not found")
            return False
        
        # Configure the summarizer
        summarizer.configure(
            model_client=model_client,
            max_parallel=max_parallel,
            context_token_limit=20000,
        )
        
        print(f"Starting summarization process with {max_parallel} parallel tasks...")
        
        # Create a progress counter
        processed = 0
        
        # Run the summarization
        summary_result = await summarizer.summarize_files(
            file_nodes, fs, repo_id
        )
        
        # Print results
        print("\nSummarization complete:")
        print(f"- Files processed: {summary_result.get('files_processed', 0)}")
        print(f"- Errors: {len(summary_result.get('errors', []))}")
        
        if summary_result.get('stats'):
            stats = summary_result['stats']
            print("\nStatistics:")
            print(f"- Total time: {stats.get('total_time', 0):.2f} seconds")
            print(f"- Total tokens: {stats.get('total_tokens', 0)}")
            print(f"- Errors: {stats.get('errors', 0)}")
        
        # Verify CodeSummary nodes
        verify_query = """
        MATCH (s:CodeSummary)
        RETURN count(s) as count
        """
        
        summary_count = connector.run_query(verify_query)[0]["count"]
        print(f"\nFound {summary_count} CodeSummary nodes in the database after summarization")
        
        return summary_count > 0
        
    except Exception as e:
        print(f"Error running summarization: {e}")
        import traceback
        traceback.print_exc()
        return False

async def main():
    if len(sys.argv) < 2:
        print("Usage: python run_summarization.py <codebase_path> [max_parallel]")
        sys.exit(1)
    
    codebase_path = sys.argv[1]
    max_parallel = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    
    print(f"Starting summarization for codebase at: {codebase_path}")
    print(f"Using {max_parallel} parallel summarization tasks")
    
    success = await run_summarization(codebase_path, max_parallel)
    
    if success:
        print("\nSuccessfully created code summaries")
        print("You can now visualize the codebase with AI summaries")
    else:
        print("\nFailed to create code summaries")
        print("Please check the error messages above")

if __name__ == "__main__":
    asyncio.run(main())