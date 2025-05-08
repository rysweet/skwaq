#!/usr/bin/env python
"""
Generate AST Summaries

This script generates AI summaries for AST nodes (Functions, Classes, Methods)
in the database that don't have summaries yet.
"""

import argparse
import asyncio
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any

# Add the project root to the Python path
sys.path.append(str(Path(__file__).parent))

from skwaq.core.openai_client import get_openai_client
from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import RelationshipTypes
from skwaq.utils.logging import get_logger
from skwaq.visualization.ast_visualizer import ASTVisualizer

logger = get_logger(__name__)


async def generate_ast_summaries(
    investigation_id: Optional[str] = None,
    repo_id: Optional[str] = None,
    limit: int = 100,
    batch_size: int = 10,
    max_concurrent: int = 3,
) -> Dict[str, int]:
    """Generate summaries for AST nodes without summaries.
    
    Args:
        investigation_id: Optional ID of the investigation to process
        repo_id: Optional ID of the repository to process
        limit: Maximum number of AST nodes to process
        batch_size: Number of AST nodes to process in each batch
        max_concurrent: Maximum number of concurrent summary generation tasks
        
    Returns:
        Dictionary with counts of processed and created summaries
    """
    try:
        # Initialize the database connector
        connector = get_connector()
        
        # Initialize OpenAI client
        openai_client = await get_openai_client(async_mode=True)
        
        # First, check AST nodes and summaries
        visualizer = ASTVisualizer()
        counts = visualizer.check_ast_summaries(investigation_id)
        logger.info(f"Before: {counts}")
        
        # Build query to get AST nodes without summaries
        query = """
        MATCH (ast)
        WHERE (ast:Function OR ast:Class OR ast:Method) 
        AND ast.code IS NOT NULL
        AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
        """
        
        if investigation_id:
            # For a specific investigation
            query += """
            MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
            MATCH (ast)-[:PART_OF]->(file)
            """
            params = {"id": investigation_id}
        elif repo_id:
            # For a specific repository
            query += """
            MATCH (r:Repository)-[:CONTAINS]->(file:File)
            WHERE r.ingestion_id = $repo_id OR elementId(r) = $repo_id
            MATCH (ast)-[:PART_OF]->(file)
            """
            params = {"repo_id": repo_id}
        else:
            # For all AST nodes
            params = {}
        
        query += """
        RETURN 
            elementId(ast) as ast_id, 
            ast.name as name, 
            ast.code as code,
            labels(ast) as labels,
            elementId(file) as file_id,
            file.name as file_name,
            file.path as file_path
        LIMIT $limit
        """
        
        params["limit"] = limit
        
        # Execute the query
        ast_nodes = connector.run_query(query, params)
        logger.info(f"Found {len(ast_nodes)} AST nodes without summaries")
        
        if not ast_nodes:
            return {"processed": 0, "created": 0}
        
        # Set up semaphore to limit concurrent tasks
        semaphore = asyncio.Semaphore(max_concurrent)
        
        # Process AST nodes in batches
        results = {"processed": 0, "created": 0}
        
        for i in range(0, len(ast_nodes), batch_size):
            batch = ast_nodes[i:i + batch_size]
            logger.info(f"Processing batch {i // batch_size + 1}/{(len(ast_nodes) + batch_size - 1) // batch_size}")
            
            # Create tasks for each AST node in the batch
            tasks = []
            for ast_node in batch:
                task = generate_ast_summary(ast_node, connector, openai_client, semaphore)
                tasks.append(task)
            
            # Wait for all tasks in the batch to complete
            batch_results = await asyncio.gather(*tasks)
            
            # Update results
            for result in batch_results:
                if result:
                    results["processed"] += 1
                    if result.get("created"):
                        results["created"] += 1
            
            logger.info(f"Completed batch: {results['created']} summaries created")
        
        # Get final counts
        counts_after = visualizer.check_ast_summaries(investigation_id)
        logger.info(f"After: {counts_after}")
        
        return results
    
    except Exception as e:
        logger.error(f"Error generating AST summaries: {str(e)}")
        import traceback
        traceback.print_exc()
        return {"processed": 0, "created": 0, "error": str(e)}


async def generate_ast_summary(
    ast_node: Dict[str, Any],
    connector: Any,
    model_client: Any,
    semaphore: asyncio.Semaphore,
) -> Optional[Dict[str, Any]]:
    """Generate a summary for a single AST node.
    
    Args:
        ast_node: AST node data from the database
        connector: Database connector
        model_client: OpenAI client for generating summaries
        semaphore: Semaphore for limiting concurrent tasks
        
    Returns:
        Dictionary with result information or None if failed
    """
    async with semaphore:
        try:
            ast_id = ast_node["ast_id"]
            ast_name = ast_node["name"]
            ast_code = ast_node["code"]
            ast_type = ast_node["labels"][0] if ast_node["labels"] else "Unknown"
            file_name = ast_node["file_name"] or "Unknown"
            file_path = ast_node["file_path"] or "Unknown"
            
            if not ast_code or len(ast_code.strip()) < 10:
                logger.debug(f"Skipping AST node {ast_name} due to insufficient code")
                return {"processed": True, "created": False, "reason": "insufficient_code"}
            
            # Create prompt
            ast_prompt = f"""
            You are analyzing a specific {ast_type} from a larger file.
            
            File name: {file_name}
            File path: {file_path}
            {ast_type} name: {ast_name}
            
            Your task is to create a detailed, accurate summary of this {ast_type.lower()}'s:
            1. Purpose and functionality 
            2. Parameters, return values, and important logic
            3. Role within the larger file
            4. Any potential security implications
            5. How it interacts with other components
            
            {ast_type} code:
            ```
            {ast_code}
            ```
            
            Summary:
            """
            
            # Generate summary
            logger.debug(f"Generating summary for AST node: {ast_name}")
            summary_start_time = time.time()
            ast_summary = await model_client.get_completion(
                ast_prompt, temperature=0.3
            )
            summary_time = time.time() - summary_start_time
            
            # Create summary node
            summary_node_id = connector.create_node(
                "CodeSummary",
                {
                    "summary": ast_summary,
                    "file_name": file_name,
                    "ast_node_id": ast_id,  # Store reference to AST node
                    "ast_name": ast_name,
                    "ast_type": ast_type,
                    "created_at": time.time(),
                    "generation_time": summary_time,
                    "summary_type": "ast",  # Mark this as an AST-level summary
                },
            )
            
            # Create relationship to AST node
            connector.create_relationship(
                summary_node_id, ast_id, RelationshipTypes.DESCRIBES
            )
            
            logger.debug(f"Created summary for AST node: {ast_name}")
            return {"processed": True, "created": True, "ast_name": ast_name, "summary_id": summary_node_id}
            
        except Exception as e:
            logger.error(f"Error creating AST summary for {ast_node.get('name', 'unknown')}: {str(e)}")
            return {"processed": True, "created": False, "error": str(e)}


async def main():
    """Command-line interface for generating AST summaries."""
    parser = argparse.ArgumentParser(
        description="Generate AI summaries for AST nodes without summaries"
    )
    parser.add_argument(
        "--investigation",
        "-i",
        help="Investigation ID to generate summaries for",
    )
    parser.add_argument(
        "--repo",
        "-r",
        help="Repository ID to generate summaries for (alternative to investigation)",
    )
    parser.add_argument(
        "--limit",
        "-l",
        type=int,
        default=100,
        help="Maximum number of AST nodes to process (default: 100)",
    )
    parser.add_argument(
        "--batch-size",
        "-b",
        type=int,
        default=10,
        help="Number of AST nodes to process in each batch (default: 10)",
    )
    parser.add_argument(
        "--max-concurrent",
        "-m",
        type=int,
        default=3,
        help="Maximum number of concurrent summary generation tasks (default: 3)",
    )
    parser.add_argument(
        "--check",
        "-c",
        action="store_true",
        help="Only check AST nodes and summaries without generating new summaries",
    )

    args = parser.parse_args()
    
    try:
        if args.check:
            # Check AST nodes and summaries
            visualizer = ASTVisualizer()
            id_to_check = args.investigation or args.repo
            counts = visualizer.check_ast_summaries(id_to_check)
            
            print(f"\nAST Node Summary for {'investigation' if args.investigation else 'repository'} {id_to_check or 'all'}:")
            print(f"AST Nodes: {counts['ast_count']}")
            print(f"AST Nodes with code: {counts['ast_with_code_count']}")
            print(f"Summary count: {counts['summary_count']}")
            print(f"AST nodes with summary: {counts['ast_with_summary_count']}")
            return 0
        
        # Generate AST summaries
        logger.info("Generating AST summaries...")
        result = await generate_ast_summaries(
            investigation_id=args.investigation,
            repo_id=args.repo,
            limit=args.limit,
            batch_size=args.batch_size,
            max_concurrent=args.max_concurrent,
        )
        
        print(f"\nAST Summary Generation Results:")
        print(f"Processed: {result['processed']} AST nodes")
        print(f"Summaries created: {result['created']}")
        
        if result.get("error"):
            print(f"Error: {result['error']}")
            return 1
        
        return 0
    
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    exit_code = asyncio.run(main())
    sys.exit(exit_code)