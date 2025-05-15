#!/usr/bin/env python3
"""
Generate AI-powered summaries for AST nodes in a codebase.

This script uses Azure OpenAI to generate summaries for AST nodes
(Functions, Classes, Methods) in a specified repository or investigation.

Usage:
    python generate_ast_summaries.py <repo_id_or_investigation_id> [--type <repo|investigation>] [--limit <n>] [--batch-size <n>] [--concurrent <n>] [--visualize]

Options:
    --type TYPE             Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)
    --limit N               Maximum number of AST nodes to process (default: 100)
    --batch-size N          Number of nodes to process in each batch (default: 10)
    --concurrent N          Number of concurrent API calls (default: 3)
    --visualize             Generate visualization after summarization
"""

import argparse
import asyncio
import os
import sys
import time
import webbrowser
from typing import Dict, List, Optional, Any

from skwaq.core.openai_client import get_openai_client
from skwaq.db.neo4j_connector import get_connector
from skwaq.db.schema import RelationshipTypes
from skwaq.utils.logging import get_logger
from skwaq.visualization.ast_visualizer import ASTVisualizer

logger = get_logger(__name__)


async def generate_ast_summaries(
    id_value: str,
    id_type: str = "investigation",
    limit: int = 100,
    batch_size: int = 10,
    max_concurrent: int = 3,
    visualize: bool = False
) -> Dict[str, int]:
    """Generate summaries for AST nodes without summaries.
    
    Args:
        id_value: ID of the repository or investigation
        id_type: Type of ID ('repository' or 'investigation')
        limit: Maximum number of AST nodes to process
        batch_size: Number of nodes to process in each batch
        max_concurrent: Maximum number of concurrent API calls
        visualize: Whether to generate visualization after summarization
        
    Returns:
        Dictionary with counts of processed and created summaries
    """
    # Set up semaphore for concurrent API calls
    semaphore = asyncio.Semaphore(max_concurrent)
    
    try:
        # Get database connector
        connector = get_connector()
        
        # Initialize OpenAI client
        print("Initializing OpenAI client...")
        openai_client = get_openai_client(async_mode=True)
        print("OpenAI client initialized.")
        
        # First, check AST nodes and summaries before processing
        visualizer = ASTVisualizer()
        if id_type == "investigation":
            counts_before = visualizer.check_ast_summaries(id_value)
        else:
            counts_before = visualizer.check_ast_summaries()
        
        logger.info(f"Before generation - AST nodes: {counts_before['ast_count']}, with summaries: {counts_before['ast_with_summary_count']}")
        
        # Build query to get AST nodes without summaries based on ID type
        if id_type == "investigation":
            query = """
            MATCH (i:Investigation {id: $id})-[:HAS_FINDING]->(f:Finding)-[:FOUND_IN]->(file:File)
            MATCH (ast)-[:PART_OF]->(file)
            WHERE (ast:Function OR ast:Class OR ast:Method) 
            AND ast.code IS NOT NULL
            AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
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
            params = {"id": id_value, "limit": limit}
        else:  # repository
            query = """
            MATCH (repo:Repository)-[:CONTAINS*]->(file:File)
            WHERE repo.ingestion_id = $id OR elementId(repo) = $id
            MATCH (ast)-[:PART_OF]->(file)
            WHERE (ast:Function OR ast:Class OR ast:Method) 
            AND ast.code IS NOT NULL
            AND NOT (ast)<-[:DESCRIBES]-(:CodeSummary)
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
            params = {"id": id_value, "limit": limit}
        
        # Execute the query
        print(f"Querying for AST nodes without summaries...")
        ast_nodes = connector.run_query(query, params)
        
        if not ast_nodes:
            print("No AST nodes without summaries found.")
            return {"processed": 0, "created": 0}
        
        print(f"Found {len(ast_nodes)} AST nodes without summaries.")
        
        # Process nodes in batches
        processed = 0
        created = 0
        total_batches = (len(ast_nodes) + batch_size - 1) // batch_size
        
        for batch_index in range(total_batches):
            batch_start = batch_index * batch_size
            batch_end = min(batch_start + batch_size, len(ast_nodes))
            batch = ast_nodes[batch_start:batch_end]
            
            print(f"Processing batch {batch_index + 1}/{total_batches} ({len(batch)} nodes)...")
            
            # Create tasks for each AST node in this batch
            tasks = []
            for ast_node in batch:
                task = generate_ast_summary(
                    ast_node, connector, openai_client, semaphore
                )
                tasks.append(task)
            
            # Run all tasks concurrently with semaphore limiting
            batch_results = await asyncio.gather(*tasks)
            
            # Count successes
            for result in batch_results:
                if result:
                    processed += 1
                    if result.get("created"):
                        created += 1
                        print(f"Created summary for {result.get('ast_type', 'AST node')} '{result.get('ast_name', 'Unknown')}'")
            
            # Progress update
            print(f"Progress: {processed}/{len(ast_nodes)} nodes processed, {created} summaries created")
        
        # Check summary counts after processing
        if id_type == "investigation":
            counts_after = visualizer.check_ast_summaries(id_value)
        else:
            counts_after = visualizer.check_ast_summaries()
        
        logger.info(f"After generation - AST nodes: {counts_after['ast_count']}, with summaries: {counts_after['ast_with_summary_count']}")
        
        # Generate visualization if requested
        if visualize and created > 0:
            print("Generating visualization...")
            try:
                if id_type == "investigation":
                    output_path = f"investigation-{id_value}-ast-summaries-visualization.html"
                    vis_path = visualizer.visualize_ast(
                        investigation_id=id_value,
                        include_files=True,
                        include_summaries=True,
                        output_path=output_path,
                        title=f"AST with Summaries: {id_value}"
                    )
                else:
                    output_path = f"repository-{id_value}-ast-summaries-visualization.html"
                    vis_path = visualizer.visualize_ast(
                        repo_id=id_value,
                        include_files=True,
                        include_summaries=True,
                        output_path=output_path,
                        title=f"AST with Summaries: {id_value}"
                    )
                
                print(f"Visualization created: {vis_path}")
                
                # Try to open in browser
                try:
                    webbrowser.open(f"file://{os.path.abspath(vis_path)}")
                    print(f"Visualization opened in browser")
                except Exception as e:
                    print(f"Could not open browser: {str(e)}")
                    print(f"Please open the file manually: {os.path.abspath(vis_path)}")
                    
            except Exception as e:
                print(f"Error creating visualization: {str(e)}")
        
        return {"processed": processed, "created": created}
        
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
            return {"processed": True, "created": True, "ast_name": ast_name, "ast_type": ast_type, "summary_id": summary_node_id}
            
        except Exception as e:
            logger.error(f"Error creating AST summary for {ast_node.get('name', 'unknown')}: {str(e)}")
            return {"processed": True, "created": False, "error": str(e)}


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate AI-powered summaries for AST nodes in a codebase."
    )
    parser.add_argument(
        "id", 
        help="Repository ID or Investigation ID to process"
    )
    parser.add_argument(
        "--type", 
        choices=["repo", "investigation"],
        help="Specify the input ID type: 'repo' or 'investigation' (default: auto-detect)"
    )
    parser.add_argument(
        "--limit", 
        type=int, 
        default=100,
        help="Maximum number of AST nodes to process (default: 100)"
    )
    parser.add_argument(
        "--batch-size", 
        type=int, 
        default=10,
        help="Number of nodes to process in each batch (default: 10)"
    )
    parser.add_argument(
        "--concurrent", 
        type=int, 
        default=3,
        help="Number of concurrent API calls (default: 3)"
    )
    parser.add_argument(
        "--visualize", 
        action="store_true",
        help="Generate visualization after summarization"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Only check AST nodes and summaries without generating new summaries"
    )
    
    args = parser.parse_args()
    
    # Determine ID type if not specified
    id_type = args.type
    input_id = args.id
    
    if not id_type:
        # Auto-detect ID type based on format
        if input_id.startswith("inv-"):
            id_type = "investigation"
            print(f"Auto-detected ID type: investigation (ID: {input_id})")
        else:
            id_type = "repo"
            print(f"Auto-detected ID type: repository (ID: {input_id})")
    
    try:
        if args.check:
            # Just check AST nodes and summaries without generating new ones
            visualizer = ASTVisualizer()
            if id_type == "investigation":
                counts = visualizer.check_ast_summaries(input_id)
            else:
                # For repo, we'll look at all AST nodes since there's no direct way to query by repo ID
                counts = visualizer.check_ast_summaries()
                
            print(f"\nAST Node Summary for {id_type} {input_id}:")
            print(f"AST Nodes: {counts['ast_count']}")
            print(f"AST Nodes with code: {counts['ast_with_code_count']}")
            print(f"AI summaries: {counts['summary_count']}")
            print(f"AST nodes with summaries: {counts['ast_with_summary_count']}")
            return 0
            
        # Run the summarization process
        print(f"Generating AST summaries for {id_type} {input_id}...")
        
        result = asyncio.run(
            generate_ast_summaries(
                id_value=input_id,
                id_type=id_type,
                limit=args.limit,
                batch_size=args.batch_size,
                max_concurrent=args.concurrent,
                visualize=args.visualize
            )
        )
        
        print(f"\nAST Summary Generation Results:")
        print(f"Processed: {result['processed']} AST nodes")
        print(f"Summaries created: {result['created']}")
        
        if result.get("error"):
            print(f"Error: {result['error']}")
            return 1
            
        return 0
        
    except Exception as e:
        print(f"Error generating summaries: {str(e)}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())