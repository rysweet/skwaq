#!/usr/bin/env python3
"""Test AI summarization functionality."""

import asyncio
import sys
from skwaq.db.neo4j_connector import get_connector
from skwaq.ingestion.summarizers.llm_summarizer import LLMSummarizer
from skwaq.core.openai_client import get_openai_client
from rich.console import Console
from rich.progress import Progress

console = Console()

async def test_summarization():
    """Test AI summarization by directly running the LLM summarizer on AST nodes."""
    # Connect to the database
    connector = get_connector()
    
    # Get the OpenAI client
    try:
        openai_client = get_openai_client(async_mode=True)
        console.print("[bold green]Successfully initialized OpenAI client")
    except Exception as e:
        console.print(f"[bold red]Failed to initialize OpenAI client: {str(e)}")
        return 1
    
    # Initialize the LLM summarizer
    summarizer = LLMSummarizer(connector, openai_client)
    console.print("[bold blue]Initialized LLM summarizer")
    
    # Get a sample of AST nodes to summarize
    query = """
    MATCH (ast:Function)
    WHERE size(ast.code) > 100 AND size(ast.code) < 1000
    RETURN elementId(ast) as id, ast.name as name, ast.code as code
    LIMIT 5
    """
    
    ast_nodes = connector.run_query(query)
    
    if not ast_nodes:
        console.print("[bold yellow]No suitable AST nodes found for summarization")
        
        # Check if AST nodes have code property
        code_query = """
        MATCH (ast:Function)
        WHERE ast.code IS NOT NULL
        RETURN count(ast) as count
        """
        
        code_count = connector.run_query(code_query)[0]["count"]
        console.print(f"[bold blue]AST nodes with code property: {code_count}")
        
        # Check total number of AST nodes
        ast_query = """
        MATCH (ast:Function)
        RETURN count(ast) as count
        """
        
        ast_count = connector.run_query(ast_query)[0]["count"]
        console.print(f"[bold blue]Total Function nodes: {ast_count}")
        
        # Get a sample of AST nodes to see what properties they have
        sample_query = """
        MATCH (ast:Function)
        RETURN elementId(ast) as id, ast.name as name, keys(ast) as properties
        LIMIT 5
        """
        
        samples = connector.run_query(sample_query)
        console.print("[bold yellow]Sample AST node properties:")
        for sample in samples:
            console.print(f"  Node ID: {sample['id']}, Name: {sample['name']}, Properties: {sample['properties']}")
        
        return 1
    
    console.print(f"[bold blue]Found {len(ast_nodes)} AST nodes to summarize")
    
    # Check for existing summaries
    summary_query = """
    MATCH (s:CodeSummary)
    RETURN count(s) as count
    """
    
    summary_count = connector.run_query(summary_query)[0]["count"]
    console.print(f"[bold blue]Existing summary nodes: {summary_count}")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Summarizing AST nodes...", total=len(ast_nodes))
        
        for ast_node in ast_nodes:
            node_id = ast_node["id"]
            node_name = ast_node["name"]
            node_code = ast_node["code"]
            
            if not node_code:
                console.print(f"[bold yellow]No code found for node: {node_name}")
                progress.update(task, advance=1)
                continue
            
            try:
                # First, check if a summary already exists
                exists_query = """
                MATCH (s:CodeSummary)-[:SUMMARIZES]->(ast)
                WHERE elementId(ast) = $ast_id
                RETURN count(s) as count
                """
                
                exists = connector.run_query(exists_query, {"ast_id": node_id})[0]["count"] > 0
                
                if exists:
                    console.print(f"[bold yellow]Summary already exists for node: {node_name}")
                else:
                    # Create a summary
                    await summarizer.summarize_ast_node(node_id, node_name, node_code)
                    console.print(f"[bold green]Created summary for node: {node_name}")
            except Exception as e:
                console.print(f"[bold red]Error summarizing node {node_name}: {str(e)}")
            
            progress.update(task, advance=1)
    
    # Check again for summaries
    summary_query = """
    MATCH (s:CodeSummary)
    RETURN count(s) as count
    """
    
    new_summary_count = connector.run_query(summary_query)[0]["count"]
    console.print(f"[bold green]Summary nodes after test: {new_summary_count}")
    
    # If we successfully created summaries, display a couple examples
    if new_summary_count > summary_count:
        example_query = """
        MATCH (s:CodeSummary)-[:SUMMARIZES]->(ast)
        RETURN s.summary as summary, ast.name as function_name
        LIMIT 2
        """
        
        examples = connector.run_query(example_query)
        
        console.print("[bold green]Example summaries:")
        for example in examples:
            console.print(f"[bold blue]Function: {example['function_name']}")
            console.print(f"[green]Summary: {example['summary']}")
            console.print()
    
    return 0

if __name__ == "__main__":
    sys.exit(asyncio.run(test_summarization()))