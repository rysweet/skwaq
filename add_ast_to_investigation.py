#\!/usr/bin/env python3
"""Add AST nodes to investigation based on included files."""

import sys
from skwaq.db.neo4j_connector import get_connector
from rich.console import Console
from rich.progress import Progress

console = Console()

def add_ast_to_investigation():
    """Add AST nodes to the most recent investigation."""
    console.print("[bold cyan]Adding AST nodes to investigation...[/bold cyan]")
    
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
        console.print("[bold red]No investigations found\!")
        return 1
    
    investigation_id = results[0]["id"]
    console.print(f"[bold green]Found investigation: {investigation_id}")
    
    # Get files that are included in the investigation
    file_query = """
    MATCH (i:Investigation {id: $id})-[:INCLUDES]->(f:File)
    RETURN elementId(f) as file_id, f.path as path
    """
    
    file_results = connector.run_query(file_query, {"id": investigation_id})
    console.print(f"[bold blue]Found {len(file_results)} files in investigation")
    
    if not file_results:
        console.print("[bold yellow]No files found in investigation.")
        return 1
    
    # Find AST nodes for these files
    file_ids = [file["file_id"] for file in file_results]
    
    ast_query = """
    MATCH (file)-[:DEFINES]->(ast)
    WHERE elementId(file) IN $file_ids AND (ast:Function OR ast:Class OR ast:Method)
    RETURN file.path as file_path, elementId(file) as file_id,
           ast.name as ast_name, elementId(ast) as ast_id, labels(ast) as ast_labels
    """
    
    ast_results = connector.run_query(ast_query, {"file_ids": file_ids})
    console.print(f"[bold blue]Found {len(ast_results)} AST nodes for files in investigation")
    
    # Find AI summaries for AST nodes
    if ast_results:
        ast_ids = [ast["ast_id"] for ast in ast_results]
        summary_query = """
        MATCH (summary:CodeSummary)-[r]->(ast)
        WHERE elementId(ast) IN $ast_ids
        RETURN summary.summary as summary_text, elementId(summary) as summary_id,
               elementId(ast) as ast_id, type(r) as relationship_type
        """
        
        summary_results = connector.run_query(summary_query, {"ast_ids": ast_ids})
        console.print(f"[bold blue]Found {len(summary_results)} AI summaries for AST nodes")
    else:
        summary_results = []
    
    # Create relationships between investigation and AST nodes
    with Progress() as progress:
        task = progress.add_task("[cyan]Adding AST nodes to investigation...", total=len(ast_results))
        
        for ast in ast_results:
            ast_id = ast["ast_id"]
            
            # Create relationship between investigation and AST node
            rel_query = """
            MATCH (i:Investigation {id: $investigation_id})
            MATCH (ast) WHERE elementId(ast) = $ast_id
            MERGE (i)-[r:INCLUDES]->(ast)
            RETURN type(r) as rel_type
            """
            
            connector.run_query(
                rel_query, {"investigation_id": investigation_id, "ast_id": ast_id}
            )
            
            progress.update(task, advance=1)
    
    # Create relationships between investigation and summary nodes
    if summary_results:
        with Progress() as progress:
            task = progress.add_task("[cyan]Adding AI summaries to investigation...", total=len(summary_results))
            
            for summary in summary_results:
                summary_id = summary["summary_id"]
                
                # Create relationship between investigation and summary node
                rel_query = """
                MATCH (i:Investigation {id: $investigation_id})
                MATCH (summary) WHERE elementId(summary) = $summary_id
                MERGE (i)-[r:INCLUDES]->(summary)
                RETURN type(r) as rel_type
                """
                
                connector.run_query(
                    rel_query, {"investigation_id": investigation_id, "summary_id": summary_id}
                )
                
                progress.update(task, advance=1)
    
    # Count relationships
    count_query = """
    MATCH (i:Investigation {id: $id})-[r:INCLUDES]->()
    RETURN count(r) as rel_count
    """
    
    count_result = connector.run_query(count_query, {"id": investigation_id})
    rel_count = count_result[0]["rel_count"] if count_result else 0
    
    console.print(f"[bold green]Total INCLUDES relationships: {rel_count}")
    
    # Verify AST node connections
    ast_rel_query = """
    MATCH (i:Investigation {id: $id})-[:INCLUDES]->(ast)
    WHERE (ast:Function OR ast:Class OR ast:Method)
    RETURN count(ast) as ast_count
    """
    
    ast_count_result = connector.run_query(ast_rel_query, {"id": investigation_id})
    ast_rel_count = ast_count_result[0]["ast_count"] if ast_count_result else 0
    
    console.print(f"[bold green]AST nodes directly connected to investigation: {ast_rel_count}")
    
    # Verify summary node connections
    summary_rel_query = """
    MATCH (i:Investigation {id: $id})-[:INCLUDES]->(summary:CodeSummary)
    RETURN count(summary) as summary_count
    """
    
    summary_count_result = connector.run_query(summary_rel_query, {"id": investigation_id})
    summary_rel_count = summary_count_result[0]["summary_count"] if summary_count_result else 0
    
    console.print(f"[bold green]AI summary nodes directly connected to investigation: {summary_rel_count}")
    
    return 0

if __name__ == "__main__":
    exit_code = add_ast_to_investigation()
    sys.exit(exit_code)
