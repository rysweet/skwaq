#\!/usr/bin/env python3
"""Check relationships between nodes in the investigation."""

import sys
from skwaq.db.neo4j_connector import get_connector
from rich.console import Console
from rich.table import Table

console = Console()

def check_investigation_relationships():
    """Check relationships between nodes in the investigation."""
    # Get the most recent investigation
    connector = get_connector()
    query = """
    MATCH (i:Investigation)
    RETURN i.id as id, i.title as title
    ORDER BY i.created_at DESC
    LIMIT 1
    """
    
    results = connector.run_query(query)
    if not results:
        console.print("[bold red]No investigations found\!")
        return 1
    
    investigation_id = results[0]["id"]
    investigation_title = results[0]["title"]
    console.print(f"[bold green]Found investigation: {investigation_id} - {investigation_title}")
    
    # Get files that are included in the investigation
    file_query = """
    MATCH (i:Investigation {id: $id})-[:INCLUDES]->(f:File)
    WHERE NOT f:Directory
    RETURN elementId(f) as file_id, f.path as path
    """
    
    file_results = connector.run_query(file_query, {"id": investigation_id})
    console.print(f"[bold blue]Found {len(file_results)} files in investigation")
    
    # Get AST nodes for these files
    ast_query = """
    MATCH (i:Investigation {id: $id})-[:INCLUDES]->(ast)
    WHERE (ast:Function OR ast:Class OR ast:Method)
    RETURN elementId(ast) as ast_id, ast.name as name, labels(ast)[0] as type
    """
    
    ast_results = connector.run_query(ast_query, {"id": investigation_id})
    console.print(f"[bold blue]Found {len(ast_results)} AST nodes in investigation")
    
    # Check if these AST nodes have DEFINES and PART_OF relationships
    file_ids = [file["file_id"] for file in file_results]
    ast_ids = [ast["ast_id"] for ast in ast_results]
    
    # Check if AST nodes have DEFINES relationships from files
    if ast_ids:
        defines_query = """
        MATCH (file:File)-[:DEFINES]->(ast)
        WHERE elementId(file) IN $file_ids AND elementId(ast) IN $ast_ids
        RETURN count(ast) as count
        """
        
        defines_count = connector.run_query(defines_query, {"file_ids": file_ids, "ast_ids": ast_ids})[0]["count"]
        console.print(f"[bold blue]AST nodes with DEFINES relationships: {defines_count} out of {len(ast_results)}")
    else:
        defines_count = 0
        console.print("[bold yellow]No AST nodes to check for DEFINES relationships")
    
    # Check if AST nodes have PART_OF relationships to files
    if ast_ids:
        part_of_query = """
        MATCH (ast)-[:PART_OF]->(file:File)
        WHERE elementId(file) IN $file_ids AND elementId(ast) IN $ast_ids
        RETURN count(ast) as count
        """
        
        part_of_count = connector.run_query(part_of_query, {"file_ids": file_ids, "ast_ids": ast_ids})[0]["count"]
        console.print(f"[bold blue]AST nodes with PART_OF relationships: {part_of_count} out of {len(ast_results)}")
    else:
        part_of_count = 0
        console.print("[bold yellow]No AST nodes to check for PART_OF relationships")
    
    # Check for AI summary nodes
    summary_query = """
    MATCH (s:CodeSummary)
    RETURN count(s) as count
    """
    
    summary_count = connector.run_query(summary_query)[0]["count"]
    console.print(f"[bold blue]Total AI summary nodes in database: {summary_count}")
    
    # Check for AI summary nodes associated with AST nodes in the investigation
    if ast_ids:
        summary_rel_query = """
        MATCH (summary:CodeSummary)-[r]->(ast)
        WHERE elementId(ast) IN $ast_ids
        RETURN count(summary) as count
        """
        
        summary_rel_count = connector.run_query(summary_rel_query, {"ast_ids": ast_ids})[0]["count"]
        console.print(f"[bold blue]AI summary nodes linked to AST nodes in investigation: {summary_rel_count}")
    else:
        summary_rel_count = 0
        console.print("[bold yellow]No AST nodes to check for AI summary relationships")
    
    # Display summary table
    table = Table(title="Investigation Relationship Summary")
    table.add_column("Relationship Type", style="cyan")
    table.add_column("Count", style="green")
    table.add_column("Percentage", style="yellow")
    
    table.add_row(
        "Files in Investigation",
        str(len(file_results)),
        "100%"
    )
    
    table.add_row(
        "AST Nodes in Investigation",
        str(len(ast_results)),
        "100%"
    )
    
    table.add_row(
        "AST Nodes with DEFINES Relationships",
        str(defines_count),
        f"{defines_count/len(ast_results)*100:.1f}%" if ast_results else "N/A"
    )
    
    table.add_row(
        "AST Nodes with PART_OF Relationships",
        str(part_of_count),
        f"{part_of_count/len(ast_results)*100:.1f}%" if ast_results else "N/A"
    )
    
    table.add_row(
        "AI Summary Nodes in Database",
        str(summary_count),
        "N/A"
    )
    
    table.add_row(
        "AI Summary Nodes Linked to Investigation AST",
        str(summary_rel_count),
        f"{summary_rel_count/len(ast_results)*100:.1f}%" if ast_results else "N/A"
    )
    
    console.print(table)
    
    return 0

if __name__ == "__main__":
    sys.exit(check_investigation_relationships())
